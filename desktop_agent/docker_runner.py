"""
Docker-раннер с security flags (ТЗ раздел 6, SECURITY_RUNNER.md).

Флаги: --network=none, --read-only, tmpfs /tmp, seccomp, uid=65534,
image whitelist, resource limits, audit log.
"""
from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import time
from typing import Callable, Dict, List, Optional, Tuple

RunnerResult = Tuple[int, str, str, List[Dict]]

LOG = logging.getLogger("docker_runner")

DOCKER_IMAGE_WHITELIST = os.environ.get("DOCKER_RUNNER_IMAGE_WHITELIST", "").split(",")
DOCKER_RUNNER_UID = int(os.environ.get("DOCKER_RUNNER_UID", "65534"))
DOCKER_RUNNER_CPUS = os.environ.get("DOCKER_RUNNER_CPUS", "2")
DOCKER_RUNNER_MEMORY = os.environ.get("DOCKER_RUNNER_MEMORY", "4g")


def _is_image_allowed(image: str) -> bool:
    if not DOCKER_IMAGE_WHITELIST or not DOCKER_IMAGE_WHITELIST[0]:
        return True  # MVP: whitelist пуст — разрешаем всё
    return any(img.strip() in image for img in DOCKER_IMAGE_WHITELIST if img.strip())


def run_docker_task(
    task: Dict,
    cfg: Dict,
    push_log: Callable[[str], None],
    progress_callback: Optional[Callable],
    timeout_seconds: int,
    should_stop: Optional[Callable[[], bool]] = None,
) -> RunnerResult:
    """
    Запуск задачи в Docker с security flags.

    Требует: benchmark_meta.runner.image, entry_point, args.
    """
    benchmark_meta = task.get("benchmark_meta") or {}
    runner = benchmark_meta.get("runner") or {}
    image = (runner.get("image") or benchmark_meta.get("image") or "").strip()
    if not image:
        raise ValueError("Docker runner requires benchmark_meta.runner.image")
    if not _is_image_allowed(image):
        raise ValueError(f"Image {image} not in whitelist")

    entry_point = runner.get("entry_point") or benchmark_meta.get("entry_point") or ""
    args_list = runner.get("args") or benchmark_meta.get("args") or []
    if isinstance(args_list, str):
        args_list = [args_list]
    contract_id = task.get("contract_id", "")
    job_id = task.get("job_id", "")
    seed = task.get("task_seed") or f"{cfg.get('client_id', '')}-{contract_id}"
    work_units = int(task.get("work_units_required") or 0)

    fmt = {
        "seed": seed,
        "contract_id": contract_id,
        "job_id": job_id,
        "client_id": cfg.get("client_id", ""),
        "steps": work_units,
    }
    args_str = [str(a).format(**fmt) for a in args_list] if args_list else []

    seccomp_path = os.path.join(os.path.dirname(__file__), "runner-seccomp.json")
    cmd = [
        "docker", "run",
        "--network=none",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
        "--user", f"{DOCKER_RUNNER_UID}:{DOCKER_RUNNER_UID}",
        "--cpus", DOCKER_RUNNER_CPUS,
        "--memory", DOCKER_RUNNER_MEMORY,
        "--rm",
    ]
    if os.path.isfile(seccomp_path):
        cmd.extend(["--security-opt", f"seccomp={seccomp_path}"])
    cmd.extend([image, entry_point or "run", *args_str])
    push_log(f"Docker runner: {' '.join(cmd[:12])}...")
    LOG.info("docker_run_start image=%s job=%s", image, job_id)

    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        while proc.poll() is None:
            elapsed = int(time.monotonic() - started)
            if should_stop and should_stop():
                proc.kill()
                raise InterruptedError("Agent stop requested")
            if progress_callback:
                progress_callback(min(elapsed, max(1, timeout_seconds - 1)), timeout_seconds)
            if elapsed >= timeout_seconds:
                proc.kill()
                raise TimeoutError(f"Docker runner timed out after {timeout_seconds}s")
            time.sleep(2)
        stdout, stderr = proc.communicate()
    except FileNotFoundError:
        raise RuntimeError("Docker not found. Install Docker or use python_compute/external runner.")

    output = (stdout or "") + "\n" + (stderr or "")
    output_hash = hashlib.sha256(output.encode("utf-8", errors="ignore")).hexdigest()
    if proc.returncode != 0:
        tail = "\n".join(output.strip().splitlines()[-5:])
        raise RuntimeError(f"Docker exited {proc.returncode}. Tail:\n{tail}")

    LOG.info("docker_run_done image=%s job=%s hash=%s", image, job_id, output_hash[:16])
    artifacts = [{"name": "stdout.log", "sha256": output_hash, "uri": "local://docker-stdout", "size_bytes": len(output.encode())}]
    return work_units, output_hash, str(seed), artifacts
