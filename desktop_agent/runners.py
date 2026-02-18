import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import time
from typing import Callable, Dict, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from shared.computation_types import COMPUTATION_TYPES, compute_simple_pow, deterministic_seed


RunnerResult = Tuple[int, str, str]


def _safe_seed(task: Dict, client_id: str, contract_id: str) -> int:
    task_seed = task.get("task_seed")
    if task_seed is None:
        return deterministic_seed(client_id, contract_id)
    try:
        return int(task_seed)
    except (TypeError, ValueError):
        return deterministic_seed(client_id, contract_id)


def _run_python_compute(task: Dict, cfg: Dict, push_log: Callable[[str], None], progress_callback) -> RunnerResult:
    contract_id = task["contract_id"]
    target_work = int(task["work_units_required"])
    difficulty = int(task.get("difficulty", 0))
    computation_type = task.get("computation_type", "simple_pow")
    compute_func = COMPUTATION_TYPES.get(computation_type) or compute_simple_pow
    if computation_type == "simple_pow":
        result_data, nonce = compute_func(
            cfg["client_id"],
            contract_id,
            target_work,
            difficulty,
            seed=task.get("task_seed"),
            progress_callback=progress_callback,
        )
        return target_work, result_data, nonce
    seed = _safe_seed(task, cfg["client_id"], contract_id)
    result_data, computed_seed = compute_func(
        cfg["client_id"], contract_id, target_work, seed=seed, progress_callback=progress_callback
    )
    return target_work, result_data, (computed_seed if computed_seed else str(seed))


def _run_external(
    task: Dict,
    cfg: Dict,
    push_log: Callable[[str], None],
    timeout_seconds: int,
    progress_callback,
) -> RunnerResult:
    benchmark_meta = task.get("benchmark_meta") if isinstance(task.get("benchmark_meta"), dict) else {}
    runner = benchmark_meta.get("runner") if isinstance(benchmark_meta.get("runner"), dict) else {}
    command_template = (
        runner.get("command")
        or runner.get("command_template")
        or benchmark_meta.get("command")
        or benchmark_meta.get("command_template")
    )
    if not command_template:
        raise ValueError("Runner command template is required for external engine")
    contract_id = task.get("contract_id", "")
    seed = _safe_seed(task, cfg["client_id"], contract_id)
    work_units = int(task.get("work_units_required") or 0)
    input_file = benchmark_meta.get("input_file") or ""
    out_prefix = f"{contract_id}-{cfg.get('device_id', 'device')}-{task.get('job_id', 'job')}"
    fmt = {
        "input_tpr": input_file,
        "input_file": input_file,
        "steps": work_units,
        "seed": seed,
        "out_prefix": out_prefix,
        "contract_id": contract_id,
        "job_id": task.get("job_id", ""),
        "client_id": cfg.get("client_id", ""),
    }
    command = command_template.format(**fmt)
    args = shlex.split(command)
    if not args:
        raise ValueError("Runner command resolved to empty command")
    binary = args[0]
    if shutil.which(binary) is None:
        raise ValueError(f"Runner binary not found in PATH: {binary}")
    push_log(f"External runner: {' '.join(args)}")
    timeout_seconds = max(30, int(timeout_seconds))
    started = time.monotonic()
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=os.getcwd(),
    )
    while proc.poll() is None:
        elapsed = int(time.monotonic() - started)
        if progress_callback:
            progress_callback(min(elapsed, max(1, timeout_seconds - 1)), timeout_seconds)
        if elapsed >= timeout_seconds:
            proc.kill()
            raise TimeoutError(f"Runner timed out after {timeout_seconds} seconds")
        time.sleep(2)
    stdout, stderr = proc.communicate()
    output = (stdout or "") + "\n" + (stderr or "")
    output_hash = hashlib.sha256(output.encode("utf-8", errors="ignore")).hexdigest()
    if proc.returncode != 0:
        tail = "\n".join(output.strip().splitlines()[-5:])
        raise RuntimeError(f"Runner exited with code {proc.returncode}. Tail:\n{tail}")
    return int(task.get("work_units_required") or 0), output_hash, str(seed)


def run_task(task: Dict, cfg: Dict, push_log: Callable[[str], None], progress_callback, submit_timeout_seconds: int):
    benchmark_meta = task.get("benchmark_meta") if isinstance(task.get("benchmark_meta"), dict) else {}
    runner = benchmark_meta.get("runner") if isinstance(benchmark_meta.get("runner"), dict) else {}
    engine = (
        runner.get("engine")
        or benchmark_meta.get("engine")
        or ("python_compute" if not benchmark_meta else "")
    ).strip()
    if engine in ("", "python_compute"):
        return _run_python_compute(task, cfg, push_log, progress_callback)
    if engine in ("python_cli", "gromacs"):
        return _run_external(task, cfg, push_log, submit_timeout_seconds, progress_callback)
    raise ValueError(f"Unsupported runner engine: {engine}")
