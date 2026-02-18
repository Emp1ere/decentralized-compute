import os
import sys
import threading
import time
import json

from api import ApiClient
from runners import run_task


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

AGENT_VERSION = "0.3.0"
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_state.json")


def in_schedule_window(now_struct, start_hhmm, end_hhmm):
    if not start_hhmm or not end_hhmm:
        return True
    try:
        sh, sm = [int(x) for x in start_hhmm.split(":")]
        eh, em = [int(x) for x in end_hhmm.split(":")]
    except (ValueError, TypeError):
        return True
    current = now_struct.tm_hour * 60 + now_struct.tm_min
    start_minutes = sh * 60 + sm
    end_minutes = eh * 60 + em
    if start_minutes == end_minutes:
        return True
    if start_minutes < end_minutes:
        return start_minutes <= current < end_minutes
    return current >= start_minutes or current < end_minutes


class DesktopAgent:
    def __init__(self, push_log):
        self.push_log = push_log
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.current_job_id = None
        self.last_task_snapshot = None
        self.last_heartbeat_at = 0.0

    def _write_state(self, state):
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
        except OSError:
            return

    def _clear_state(self):
        self.last_task_snapshot = None
        self._write_state({"status": "idle", "updated_at": int(time.time())})

    def is_running(self):
        return self.worker_thread is not None and self.worker_thread.is_alive()

    def start(self, cfg):
        if self.is_running():
            self.push_log("Агент уже запущен.")
            return
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._loop, args=(cfg,), daemon=False)
        self.worker_thread.start()
        self.push_log("Агент запущен.")

    def stop(self):
        self.stop_event.set()
        if self.last_task_snapshot:
            snapshot = dict(self.last_task_snapshot)
            snapshot["status"] = "stopping"
            snapshot["updated_at"] = int(time.time())
            self._write_state(snapshot)
        self.push_log("Остановка агента...")

    def _heartbeat(self, api, cfg):
        if not self.current_job_id:
            return
        now = time.time()
        profile = ((self.last_task_snapshot or {}).get("task_profile") or {})
        min_interval = max(2, int(profile.get("recommended_heartbeat_seconds", 20) or 20))
        if now - self.last_heartbeat_at < min_interval:
            return
        try:
            api.request("POST", f"/agent/job/{self.current_job_id}/heartbeat", payload={}, timeout=3)
        except Exception:
            return
        self.last_heartbeat_at = now
        try:
            api.request(
                "POST",
                "/agent/devices/heartbeat",
                payload={
                    "device_id": cfg.get("device_id"),
                    "agent_version": AGENT_VERSION,
                    "device_capabilities": cfg.get("device_capabilities") or {},
                },
                timeout=3,
            )
        except Exception:
            return

    def _fetch_task(self, api, cfg):
        payload = {
            # Передаём capabilities/profile, чтобы оркестратор применил policy matching/ranking.
            "device_capabilities": cfg.get("device_capabilities") or {},
            "scheduler_profile": cfg.get("scheduler_profile", "adaptive"),
        }
        if cfg.get("sector_id"):
            payload["sector_id"] = cfg["sector_id"]
        if cfg.get("contract_id"):
            payload["contract_id"] = cfg["contract_id"]
        return api.request("POST", "/agent/get_task", payload=payload, timeout=15)

    def _compute(self, api, cfg, task):
        contract_id = task["contract_id"]
        target_work = int(task["work_units_required"])
        computation_type = task.get("computation_type", "simple_pow")
        throttle = max(0, min(95, int(cfg.get("throttle_percent", 0) or 0)))
        submit_timeout = int(((task.get("task_profile") or {}).get("recommended_submit_timeout_seconds") or 900))
        validation_policy = task.get("validation_policy") if isinstance(task.get("validation_policy"), dict) else {}
        escrow_policy = task.get("escrow_policy") if isinstance(task.get("escrow_policy"), dict) else {}
        self.push_log(
            f"Выполнение: contract={contract_id} type={computation_type} units={target_work} job={task.get('job_id')}"
        )
        if validation_policy:
            mode = validation_policy.get("mode", "deterministic")
            repl = validation_policy.get("replication_factor", 1)
            self.push_log(f"Validation policy: mode={mode}, replication={repl}")
        if escrow_policy and escrow_policy.get("enabled"):
            self.push_log(
                f"Escrow policy: collateral={escrow_policy.get('worker_collateral', 0)}, "
                f"penalty={escrow_policy.get('penalty_percent_on_reject', 0)}%"
            )

        def progress(cur, total):
            if total:
                pct = int(cur * 100 / total)
                self.push_log(f"Прогресс {contract_id}: {pct}%")
                if self.last_task_snapshot is not None:
                    self.last_task_snapshot["progress_pct"] = pct
                    self.last_task_snapshot["updated_at"] = int(time.time())
                    self._write_state(self.last_task_snapshot)
            self._heartbeat(api, cfg)
            if throttle > 0:
                time.sleep(throttle / 100.0)

        return run_task(
            task=task,
            cfg=cfg,
            push_log=self.push_log,
            progress_callback=progress,
            submit_timeout_seconds=submit_timeout,
        )

    def _check_updates(self, api):
        try:
            payload = api.public_get("/agent/version", timeout=5)
            latest = (payload.get("latest_version") or "").strip()
            if latest and latest != AGENT_VERSION:
                self.push_log(
                    f"Доступна новая версия desktop-agent: {latest} (текущая {AGENT_VERSION}). "
                    f"Скачивание: {payload.get('download_url', '/download/desktop-agent')}"
                )
        except Exception:
            return

    def _loop(self, cfg):
        api = ApiClient(cfg["base_url"], cfg["api_key"], cfg["verify_ssl"])
        self._write_state({"status": "starting", "updated_at": int(time.time())})
        while not self.stop_event.is_set():
            now = time.localtime()
            if not in_schedule_window(now, cfg.get("start_time"), cfg.get("end_time")):
                self.push_log("Вне окна расписания, ожидание...")
                self.stop_event.wait(20)
                continue
            try:
                self._heartbeat(api, cfg)
                task = self._fetch_task(api, cfg)
                self.current_job_id = task.get("job_id")
                self.last_task_snapshot = {
                    "job_id": self.current_job_id,
                    "contract_id": task.get("contract_id"),
                    "assigned_at": int(time.time()),
                    "task_profile": task.get("task_profile") if isinstance(task.get("task_profile"), dict) else {},
                    "status": "in_progress",
                    "progress_pct": 0,
                    "updated_at": int(time.time()),
                }
                self._write_state(self.last_task_snapshot)
                work_done, result_data, nonce = self._compute(api, cfg, task)
                if not result_data or nonce is None:
                    self.push_log("Результат не получен, повтор позже.")
                    self.stop_event.wait(8)
                    continue
                api.request(
                    "POST",
                    f"/agent/job/{task['job_id']}/complete_ack",
                    payload={"result_data": result_data, "nonce": nonce},
                    timeout=5,
                )
                submit_result = api.request(
                    "POST",
                    "/submit_work",
                    payload={
                        "client_id": cfg["client_id"],
                        "contract_id": task["contract_id"],
                        "job_id": task.get("job_id"),
                        "work_units_done": int(work_done),
                        "result_data": result_data,
                        "nonce": nonce,
                    },
                    timeout=int(
                        ((task.get("task_profile") or {}).get("recommended_submit_timeout_seconds") or 900)
                    ),
                )
                reward = submit_result.get("reward_issued")
                currency = submit_result.get("reward_currency", "")
                self.push_log(f"Сдано успешно. Награда: {reward} {currency}".strip())
                self._clear_state()
                if cfg.get("check_updates", True):
                    self._check_updates(api)
            except Exception as exc:
                self.push_log(f"Ошибка выполнения: {exc}")
                if self.last_task_snapshot:
                    failed = dict(self.last_task_snapshot)
                    failed["status"] = "error"
                    failed["error"] = str(exc)
                    failed["updated_at"] = int(time.time())
                    self._write_state(failed)
                self.stop_event.wait(8)
                continue
            finally:
                self.current_job_id = None
                self.last_heartbeat_at = 0.0
            if not cfg.get("auto_next", True):
                self.push_log("Авто-следующая часть отключена, агент в режиме ожидания.")
                break
            self.stop_event.wait(2)
        self._clear_state()
        self.push_log("Агент остановлен.")
