import os
import sys
import threading
import time

from api import ApiClient


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from shared.computation_types import COMPUTATION_TYPES, deterministic_seed, compute_simple_pow  # noqa: E402


AGENT_VERSION = "0.3.0"


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
        self.push_log("Остановка агента...")

    def _heartbeat(self, api, cfg):
        if not self.current_job_id:
            return
        try:
            api.request("POST", f"/agent/job/{self.current_job_id}/heartbeat", payload={}, timeout=3)
        except Exception:
            return
        try:
            api.request(
                "POST",
                "/agent/devices/heartbeat",
                payload={"device_id": cfg.get("device_id"), "agent_version": AGENT_VERSION},
                timeout=3,
            )
        except Exception:
            return

    def _fetch_task(self, api, cfg):
        payload = {}
        if cfg.get("sector_id"):
            payload["sector_id"] = cfg["sector_id"]
        if cfg.get("contract_id"):
            payload["contract_id"] = cfg["contract_id"]
        return api.request("POST", "/agent/get_task", payload=payload, timeout=15)

    def _compute(self, api, cfg, task):
        contract_id = task["contract_id"]
        target_work = int(task["work_units_required"])
        difficulty = int(task.get("difficulty", 0))
        computation_type = task.get("computation_type", "simple_pow")
        task_seed = task.get("task_seed")
        throttle = max(0, min(95, int(cfg.get("throttle_percent", 0) or 0)))
        self.push_log(
            f"Выполнение: contract={contract_id} type={computation_type} units={target_work} job={task.get('job_id')}"
        )
        compute_func = COMPUTATION_TYPES.get(computation_type) or compute_simple_pow
        if computation_type == "simple_pow":
            self._heartbeat(api, cfg)
            result_data, solution_nonce = compute_func(
                cfg["client_id"],
                contract_id,
                target_work,
                difficulty,
                seed=task_seed,
                progress_callback=(lambda cur, total: self._heartbeat(api, cfg)),
            )
            if throttle > 0:
                time.sleep(throttle / 100.0)
            return target_work, result_data, solution_nonce

        if task_seed is not None:
            try:
                seed = int(task_seed)
            except (TypeError, ValueError):
                seed = deterministic_seed(cfg["client_id"], contract_id)
        else:
            seed = deterministic_seed(cfg["client_id"], contract_id)

        def progress(cur, total):
            if total:
                pct = int(cur * 100 / total)
                self.push_log(f"Прогресс {contract_id}: {pct}%")
            self._heartbeat(api, cfg)
            if throttle > 0:
                time.sleep(throttle / 100.0)

        result_data, computed_seed = compute_func(
            cfg["client_id"], contract_id, target_work, seed=seed, progress_callback=progress
        )
        return target_work, result_data, (computed_seed if computed_seed else str(seed))

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
                }
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
                    timeout=900,
                )
                reward = submit_result.get("reward_issued")
                currency = submit_result.get("reward_currency", "")
                self.push_log(f"Сдано успешно. Награда: {reward} {currency}".strip())
                if cfg.get("check_updates", True):
                    self._check_updates(api)
            except Exception as exc:
                self.push_log(f"Ошибка выполнения: {exc}")
                self.stop_event.wait(8)
                continue
            finally:
                self.current_job_id = None
            if not cfg.get("auto_next", True):
                self.push_log("Авто-следующая часть отключена, агент в режиме ожидания.")
                break
            self.stop_event.wait(2)
        self.push_log("Агент остановлен.")
