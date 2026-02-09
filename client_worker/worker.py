import requests
import time
import hashlib
import os
import logging

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("worker")

# Адрес оркестратора (из docker-compose или env); для HTTPS укажите https://...
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator_node:5000")
# Для самоподписанных сертификатов (TLS) можно задать VERIFY_SSL=false
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() not in ("0", "false", "no")
# Опционально: брать только задачи по указанному контракту (для запуска из интерфейса «Выполнить в воркере»).
# Если не задан, воркер запрашивает случайный контракт каждый раз — награды могут идти за любые контракты.
CONTRACT_ID = os.environ.get("CONTRACT_ID", "").strip() or None
# RUN_ONCE=1: выполнить одну задачу и выйти (иначе — цикл по образцу BOINC: много задач до остановки).
RUN_ONCE = os.environ.get("RUN_ONCE", "").strip().lower() in ("1", "true", "yes")
# Если заданы API_KEY и CLIENT_ID (при запуске из интерфейса), воркер работает от этого аккаунта — награда идёт на ваш баланс
API_KEY_FROM_ENV = os.environ.get("API_KEY", "").strip() or None
CLIENT_ID_FROM_ENV = os.environ.get("CLIENT_ID", "").strip() or None


class ClientWorker:
    def __init__(self):
        self.client_id = None
        self.api_key = None  # Секрет для аутентификации (Authorization: Bearer)
        if API_KEY_FROM_ENV and CLIENT_ID_FROM_ENV:
            self.api_key = API_KEY_FROM_ENV
            self.client_id = CLIENT_ID_FROM_ENV
            logger.info("Using account from interface: client_id=%s... (rewards will be credited to this ID)", self.client_id[:8])
        elif API_KEY_FROM_ENV:
            self._use_existing_key()
        else:
            self.register()  # Сразу регистрируемся при создании

    def _auth_headers(self):
        """Заголовки с API-ключом для аутентификации (и опционально для TLS — используйте https в ORCHESTRATOR_URL)."""
        if not self.api_key:
            return {}
        return {"Authorization": f"Bearer {self.api_key}"}

    def _use_existing_key(self):
        """Использовать переданный API-ключ (из интерфейса): получаем client_id через /me, награда пойдёт на этот аккаунт."""
        self.api_key = API_KEY_FROM_ENV
        while True:
            try:
                response = requests.get(
                    f"{ORCHESTRATOR_URL}/me",
                    headers=self._auth_headers(),
                    verify=VERIFY_SSL,
                    timeout=10,
                )
                response.raise_for_status()
                data = response.json()
                self.client_id = data.get("client_id")
                if not self.client_id:
                    raise ValueError("Missing client_id in /me response")
                logger.info("Using existing account: client_id=%s... (rewards will be credited to this ID)", self.client_id[:8])
                return
            except requests.RequestException as e:
                logger.warning("Failed to get /me (retry in 5s): %s", e)
                time.sleep(5)
            except (KeyError, ValueError) as e:
                logger.error("Invalid /me response: %s", e)
                time.sleep(5)

    def register(self):
        """Регистрация на оркестраторе: получаем client_id и api_key для последующих запросов."""
        while True:
            try:
                response = requests.get(f"{ORCHESTRATOR_URL}/register", verify=VERIFY_SSL, timeout=10)
                response.raise_for_status()
                data = response.json()
                self.client_id = data.get("client_id")
                self.api_key = data.get("api_key")
                if not self.client_id or not self.api_key:
                    raise ValueError("Missing client_id or api_key in response")
                logger.info("Registered: client_id=%s...", self.client_id[:8])
                return
            except requests.RequestException as e:
                logger.warning("Register failed (retry in 5s): %s", e)
                time.sleep(5)
            except (KeyError, ValueError) as e:
                logger.error("Register invalid response: %s", e)
                time.sleep(5)

    def fetch_task(self):
        """Запрос задачи: оркестратор возвращает минимальную спецификацию (contract_id, work_units_required, difficulty)."""
        try:
            url = f"{ORCHESTRATOR_URL}/get_task"
            if CONTRACT_ID:
                url += f"?contract_id={requests.utils.quote(CONTRACT_ID)}"
            response = requests.get(
                url,
                headers=self._auth_headers(),
                verify=VERIFY_SSL,
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict) or "contract_id" not in data:
                logger.warning("fetch_task invalid response")
                return None
            return data
        except requests.RequestException as e:
            logger.warning("fetch_task failed: %s", e)
            return None

    def perform_computation(self, task):
        """
        Выполнение работы по спецификации контракта.
        Использует разные типы вычислений в зависимости от типа задачи:
        - simple_pow: простой PoW (для тестовых задач)
        - cosmological, supernova, mhd, radiative, gravitational_waves: реалистичные астрофизические вычисления
        """
        try:
            contract_id = task["contract_id"]
            target_work = int(task["work_units_required"])
            difficulty = int(task.get("difficulty", 0))
            computation_type = task.get("computation_type", "simple_pow")
        except (KeyError, TypeError, ValueError) as e:
            logger.error("perform_computation invalid task: %s", e)
            return 0, "", None
        
        # Единый модуль shared (тот же код, что у оркестратора) — детерминированный seed по SHA256
        from shared.computation_types import COMPUTATION_TYPES, deterministic_seed, compute_simple_pow

        compute_func = COMPUTATION_TYPES.get(computation_type)
        if not compute_func:
            logger.warning("Unknown computation_type %s, using simple_pow", computation_type)
            compute_func = compute_simple_pow

        logger.info("Starting computation: type=%s contract_id=%s work_units=%s",
                   computation_type, contract_id, target_work)
        if target_work >= 10000 and computation_type != "simple_pow":
            logger.info("Large task (%s units): computation may take 10-60 minutes; progress will be logged every 10000 steps.",
                        target_work)

        if computation_type == "simple_pow":
            task_seed = task.get("task_seed")
            result_data, solution_nonce = compute_func(
                self.client_id, contract_id, target_work, difficulty, seed=task_seed
            )
            work_units_done = target_work
        else:
            # Уникальный task_seed от оркестратора при каждой выдаче — чтобы повторные задачи по тому же
            # контракту давали разный результат и не отклонялись как "Proof already used".
            task_seed = task.get("task_seed")
            if task_seed is not None:
                try:
                    seed = int(task_seed)
                except (TypeError, ValueError):
                    seed = deterministic_seed(self.client_id, contract_id)
            else:
                seed = deterministic_seed(self.client_id, contract_id)
            def _progress(cur, total):
                pct = 100.0 * cur / total if total else 0
                logger.info("Progress: %s / %s (%.0f%%)", cur, total, pct)
                self._report_progress(contract_id, cur, total)
            result_data, computed_seed = compute_func(
                self.client_id, contract_id, target_work, seed=seed,
                progress_callback=_progress
            )
            work_units_done = target_work
            solution_nonce = computed_seed if computed_seed else str(seed)
        
        logger.info("Computation completed: result_hash=%s... nonce=%s", 
                   result_data[:16] if result_data else "none", solution_nonce)
        
        return work_units_done, result_data or "", solution_nonce

    def submit_work(self, task, work_done, result_data, solution_nonce=None):
        """Отправка результата оркестратору. Повторные попытки при сбое — чтобы не терять выполненную работу."""
        payload = {
            "client_id": self.client_id,
            "contract_id": task["contract_id"],
            "work_units_done": work_done,
            "result_data": result_data,
            "nonce": solution_nonce,
        }
        max_attempts = 4
        # Оркестратор заново выполняет полную верификацию (те же 60k/70k шагов) — может занять 10–15 мин
        submit_timeout = 900  # 15 минут
        for attempt in range(1, max_attempts + 1):
            try:
                logger.info("Submitting result to %s/submit_work (attempt %s/%s, timeout %ss)",
                            ORCHESTRATOR_URL, attempt, max_attempts, submit_timeout)
                response = requests.post(
                    f"{ORCHESTRATOR_URL}/submit_work",
                    json=payload,
                    headers=self._auth_headers(),
                    verify=VERIFY_SSL,
                    timeout=submit_timeout,
                )
                response.raise_for_status()
                data = response.json()
                logger.info("submit_work success: reward_issued=%s", data.get("reward_issued"))
                return
            except requests.RequestException as e:
                body = ""
                if hasattr(e, "response") and e.response is not None:
                    body = (e.response.text or "")[:500]
                logger.warning("submit_work attempt %s/%s failed: %s response=%s", attempt, max_attempts, e, body)
                if attempt < max_attempts:
                    delay = 5 * attempt
                    logger.info("Retrying submit_work in %s seconds...", delay)
                    time.sleep(delay)
        logger.error("submit_work failed after %s attempts; result not submitted, reward not issued.", max_attempts)

    def _report_progress(self, contract_id, step, total):
        """Отправить прогресс в оркестратор для отображения в интерфейсе."""
        try:
            requests.post(
                f"{ORCHESTRATOR_URL}/worker_progress",
                json={"contract_id": contract_id, "step": step, "total": total},
                headers=self._auth_headers(),
                verify=VERIFY_SSL,
                timeout=3,
            )
        except requests.RequestException:
            pass

    def check_balance(self):
        """Запрос текущего баланса по client_id (требуется аутентификация)."""
        try:
            response = requests.get(
                f"{ORCHESTRATOR_URL}/get_balance/{self.client_id}",
                headers=self._auth_headers(),
                verify=VERIFY_SSL,
            )
            response.raise_for_status()
            data = response.json()
            logger.info("Balance: %s", data.get("balance", 0))
        except requests.RequestException as e:
            logger.warning("check_balance failed: %s", e)

    def run(self):
        """Запрос задачи → вычисление → отправка результата → проверка баланса. При RUN_ONCE — один проход и выход."""
        if not self.client_id:
            return
        while True:
            task = self.fetch_task()
            if task:
                work_done, result, solution_nonce = self.perform_computation(task)
                self._report_progress(task["contract_id"], work_done, work_done)
                self.submit_work(task, work_done, result, solution_nonce)
                self.check_balance()
                if RUN_ONCE:
                    logger.info("RUN_ONCE: one task done, exiting.")
                    return
            if RUN_ONCE:
                logger.warning("RUN_ONCE: no task received, exiting.")
                return
            time.sleep(10)  # Пауза перед следующей задачей


if __name__ == "__main__":
    if CONTRACT_ID:
        logger.info("Contract filter: only tasks for contract_id=%s (other contracts will NOT be requested)", CONTRACT_ID)
    else:
        logger.warning("No CONTRACT_ID set: worker will request random contracts (rewards may be for any contract)")
    worker = ClientWorker()
    if worker.client_id:
        logger.info("Worker started. Rewards will go to client_id=%s...", worker.client_id[:8])
    worker.run()
