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
# Опционально: брать только задачи по указанному контракту (для запуска из интерфейса «Выполнить в воркере»)
CONTRACT_ID = os.environ.get("CONTRACT_ID", "").strip() or None
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
            logger.info("Using account from interface: client_id=%s...", self.client_id[:8])
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
                logger.info("Using existing account: client_id=%s...", self.client_id[:8])
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

        if computation_type == "simple_pow":
            result_data, solution_nonce = compute_func(
                self.client_id, contract_id, target_work, difficulty
            )
            work_units_done = target_work
        else:
            seed = deterministic_seed(self.client_id, contract_id)
            result_data, computed_seed = compute_func(
                self.client_id, contract_id, target_work, seed=seed
            )
            work_units_done = target_work
            solution_nonce = computed_seed if computed_seed else str(seed)
        
        logger.info("Computation completed: result_hash=%s... nonce=%s", 
                   result_data[:16] if result_data else "none", solution_nonce)
        
        return work_units_done, result_data or "", solution_nonce

    def submit_work(self, task, work_done, result_data, solution_nonce=None):
        """Отправка результата оркестратору: contract_id, work_units_done, result_data, nonce (для строгой проверки контрактом)."""
        payload = {
            "client_id": self.client_id,
            "contract_id": task["contract_id"],
            "work_units_done": work_done,
            "result_data": result_data,
            "nonce": solution_nonce,  # Контракт пересчитает хеш и сравнит с result_data
        }
        try:
            response = requests.post(
                f"{ORCHESTRATOR_URL}/submit_work",
                json=payload,
                headers=self._auth_headers(),
                verify=VERIFY_SSL,
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()
            logger.info("submit_work success: reward_issued=%s", data.get("reward_issued"))
        except requests.RequestException as e:
            body = ""
            if hasattr(e, "response") and e.response is not None:
                body = (e.response.text or "")[:500]
            logger.warning("submit_work failed: %s response=%s", e, body)

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
        """Цикл: запрос задачи → вычисление → отправка результата → проверка баланса."""
        if not self.client_id:
            return
        while True:
            task = self.fetch_task()
            if task:
                work_done, result, solution_nonce = self.perform_computation(task)
                self.submit_work(task, work_done, result, solution_nonce)
                self.check_balance()
            time.sleep(10)  # Пауза перед следующей задачей


if __name__ == "__main__":
    worker = ClientWorker()
    worker.run()
