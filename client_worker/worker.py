import requests
import time
import hashlib
import os

# Адрес оркестратора (из docker-compose или env); для HTTPS укажите https://...
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator_node:5000")
# Для самоподписанных сертификатов (TLS) можно задать VERIFY_SSL=false
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() not in ("0", "false", "no")


class ClientWorker:
    def __init__(self):
        self.client_id = None
        self.api_key = None  # Секрет для аутентификации (Authorization: Bearer)
        self.register()  # Сразу регистрируемся при создании

    def _auth_headers(self):
        """Заголовки с API-ключом для аутентификации (и опционально для TLS — используйте https в ORCHESTRATOR_URL)."""
        if not self.api_key:
            return {}
        return {"Authorization": f"Bearer {self.api_key}"}

    def register(self):
        """Регистрация на оркестраторе: получаем client_id и api_key для последующих запросов."""
        try:
            response = requests.get(f"{ORCHESTRATOR_URL}/register", verify=VERIFY_SSL)
            response.raise_for_status()
            data = response.json()
            self.client_id = data["client_id"]
            self.api_key = data["api_key"]  # Сохраняем для Authorization: Bearer
        except Exception as e:
            print(f"Error registering: {e}")
            time.sleep(5)
            self.register()  # Повторная попытка через 5 сек

    def fetch_task(self):
        """Запрос задачи: оркестратор возвращает минимальную спецификацию (contract_id, work_units_required, difficulty)."""
        try:
            response = requests.get(
                f"{ORCHESTRATOR_URL}/get_task", headers=self._auth_headers(), verify=VERIFY_SSL
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching task: {e}")
            return None

    def perform_computation(self, task):
        """Выполнение работы по спецификации контракта: PoW до work_units_required и до нахождения валидного хеша."""
        contract_id = task["contract_id"]
        target_work = task["work_units_required"]  # Сколько единиц работы нужно
        difficulty = task["difficulty"]  # Число ведущих нулей в хеше
        target_prefix = "0" * difficulty

        work_units_done = 0
        final_result = None  # Хеш с нужным префиксом (для отчёта)
        solution_nonce = None  # Nonce этого хеша (для строгой проверки контрактом)

        while work_units_done < target_work or solution_nonce is None:
            work_units_done += 1
            nonce = str(work_units_done)
            text = f"{self.client_id}-{contract_id}-{nonce}"  # Та же формула, что в контракте при проверке
            hash_result = hashlib.sha256(text.encode()).hexdigest()

            if hash_result.startswith(target_prefix):
                final_result = hash_result
                solution_nonce = nonce  # Запоминаем nonce для верификации на оркестраторе

        return work_units_done, final_result or "", solution_nonce

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
            )
            response.raise_for_status()
        except Exception as e:
            print(f"Error submitting work: {e}")

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
            print(f"Balance: {data.get('balance', 0)}")
        except Exception as e:
            print(f"Error checking balance: {e}")

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
