# Исполняемые смарт-контракты: только проверка работы и вознаграждение (минимальная «стоимость»).
import hashlib  # Для проверки хеша результата вычислителя


class BaseContract:
    """Базовый контракт: только верификация результата и размер вознаграждения."""

    contract_id = None   # Уникальный идентификатор контракта
    work_units_required = 0  # Минимальное число единиц работы для выплаты
    reward = 0  # Размер вознаграждения в токенах

    def get_task_spec(self):
        """Минимальные данные для вычислителя: что сделать и сколько нужно единиц работы."""
        return {
            "contract_id": self.contract_id,  # Идентификатор для отчёта
            "work_units_required": self.work_units_required,  # Сколько единиц работы нужно
            "difficulty": self._difficulty(),  # Сложность хеша (число ведущих нулей)
        }

    def _difficulty(self):
        """Число ведущих нулей в хеше (переопределяется в подклассах)."""
        return 0

    def verify(self, client_id, contract_id, work_units_done, result_data, nonce=None):
        """
        Проверка выполнения работы. Возвращает True только если работа выполнена и результат корректен.
        """
        if contract_id != self.contract_id:  # Контракт должен совпадать
            return False
        if work_units_done < self.work_units_required:  # Объём работы не достигнут
            return False
        prefix = "0" * self._difficulty()  # Требуемый префикс хеша
        if not (result_data and isinstance(result_data, str) and result_data.startswith(prefix)):
            return False  # Результат не является хешем с нужным префиксом
        # Строгая проверка: пересчитываем хеш по (client_id, contract_id, nonce) и сравниваем
        if nonce is not None:
            expected_input = f"{client_id}-{contract_id}-{nonce}"  # Та же строка, что у воркера
            expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
            if expected_hash != result_data:  # Хеш должен совпадать
                return False
        return True  # Все проверки пройдены

    def get_reward(self):
        """Размер вознаграждения за выполнение контракта."""
        return self.reward


class SimpleHashPoW(BaseContract):
    """Контракт: PoW с 3 ведущими нулями, 1000 единиц работы, фиксированное вознаграждение."""

    contract_id = "sc-001"
    work_units_required = 1000
    reward = 10

    def _difficulty(self):
        return 3  # Хеш должен начинаться с "000"


class ComplexHashPoW(BaseContract):
    """Контракт: PoW с 4 ведущими нулями, 5000 единиц работы, фиксированное вознаграждение."""

    contract_id = "sc-002"
    work_units_required = 5000
    reward = 50

    def _difficulty(self):
        return 4  # Хеш должен начинаться с "0000"


# Реестр контрактов по contract_id: один экземпляр на тип, быстрый доступ по id
CONTRACTS = {c.contract_id: c() for c in (SimpleHashPoW, ComplexHashPoW)}
