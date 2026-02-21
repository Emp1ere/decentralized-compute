# Исполняемые смарт-контракты: только проверка работы и вознаграждение (минимальная «стоимость»).
import hashlib  # Для проверки хеша результата вычислителя

SUPPORTED_COMPUTATION_TYPES = (
    "simple_pow",
    "cosmological",
    "supernova",
    "mhd",
    "radiative",
    "gravitational_waves",
    "molecular_dynamics_benchpep",
    "tee",  # TEE/SGX — placeholder, Phase 4
)

DEFAULT_DIFFICULTY_BY_COMPUTATION = {
    "simple_pow": 3,
    "cosmological": 5,
    "supernova": 5,
    "mhd": 4,
    "radiative": 4,
    "gravitational_waves": 6,
    "molecular_dynamics_benchpep": 4,
}

DEFAULT_BUDGET_CURRENCY_BY_COMPUTATION = {
    "simple_pow": "RUB",
    "cosmological": "USD",
    "supernova": "USD",
    "mhd": "EUR",
    "radiative": "EUR",
    "gravitational_waves": "USD",
    "molecular_dynamics_benchpep": "USD",
}


def default_difficulty_for(computation_type):
    """Возвращает сложность по умолчанию для типа вычислений."""
    return DEFAULT_DIFFICULTY_BY_COMPUTATION.get(computation_type, 3)


def default_budget_currency_for(computation_type):
    """Возвращает валюту бюджета по умолчанию для типа вычислений."""
    return DEFAULT_BUDGET_CURRENCY_BY_COMPUTATION.get(computation_type, "RUB")


def verify_contract_result(
    *,
    expected_contract_id,
    expected_work_units_required,
    expected_difficulty,
    expected_computation_type,
    client_id,
    contract_id,
    work_units_done,
    result_data,
    nonce=None,
):
    """
    Унифицированная верификация результата для системных и пользовательских контрактов.
    """
    if contract_id != expected_contract_id:
        return False
    if work_units_done < expected_work_units_required:
        return False

    # Для простого PoW проверяем хеш с префиксом
    if expected_computation_type == "simple_pow":
        prefix = "0" * expected_difficulty
        if not (result_data and isinstance(result_data, str) and result_data.startswith(prefix)):
            return False
        if nonce is None or nonce == "":
            return False
        expected_input = f"{client_id}-{contract_id}-{nonce}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if expected_hash != result_data:
            return False
        return True

    # Астрофизические задачи: строгая верификация через shared.computation_types
    if expected_computation_type in (
        "cosmological",
        "supernova",
        "mhd",
        "radiative",
        "gravitational_waves",
        "molecular_dynamics_benchpep",
    ):
        if not (result_data and isinstance(result_data, str) and len(result_data) == 64):
            return False
        try:
            int(result_data, 16)
        except ValueError:
            return False
        if nonce is None or nonce == "":
            return False
        try:
            seed_val = int(nonce)
        except (ValueError, TypeError):
            return False
        try:
            from shared.computation_types import (
                COMPUTATION_TYPES,
                SEED_MIN,
                SEED_MAX,
            )
        except ImportError:
            # Fail-closed: если модуль верификации недоступен, работу нельзя считать подтверждённой.
            return False
        if not (SEED_MIN <= seed_val <= SEED_MAX):
            return False
        compute_func = COMPUTATION_TYPES.get(expected_computation_type)
        if not compute_func:
            return False
        try:
            expected_result, _ = compute_func(
                client_id, contract_id, expected_work_units_required, seed=seed_val
            )
            return expected_result == result_data
        except Exception:
            return False

    # TEE (SGX): placeholder — требуется attestation (ТЗ раздел 5, Phase 4)
    if expected_computation_type == "tee":
        if not (result_data and isinstance(result_data, str)):
            return False
        # TODO: verify SGX attestation, quote
        return False

    return False


class BaseContract:
    """Базовый контракт: только верификация результата и размер вознаграждения."""

    contract_id = None   # Уникальный идентификатор контракта
    work_units_required = 0  # Минимальное число единиц работы для выплаты
    reward = 0  # Размер вознаграждения в токенах
    task_name = ""  # Название задачи (для интерфейса)
    task_description = ""  # Описание задачи (для интерфейса)
    task_category = ""  # Категория задачи (например, "Астрофизика")
    computation_type = "simple_pow"  # Тип вычислений: cosmological, supernova, mhd, radiative, gravitational_waves, simple_pow
    # Опционально: целевой объём работы по контракту для отображения % выполнения (если None — считается от work_units_required * 10)
    target_total_work_units = None

    def get_task_spec(self):
        """Минимальные данные для вычислителя: что сделать и сколько нужно единиц работы."""
        return {
            "contract_id": self.contract_id,  # Идентификатор для отчёта
            "work_units_required": self.work_units_required,  # Сколько единиц работы нужно
            "difficulty": self._difficulty(),  # Сложность хеша (число ведущих нулей)
            "task_name": self.task_name,  # Название задачи
            "task_description": self.task_description,  # Описание задачи
            "task_category": self.task_category,  # Категория задачи
            "computation_type": self.computation_type,  # Тип вычислений
        }

    def _difficulty(self):
        """Число ведущих нулей в хеше (переопределяется в подклассах)."""
        return 0

    def verify(self, client_id, contract_id, work_units_done, result_data, nonce=None):
        """
        Проверка выполнения работы. Возвращает True только если работа выполнена и результат корректен.
        Для разных типов вычислений используется разная верификация.
        В терминах BOINC: роль validator — определение корректности результата (без репликации по большинству).
        """
        return verify_contract_result(
            expected_contract_id=self.contract_id,
            expected_work_units_required=self.work_units_required,
            expected_difficulty=self._difficulty(),
            expected_computation_type=self.computation_type,
            client_id=client_id,
            contract_id=contract_id,
            work_units_done=work_units_done,
            result_data=result_data,
            nonce=nonce,
        )

    def get_reward(self):
        """Размер вознаграждения за выполнение контракта."""
        return self.reward


class QuickTestPoW(BaseContract):
    """Быстрый тест: 1 ведущий нуль, 100 попыток — решение находится почти всегда за 1–2 секунды."""

    contract_id = "sc-000"
    work_units_required = 100
    reward = 2
    task_name = "Быстрый тест"
    task_description = "Найти хеш с 1 ведущим нулём (для быстрой проверки сдачи)"
    task_category = "Тестовая"

    def _difficulty(self):
        return 1  # Хеш должен начинаться с "0" — за 100 попыток решение находится почти всегда


class SimpleHashPoW(BaseContract):
    """Контракт: PoW с 3 ведущими нулями, 1000 единиц работы, фиксированное вознаграждение."""

    contract_id = "sc-001"
    work_units_required = 1000
    reward = 10
    task_name = "Простая хеш-задача"
    task_description = "Найти хеш с 3 ведущими нулями"
    task_category = "Тестовая"

    def _difficulty(self):
        return 3  # Хеш должен начинаться с "000"


class ComplexHashPoW(BaseContract):
    """Контракт: PoW с 4 ведущими нулями, 5000 единиц работы, фиксированное вознаграждение."""

    contract_id = "sc-002"
    work_units_required = 5000
    reward = 50
    task_name = "Сложная хеш-задача"
    task_description = "Найти хеш с 4 ведущими нулями"
    task_category = "Тестовая"

    def _difficulty(self):
        return 4  # Хеш должен начинаться с "0000"


# --- Астрофизические задачи ---

class CosmologicalSimulation(BaseContract):
    """
    Космологические симуляции (Illustris, EAGLE, Millennium).
    Моделирование крупномасштабной структуры Вселенной с учётом гравитации,
    гидродинамики, процессов звездообразования и обратной связи от чёрных дыр.
    Требует миллионы вычислительных операций.
    """

    contract_id = "astro-001"
    work_units_required = 100000  # Большой объём работы
    reward = 500
    task_name = "Космологическая симуляция"
    task_description = "Моделирование крупномасштабной структуры Вселенной: гравитация, гидродинамика, звездообразование, обратная связь от чёрных дыр"
    task_category = "Моделирование и симуляции"
    computation_type = "cosmological"

    def _difficulty(self):
        return 5  # Высокая сложность вычислений


class SupernovaModeling(BaseContract):
    """
    Моделирование сверхновых.
    Параллельные вычисления радиационно-гидродинамического взрыва
    с учётом нейтринного транспорта.
    """

    contract_id = "astro-002"
    work_units_required = 80000
    reward = 400
    task_name = "Моделирование сверхновой"
    task_description = "Радиационно-гидродинамическое моделирование взрыва сверхновой с учётом нейтринного транспорта"
    task_category = "Моделирование и симуляции"
    computation_type = "supernova"

    def _difficulty(self):
        return 5


class MHDJetAccretion(BaseContract):
    """
    МГД джетов и аккреции.
    Используются адаптивные сетки и сложные условия на границах,
    требуются гибкие и масштабируемые алгоритмы.
    """

    contract_id = "astro-003"
    work_units_required = 60000
    reward = 300
    task_name = "МГД джетов и аккреции"
    task_description = "Магнитогидродинамическое моделирование джетов и аккреционных дисков с адаптивными сетками"
    task_category = "Моделирование и симуляции"
    computation_type = "mhd"

    def _difficulty(self):
        return 4


class RadiativeTransfer(BaseContract):
    """
    Радиационный перенос.
    Прямое решение уравнения переноса излучения в многомерных пространствах
    требует распараллеливания по углам, частотам и пространственным координатам.
    """

    contract_id = "astro-004"
    work_units_required = 70000
    reward = 350
    task_name = "Радиационный перенос"
    task_description = "Решение уравнения переноса излучения в многомерных пространствах (распараллеливание по углам, частотам, координатам)"
    task_category = "Моделирование и симуляции"
    computation_type = "radiative"

    def _difficulty(self):
        return 4


class GravitationalWaves(BaseContract):
    """
    Гравитационные волны.
    Численные решения уравнений Эйнштейна при моделировании слияний
    нейтронных звёзд и чёрных дыр (коды типа SpEC).
    Требуют десятки тысяч процессоров.
    """

    contract_id = "astro-005"
    work_units_required = 150000  # Самый большой объём работы
    reward = 750
    task_name = "Гравитационные волны"
    task_description = "Численное решение уравнений Эйнштейна для моделирования слияний нейтронных звёзд и чёрных дыр"
    task_category = "Моделирование и симуляции"
    computation_type = "gravitational_waves"

    def _difficulty(self):
        return 6  # Максимальная сложность


SYSTEM_CONTRACT_CLASSES = (
    QuickTestPoW,
    SimpleHashPoW,
    ComplexHashPoW,
    CosmologicalSimulation,
    SupernovaModeling,
    MHDJetAccretion,
    RadiativeTransfer,
    GravitationalWaves,
)


def _to_provider_template(contract):
    spec = contract.get_task_spec()
    work_units_required = int(spec["work_units_required"])
    target_total = int(getattr(contract, "target_total_work_units", None) or (10 * work_units_required))
    reward = int(contract.get_reward())
    jobs_estimate = max(1, target_total // max(1, work_units_required))
    return {
        "contract_id": contract.contract_id,
        "task_name": spec.get("task_name", contract.contract_id),
        "task_description": spec.get("task_description", ""),
        "task_category": spec.get("task_category", "Пользовательская"),
        "computation_type": spec.get("computation_type", "simple_pow"),
        "work_units_required": work_units_required,
        "difficulty": int(spec.get("difficulty", default_difficulty_for(spec.get("computation_type", "simple_pow")))),
        "reward_per_task": reward,
        "target_total_work_units": target_total,
        "initial_budget_tokens": reward * jobs_estimate,
        "budget_currency": default_budget_currency_for(spec.get("computation_type", "simple_pow")),
    }


SYSTEM_CONTRACT_TEMPLATES = [_to_provider_template(cls()) for cls in SYSTEM_CONTRACT_CLASSES]
