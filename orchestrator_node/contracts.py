# Исполняемые смарт-контракты: только проверка работы и вознаграждение (минимальная «стоимость»).
import hashlib  # Для проверки хеша результата вычислителя


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
        if contract_id != self.contract_id:  # Контракт должен совпадать
            return False
        if work_units_done < self.work_units_required:  # Объём работы не достигнут
            return False
        
        # Для простого PoW проверяем хеш с префиксом
        if self.computation_type == "simple_pow":
            prefix = "0" * self._difficulty()  # Требуемый префикс хеша
            if not (result_data and isinstance(result_data, str) and result_data.startswith(prefix)):
                return False  # Результат не является хешем с нужным префиксом
            # Защита от мошенничества: nonce обязателен
            if nonce is None or nonce == "":
                return False
            expected_input = f"{client_id}-{contract_id}-{nonce}"
            expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
            if expected_hash != result_data:
                return False
            return True
        
        # Астрофизические задачи: строгая верификация через общий модуль shared.computation_types
        # (одинаковый код и детерминированный seed по nonce). Fallback на приём по формату, если shared недоступен.
        if self.computation_type in ("cosmological", "supernova", "mhd", "radiative", "gravitational_waves"):
            if not (result_data and isinstance(result_data, str) and len(result_data) == 64):
                return False
            try:
                int(result_data, 16)
            except ValueError:
                return False
            if nonce is None or nonce == "":
                return False
            # Валидация nonce: только число в допустимом диапазоне (защита от DoS и переполнения)
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
                # Старые образы без shared: принимаем по формату (fallback без потери работоспособности)
                return True

            if not (SEED_MIN <= seed_val <= SEED_MAX):
                return False
            compute_func = COMPUTATION_TYPES.get(self.computation_type)
            if not compute_func:
                return False
            try:
                expected_result, _ = compute_func(
                    client_id, contract_id, self.work_units_required, seed=seed_val
                )
                return expected_result == result_data
            except Exception:
                return False
        
        # Неизвестный тип вычислений или fallback не сработал
        return False

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
    task_category = "Астрофизика"
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
    task_category = "Астрофизика"
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
    task_category = "Астрофизика"
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
    task_category = "Астрофизика"
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
    task_category = "Астрофизика"
    computation_type = "gravitational_waves"

    def _difficulty(self):
        return 6  # Максимальная сложность


# Реестр контрактов по contract_id: один экземпляр на тип, быстрый доступ по id
CONTRACTS = {
    c.contract_id: c() for c in (
        QuickTestPoW,
        SimpleHashPoW,
        ComplexHashPoW,
        CosmologicalSimulation,
        SupernovaModeling,
        MHDJetAccretion,
        RadiativeTransfer,
        GravitationalWaves,
    )
}
