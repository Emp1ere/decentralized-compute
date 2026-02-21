"""
Интерфейс региональных платёжных провайдеров (ТЗ раздел 3).

RU: ЮKassa, СБП/банк
EU: Stripe (карты, SEPA), Stripe Connect
US: Stripe (карты, ACH), Stripe Connect
CN: Alipay/WeChat Pay (через Adyen)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

REGIONS = ("RU", "EU", "US", "CN")


class PaymentProvider(ABC):
    """Базовый интерфейс платёжного провайдера."""

    @property
    @abstractmethod
    def region(self) -> str:
        """Код региона: RU, EU, US, CN."""
        pass

    @abstractmethod
    def create_deposit(self, amount: int, currency: str, client_id: str, metadata: Optional[dict] = None) -> Tuple[Optional[dict], Optional[str]]:
        """Создать депозит. Returns (payment_data, error)."""
        pass

    @abstractmethod
    def create_payout(
        self,
        amount: int,
        currency: str,
        client_id: str,
        destination: str,
        metadata: Optional[dict] = None,
    ) -> Tuple[Optional[dict], Optional[str]]:
        """Создать выплату. Returns (payout_data, error)."""
        pass

    @abstractmethod
    def get_status(self, operation_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Статус операции. Returns (status, error)."""
        pass


class _SandboxProvider(PaymentProvider):
    """Базовый sandbox-провайдер (общая логика)."""

    def __init__(self, region_code: str):
        self._region = region_code

    @property
    def region(self) -> str:
        return self._region

    def create_deposit(self, amount: int, currency: str, client_id: str, metadata: Optional[dict] = None) -> Tuple[Optional[dict], Optional[str]]:
        return {"simulated": True, "amount": amount, "currency": currency, "region": self._region}, None

    def create_payout(
        self,
        amount: int,
        currency: str,
        client_id: str,
        destination: str,
        metadata: Optional[dict] = None,
    ) -> Tuple[Optional[dict], Optional[str]]:
        op_id = (metadata or {}).get("operation_id", "unknown")
        return {"simulated": True, "amount": amount, "destination": destination, "provider_ref": f"sim-{self._region}-{op_id}"}, None

    def get_status(self, operation_id: str) -> Tuple[Optional[str], Optional[str]]:
        return "completed", None


class SimulatedProvider(_SandboxProvider):
    """Симуляция для разработки (RU по умолчанию)."""

    def __init__(self):
        super().__init__("RU")


class YooKassaSandboxProvider(_SandboxProvider):
    """Stub ЮKassa (RU). Интеграция — Phase 5."""

    def __init__(self):
        super().__init__("RU")


class StripeSandboxProvider(_SandboxProvider):
    """Stub Stripe (EU/US). Интеграция — Phase 5."""

    def __init__(self, region_code: str = "EU"):
        super().__init__(region_code)


class AdyenSandboxProvider(_SandboxProvider):
    """Stub Adyen (CN). Интеграция — Phase 5."""

    def __init__(self):
        super().__init__("CN")


def get_provider_for_region(region: str) -> PaymentProvider:
    """Фабрика провайдеров по региону. Сейчас — sandbox stubs."""
    region = (region or "RU").strip().upper()
    if region not in REGIONS:
        region = "RU"
    if region == "RU":
        return YooKassaSandboxProvider()
    if region in ("EU", "US"):
        return StripeSandboxProvider(region)
    if region == "CN":
        return AdyenSandboxProvider()
    return SimulatedProvider()
