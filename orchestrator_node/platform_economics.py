"""
Комиссия платформы DSCM v2 (ТЗ раздел 1).

Монетизация: 8% до $10k/мес, 12% выше.
"""
from __future__ import annotations

import os
from typing import Tuple

PLATFORM_COMMISSION_THRESHOLD_USD = float(
    os.environ.get("PLATFORM_COMMISSION_THRESHOLD_USD", "10000")
)
PLATFORM_COMMISSION_LOW_PERCENT = float(
    os.environ.get("PLATFORM_COMMISSION_LOW_PERCENT", "8")
)
PLATFORM_COMMISSION_HIGH_PERCENT = float(
    os.environ.get("PLATFORM_COMMISSION_HIGH_PERCENT", "12")
)


def platform_commission_percent(monthly_volume_usd: float) -> float:
    """Процент комиссии в зависимости от месячного объёма (USD)."""
    if monthly_volume_usd <= PLATFORM_COMMISSION_THRESHOLD_USD:
        return PLATFORM_COMMISSION_LOW_PERCENT
    return PLATFORM_COMMISSION_HIGH_PERCENT


def compute_platform_commission(
    amount_usd: float, monthly_volume_usd: float
) -> Tuple[float, float]:
    """
    Комиссия платформы с транзакции.

    Returns:
        (commission_amount_usd, commission_percent)
    """
    pct = platform_commission_percent(monthly_volume_usd)
    commission = amount_usd * (pct / 100.0)
    return round(commission, 2), pct
