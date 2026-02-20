from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from onchain_accounting import SUPPORTED_BUDGET_CURRENCIES


def _to_float(value, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(fallback)


def _to_int(value, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(fallback)


def _target_min(currency: str) -> int:
    key = f"TREASURY_TARGET_MIN_{currency}"
    return max(0, _to_int(os.environ.get(key, "0"), 0))


def _target_max(currency: str) -> int:
    key = f"TREASURY_TARGET_MAX_{currency}"
    default = _target_min(currency) * 3
    return max(_target_min(currency), _to_int(os.environ.get(key, str(default)), default))


def compute_treasury_state(*, chain, rules: Optional[dict] = None) -> dict:
    # Импорт локально, чтобы избежать циклов импорта.
    from onchain_accounting import _wallets_and_audit

    wallets, _, _, _, _, active_rules = _wallets_and_audit(chain)
    fx_rules = rules or active_rules
    rates = (fx_rules or {}).get("rates_to_rub") or {}

    reserves = {c: 0 for c in SUPPORTED_BUDGET_CURRENCIES}
    for wallet in wallets.values():
        for currency in SUPPORTED_BUDGET_CURRENCIES:
            reserves[currency] += int(wallet.get(currency, 0) or 0)

    targets = {}
    reserve_buffer = {}
    total_rub = 0.0
    for currency in SUPPORTED_BUDGET_CURRENCIES:
        t_min = _target_min(currency)
        t_max = _target_max(currency)
        current = int(reserves.get(currency, 0))
        targets[currency] = {"min": t_min, "max": t_max}
        if t_min <= 0:
            reserve_buffer[currency] = 1.0
        else:
            reserve_buffer[currency] = round((current - t_min) / float(t_min), 4)
        total_rub += float(current) * float(rates.get(currency, 0) or 0)

    return {
        "reserves": reserves,
        "targets": targets,
        "reserve_buffer": reserve_buffer,
        "treasury_total_rub_estimate": int(round(total_rub)),
    }


def compute_dynamic_spread(
    *,
    base_spread_percent: float,
    volatility_score: float,
    liquidity_pressure: float,
) -> float:
    spread_volatility_coef = _to_float(os.environ.get("TREASURY_VOLATILITY_SPREAD_COEF", "0.05"), 0.05)
    spread_liquidity_coef = _to_float(os.environ.get("TREASURY_LIQUIDITY_SPREAD_COEF", "2.0"), 2.0)
    spread_cap = _to_float(os.environ.get("TREASURY_DYNAMIC_SPREAD_CAP", "8.0"), 8.0)
    dynamic = float(base_spread_percent) + float(volatility_score) * spread_volatility_coef + float(liquidity_pressure) * spread_liquidity_coef
    dynamic = max(float(base_spread_percent), dynamic)
    dynamic = min(spread_cap, dynamic)
    return round(dynamic, 4)


def estimate_liquidity_pressure(*, treasury_state: dict, source_currency: str, source_amount: int) -> float:
    reserves = treasury_state.get("reserves") or {}
    targets = treasury_state.get("targets") or {}
    current = float(reserves.get(source_currency, 0) or 0)
    target_min = float((targets.get(source_currency) or {}).get("min", 0) or 0)
    if target_min <= 0:
        return 0.0
    post_op = current - float(max(0, source_amount))
    if post_op >= target_min:
        return 0.0
    deficit = target_min - post_op
    return round(deficit / target_min, 6)


def convert_with_dynamic_spread(
    *,
    rules: dict,
    from_currency: str,
    to_currency: str,
    amount: int,
    dynamic_spread_percent: float,
) -> Tuple[Optional[int], Optional[str], Optional[dict]]:
    rates = (rules or {}).get("rates_to_rub") or {}
    src = str(from_currency or "").upper()
    dst = str(to_currency or "").upper()
    if src not in SUPPORTED_BUDGET_CURRENCIES or dst not in SUPPORTED_BUDGET_CURRENCIES:
        return None, "Unsupported currency", None
    if src == dst:
        return None, "from_currency and to_currency must differ", None
    try:
        source_amount = int(amount)
    except (TypeError, ValueError):
        source_amount = 0
    if source_amount <= 0:
        return None, "amount must be > 0", None
    src_rate = float(rates.get(src, 0) or 0)
    dst_rate = float(rates.get(dst, 0) or 0)
    if src_rate <= 0 or dst_rate <= 0:
        return None, "Invalid FX rates", None

    source_rub = float(source_amount) * src_rate
    gross_target = source_rub / dst_rate
    net_target = int(gross_target * (100.0 - float(dynamic_spread_percent)) / 100.0)
    if net_target <= 0:
        return None, "Converted amount is too small", None

    pnl_rub = source_rub - (float(net_target) * dst_rate)
    quote = {
        "source_rub_value": round(source_rub, 4),
        "gross_target_amount": int(gross_target),
        "pnl_rub_estimate": int(round(max(0.0, pnl_rub))),
    }
    return net_target, None, quote
