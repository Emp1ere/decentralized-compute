"""
On-chain бухгалтерия (без отдельного JSON-хранилища экономики).

Экономическое состояние выводится детерминированно из блокчейна:
- правила курсов FX (fx_rules_update);
- мультивалютные кошельки пользователей;
- бюджетные события контрактов;
- выплаты исполнителям;
- заявки/статусы вывода на карту;
- аудит по экономическим событиям.
"""
from __future__ import annotations

import copy
import os
import time
from typing import Dict, Iterable, List, Optional, Tuple

SUPPORTED_BUDGET_CURRENCIES = ("RUB", "USD", "EUR")
DEFAULT_CURRENCY = "RUB"

DEFAULT_RATES_TO_RUB = {
    "RUB": float(os.environ.get("FX_RUB_TO_RUB", "1")),
    "USD": float(os.environ.get("FX_USD_TO_RUB", "92")),
    "EUR": float(os.environ.get("FX_EUR_TO_RUB", "99")),
}
DEFAULT_SPREAD_PERCENT = float(os.environ.get("FX_SPREAD_PERCENT", "1.5"))

WITHDRAWAL_STATUSES = {"queued", "processing", "completed", "rejected"}
CONTRACT_STATUSES = {"draft", "active", "paused", "closed"}

ONCHAIN_ECONOMIC_TX_TYPES = {
    "fx_rules_update",
    "fx_oracle_commit",
    "fx_oracle_submit",
    "fx_oracle_penalty",
    "fx_epoch_finalized",
    "fiat_topup",
    "fiat_conversion",
    "fiat_withdrawal_request",
    "fiat_withdrawal_status",
    "contract_create_event",
    "contract_status_event",
    "contract_budget_fund_event",
    "contract_budget_refund_event",
    "contract_reward_settlement",
    "contract_worker_escrow_hold",
    "contract_worker_escrow_release",
    "contract_worker_escrow_penalty",
}


def now_ts() -> int:
    return int(time.time())


def normalize_currency(raw_currency: Optional[str]) -> Optional[str]:
    if not isinstance(raw_currency, str):
        return None
    normalized = raw_currency.strip().upper()
    if normalized not in SUPPORTED_BUDGET_CURRENCIES:
        return None
    return normalized


def mask_card_number(raw_card: str) -> Optional[str]:
    digits = "".join(ch for ch in str(raw_card or "") if ch.isdigit())
    if len(digits) < 12 or len(digits) > 19:
        return None
    return "****" + digits[-4:]


def _positive_int(value) -> Optional[int]:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _non_negative_float(value) -> Optional[float]:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed < 0:
        return None
    return parsed


def _wallet_template() -> Dict[str, int]:
    return {c: 0 for c in SUPPORTED_BUDGET_CURRENCIES}


def _ensure_wallet(wallets: Dict[str, Dict[str, int]], client_id: str) -> Dict[str, int]:
    if client_id not in wallets:
        wallets[client_id] = _wallet_template()
    row = wallets[client_id]
    for c in SUPPORTED_BUDGET_CURRENCIES:
        if c not in row or not isinstance(row[c], int):
            row[c] = int(row.get(c, 0) or 0)
        if row[c] < 0:
            row[c] = 0
    return row


def _iter_block_txs(chain: Iterable) -> Iterable[Tuple[int, int, dict]]:
    for block in chain:
        block_index = int(getattr(block, "index", 0))
        ts = int(getattr(block, "timestamp", 0) or 0)
        for tx in list(getattr(block, "transactions", []) or []):
            if isinstance(tx, dict):
                yield block_index, ts, tx


def is_valid_onchain_economic_tx(tx: dict) -> bool:
    if not isinstance(tx, dict):
        return False
    tx_type = tx.get("type")
    if tx_type not in ONCHAIN_ECONOMIC_TX_TYPES:
        return False

    if tx_type == "fx_rules_update":
        rates = tx.get("rates_to_rub")
        spread = tx.get("spread_percent")
        if rates is None and spread is None:
            return False
        if rates is not None:
            if not isinstance(rates, dict):
                return False
            for c, v in rates.items():
                if normalize_currency(c) is None:
                    return False
                if _non_negative_float(v) is None or float(v) <= 0:
                    return False
        if spread is not None and _non_negative_float(spread) is None:
            return False
        return True

    if tx_type == "fx_oracle_submit":
        rates = tx.get("rates_to_rub")
        if not isinstance(rates, dict):
            return False
        for c in SUPPORTED_BUDGET_CURRENCIES:
            if c not in rates:
                return False
            if _non_negative_float(rates.get(c)) is None or float(rates.get(c)) <= 0:
                return False
        return (
            isinstance(tx.get("oracle_id"), str)
            and bool(tx.get("oracle_id"))
            and isinstance(tx.get("epoch_id"), str)
            and bool(tx.get("epoch_id"))
            and isinstance(tx.get("signature"), str)
            and bool(tx.get("signature"))
        )

    if tx_type == "fx_oracle_commit":
        commit_hash = (tx.get("commit_hash") or "").strip().lower()
        return (
            isinstance(tx.get("oracle_id"), str)
            and bool(tx.get("oracle_id"))
            and isinstance(tx.get("epoch_id"), str)
            and bool(tx.get("epoch_id"))
            and len(commit_hash) == 64
            and all(ch in "0123456789abcdef" for ch in commit_hash)
        )

    if tx_type == "fx_oracle_penalty":
        return (
            isinstance(tx.get("oracle_id"), str)
            and bool(tx.get("oracle_id"))
            and isinstance(tx.get("epoch_id"), str)
            and bool(tx.get("epoch_id"))
            and _positive_int(tx.get("penalty_points")) is not None
            and isinstance(tx.get("reason"), str)
            and bool(tx.get("reason"))
        )

    if tx_type == "fx_epoch_finalized":
        rates = tx.get("rates_to_rub")
        if not isinstance(rates, dict):
            return False
        for c in SUPPORTED_BUDGET_CURRENCIES:
            if c not in rates:
                return False
            if _non_negative_float(rates.get(c)) is None or float(rates.get(c)) <= 0:
                return False
        return (
            isinstance(tx.get("epoch_id"), str)
            and bool(tx.get("epoch_id"))
            and _non_negative_float(tx.get("confidence", 0)) is not None
            and _non_negative_float(tx.get("volatility_score", 0)) is not None
            and _non_negative_float(tx.get("spread_percent", 0)) is not None
        )

    if tx_type == "fiat_topup":
        return (
            isinstance(tx.get("client_id"), str)
            and bool(tx.get("client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
        )

    if tx_type == "fiat_conversion":
        return (
            isinstance(tx.get("client_id"), str)
            and bool(tx.get("client_id"))
            and normalize_currency(tx.get("from_currency")) is not None
            and normalize_currency(tx.get("to_currency")) is not None
            and tx.get("from_currency") != tx.get("to_currency")
            and _positive_int(tx.get("source_amount")) is not None
            and _positive_int(tx.get("target_amount")) is not None
            and _non_negative_float(tx.get("spread_percent", 0)) is not None
        )

    if tx_type == "fiat_withdrawal_request":
        return (
            isinstance(tx.get("withdrawal_id"), str)
            and bool(tx.get("withdrawal_id"))
            and isinstance(tx.get("client_id"), str)
            and bool(tx.get("client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
            and isinstance(tx.get("card_mask"), str)
            and bool(tx.get("card_mask"))
            and tx.get("status") in WITHDRAWAL_STATUSES
        )

    if tx_type == "fiat_withdrawal_status":
        return (
            isinstance(tx.get("withdrawal_id"), str)
            and bool(tx.get("withdrawal_id"))
            and tx.get("status") in WITHDRAWAL_STATUSES
        )

    if tx_type == "contract_create_event":
        return (
            isinstance(tx.get("contract_id"), str)
            and bool(tx.get("contract_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and normalize_currency(tx.get("budget_currency")) is not None
            and _positive_int(tx.get("reward_per_task")) is not None
            and tx.get("status") in CONTRACT_STATUSES
        )

    if tx_type == "contract_status_event":
        return (
            isinstance(tx.get("contract_id"), str)
            and bool(tx.get("contract_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and tx.get("status") in CONTRACT_STATUSES
        )

    if tx_type == "contract_budget_fund_event":
        return (
            isinstance(tx.get("contract_id"), str)
            and bool(tx.get("contract_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
        )

    if tx_type == "contract_budget_refund_event":
        return (
            isinstance(tx.get("contract_id"), str)
            and bool(tx.get("contract_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
        )

    if tx_type == "contract_reward_settlement":
        return (
            isinstance(tx.get("reward_id"), str)
            and bool(tx.get("reward_id"))
            and isinstance(tx.get("contract_id"), str)
            and bool(tx.get("contract_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and isinstance(tx.get("worker_client_id"), str)
            and bool(tx.get("worker_client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
            and _positive_int(tx.get("work_units")) is not None
        )

    if tx_type == "contract_worker_escrow_hold":
        return (
            isinstance(tx.get("hold_id"), str)
            and bool(tx.get("hold_id"))
            and isinstance(tx.get("job_id"), str)
            and bool(tx.get("job_id"))
            and isinstance(tx.get("contract_id"), str)
            and bool(tx.get("contract_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and isinstance(tx.get("worker_client_id"), str)
            and bool(tx.get("worker_client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
        )

    if tx_type == "contract_worker_escrow_release":
        return (
            isinstance(tx.get("hold_id"), str)
            and bool(tx.get("hold_id"))
            and isinstance(tx.get("worker_client_id"), str)
            and bool(tx.get("worker_client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("amount")) is not None
        )

    if tx_type == "contract_worker_escrow_penalty":
        return (
            isinstance(tx.get("hold_id"), str)
            and bool(tx.get("hold_id"))
            and isinstance(tx.get("provider_client_id"), str)
            and bool(tx.get("provider_client_id"))
            and isinstance(tx.get("worker_client_id"), str)
            and bool(tx.get("worker_client_id"))
            and normalize_currency(tx.get("currency")) is not None
            and _positive_int(tx.get("penalty_amount")) is not None
        )

    return False


def get_effective_fx_rules(chain: Iterable) -> dict:
    rates = copy.deepcopy(DEFAULT_RATES_TO_RUB)
    spread_percent = float(DEFAULT_SPREAD_PERCENT)
    updated_at = None
    for _, ts, tx in _iter_block_txs(chain):
        if tx.get("type") != "fx_rules_update":
            continue
        rates_payload = tx.get("rates_to_rub")
        if isinstance(rates_payload, dict):
            for c, v in rates_payload.items():
                normalized = normalize_currency(c)
                if normalized is None:
                    continue
                try:
                    parsed = float(v)
                except (TypeError, ValueError):
                    continue
                if parsed > 0:
                    rates[normalized] = parsed
        spread_payload = tx.get("spread_percent")
        if spread_payload is not None:
            parsed_spread = _non_negative_float(spread_payload)
            if parsed_spread is not None:
                spread_percent = float(parsed_spread)
        updated_at = ts
    return {
        "rates_to_rub": rates,
        "spread_percent": spread_percent,
        "updated_at": updated_at,
        "supported_currencies": list(SUPPORTED_BUDGET_CURRENCIES),
    }


def convert_with_rules(*, rules: dict, from_currency: str, to_currency: str, amount: int) -> Tuple[Optional[int], Optional[str]]:
    src = normalize_currency(from_currency)
    dst = normalize_currency(to_currency)
    if not src or not dst:
        return None, "Unsupported currency"
    if src == dst:
        return None, "from_currency and to_currency must differ"
    source_amount = _positive_int(amount)
    if source_amount is None:
        return None, "amount must be > 0"
    rates = rules.get("rates_to_rub") or {}
    src_rate = float(rates.get(src, 0))
    dst_rate = float(rates.get(dst, 0))
    if src_rate <= 0 or dst_rate <= 0:
        return None, "Invalid FX rates"
    spread_percent = float(rules.get("spread_percent", DEFAULT_SPREAD_PERCENT))
    gross = (float(source_amount) * src_rate) / dst_rate
    net = int(gross * (100.0 - spread_percent) / 100.0)
    if net <= 0:
        return None, "Converted amount is too small"
    return net, None


def _wallets_and_audit(chain: Iterable) -> tuple:
    rules = get_effective_fx_rules(chain)
    wallets: Dict[str, Dict[str, int]] = {}
    withdrawals: Dict[str, dict] = {}
    settlements_seen = set()
    contract_state: Dict[str, dict] = {}
    audit_rows: List[dict] = []

    for block_index, ts, tx in _iter_block_txs(chain):
        tx_type = tx.get("type")
        if tx_type not in ONCHAIN_ECONOMIC_TX_TYPES:
            continue
        audit_rows.append(
            {
                "block_index": block_index,
                "timestamp": ts,
                "type": tx_type,
                "tx": copy.deepcopy(tx),
            }
        )

        if tx_type == "fiat_topup":
            cid = tx.get("client_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            if cid and cur and amount:
                _ensure_wallet(wallets, cid)[cur] += amount
            continue

        if tx_type == "contract_budget_fund_event":
            cid = tx.get("provider_client_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            contract_id = tx.get("contract_id")
            if cid and cur and amount:
                _ensure_wallet(wallets, cid)[cur] = max(0, _ensure_wallet(wallets, cid)[cur] - amount)
            if contract_id:
                row = contract_state.setdefault(contract_id, {"contract_id": contract_id})
                row["budget_currency"] = cur or row.get("budget_currency")
                row["funded_total"] = int(row.get("funded_total", 0)) + int(amount or 0)
            continue

        if tx_type == "contract_budget_refund_event":
            cid = tx.get("provider_client_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            contract_id = tx.get("contract_id")
            if cid and cur and amount:
                _ensure_wallet(wallets, cid)[cur] += amount
            if contract_id:
                row = contract_state.setdefault(contract_id, {"contract_id": contract_id})
                row["budget_currency"] = cur or row.get("budget_currency")
                row["refunded_total"] = int(row.get("refunded_total", 0)) + int(amount or 0)
            continue

        if tx_type == "contract_reward_settlement":
            reward_id = tx.get("reward_id")
            if reward_id in settlements_seen:
                continue
            settlements_seen.add(reward_id)
            worker = tx.get("worker_client_id")
            contract_id = tx.get("contract_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            work_units = _positive_int(tx.get("work_units")) or 0
            provider = tx.get("provider_client_id")
            if worker and cur and amount:
                _ensure_wallet(wallets, worker)[cur] += amount
            if contract_id:
                row = contract_state.setdefault(contract_id, {"contract_id": contract_id})
                row["provider_client_id"] = provider or row.get("provider_client_id")
                row["budget_currency"] = cur or row.get("budget_currency")
                row["settled_total"] = int(row.get("settled_total", 0)) + int(amount or 0)
                row["jobs_completed"] = int(row.get("jobs_completed", 0)) + 1
                row["work_units_done"] = int(row.get("work_units_done", 0)) + int(work_units)
            continue

        if tx_type == "contract_worker_escrow_hold":
            worker = tx.get("worker_client_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            if worker and cur and amount:
                wallet = _ensure_wallet(wallets, worker)
                wallet[cur] = max(0, wallet[cur] - amount)
            continue

        if tx_type == "contract_worker_escrow_release":
            worker = tx.get("worker_client_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            if worker and cur and amount:
                _ensure_wallet(wallets, worker)[cur] += amount
            continue

        if tx_type == "contract_worker_escrow_penalty":
            worker = tx.get("worker_client_id")
            provider = tx.get("provider_client_id")
            cur = normalize_currency(tx.get("currency"))
            penalty_amount = _positive_int(tx.get("penalty_amount"))
            if worker and cur and penalty_amount:
                wallet = _ensure_wallet(wallets, worker)
                wallet[cur] = max(0, wallet[cur] - penalty_amount)
            if provider and cur and penalty_amount:
                _ensure_wallet(wallets, provider)[cur] += penalty_amount
            continue

        if tx_type == "fiat_conversion":
            cid = tx.get("client_id")
            src = normalize_currency(tx.get("from_currency"))
            dst = normalize_currency(tx.get("to_currency"))
            source_amount = _positive_int(tx.get("source_amount"))
            target_amount = _positive_int(tx.get("target_amount"))
            if cid and src and dst and source_amount and target_amount:
                wallet = _ensure_wallet(wallets, cid)
                wallet[src] = max(0, wallet[src] - source_amount)
                wallet[dst] += target_amount
            continue

        if tx_type == "fiat_withdrawal_request":
            wid = tx.get("withdrawal_id")
            cid = tx.get("client_id")
            cur = normalize_currency(tx.get("currency"))
            amount = _positive_int(tx.get("amount"))
            if wid and cid and cur and amount:
                wallet = _ensure_wallet(wallets, cid)
                wallet[cur] = max(0, wallet[cur] - amount)
                withdrawals[wid] = {
                    "withdrawal_id": wid,
                    "client_id": cid,
                    "currency": cur,
                    "amount": amount,
                    "card_mask": tx.get("card_mask"),
                    "status": tx.get("status", "queued"),
                    "created_at": int(tx.get("created_at", ts or now_ts())),
                    "updated_at": int(tx.get("created_at", ts or now_ts())),
                }
            continue

        if tx_type == "fiat_withdrawal_status":
            wid = tx.get("withdrawal_id")
            status = tx.get("status")
            row = withdrawals.get(wid)
            if row and status in WITHDRAWAL_STATUSES:
                old_status = row.get("status")
                row["status"] = status
                row["updated_at"] = int(tx.get("updated_at", ts or now_ts()))
                if status == "rejected" and old_status != "rejected":
                    cid = row.get("client_id")
                    cur = normalize_currency(row.get("currency"))
                    amount = _positive_int(row.get("amount"))
                    if cid and cur and amount:
                        _ensure_wallet(wallets, cid)[cur] += amount
            continue

        if tx_type == "contract_create_event":
            cid = tx.get("contract_id")
            if cid:
                row = contract_state.setdefault(cid, {"contract_id": cid})
                row.update(
                    {
                        "provider_client_id": tx.get("provider_client_id"),
                        "budget_currency": normalize_currency(tx.get("budget_currency")) or DEFAULT_CURRENCY,
                        "status": tx.get("status"),
                        "task_name": tx.get("task_name"),
                        "reward_per_task": tx.get("reward_per_task"),
                        "created_at": int(tx.get("created_at", ts or now_ts())),
                        "updated_at": int(tx.get("created_at", ts or now_ts())),
                    }
                )
            continue

        if tx_type == "contract_status_event":
            cid = tx.get("contract_id")
            if cid:
                row = contract_state.setdefault(cid, {"contract_id": cid})
                row["provider_client_id"] = tx.get("provider_client_id") or row.get("provider_client_id")
                row["status"] = tx.get("status")
                row["updated_at"] = int(tx.get("updated_at", ts or now_ts()))
            continue

    # Обогащаем статусы контрактов агрегатами бюджета.
    for row in contract_state.values():
        funded = int(row.get("funded_total", 0))
        refunded = int(row.get("refunded_total", 0))
        settled = int(row.get("settled_total", 0))
        row["budget_total"] = funded
        row["budget_spent"] = settled
        row["budget_refunded"] = refunded
        row["budget_available"] = max(0, funded - refunded - settled)

    return wallets, withdrawals, settlements_seen, contract_state, audit_rows, rules


def get_wallet_from_chain(chain: Iterable, client_id: str) -> dict:
    wallets, _, _, _, _, rules = _wallets_and_audit(chain)
    wallet = wallets.get(client_id, _wallet_template())
    rates = rules.get("rates_to_rub") or {}
    rub_total = 0.0
    for c, amount in wallet.items():
        rub_total += float(amount) * float(rates.get(c, 0))
    return {
        "client_id": client_id,
        "balances": copy.deepcopy(wallet),
        "total_rub_estimate": int(round(rub_total)),
    }


def get_wallet_amount(chain: Iterable, client_id: str, currency: str) -> int:
    wallet = get_wallet_from_chain(chain, client_id)
    normalized = normalize_currency(currency)
    if not normalized:
        return 0
    return int(wallet["balances"].get(normalized, 0))


def is_reward_settled(chain: Iterable, reward_id: str) -> bool:
    if not reward_id:
        return False
    _, _, settled_ids, _, _, _ = _wallets_and_audit(chain)
    return reward_id in settled_ids


def list_withdrawals_from_chain(chain: Iterable, client_id: str, limit: int = 50) -> List[dict]:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(200, limit))
    _, withdrawals, _, _, _, _ = _wallets_and_audit(chain)
    rows = [w for w in withdrawals.values() if w.get("client_id") == client_id]
    rows.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)
    return rows[:limit]


def list_contracts_onchain(chain: Iterable, provider_client_id: Optional[str] = None) -> List[dict]:
    _, _, _, contract_state, _, _ = _wallets_and_audit(chain)
    rows = list(contract_state.values())
    if provider_client_id:
        rows = [r for r in rows if r.get("provider_client_id") == provider_client_id]
    rows.sort(key=lambda x: int(x.get("updated_at", x.get("created_at", 0) or 0)), reverse=True)
    return copy.deepcopy(rows)


def list_audit_events(
    chain: Iterable,
    *,
    client_id: Optional[str] = None,
    contract_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 200,
) -> List[dict]:
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 200
    limit = max(1, min(1000, limit))

    _, _, _, _, audit_rows, _ = _wallets_and_audit(chain)
    rows = []
    for row in audit_rows:
        tx = row.get("tx") or {}
        if event_type and tx.get("type") != event_type:
            continue
        if contract_id and tx.get("contract_id") != contract_id:
            continue
        if client_id:
            linked_ids = {
                tx.get("client_id"),
                tx.get("provider_client_id"),
                tx.get("worker_client_id"),
            }
            if client_id not in linked_ids:
                continue
        rows.append(row)
    rows.sort(key=lambda x: (int(x.get("block_index", 0)), int(x.get("timestamp", 0))), reverse=True)
    return rows[:limit]

