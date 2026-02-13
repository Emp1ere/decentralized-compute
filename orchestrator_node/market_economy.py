"""
Рыночная экономика платформы (без криптовалют):
- кошельки пользователей в фиатных валютах;
- конвертация по курсам;
- начисления исполнителям за выполненные контракты;
- вывод средств на банковскую карту.
"""
import copy
import json
import os
import threading
import time
import uuid

SUPPORTED_BUDGET_CURRENCIES = ("RUB", "USD", "EUR")
DEFAULT_CURRENCY = "RUB"
DEFAULT_RATES_TO_RUB = {
    "RUB": float(os.environ.get("FX_RUB_TO_RUB", "1")),
    "USD": float(os.environ.get("FX_USD_TO_RUB", "92")),
    "EUR": float(os.environ.get("FX_EUR_TO_RUB", "99")),
}
FX_SPREAD_PERCENT = float(os.environ.get("FX_SPREAD_PERCENT", "1.5"))

DATA_DIR = os.environ.get("AUTH_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
MARKET_ACCOUNTS_FILE = os.path.join(DATA_DIR, "market_accounts.json")
_lock = threading.Lock()


def _now():
    return int(time.time())


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _normalize_currency(currency):
    if not isinstance(currency, str):
        return None
    normalized = currency.strip().upper()
    if normalized not in SUPPORTED_BUDGET_CURRENCIES:
        return None
    return normalized


def _empty_wallet():
    return {c: 0 for c in SUPPORTED_BUDGET_CURRENCIES}


def _sanitize_wallet(raw_wallet):
    wallet = _empty_wallet()
    if not isinstance(raw_wallet, dict):
        return wallet
    for currency in SUPPORTED_BUDGET_CURRENCIES:
        try:
            wallet[currency] = max(0, int(raw_wallet.get(currency, 0)))
        except (TypeError, ValueError):
            wallet[currency] = 0
    return wallet


def _default_state():
    return {
        "wallets": {},
        "ledger": [],
        "withdrawals": [],
        "processed_reward_ids": [],
    }


def _load_state():
    _ensure_dir()
    if not os.path.exists(MARKET_ACCOUNTS_FILE):
        return _default_state()
    try:
        with open(MARKET_ACCOUNTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _default_state()
        state = _default_state()
        wallets = data.get("wallets")
        if isinstance(wallets, dict):
            state["wallets"] = {k: _sanitize_wallet(v) for k, v in wallets.items()}
        if isinstance(data.get("ledger"), list):
            state["ledger"] = data["ledger"]
        if isinstance(data.get("withdrawals"), list):
            state["withdrawals"] = data["withdrawals"]
        if isinstance(data.get("processed_reward_ids"), list):
            state["processed_reward_ids"] = data["processed_reward_ids"]
        return state
    except (OSError, json.JSONDecodeError):
        return _default_state()


def _save_state(state):
    _ensure_dir()
    with open(MARKET_ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _wallet_rub_estimate(wallet):
    total = 0.0
    for currency, amount in wallet.items():
        rate = float(DEFAULT_RATES_TO_RUB.get(currency, 0))
        total += float(amount) * rate
    return int(round(total))


class MarketEconomy:
    def get_rates(self):
        return {
            "to_rub": copy.deepcopy(DEFAULT_RATES_TO_RUB),
            "spread_percent": FX_SPREAD_PERCENT,
            "supported_currencies": list(SUPPORTED_BUDGET_CURRENCIES),
        }

    def get_wallet(self, client_id):
        with _lock:
            state = _load_state()
            wallet = _sanitize_wallet(state["wallets"].get(client_id))
            state["wallets"][client_id] = wallet
            _save_state(state)
        return {
            "client_id": client_id,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }

    def _append_ledger(self, *, state, entry):
        state["ledger"].append(entry)
        # Ограничиваем размер леджера, чтобы файл не рос бесконечно
        if len(state["ledger"]) > 5000:
            state["ledger"] = state["ledger"][-5000:]

    def top_up_wallet(self, *, client_id, currency, amount, source="bank_transfer"):
        normalized_currency = _normalize_currency(currency)
        if not normalized_currency:
            return None, "Unsupported currency"
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return None, "amount must be integer"
        if amount <= 0:
            return None, "amount must be > 0"
        with _lock:
            state = _load_state()
            wallet = _sanitize_wallet(state["wallets"].get(client_id))
            wallet[normalized_currency] += amount
            state["wallets"][client_id] = wallet
            self._append_ledger(
                state=state,
                entry={
                    "entry_id": f"lg-{uuid.uuid4().hex[:16]}",
                    "type": "wallet_topup",
                    "client_id": client_id,
                    "currency": normalized_currency,
                    "amount": amount,
                    "source": source,
                    "created_at": _now(),
                },
            )
            _save_state(state)
        return {
            "client_id": client_id,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }, None

    def credit_wallet(self, *, client_id, currency, amount, purpose, meta=None):
        normalized_currency = _normalize_currency(currency)
        if not normalized_currency:
            return None, "Unsupported currency"
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return None, "amount must be integer"
        if amount <= 0:
            return None, "amount must be > 0"
        with _lock:
            state = _load_state()
            wallet = _sanitize_wallet(state["wallets"].get(client_id))
            wallet[normalized_currency] += amount
            state["wallets"][client_id] = wallet
            self._append_ledger(
                state=state,
                entry={
                    "entry_id": f"lg-{uuid.uuid4().hex[:16]}",
                    "type": "wallet_credit",
                    "purpose": purpose,
                    "client_id": client_id,
                    "currency": normalized_currency,
                    "amount": amount,
                    "meta": meta or {},
                    "created_at": _now(),
                },
            )
            _save_state(state)
        return {
            "client_id": client_id,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }, None

    def debit_wallet(self, *, client_id, currency, amount, purpose, meta=None):
        normalized_currency = _normalize_currency(currency)
        if not normalized_currency:
            return None, "Unsupported currency"
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return None, "amount must be integer"
        if amount <= 0:
            return None, "amount must be > 0"
        with _lock:
            state = _load_state()
            wallet = _sanitize_wallet(state["wallets"].get(client_id))
            if wallet[normalized_currency] < amount:
                return None, "Insufficient wallet balance"
            wallet[normalized_currency] -= amount
            state["wallets"][client_id] = wallet
            self._append_ledger(
                state=state,
                entry={
                    "entry_id": f"lg-{uuid.uuid4().hex[:16]}",
                    "type": "wallet_debit",
                    "purpose": purpose,
                    "client_id": client_id,
                    "currency": normalized_currency,
                    "amount": amount,
                    "meta": meta or {},
                    "created_at": _now(),
                },
            )
            _save_state(state)
        return {
            "client_id": client_id,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }, None

    def credit_reward_once(
        self,
        *,
        reward_id,
        worker_client_id,
        currency,
        amount,
        provider_client_id=None,
        contract_id=None,
    ):
        normalized_currency = _normalize_currency(currency)
        if not normalized_currency:
            return None, False, "Unsupported currency"
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return None, False, "amount must be integer"
        if amount <= 0:
            return None, False, "amount must be > 0"
        if not reward_id:
            return None, False, "reward_id is required"
        with _lock:
            state = _load_state()
            processed = set(state.get("processed_reward_ids", []))
            wallet = _sanitize_wallet(state["wallets"].get(worker_client_id))
            if reward_id in processed:
                state["wallets"][worker_client_id] = wallet
                _save_state(state)
                return {
                    "client_id": worker_client_id,
                    "balances": copy.deepcopy(wallet),
                    "total_rub_estimate": _wallet_rub_estimate(wallet),
                }, False, None
            wallet[normalized_currency] += amount
            state["wallets"][worker_client_id] = wallet
            processed.add(reward_id)
            state["processed_reward_ids"] = list(processed)
            self._append_ledger(
                state=state,
                entry={
                    "entry_id": f"lg-{uuid.uuid4().hex[:16]}",
                    "type": "work_reward",
                    "reward_id": reward_id,
                    "worker_client_id": worker_client_id,
                    "provider_client_id": provider_client_id,
                    "contract_id": contract_id,
                    "currency": normalized_currency,
                    "amount": amount,
                    "created_at": _now(),
                },
            )
            _save_state(state)
        return {
            "client_id": worker_client_id,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }, True, None

    def convert_currency(self, *, client_id, from_currency, to_currency, amount):
        src = _normalize_currency(from_currency)
        dst = _normalize_currency(to_currency)
        if not src or not dst:
            return None, "Unsupported currency"
        if src == dst:
            return None, "from_currency and to_currency must differ"
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return None, "amount must be integer"
        if amount <= 0:
            return None, "amount must be > 0"
        src_rate = float(DEFAULT_RATES_TO_RUB.get(src, 0))
        dst_rate = float(DEFAULT_RATES_TO_RUB.get(dst, 0))
        if src_rate <= 0 or dst_rate <= 0:
            return None, "Invalid FX rates"
        gross_dst = (float(amount) * src_rate) / dst_rate
        net_dst = int(gross_dst * (100.0 - FX_SPREAD_PERCENT) / 100.0)
        if net_dst <= 0:
            return None, "Converted amount is too small"
        with _lock:
            state = _load_state()
            wallet = _sanitize_wallet(state["wallets"].get(client_id))
            if wallet[src] < amount:
                return None, "Insufficient wallet balance"
            wallet[src] -= amount
            wallet[dst] += net_dst
            state["wallets"][client_id] = wallet
            self._append_ledger(
                state=state,
                entry={
                    "entry_id": f"lg-{uuid.uuid4().hex[:16]}",
                    "type": "fx_conversion",
                    "client_id": client_id,
                    "from_currency": src,
                    "to_currency": dst,
                    "source_amount": amount,
                    "target_amount": net_dst,
                    "spread_percent": FX_SPREAD_PERCENT,
                    "src_to_rub": src_rate,
                    "dst_to_rub": dst_rate,
                    "created_at": _now(),
                },
            )
            _save_state(state)
        return {
            "client_id": client_id,
            "from_currency": src,
            "to_currency": dst,
            "source_amount": amount,
            "target_amount": net_dst,
            "spread_percent": FX_SPREAD_PERCENT,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }, None

    def request_withdrawal(self, *, client_id, currency, amount, card_number):
        normalized_currency = _normalize_currency(currency)
        if not normalized_currency:
            return None, None, "Unsupported currency"
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return None, None, "amount must be integer"
        if amount <= 0:
            return None, None, "amount must be > 0"
        card_digits = "".join(ch for ch in str(card_number or "") if ch.isdigit())
        if len(card_digits) < 12 or len(card_digits) > 19:
            return None, None, "Invalid card number format"
        masked = "****" + card_digits[-4:]
        with _lock:
            state = _load_state()
            wallet = _sanitize_wallet(state["wallets"].get(client_id))
            if wallet[normalized_currency] < amount:
                return None, None, "Insufficient wallet balance"
            wallet[normalized_currency] -= amount
            state["wallets"][client_id] = wallet
            withdrawal = {
                "withdrawal_id": f"wd-{uuid.uuid4().hex[:16]}",
                "client_id": client_id,
                "currency": normalized_currency,
                "amount": amount,
                "payout_method": "bank_card",
                "card_mask": masked,
                "status": "queued",
                "created_at": _now(),
            }
            state["withdrawals"].append(withdrawal)
            self._append_ledger(
                state=state,
                entry={
                    "entry_id": f"lg-{uuid.uuid4().hex[:16]}",
                    "type": "withdrawal",
                    "client_id": client_id,
                    "currency": normalized_currency,
                    "amount": amount,
                    "withdrawal_id": withdrawal["withdrawal_id"],
                    "card_mask": masked,
                    "created_at": withdrawal["created_at"],
                },
            )
            _save_state(state)
        return withdrawal, {
            "client_id": client_id,
            "balances": copy.deepcopy(wallet),
            "total_rub_estimate": _wallet_rub_estimate(wallet),
        }, None

    def list_withdrawals(self, *, client_id, limit=50):
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 50
        limit = max(1, min(200, limit))
        with _lock:
            state = _load_state()
            rows = [w for w in state["withdrawals"] if w.get("client_id") == client_id]
        rows.sort(key=lambda x: int(x.get("created_at", 0)), reverse=True)
        return rows[:limit]
