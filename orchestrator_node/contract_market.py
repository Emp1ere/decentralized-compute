"""
Хранилище пользовательских контрактов поставщиков (provider contracts).

Контракты хранятся в data/provider_contracts.json и имеют жизненный цикл:
draft -> active -> paused -> closed.
"""
import copy
import json
import os
import threading
import time
import uuid

DATA_DIR = os.environ.get("AUTH_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
MARKET_FILE = os.path.join(DATA_DIR, "provider_contracts.json")
_lock = threading.Lock()

STATUS_DRAFT = "draft"
STATUS_ACTIVE = "active"
STATUS_PAUSED = "paused"
STATUS_CLOSED = "closed"
SUPPORTED_STATUSES = {STATUS_DRAFT, STATUS_ACTIVE, STATUS_PAUSED, STATUS_CLOSED}


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_state():
    _ensure_dir()
    if not os.path.exists(MARKET_FILE):
        return {"contracts": []}
    try:
        with open(MARKET_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("contracts"), list):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {"contracts": []}


def _save_state(state):
    _ensure_dir()
    with open(MARKET_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _now():
    return int(time.time())


def _budget_available(rec):
    return max(
        0,
        int(rec.get("budget_tokens_total", 0))
        - int(rec.get("budget_tokens_spent", 0))
        - int(rec.get("budget_tokens_refunded", 0)),
    )


def _remaining_work_units(rec):
    return max(
        0,
        int(rec.get("target_total_work_units", 0)) - int(rec.get("completed_work_units", 0)),
    )


def _enrich_contract(rec):
    out = copy.deepcopy(rec)
    out["budget_tokens_available"] = _budget_available(rec)
    out["remaining_work_units"] = _remaining_work_units(rec)
    return out


class ContractMarket:
    def create_contract(
        self,
        *,
        provider_client_id,
        task_name,
        task_description,
        task_category,
        computation_type,
        work_units_required,
        reward_per_task,
        target_total_work_units,
        difficulty,
        initial_budget_tokens=0,
        contract_id=None,
        status=STATUS_DRAFT,
    ):
        if status not in SUPPORTED_STATUSES:
            raise ValueError("Unsupported contract status")
        now = _now()
        normalized_contract_id = (contract_id or "").strip() or f"usr-{uuid.uuid4().hex[:12]}"
        record = {
            "contract_id": normalized_contract_id,
            "provider_client_id": provider_client_id,
            "task_name": task_name,
            "task_description": task_description,
            "task_category": task_category,
            "computation_type": computation_type,
            "work_units_required": int(work_units_required),
            "reward_per_task": int(reward_per_task),
            "target_total_work_units": int(target_total_work_units),
            "difficulty": int(difficulty),
            "status": status,
            "budget_tokens_total": int(initial_budget_tokens),
            "budget_tokens_spent": 0,
            "budget_tokens_refunded": 0,
            "completed_work_units": 0,
            "jobs_completed": 0,
            "created_at": now,
            "updated_at": now,
        }
        with _lock:
            state = _load_state()
            if any(c.get("contract_id") == normalized_contract_id for c in state["contracts"]):
                raise ValueError("Contract ID already exists")
            state["contracts"].append(record)
            _save_state(state)
        return _enrich_contract(record)

    def list_provider_contracts(self, provider_client_id):
        with _lock:
            state = _load_state()
            result = [
                _enrich_contract(c)
                for c in state["contracts"]
                if c.get("provider_client_id") == provider_client_id
            ]
        return sorted(result, key=lambda x: x.get("created_at", 0), reverse=True)

    def list_active_contracts(self):
        with _lock:
            state = _load_state()
            result = []
            for c in state["contracts"]:
                ec = _enrich_contract(c)
                if self.is_assignable(ec):
                    result.append(ec)
        return result

    def get_contract(self, contract_id):
        with _lock:
            state = _load_state()
            for c in state["contracts"]:
                if c.get("contract_id") == contract_id:
                    return _enrich_contract(c)
        return None

    def set_status(self, *, contract_id, provider_client_id, new_status):
        if new_status not in SUPPORTED_STATUSES:
            return None, "Unsupported status"
        with _lock:
            state = _load_state()
            for c in state["contracts"]:
                if c.get("contract_id") != contract_id:
                    continue
                if c.get("provider_client_id") != provider_client_id:
                    return None, "Forbidden"
                old_status = c.get("status")
                if old_status == STATUS_CLOSED and new_status != STATUS_CLOSED:
                    return None, "Closed contract cannot be reopened"
                if new_status == STATUS_ACTIVE:
                    if _budget_available(c) < int(c.get("reward_per_task", 0)):
                        return None, "Cannot activate contract without available budget/work"
                    if _remaining_work_units(c) <= 0:
                        return None, "Cannot activate contract without available budget/work"
                c["status"] = new_status
                c["updated_at"] = _now()
                _save_state(state)
                return _enrich_contract(c), None
        return None, "Contract not found"

    def fund_contract(self, *, contract_id, provider_client_id, amount):
        amount = int(amount)
        if amount <= 0:
            return None, "Amount must be > 0"
        with _lock:
            state = _load_state()
            for c in state["contracts"]:
                if c.get("contract_id") != contract_id:
                    continue
                if c.get("provider_client_id") != provider_client_id:
                    return None, "Forbidden"
                if c.get("status") == STATUS_CLOSED:
                    return None, "Closed contract cannot be funded"
                c["budget_tokens_total"] = int(c.get("budget_tokens_total", 0)) + amount
                c["updated_at"] = _now()
                _save_state(state)
                return _enrich_contract(c), None
        return None, "Contract not found"

    def refund_contract(self, *, contract_id, provider_client_id, amount=None):
        with _lock:
            state = _load_state()
            for c in state["contracts"]:
                if c.get("contract_id") != contract_id:
                    continue
                if c.get("provider_client_id") != provider_client_id:
                    return None, None, "Forbidden"
                available = _budget_available(c)
                if available <= 0:
                    return None, None, "No available budget to refund"
                if amount is None:
                    refund_amount = available
                else:
                    refund_amount = int(amount)
                    if refund_amount <= 0:
                        return None, None, "Amount must be > 0"
                    if refund_amount > available:
                        return None, None, "Refund amount exceeds available budget"
                c["budget_tokens_refunded"] = int(c.get("budget_tokens_refunded", 0)) + refund_amount
                if c.get("status") == STATUS_ACTIVE and not self.is_assignable(c):
                    c["status"] = STATUS_PAUSED
                c["updated_at"] = _now()
                _save_state(state)
                return _enrich_contract(c), refund_amount, None
        return None, None, "Contract not found"

    def reserve_submission(self, *, contract_id, reward_amount, work_units_done):
        reward_amount = int(reward_amount)
        work_units_done = int(work_units_done)
        if reward_amount <= 0:
            return None, "Invalid reward amount"
        if work_units_done <= 0:
            return None, "Invalid work_units_done"
        with _lock:
            state = _load_state()
            for c in state["contracts"]:
                if c.get("contract_id") != contract_id:
                    continue
                status = c.get("status")
                if status not in (STATUS_ACTIVE, STATUS_PAUSED):
                    return None, "Contract is closed"
                available = _budget_available(c)
                if available < reward_amount:
                    return None, "Contract budget exhausted"
                remaining = _remaining_work_units(c)
                if remaining <= 0:
                    return None, "Contract target volume reached"
                accepted_work = min(work_units_done, remaining)
                c["budget_tokens_spent"] = int(c.get("budget_tokens_spent", 0)) + reward_amount
                c["completed_work_units"] = int(c.get("completed_work_units", 0)) + accepted_work
                c["jobs_completed"] = int(c.get("jobs_completed", 0)) + 1
                # Автозакрываем контракт, если больше не из чего платить или цель достигнута
                next_available = _budget_available(c)
                next_remaining = _remaining_work_units(c)
                if next_available < int(c.get("reward_per_task", 0)) or next_remaining <= 0:
                    c["status"] = STATUS_CLOSED
                c["updated_at"] = _now()
                _save_state(state)
                reservation = {
                    "reward_amount": reward_amount,
                    "accepted_work": accepted_work,
                }
                return reservation, None
        return None, "Contract not found"

    def rollback_submission(self, *, contract_id, reservation):
        if not reservation:
            return
        reward_amount = int(reservation.get("reward_amount", 0))
        accepted_work = int(reservation.get("accepted_work", 0))
        with _lock:
            state = _load_state()
            for c in state["contracts"]:
                if c.get("contract_id") != contract_id:
                    continue
                c["budget_tokens_spent"] = max(0, int(c.get("budget_tokens_spent", 0)) - reward_amount)
                c["completed_work_units"] = max(0, int(c.get("completed_work_units", 0)) - accepted_work)
                c["jobs_completed"] = max(0, int(c.get("jobs_completed", 0)) - 1)
                if (
                    c.get("status") == STATUS_CLOSED
                    and _budget_available(c) >= int(c.get("reward_per_task", 0))
                    and _remaining_work_units(c) > 0
                ):
                    c["status"] = STATUS_ACTIVE
                c["updated_at"] = _now()
                _save_state(state)
                return

    def is_assignable(self, contract_record):
        if not contract_record:
            return False
        if contract_record.get("status") != STATUS_ACTIVE:
            return False
        if _budget_available(contract_record) < int(contract_record.get("reward_per_task", 0)):
            return False
        if _remaining_work_units(contract_record) <= 0:
            return False
        return True

    def upsert_seed_contracts(self, *, provider_client_id, templates):
        """
        Инициализация/миграция стартовых контрактов в формат пользовательских.
        Не изменяет существующие контракты, если contract_id уже есть.
        """
        created = []
        with _lock:
            state = _load_state()
            existing_ids = {c.get("contract_id") for c in state["contracts"]}
            now = _now()
            for tpl in templates:
                cid = (tpl.get("contract_id") or "").strip()
                if not cid or cid in existing_ids:
                    continue
                reward = int(tpl.get("reward_per_task", 0))
                target = int(tpl.get("target_total_work_units", 0))
                wu_required = int(tpl.get("work_units_required", 1))
                jobs_estimate = max(1, target // max(1, wu_required))
                initial_budget = int(tpl.get("initial_budget_tokens", reward * jobs_estimate))
                rec = {
                    "contract_id": cid,
                    "provider_client_id": provider_client_id,
                    "task_name": tpl.get("task_name", cid),
                    "task_description": tpl.get("task_description", ""),
                    "task_category": tpl.get("task_category", "Пользовательская"),
                    "computation_type": tpl.get("computation_type", "simple_pow"),
                    "work_units_required": wu_required,
                    "reward_per_task": reward,
                    "target_total_work_units": target,
                    "difficulty": int(tpl.get("difficulty", 1)),
                    "status": tpl.get("status", STATUS_ACTIVE),
                    "budget_tokens_total": initial_budget,
                    "budget_tokens_spent": 0,
                    "budget_tokens_refunded": 0,
                    "completed_work_units": 0,
                    "jobs_completed": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                state["contracts"].append(rec)
                existing_ids.add(cid)
                created.append(_enrich_contract(rec))
            if created:
                _save_state(state)
        return created

