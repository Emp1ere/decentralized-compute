import json
import os
import random
import threading
import time
import uuid
from typing import Dict, Optional


DATA_DIR = os.environ.get("AUTH_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
CASES_FILE = os.path.join(DATA_DIR, "compliance_cases.json")
_lock = threading.Lock()
_rng = random.Random(42)


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _now():
    return int(time.time())


def _blank_state():
    return {
        "cases": {},
        "webhook_events": [],
    }


def _load_state():
    _ensure_dir()
    if not os.path.exists(CASES_FILE):
        return _blank_state()
    try:
        with open(CASES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _blank_state()
        state = _blank_state()
        if isinstance(data.get("cases"), dict):
            state["cases"] = data["cases"]
        if isinstance(data.get("webhook_events"), list):
            state["webhook_events"] = data["webhook_events"]
        return state
    except (json.JSONDecodeError, OSError):
        return _blank_state()


def _save_state(state):
    _ensure_dir()
    with open(CASES_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _risk_score(*, amount, currency, country_code, kyc_tier):
    score = min(100, int(amount // 300))
    if (currency or "RUB").upper() in {"USD", "EUR"}:
        score = min(100, score + 10)
    if (country_code or "UNSET").upper() in {"UNSET", "BLOCKED"}:
        score = min(100, score + 20)
    if (kyc_tier or "").strip() == "tier0_unverified":
        score = min(100, score + 20)
    return score


def _decision_from_score(score):
    if score >= 85:
        return "reject"
    if score >= 55:
        return "review"
    return "allow"


def create_case(
    *,
    client_id: str,
    operation: str,
    amount: int,
    currency: str,
    country_code: Optional[str],
    kyc_tier: str,
):
    with _lock:
        state = _load_state()
        now = _now()
        case_id = f"cp-{uuid.uuid4().hex[:16]}"
        risk = _risk_score(
            amount=max(0, int(amount or 0)),
            currency=(currency or "RUB").upper(),
            country_code=(country_code or "UNSET").upper(),
            kyc_tier=kyc_tier,
        )
        decision = _decision_from_score(risk)
        in_review_seconds = int(os.environ.get("COMPLIANCE_SIM_REVIEW_SECONDS", "10"))
        jitter = _rng.randint(0, 5)
        case = {
            "case_id": case_id,
            "client_id": client_id,
            "operation": (operation or "withdrawal").strip().lower(),
            "amount": max(0, int(amount or 0)),
            "currency": (currency or "RUB").upper(),
            "country_code": (country_code or "UNSET").upper(),
            "kyc_tier": kyc_tier,
            "risk_score": risk,
            "status": "pending",
            "decision": None,
            "decision_reason": None,
            "created_at": now,
            "review_started_at": None,
            "eta_decision_at": now + in_review_seconds + jitter,
            "updated_at": now,
            "simulated_outcome": decision,
        }
        state["cases"][case_id] = case
        _save_state(state)
        return dict(case)


def get_case(case_id: str):
    with _lock:
        state = _load_state()
        row = state["cases"].get(case_id)
        if not row:
            return None
        return dict(row)


def find_recent_case(*, client_id, operation, amount, currency, max_age_seconds=120):
    now = _now()
    with _lock:
        state = _load_state()
        for row in state["cases"].values():
            if row.get("client_id") != client_id:
                continue
            if row.get("operation") != operation:
                continue
            if int(row.get("amount", 0) or 0) != int(amount):
                continue
            if (row.get("currency") or "").upper() != (currency or "RUB").upper():
                continue
            if now - int(row.get("created_at", 0) or 0) > max_age_seconds:
                continue
            return dict(row)
    return None


def process_cases():
    dispatched = []
    now = _now()
    with _lock:
        state = _load_state()
        for row in state["cases"].values():
            status = (row.get("status") or "").strip()
            if status in {"allow", "review", "reject"}:
                continue
            eta = int(row.get("eta_decision_at", 0) or 0)
            if status == "pending":
                row["status"] = "in_review"
                row["review_started_at"] = now
                row["updated_at"] = now
                event = {
                    "event_id": f"ev-{uuid.uuid4().hex[:12]}",
                    "event_type": "case.in_review",
                    "case_id": row.get("case_id"),
                    "created_at": now,
                    "payload": {"case_id": row.get("case_id"), "status": "in_review"},
                }
                state["webhook_events"].append(event)
                dispatched.append(event)
                continue
            if status == "in_review" and eta and now >= eta:
                final_decision = row.get("simulated_outcome") or "review"
                row["status"] = final_decision
                row["decision"] = final_decision
                row["decision_reason"] = f"simulated_{final_decision}"
                row["updated_at"] = now
                event = {
                    "event_id": f"ev-{uuid.uuid4().hex[:12]}",
                    "event_type": "case.decision",
                    "case_id": row.get("case_id"),
                    "created_at": now,
                    "payload": {
                        "case_id": row.get("case_id"),
                        "status": final_decision,
                        "decision": final_decision,
                        "risk_score": row.get("risk_score"),
                    },
                }
                state["webhook_events"].append(event)
                dispatched.append(event)
        state["webhook_events"] = state["webhook_events"][-500:]
        _save_state(state)
    return dispatched


def list_cases(*, limit=100, status=None):
    limit = max(1, min(500, int(limit)))
    with _lock:
        state = _load_state()
        rows = [dict(v) for v in state["cases"].values()]
    if status:
        normalized = (status or "").strip().lower()
        rows = [r for r in rows if (r.get("status") or "").strip().lower() == normalized]
    rows.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
    return rows[:limit]


def list_webhook_events(*, limit=100):
    limit = max(1, min(500, int(limit)))
    with _lock:
        state = _load_state()
        rows = list(state.get("webhook_events") or [])
    rows.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
    return rows[:limit]


def evaluate_or_create_case(
    *,
    client_id: str,
    operation: str,
    amount: int,
    currency: str,
    country_code: Optional[str],
    kyc_tier: str,
):
    process_cases()
    recent = find_recent_case(
        client_id=client_id,
        operation=(operation or "withdrawal").strip().lower(),
        amount=max(0, int(amount or 0)),
        currency=(currency or "RUB").upper(),
    )
    if recent:
        return recent
    return create_case(
        client_id=client_id,
        operation=operation,
        amount=amount,
        currency=currency,
        country_code=country_code,
        kyc_tier=kyc_tier,
    )
