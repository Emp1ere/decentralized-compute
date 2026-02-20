from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Dict, List, Optional, Tuple


PAYMENT_HUB_ENGINE_VERSION = os.environ.get("PAYMENT_HUB_ENGINE_VERSION", "payment-hub-v1")
PAYMENT_HUB_POLICY_VERSION = os.environ.get("PAYMENT_HUB_POLICY_VERSION", "pay-policy-v1")
PAYMENT_HUB_PROVIDER_NAME = os.environ.get("PAYMENT_HUB_PROVIDER_NAME", "simulated-bank")
PAYMENT_HUB_SUCCESS_RATE = float(os.environ.get("PAYMENT_HUB_SUCCESS_RATE", "0.9"))
PAYMENT_HUB_MAX_RETRIES = int(os.environ.get("PAYMENT_HUB_MAX_RETRIES", "3"))
PAYMENT_HUB_DB_PATH = os.environ.get(
    "PAYMENT_HUB_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "payment_hub.json"),
)

_LOCK = threading.Lock()


def _ensure_parent_dir(path: str):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _blank_state() -> dict:
    return {
        "operations": {},
        "webhook_events": [],
        "reconciliations": [],
        "documents": [],
    }


def _load_state() -> dict:
    _ensure_parent_dir(PAYMENT_HUB_DB_PATH)
    if not os.path.exists(PAYMENT_HUB_DB_PATH):
        return _blank_state()
    try:
        with open(PAYMENT_HUB_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _blank_state()
    except Exception:
        return _blank_state()
    merged = _blank_state()
    for key in merged.keys():
        value = data.get(key, merged[key])
        if isinstance(merged[key], dict) and not isinstance(value, dict):
            value = {}
        if isinstance(merged[key], list) and not isinstance(value, list):
            value = []
        merged[key] = value
    return merged


def _save_state(state: dict):
    _ensure_parent_dir(PAYMENT_HUB_DB_PATH)
    with open(PAYMENT_HUB_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _now() -> int:
    return int(time.time())


def _hash_ratio(value: str) -> float:
    digest = hashlib.sha256(value.encode()).hexdigest()
    sample = int(digest[:8], 16)
    return float(sample) / float(0xFFFFFFFF)


def _next_provider_ref(withdrawal_id: str, retries: int) -> str:
    return f"{PAYMENT_HUB_PROVIDER_NAME}-{withdrawal_id}-{retries}"


def ensure_operation(withdrawal: dict) -> Tuple[dict, bool]:
    if not isinstance(withdrawal, dict):
        raise ValueError("withdrawal must be object")
    withdrawal_id = str(withdrawal.get("withdrawal_id") or "").strip()
    if not withdrawal_id:
        raise ValueError("withdrawal_id is required")
    with _LOCK:
        state = _load_state()
        ops = state["operations"]
        existing = ops.get(withdrawal_id)
        if existing:
            return dict(existing), True
        now_ts = _now()
        row = {
            "operation_id": withdrawal_id,
            "client_id": withdrawal.get("client_id"),
            "currency": withdrawal.get("currency"),
            "amount": int(withdrawal.get("amount", 0) or 0),
            "card_mask": withdrawal.get("card_mask"),
            "provider": PAYMENT_HUB_PROVIDER_NAME,
            "provider_ref": None,
            "status": "queued",
            "retries": 0,
            "idempotency_key": f"wd:{withdrawal_id}",
            "last_error": None,
            "created_at": now_ts,
            "updated_at": now_ts,
            "onchain_last_status": None,
            "onchain_last_status_at": None,
            "policy_version": PAYMENT_HUB_POLICY_VERSION,
            "engine_version": PAYMENT_HUB_ENGINE_VERSION,
        }
        ops[withdrawal_id] = row
        state["documents"].append(
            {
                "document_id": f"doc-{withdrawal_id}",
                "type": "withdrawal_operation_created",
                "operation_id": withdrawal_id,
                "client_id": row.get("client_id"),
                "created_at": now_ts,
                "policy_version": PAYMENT_HUB_POLICY_VERSION,
                "engine_version": PAYMENT_HUB_ENGINE_VERSION,
            }
        )
        _save_state(state)
        return dict(row), False


def list_operations(*, status: Optional[str] = None, limit: int = 200) -> dict:
    with _LOCK:
        state = _load_state()
        rows = list(state["operations"].values())
    if status:
        status_norm = str(status).strip().lower()
        rows = [row for row in rows if str(row.get("status", "")).lower() == status_norm]
    rows.sort(key=lambda x: int(x.get("updated_at", 0) or 0), reverse=True)
    limit = max(1, min(1000, int(limit)))
    return {"operations": rows[:limit], "provider": PAYMENT_HUB_PROVIDER_NAME}


def list_webhook_events(*, limit: int = 200) -> dict:
    with _LOCK:
        state = _load_state()
        rows = list(state["webhook_events"])
    rows.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
    limit = max(1, min(1000, int(limit)))
    return {"events": rows[:limit], "provider": PAYMENT_HUB_PROVIDER_NAME}


def list_documents(*, limit: int = 200, client_id: Optional[str] = None) -> dict:
    with _LOCK:
        state = _load_state()
        rows = list(state["documents"])
        operations = state["operations"]
    if client_id:
        client_norm = str(client_id).strip()
        filtered = []
        for row in rows:
            doc_client = row.get("client_id")
            if doc_client and str(doc_client).strip() == client_norm:
                filtered.append(row)
                continue
            operation_id = str(row.get("operation_id") or "").strip()
            if operation_id:
                op = operations.get(operation_id)
                if op and str(op.get("client_id") or "").strip() == client_norm:
                    filtered.append(row)
        rows = filtered
    rows.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
    limit = max(1, min(1000, int(limit)))
    return {"documents": rows[:limit]}


def dispatch_pending(*, max_batch: int = 50) -> dict:
    max_batch = max(1, min(500, int(max_batch)))
    updated = []
    events = []
    with _LOCK:
        state = _load_state()
        ops = state["operations"]
        pending_rows = [
            row for row in ops.values() if row.get("status") in {"queued", "retry"}
        ]
        pending_rows.sort(key=lambda x: int(x.get("updated_at", 0) or 0))
        for row in pending_rows[:max_batch]:
            operation_id = str(row.get("operation_id"))
            retries = int(row.get("retries", 0) or 0)
            if retries >= PAYMENT_HUB_MAX_RETRIES:
                row["status"] = "rejected"
                row["last_error"] = "max retries reached"
            else:
                sample = _hash_ratio(f"{operation_id}:{retries}")
                if sample <= PAYMENT_HUB_SUCCESS_RATE:
                    row["status"] = "completed"
                    row["provider_ref"] = _next_provider_ref(operation_id, retries)
                    row["last_error"] = None
                else:
                    row["status"] = "retry"
                    row["provider_ref"] = _next_provider_ref(operation_id, retries)
                    row["last_error"] = "temporary provider failure"
                    row["retries"] = retries + 1
            row["updated_at"] = _now()
            event = {
                "event_id": f"evt-{operation_id}-{row['updated_at']}",
                "provider": PAYMENT_HUB_PROVIDER_NAME,
                "event": "withdrawal.status",
                "operation_id": operation_id,
                "payload": {
                    "operation_id": operation_id,
                    "status": row["status"],
                    "provider_ref": row.get("provider_ref"),
                    "error": row.get("last_error"),
                },
                "created_at": row["updated_at"],
            }
            state["webhook_events"].append(event)
            state["documents"].append(
                {
                    "document_id": f"doc-{operation_id}-{row['updated_at']}",
                    "type": "payment_status_update",
                    "operation_id": operation_id,
                    "client_id": row.get("client_id"),
                    "status": row["status"],
                    "provider_ref": row.get("provider_ref"),
                    "created_at": row["updated_at"],
                    "policy_version": PAYMENT_HUB_POLICY_VERSION,
                    "engine_version": PAYMENT_HUB_ENGINE_VERSION,
                }
            )
            updated.append(dict(row))
            events.append(event)
        _save_state(state)
    return {
        "provider": PAYMENT_HUB_PROVIDER_NAME,
        "updated_operations": updated,
        "webhook_events": events,
        "engine_version": PAYMENT_HUB_ENGINE_VERSION,
        "policy_version": PAYMENT_HUB_POLICY_VERSION,
    }


def apply_webhook(*, provider: str, payload: dict) -> Tuple[dict, Optional[str]]:
    provider_norm = str(provider or "").strip().lower()
    if provider_norm != PAYMENT_HUB_PROVIDER_NAME.lower():
        return {}, "Unknown provider"
    if not isinstance(payload, dict):
        return {}, "payload must be object"
    operation_id = str(payload.get("operation_id") or "").strip()
    status = str(payload.get("status") or "").strip().lower()
    if not operation_id:
        return {}, "operation_id is required"
    if status not in {"queued", "retry", "processing", "completed", "rejected"}:
        return {}, "unsupported status"
    with _LOCK:
        state = _load_state()
        row = state["operations"].get(operation_id)
        if not row:
            return {}, "operation not found"
        row["status"] = status
        row["provider_ref"] = payload.get("provider_ref") or row.get("provider_ref")
        row["last_error"] = payload.get("error")
        row["updated_at"] = _now()
        event = {
            "event_id": f"evt-manual-{operation_id}-{row['updated_at']}",
            "provider": PAYMENT_HUB_PROVIDER_NAME,
            "event": "withdrawal.webhook",
            "operation_id": operation_id,
            "payload": dict(payload),
            "created_at": row["updated_at"],
        }
        state["webhook_events"].append(event)
        _save_state(state)
    return {"operation": dict(row), "event": event}, None


def mark_onchain_status(*, operation_id: str, status: str) -> Tuple[dict, Optional[str]]:
    op_id = str(operation_id or "").strip()
    status_norm = str(status or "").strip().lower()
    if not op_id:
        return {}, "operation_id is required"
    if status_norm not in {"queued", "retry", "processing", "completed", "rejected"}:
        return {}, "unsupported status"
    with _LOCK:
        state = _load_state()
        row = state["operations"].get(op_id)
        if not row:
            return {}, "operation not found"
        row["onchain_last_status"] = status_norm
        row["onchain_last_status_at"] = _now()
        row["updated_at"] = _now()
        _save_state(state)
        return dict(row), None


def reconcile_with_withdrawals(*, onchain_rows: List[dict], client_id: Optional[str] = None) -> dict:
    mismatches = []
    with _LOCK:
        state = _load_state()
        ops = state["operations"]
        onchain_map = {str(row.get("withdrawal_id") or ""): row for row in onchain_rows if row.get("withdrawal_id")}
        checked_operations = 0
        for operation_id, op in ops.items():
            if client_id and op.get("client_id") != client_id:
                continue
            checked_operations += 1
            chain_row = onchain_map.get(operation_id)
            if not chain_row:
                mismatches.append(
                    {
                        "operation_id": operation_id,
                        "reason": "missing_onchain_withdrawal",
                        "hub_status": op.get("status"),
                        "onchain_status": None,
                    }
                )
                continue
            hub_status = str(op.get("status") or "").lower()
            chain_status = str(chain_row.get("status") or "").lower()
            if hub_status in {"completed", "rejected"} and chain_status != hub_status:
                mismatches.append(
                    {
                        "operation_id": operation_id,
                        "reason": "status_mismatch",
                        "hub_status": hub_status,
                        "onchain_status": chain_status,
                    }
                )
        report = {
            "report_id": f"recon-{_now()}",
            "provider": PAYMENT_HUB_PROVIDER_NAME,
            "client_id": client_id,
            "checked_operations": checked_operations,
            "mismatch_count": len(mismatches),
            "mismatches": mismatches,
            "created_at": _now(),
        }
        state["reconciliations"].append(report)
        state["documents"].append(
            {
                "document_id": f"doc-{report['report_id']}",
                "type": "reconciliation_report",
                "report_id": report["report_id"],
                "client_id": client_id,
                "created_at": report["created_at"],
                "policy_version": PAYMENT_HUB_POLICY_VERSION,
                "engine_version": PAYMENT_HUB_ENGINE_VERSION,
            }
        )
        _save_state(state)
    return report


def list_reconciliations(*, limit: int = 50, client_id: Optional[str] = None) -> dict:
    with _LOCK:
        state = _load_state()
        rows = list(state["reconciliations"])
    if client_id:
        client_norm = str(client_id).strip()
        rows = [row for row in rows if str(row.get("client_id") or "").strip() == client_norm]
    rows.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
    limit = max(1, min(500, int(limit)))
    return {"reports": rows[:limit], "provider": PAYMENT_HUB_PROVIDER_NAME}
