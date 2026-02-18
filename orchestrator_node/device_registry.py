import json
import os
import sys
import threading
import time
import uuid


DATA_DIR = os.environ.get("AUTH_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
DEVICES_FILE = os.path.join(DATA_DIR, "devices.json")
_lock = threading.Lock()
_test_state = {"devices": []}


def _is_test_runtime():
    if str(os.environ.get("PYTEST_CURRENT_TEST", "")).strip():
        return True
    return any("pytest" in str(arg).lower() for arg in sys.argv)


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load():
    if _is_test_runtime():
        return {"devices": [dict(d) for d in _test_state.get("devices", [])]}
    _ensure_dir()
    if not os.path.exists(DEVICES_FILE):
        return {"devices": []}
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("devices"), list):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"devices": []}


def _save(state):
    if _is_test_runtime():
        _test_state["devices"] = [dict(d) for d in (state.get("devices") or [])]
        return
    _ensure_dir()
    with open(DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def _normalize(device):
    out = dict(device)
    out["device_name"] = (device.get("device_name") or "Desktop agent").strip()
    out["device_id"] = (device.get("device_id") or "").strip()
    out["client_id"] = (device.get("client_id") or "").strip()
    out["agent_version"] = (device.get("agent_version") or "unknown").strip()
    out["last_seen_at"] = int(device.get("last_seen_at", 0) or 0)
    out["created_at"] = int(device.get("created_at", 0) or 0)
    out["is_disabled"] = bool(device.get("is_disabled", False))
    # capabilities — ключ для policy matching: сервер сопоставляет требования задач с возможностями устройства.
    caps = device.get("capabilities")
    out["capabilities"] = caps if isinstance(caps, dict) else {}
    out["status"] = "offline"
    out["status_reason"] = "No recent heartbeat"
    ttl = int(os.environ.get("DEVICE_ONLINE_TTL_SECONDS", "120"))
    if out["last_seen_at"] and (int(time.time()) - out["last_seen_at"]) <= ttl and not out["is_disabled"]:
        out["status"] = "online"
        out["status_reason"] = "Heartbeat is fresh"
    if out["is_disabled"]:
        out["status"] = "offline"
        out["status_reason"] = "Device disabled by owner"
    return out


def register_or_update_device(
    *,
    client_id,
    device_id=None,
    device_name=None,
    agent_version=None,
    capabilities=None,
):
    now = int(time.time())
    normalized_id = (device_id or "").strip() or f"dev-{uuid.uuid4().hex[:12]}"
    with _lock:
        state = _load()
        for row in state["devices"]:
            if row.get("device_id") != normalized_id:
                continue
            if row.get("client_id") != client_id:
                return None, "Forbidden"
            row["device_name"] = (device_name or row.get("device_name") or "Desktop agent").strip()
            row["agent_version"] = (agent_version or row.get("agent_version") or "unknown").strip()
            if isinstance(capabilities, dict):
                row["capabilities"] = dict(capabilities)
            row["last_seen_at"] = now
            _save(state)
            return _normalize(row), None
        rec = {
            "device_id": normalized_id,
            "client_id": client_id,
            "device_name": (device_name or "Desktop agent").strip(),
            "agent_version": (agent_version or "unknown").strip(),
            "created_at": now,
            "last_seen_at": now,
            "is_disabled": False,
            "capabilities": dict(capabilities) if isinstance(capabilities, dict) else {},
        }
        state["devices"].append(rec)
        _save(state)
        return _normalize(rec), None


def heartbeat_device(*, client_id, device_id, agent_version=None, capabilities=None):
    now = int(time.time())
    normalized_id = (device_id or "").strip()
    if not normalized_id:
        return None, "device_id is required"
    with _lock:
        state = _load()
        for row in state["devices"]:
            if row.get("device_id") != normalized_id:
                continue
            if row.get("client_id") != client_id:
                return None, "Forbidden"
            if row.get("is_disabled"):
                return None, "Device is disabled"
            row["last_seen_at"] = now
            if agent_version:
                row["agent_version"] = (agent_version or "").strip() or row.get("agent_version")
            if isinstance(capabilities, dict):
                row["capabilities"] = dict(capabilities)
            _save(state)
            return _normalize(row), None
    return None, "Device not found"


def list_devices_for_client(client_id):
    with _lock:
        state = _load()
        rows = [_normalize(d) for d in state["devices"] if d.get("client_id") == client_id]
    rows.sort(key=lambda x: x.get("last_seen_at", 0), reverse=True)
    return rows


def set_device_disabled(*, client_id, device_id, is_disabled):
    normalized_id = (device_id or "").strip()
    with _lock:
        state = _load()
        for row in state["devices"]:
            if row.get("device_id") != normalized_id:
                continue
            if row.get("client_id") != client_id:
                return None, "Forbidden"
            row["is_disabled"] = bool(is_disabled)
            _save(state)
            return _normalize(row), None
    return None, "Device not found"
