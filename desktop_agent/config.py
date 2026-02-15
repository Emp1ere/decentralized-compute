import json
import os
import re
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken


APP_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
KEY_FILE = os.path.join(APP_DIR, "settings.key")

_TIME_RE = re.compile(r"^\d{2}:\d{2}$")
_DEVICE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_.]{2,127}$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _get_fernet():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return Fernet(key)


def encrypt_api_key(api_key):
    if not api_key:
        return ""
    token = _get_fernet().encrypt(api_key.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_api_key(token):
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def read_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {}
    except (OSError, json.JSONDecodeError):
        return {}
    encrypted = data.pop("api_key_encrypted", "")
    data["api_key"] = decrypt_api_key(encrypted)
    data.pop("api_key", None)
    return data


def write_settings(payload):
    serialized = dict(payload or {})
    api_key = serialized.pop("api_key", "")
    serialized["api_key_encrypted"] = encrypt_api_key(api_key)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(serialized, f, ensure_ascii=False, indent=2)


def validate_url(value):
    parsed = urlparse((value or "").strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    return True


def validate_client_id(value):
    return bool(_UUID_RE.match((value or "").strip()))


def validate_device_id(value):
    return bool(_DEVICE_RE.match((value or "").strip()))


def validate_hhmm(value):
    value = (value or "").strip()
    if not _TIME_RE.match(value):
        return False
    hh, mm = [int(x) for x in value.split(":")]
    return 0 <= hh <= 23 and 0 <= mm <= 59
