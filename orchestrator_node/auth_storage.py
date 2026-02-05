# Постоянное хранение аккаунтов: логин, пароль (хеш), client_id, api_key, никнейм.
# Файл data/users.json; при старте оркестратора загружаем и восстанавливаем api_key_to_client.
import os
import json
import threading
from werkzeug.security import generate_password_hash, check_password_hash

DATA_DIR = os.environ.get("AUTH_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
USERS_FILE = os.path.join(DATA_DIR, "users.json")
_lock = threading.Lock()


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_raw():
    """Загрузить сырой список пользователей из файла."""
    _ensure_dir()
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("users", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    except (json.JSONDecodeError, IOError):
        return []


def _save_raw(users):
    """Сохранить список пользователей в файл."""
    _ensure_dir()
    with _lock:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump({"users": users}, f, ensure_ascii=False, indent=2)


def load_all_into(api_key_to_client):
    """
    Загрузить пользователей из файла и заполнить api_key_to_client.
    Вызывать при старте приложения.
    """
    users = _load_raw()
    for u in users:
        if isinstance(u, dict) and u.get("api_key") and u.get("client_id"):
            api_key_to_client[u["api_key"]] = u["client_id"]
    return len(users)


def find_by_login(login):
    """Найти пользователя по логину. Возвращает dict или None."""
    users = _load_raw()
    login_lower = (login or "").strip().lower()
    for u in users:
        if isinstance(u, dict) and (u.get("login") or "").strip().lower() == login_lower:
            return u
    return None


def find_by_client_id(client_id):
    """Найти пользователя по client_id. Возвращает dict с login, nickname или None."""
    users = _load_raw()
    cid = (client_id or "").strip()
    for u in users:
        if isinstance(u, dict) and (u.get("client_id") or "").strip() == cid:
            return {"login": u.get("login"), "nickname": u.get("nickname") or u.get("login")}
    return None


def create_user(login, password, nickname=None):
    """
    Создать пользователя (логин, пароль, опционально никнейм).
    Возвращает (user_dict, error_message). user_dict с полями client_id, api_key, login, nickname.
    """
    import uuid
    import secrets
    login = (login or "").strip()
    if not login:
        return None, "Login required"
    if len(login) < 2:
        return None, "Login too short"
    if find_by_login(login):
        return None, "Login already taken"
    password = password or ""
    if len(password) < 6:
        return None, "Password must be at least 6 characters"
    nickname = (nickname or login).strip() or login
    client_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)
    password_hash = generate_password_hash(password, method="pbkdf2:sha256")
    user = {
        "login": login,
        "password_hash": password_hash,
        "client_id": client_id,
        "api_key": api_key,
        "nickname": nickname,
    }
    users = _load_raw()
    users.append(user)
    _save_raw(users)
    return {"client_id": client_id, "api_key": api_key, "login": login, "nickname": nickname}, None


def verify_login(login, password):
    """
    Проверить логин и пароль. Возвращает (user_dict, error_message).
    user_dict: client_id, api_key, login, nickname (без password_hash).
    """
    user = find_by_login(login)
    if not user:
        return None, "Invalid login or password"
    if not check_password_hash(user.get("password_hash") or "", password or ""):
        return None, "Invalid login or password"
    return {
        "client_id": user["client_id"],
        "api_key": user["api_key"],
        "login": user["login"],
        "nickname": user.get("nickname") or user["login"],
    }, None
