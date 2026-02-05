from flask import Flask, request, jsonify, send_from_directory
from blockchain import Blockchain, FEE_PER_WORK_RECEIPT
from contracts import CONTRACTS  # Исполняемые контракты вместо JSON
import uuid
import random
import os
import requests
import threading
import time
import secrets
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address  # для rate_limit_key по IP

from logger_config import setup_logging, get_logger

setup_logging()
logger = get_logger("orchestrator")

app = Flask(__name__)
# Защита от DoS: ограничение размера запросов (16 MB максимум)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

# Счётчики для мониторинга (запросы по эндпоинтам и ошибки)
_request_counts = {}
_error_counts = {}

# Инициализируем наш блокчейн
blockchain = Blockchain()

# --- Критическое исправление: блокировка при создании блока (защита от race condition) ---
_block_creation_lock = threading.Lock()

# --- Безопасность: аутентификация по API-ключу ---
# api_key -> client_id (ключ выдаётся при регистрации; для постоянных аккаунтов загружаем из auth_storage)
api_key_to_client = {}
try:
    from auth_storage import load_all_into as auth_load_all, create_user as auth_create_user, verify_login as auth_verify_login, find_by_client_id as auth_find_by_client_id
    n = auth_load_all(api_key_to_client)
    if n:
        logger.info("auth_loaded: %s persistent account(s)", n)
except Exception as e:
    logger.warning("auth_storage not loaded: %s", e)

# --- Активные вычислители по контрактам: (contract_id, client_id) -> timestamp ---
# Используется для отображения "количество активных вычислителей" в интерфейсе.
# Записи старше ACTIVE_WORKER_TTL секунд не учитываются.
_active_task_takers = {}  # (contract_id, client_id) -> timestamp
ACTIVE_WORKER_TTL = 900  # 15 минут

def get_client_id_from_auth():
    """Из заголовка Authorization: Bearer <api_key> возвращаем client_id или None."""
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    return api_key_to_client.get(token)

def rate_limit_key():
    """Ключ для лимитов: по API-ключу для авторизованных, иначе по IP (защита от DDoS)."""
    client_id = get_client_id_from_auth()
    if client_id is not None:
        return request.headers.get("Authorization", "").strip()
    return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=rate_limit_key,
    default_limits=["200 per day", "60 per minute"],
    storage_uri="memory://",
)

# URL второго узла для синхронизации блокчейна (децентрализация)
PEER_URL = os.environ.get("PEER_URL", "")
# Интервал периодической синхронизации (секунды)
# Критическое исправление: уменьшен до 10 секунд для более быстрого разрешения форков
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "10"))
# Секрет для запросов между узлами (receive_block, receive_chain, add_pending_tx) — опционально
NODE_SECRET = os.environ.get("NODE_SECRET", "")

# --- Решение централизации: ротация лидера между узлами ---
# Идентификатор текущего узла (уникальный для каждого узла в сети)
NODE_ID = os.environ.get("NODE_ID", "node-1")
# Список всех узлов в сети (через запятую, например "node-1,node-2,node-3")
# Если не задан, выводится из PEER_URL (для двух узлов)
NODE_IDS_STR = os.environ.get("NODE_IDS", "")
if NODE_IDS_STR:
    NODE_IDS = [nid.strip() for nid in NODE_IDS_STR.split(",") if nid.strip()]
else:
    # Автоматически определяем список узлов для двух узлов
    # Если есть PEER_URL, предполагаем два узла: текущий и пир
    if PEER_URL:
        # Извлекаем имя узла из PEER_URL (например, http://orchestrator_node_2:5000 -> node-2)
        # Или используем простую схему: node-1 и node-2
        NODE_IDS = ["node-1", "node-2"]
    else:
        NODE_IDS = [NODE_ID]  # Один узел


@app.before_request
def _count_request():
    """Учёт запросов по пути для /metrics."""
    path = request.path or "unknown"
    _request_counts[path] = _request_counts.get(path, 0) + 1


@app.errorhandler(500)
def _handle_500(e):
    """Единая обработка внутренних ошибок сервера."""
    _error_counts["500"] = _error_counts.get("500", 0) + 1
    logger.exception("internal_error")
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(429)
def _handle_429(e):
    """Ответ при превышении лимита (DDoS)."""
    _error_counts["429"] = _error_counts.get("429", 0) + 1
    logger.warning("rate_limit_exceeded: %s", request.path)
    return jsonify({"error": "Too many requests"}), 429


def require_node_secret(f):
    """Проверка секрета узла для эндпоинтов синхронизации (опционально, если NODE_SECRET задан)."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if NODE_SECRET and request.headers.get("X-Node-Secret") != NODE_SECRET:
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapped


def get_current_leader():
    """
    Решение централизации: определяет текущего лидера по хешу последнего блока.
    Лидер ротируется между узлами детерминированно на основе хеша блока.
    Это обеспечивает справедливое распределение создания блоков между узлами.
    """
    if not blockchain.chain:
        return NODE_IDS[0] if NODE_IDS else NODE_ID
    last_block_hash = blockchain.get_last_block().hash
    # Берём первые 8 символов хеша как число и берём остаток от деления на количество узлов
    hash_int = int(last_block_hash[:8], 16)
    leader_index = hash_int % len(NODE_IDS)
    return NODE_IDS[leader_index]


def get_leader_url(leader_id):
    """
    Получить URL лидера по его идентификатору.
    Для простоты используем схему: node-1 -> orchestrator_node_1:5000, node-2 -> orchestrator_node_2:5000
    """
    if leader_id == NODE_ID:
        return None  # Это мы сами, не нужно отправлять запрос
    
    # Маппинг идентификаторов узлов на их URL в Docker-сети
    node_url_map = {
        "node-1": "http://orchestrator_node_1:5000",
        "node-2": "http://orchestrator_node_2:5000",
        "node-3": "http://orchestrator_node_3:5000",
    }
    
    if leader_id in node_url_map:
        return node_url_map[leader_id]
    
    # Если формат нестандартный, используем PEER_URL как fallback
    # (предполагаем, что пир может быть лидером)
    return PEER_URL


def sync_pending_from_peer():
    """
    Критическое исправление: синхронизация pending транзакций с пиром перед созданием блока.
    Запрашивает pending у пира и объединяет с локальным (убирает дубликаты по result_data).
    Это предотвращает создание блоков с разными транзакциями на разных узлах.
    """
    if not PEER_URL:
        return
    try:
        headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
        response = requests.get(f"{PEER_URL.rstrip('/')}/pending", timeout=2, headers=headers)
        if response.status_code == 200:
            peer_pending = response.json()
            # Объединяем транзакции (убираем дубликаты по result_data для work_receipt)
            local_result_data = {tx.get("result_data") for tx in blockchain.pending_transactions if tx.get("type") == "work_receipt" and tx.get("result_data")}
            for tx in peer_pending:
                # Проверяем, нет ли уже такой транзакции
                if tx.get("type") == "work_receipt" and tx.get("result_data"):
                    if tx.get("result_data") in local_result_data:
                        continue  # Уже есть
                # Пытаемся добавить транзакцию (может быть отклонена из-за лимитов)
                try:
                    blockchain.add_transaction(tx)
                except ValueError:
                    pass  # Уже есть или невалидна (не критично)
            logger.debug("sync_pending_completed: local=%s peer=%s", len(blockchain.pending_transactions), len(peer_pending))
    except requests.RequestException as e:
        logger.debug("sync_pending_failed: %s", e)
    except Exception:
        logger.debug("sync_pending_error")


def sync_chain_from_peer():
    """Запросить цепочку у пира и заменить локальную, если пир имеет более длинную валидную цепочку."""
    if not PEER_URL:
        return
    try:
        # Запрашиваем цепочку у пира
        headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
        response = requests.get(f"{PEER_URL.rstrip('/')}/chain", timeout=5, headers=headers)
        if response.status_code == 200:
            peer_chain = response.json()
            # Пытаемся заменить локальную цепочку на цепочку пира (longest valid chain)
            ok, err = blockchain.replace_chain_from_peer(peer_chain)
            if ok:
                logger.info("sync_chain_replaced: blocks=%s", len(peer_chain))
            else:
                logger.debug("sync_chain_not_replaced: %s", err)
    except requests.RequestException as e:
        logger.warning("sync_chain_failed: %s", e)
    except Exception:
        logger.exception("sync_chain_error")


def startup_sync():
    """Начальная синхронизация при старте узла: ждём 3 секунды, затем один раз синхронизируемся с пиром."""
    time.sleep(3)  # Ждём, чтобы пир успел подняться
    sync_chain_from_peer()


def periodic_sync():
    """Периодическая синхронизация: раз в SYNC_INTERVAL секунд запрашиваем цепочку у пира."""
    while True:
        time.sleep(SYNC_INTERVAL)
        sync_chain_from_peer()


# --- API Эндпоинты ---

@app.route("/auth/register", methods=["POST"])
@limiter.limit("10 per minute")
def auth_register():
    """
    Регистрация постоянного аккаунта: логин, пароль, опционально никнейм.
    Тело: {"login": "...", "password": "...", "nickname": "..."}.
    Возвращает client_id, api_key, login, nickname. Аккаунт сохраняется в data/users.json.
    """
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    login = (data.get("login") or "").strip()
    password = data.get("password") or ""
    nickname = (data.get("nickname") or "").strip() or login
    try:
        user, err = auth_create_user(login, password, nickname)
    except NameError:
        return jsonify({"error": "Auth storage not available"}), 503
    if err:
        return jsonify({"error": err}), 400
    api_key_to_client[user["api_key"]] = user["client_id"]
    blockchain.balances[user["client_id"]] = blockchain.balances.get(user["client_id"], 0)
    logger.info("auth_registered: login=%s client_id=%s...", login, user["client_id"][:8])
    return jsonify({
        "client_id": user["client_id"],
        "api_key": user["api_key"],
        "login": user["login"],
        "nickname": user["nickname"],
    }), 201


@app.route("/auth/login", methods=["POST"])
@limiter.limit("20 per minute")
def auth_login():
    """
    Вход в постоянный аккаунт: логин и пароль.
    Тело: {"login": "...", "password": "..."}.
    Возвращает client_id, api_key, login, nickname, balance.
    """
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
    login = (data.get("login") or "").strip()
    password = data.get("password") or ""
    try:
        user, err = auth_verify_login(login, password)
    except NameError:
        return jsonify({"error": "Auth storage not available"}), 503
    if err:
        return jsonify({"error": err}), 401
    api_key_to_client[user["api_key"]] = user["client_id"]
    balance = blockchain.get_balance(user["client_id"])
    logger.info("auth_login: login=%s client_id=%s...", login, user["client_id"][:8])
    return jsonify({
        "client_id": user["client_id"],
        "api_key": user["api_key"],
        "login": user["login"],
        "nickname": user["nickname"],
        "balance": balance,
    }), 200


@app.route("/register", methods=["GET"])
@limiter.limit("10 per minute")  # Защита от DDoS: не более 10 регистраций с одного IP в минуту
def register_client():
    """
    Регистрация клиента. Выдаём client_id и api_key (секретный ключ для последующих запросов).
    api_key нужно передавать в заголовке: Authorization: Bearer <api_key>.
    """
    client_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)
    api_key_to_client[api_key] = client_id
    blockchain.balances[client_id] = 0
    logger.info("client_registered: %s...", client_id[:8])
    return jsonify({"client_id": client_id, "api_key": api_key}), 200

def _active_workers_count(contract_id):
    """Число активных вычислителей по контракту (получили задачу и не сдали за ACTIVE_WORKER_TTL сек)."""
    now = time.time()
    cutoff = now - ACTIVE_WORKER_TTL
    seen = set()
    to_del = []
    for (cid, clid), ts in list(_active_task_takers.items()):
        if ts < cutoff:
            to_del.append((cid, clid))
        elif cid == contract_id:
            seen.add(clid)
    for k in to_del:
        _active_task_takers.pop(k, None)
    return len(seen)


@app.route("/get_task", methods=["GET"])
@limiter.limit("60 per minute")  # Защита от DDoS: не более 60 запросов задач в минуту на ключ
def get_task():
    """
    Клиент запрашивает задачу (смарт-контракт). Требуется аутентификация: Authorization: Bearer <api_key>.
    Опциональный query-параметр contract_id — выдать задачу по указанному контракту (для выбора из блока «Контракты»).
    """
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    contract_id = request.args.get("contract_id")
    if contract_id:
        contract = CONTRACTS.get(contract_id)
        if not contract:
            return jsonify({"error": "Unknown contract_id"}), 400
    else:
        contract = random.choice(list(CONTRACTS.values()))
    # Учитываем активного вычислителя по этому контракту
    _active_task_takers[(contract.contract_id, client_id)] = time.time()
    logger.info("task_issued: contract_id=%s client_id=%s...", contract.contract_id, client_id[:8])
    return jsonify(contract.get_task_spec()), 200

@app.route("/submit_work", methods=["POST"])
@limiter.limit("30 per minute")  # Защита от DDoS: не более 30 сдач в минуту на ключ
def submit_work():
    """
    Клиент отправляет результат своей работы. Требуется аутентификация: Authorization: Bearer <api_key>.
    client_id в теле должен совпадать с владельцем api_key.
    """
    client_id_from_key = get_client_id_from_auth()
    if client_id_from_key is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        logger.warning("submit_work_invalid_json")
        return jsonify({"error": "Invalid JSON"}), 400
    client_id = data.get("client_id")
    if client_id != client_id_from_key:
        return jsonify({"error": "client_id does not match authenticated client"}), 403
    contract_id = data.get("contract_id")
    work_units_done = data.get("work_units_done")
    result_data = data.get("result_data")
    nonce = data.get("nonce")  # Nonce для строгой проверки контрактом

    if not all([client_id, contract_id, work_units_done is not None]):
        return jsonify({"error": "Missing data"}), 400

    # Защита от мошенничества: обязателен nonce для строгой верификации (невозможно подделать результат)
    if nonce is None or nonce == "":
        return jsonify({"error": "nonce required for verification"}), 400

    # Защита от повторной сдачи (replay): одно и то же доказательство нельзя использовать дважды
    used_proofs = blockchain.get_used_proof_ids()
    if result_data and result_data in used_proofs:
        return jsonify({"error": "Proof already used (replay attack rejected)"}), 400

    # Находим контракт по contract_id
    contract = CONTRACTS.get(contract_id)
    if not contract:
        return jsonify({"error": "Invalid contract ID"}), 400

    # Верификация работы через исполняемый контракт (с nonce — строгая проверка хеша)
    if not contract.verify(client_id, contract_id, work_units_done, result_data, nonce):
        return jsonify({"error": "Work verification failed"}), 400

    reward_amount = contract.get_reward()
    if reward_amount < FEE_PER_WORK_RECEIPT:
        logger.warning("Contract reward %s less than fee %s", reward_amount, FEE_PER_WORK_RECEIPT)
    logger.info("work_verified: client_id=%s... reward=%s contract_id=%s", client_id[:8], reward_amount, contract_id)

    # Создаём транзакцию вознаграждения
    reward_tx = {
        "type": "reward",
        "from": "system_contract",
        "to": client_id,
        "amount": reward_amount,
        "contract_id": contract_id
    }
    
    # Создаём "квитанцию" о работе (result_data для replay; fee — комиссия, сжигается в блоке)
    work_receipt_tx = {
        "type": "work_receipt",
        "client_id": client_id,
        "contract_id": contract_id,
        "work_units": work_units_done,
        "result_data": result_data,
        "fee": FEE_PER_WORK_RECEIPT,  # Экономическая модель: комиссия списывается с клиента после начисления награды
    }
    
    # Решение централизации: проверяем, является ли текущий узел лидером
    current_leader = get_current_leader()
    is_leader = (current_leader == NODE_ID)
    
    if not is_leader:
        # Не лидер: отправляем транзакции лидеру через /add_pending_tx
        # Лидер создаст блок при следующем submit_work или периодически
        leader_url = get_leader_url(current_leader)
        if leader_url:
            try:
                headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
                response = requests.post(
                    f"{leader_url.rstrip('/')}/add_pending_tx",
                    json=[reward_tx, work_receipt_tx],
                    timeout=5,
                    headers=headers,
                )
                if response.status_code == 200:
                    logger.info("transactions_sent_to_leader: leader=%s", current_leader)
                    return jsonify({
                        "status": "success",
                        "reward_issued": reward_amount,
                        "message": f"Transactions sent to leader {current_leader}, block will be created by leader"
                    }), 200
                else:
                    logger.warning("failed_to_send_to_leader: leader=%s status=%s", current_leader, response.status_code)
            except requests.RequestException as e:
                logger.warning("send_to_leader_failed: leader=%s error=%s", current_leader, e)
        # Если не удалось отправить лидеру, продолжаем как обычно (fallback)
        logger.warning("leader_unreachable: continuing_as_fallback leader=%s", current_leader)
    
    # Лидер или fallback: добавляем транзакции локально и создаём блок
    blockchain.add_transaction(reward_tx)
    blockchain.add_transaction(work_receipt_tx)

    # Критическое исправление: блокировка + синхронизация pending перед созданием блока
    # Это предотвращает race condition и расхождение pending между узлами
    with _block_creation_lock:
        # Синхронизируем pending с пиром перед созданием блока (предотвращает разные блоки с разными tx)
        sync_pending_from_peer()
        # PoUW: создаём блок сразу (без mining_loop, блок создаётся при полезной работе)
        new_block = blockchain.mine_pending_transactions(mining_reward_address=None)

    # Синхронизация с пиром: отправляем готовый блок
    if new_block and PEER_URL:
        try:
            headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
            response = requests.post(
                f"{PEER_URL.rstrip('/')}/receive_block",
                json=new_block.__dict__,
                timeout=5,
                headers=headers,
            )
            if response.status_code == 200 and response.json().get("accepted"):
                logger.info("peer_accepted_block: index=%s", new_block.index)
            else:
                logger.warning("peer_rejected_block: index=%s error=%s", new_block.index, response.text[:200])
                sync_chain_from_peer()  # Подтягиваем более длинную цепочку пира
        except requests.RequestException as e:
            logger.warning("push_block_failed: %s", e)

    return jsonify({
        "status": "success", 
        "reward_issued": reward_amount
    }), 200

@app.route("/me", methods=["GET"])
@limiter.limit("60 per minute")
def me():
    """По API-ключу возвращает client_id, nickname (если есть), balance и число сданных работ."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    out = {"client_id": client_id}
    try:
        profile = auth_find_by_client_id(client_id)
        if profile:
            out["nickname"] = profile.get("nickname") or profile.get("login")
            out["login"] = profile.get("login")
    except Exception:
        pass
    out["balance"] = blockchain.get_balance(client_id)
    work_count = 0
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.get("type") == "work_receipt" and tx.get("client_id") == client_id:
                work_count += 1
    out["submissions_count"] = work_count
    return jsonify(out), 200


@app.route("/get_balance/<client_id>", methods=["GET"])
@limiter.limit("60 per minute")  # Защита от DDoS
def get_balance(client_id):
    """Получить баланс клиента. Требуется аутентификация; можно запрашивать только свой баланс."""
    client_id_from_key = get_client_id_from_auth()
    if client_id_from_key is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if client_id != client_id_from_key:
        return jsonify({"error": "Forbidden: can only request own balance"}), 403
    balance = blockchain.get_balance(client_id)
    return jsonify({"client_id": client_id, "balance": balance}), 200

@app.route("/health", methods=["GET"])
def health():
    """Проверка живости узла (для балансировщика нагрузки и мониторинга)."""
    return jsonify({"status": "ok"}), 200


@app.route("/metrics", methods=["GET"])
def metrics():
    """Метрики для мониторинга: длина цепочки, число клиентов, pending, счётчики запросов (если велись)."""
    try:
        chain_len = len(blockchain.chain)
        num_clients = len(blockchain.balances)
        pending = len(blockchain.pending_transactions)
        
        # Решение централизации: метрика распределения блоков между узлами
        # Подсчитываем, сколько блоков создал каждый узел (по timestamp или другим признакам)
        # Для простоты считаем блоки, созданные на этом узле (по NODE_ID в логах или метаданным)
        # В реальной системе можно добавить поле creator_node_id в блок
        current_leader = get_current_leader()
        is_current_leader = (current_leader == NODE_ID)
    except Exception as e:
        logger.exception("metrics_error")
        return jsonify({"error": "metrics failed"}), 500
    body = {
        "chain_length": chain_len,
        "clients_count": num_clients,
        "pending_transactions": pending,
        "request_counts": _request_counts,
        "error_counts": _error_counts,
        "node_id": NODE_ID,
        "current_leader": current_leader,
        "is_leader": is_current_leader,
        "all_node_ids": NODE_IDS,
    }
    return jsonify(body), 200

@app.route("/chain", methods=["GET"])
@limiter.limit("120 per minute")  # Публичный read-only; лимит от DDoS
def get_chain():
    """Посмотреть весь блокчейн (для синхронизации и просмотра)."""
    return jsonify(blockchain.get_chain_json()), 200

@app.route("/pending", methods=["GET"])
@require_node_secret
def get_pending():
    """
    Критическое исправление: эндпоинт для синхронизации pending транзакций между узлами.
    Возвращает список pending транзакций (для синхронизации перед созданием блока).
    """
    return jsonify(blockchain.pending_transactions), 200


@app.route("/contracts", methods=["GET"])
@limiter.limit("60 per minute")
def get_contracts():
    """
    Список контрактов для веб-интерфейса с расширенной статистикой:
    общий % выполнения, активные вычислители, свободный объём, вознаграждение за задачу.
    """
    chain_stats = blockchain.get_contract_stats()
    out = []
    for cid, c in CONTRACTS.items():
        spec = c.get_task_spec()
        wu_required = spec["work_units_required"]
        total_done = chain_stats.get(cid, {}).get("total_work_done", 0)
        jobs_count = chain_stats.get(cid, {}).get("jobs_count", 0)
        target = getattr(c, "target_total_work_units", None) or (10 * wu_required)
        completion_pct = min(100.0, (total_done / target * 100)) if target else 0.0
        active_workers = _active_workers_count(cid)
        out.append({
            "contract_id": cid,
            "work_units_required": wu_required,
            "difficulty": spec["difficulty"],
            "reward": c.get_reward(),
            "task_name": spec.get("task_name", ""),
            "task_description": spec.get("task_description", ""),
            "task_category": spec.get("task_category", ""),
            "computation_type": spec.get("computation_type", "simple_pow"),
            "total_work_done": total_done,
            "jobs_count": jobs_count,
            "completion_pct": round(completion_pct, 1),
            "active_workers": active_workers,
            "free_volume": wu_required,  # объём одной задачи, который можно взять
            "reward_per_task": c.get_reward(),
        })
    return jsonify(out), 200


def _run_worker_container(contract_id, api_key=None, client_id=None):
    """
    Запуск контейнера воркера с CONTRACT_ID (для выбранной задачи).
    Если переданы api_key и client_id, воркер работает от этого аккаунта — награда попадёт на ваш баланс.
    Требует: доступ к Docker (сокет), env WORKER_IMAGE, ORCHESTRATOR_URL_FOR_WORKER, DOCKER_NETWORK.
    Возвращает (success: bool, message: str).
    """
    if contract_id not in CONTRACTS:
        return False, "Unknown contract_id"
    worker_image = os.environ.get("WORKER_IMAGE", "").strip()
    orchestrator_url = os.environ.get("ORCHESTRATOR_URL_FOR_WORKER", "http://orchestrator_node_1:5000").strip()
    docker_network = os.environ.get("DOCKER_NETWORK", "distributed-compute_default").strip()
    if not worker_image:
        return False, "WORKER_IMAGE not set (run_worker disabled)"
    env = {"CONTRACT_ID": contract_id, "ORCHESTRATOR_URL": orchestrator_url}
    if api_key and api_key.strip():
        env["API_KEY"] = api_key.strip()
    if client_id and str(client_id).strip():
        env["CLIENT_ID"] = str(client_id).strip()
    try:
        import docker as docker_module
        client = docker_module.from_env()
        container = client.containers.run(
            image=worker_image,
            environment=env,
            network=docker_network,
            remove=True,
            detach=True,
        )
        logger.info("run_worker started container for contract_id=%s", contract_id)
        return True, "Worker started (one task, then container will exit)"
    except Exception as e:
        err = str(e)
        logger.warning("run_worker failed: %s", e)
        if "no such image" in err.lower() or "image not found" in err.lower() or "404" in err:
            return False, "Image '%s' not found. In project folder run: docker-compose build client_worker_1 then docker-compose up -d" % worker_image
        if "cannot connect" in err.lower() or "connection refused" in err.lower() or "docker.sock" in err.lower():
            return False, "Cannot connect to Docker. Ensure Docker Desktop is running and containers were started via start.bat"
        if "network" in err.lower() and ("not found" in err.lower() or "does not exist" in err.lower()):
            return False, "Docker network '%s' not found. Run start.bat first to create it." % docker_network
        return False, err


@app.route("/run_worker", methods=["POST"])
@limiter.limit("5 per minute")  # Защита от злоупотребления
def run_worker():
    """
    Запуск воркера в Docker для выполнения выбранной задачи (контракта).
    Требуется авторизация. Тело: {"contract_id": "sc-001"}.
    Работает только если оркестратор имеет доступ к Docker (сокет смонтирован и заданы WORKER_IMAGE, DOCKER_NETWORK).
    """
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    api_key = auth[7:].strip()
    client_id = api_key_to_client.get(api_key)
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    contract_id = (data.get("contract_id") or "").strip()
    if not contract_id:
        return jsonify({"error": "contract_id required"}), 400
    ok, msg = _run_worker_container(contract_id, api_key=api_key, client_id=client_id)
    if ok:
        return jsonify({"status": "started", "message": msg, "contract_id": contract_id}), 202
    if "not set" in msg or "WORKER_IMAGE" in msg:
        return jsonify({"error": "Worker auto-start disabled (WORKER_IMAGE not set)", "detail": msg}), 503
    return jsonify({"error": "Failed to start worker", "detail": msg}), 500


@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Веб-интерфейс (дашборд по принципам BOINC)."""
    return send_from_directory(app.static_folder or "static", "dashboard.html")

@app.route("/receive_block", methods=["POST"])
@require_node_secret
def receive_block():
    """
    Принять блок от другого узла (децентрализованная синхронизация).
    PoUW: первый валидный блок принимается, pending очищается (блок создаёт только узел, принявший submit_work).
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"accepted": False, "error": "No JSON"}), 400
    ok, err = blockchain.add_block_from_peer(data)
    if ok:
        if PEER_URL:
            try:
                headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
                requests.post(
                    f"{PEER_URL.rstrip('/')}/receive_block",
                    json=data,
                    timeout=5,
                    headers=headers,
                )
            except requests.RequestException as e:
                logger.warning("forward_block_failed: %s", e)
        return jsonify({"accepted": True}), 200
    logger.debug("receive_block_rejected: %s", err)
    return jsonify({"accepted": False, "error": err}), 400

@app.route("/receive_chain", methods=["POST"])
@require_node_secret
def receive_chain():
    """
    Принять полную цепочку от пира (для push-синхронизации).
    Если цепочка пира длиннее и валидна, заменяем локальную.
    """
    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"accepted": False, "error": "Invalid chain format"}), 400
    ok, err = blockchain.replace_chain_from_peer(data)
    if ok:
        return jsonify({"accepted": True}), 200
    return jsonify({"accepted": False, "error": err}), 400

@app.route("/add_pending_tx", methods=["POST"])
@require_node_secret
def add_pending_tx():
    """
    Принять pending транзакции от пира (для совместимости).
    PoUW: эндпоинт оставлен для совместимости, но при PoUW блок создаёт только узел, принявший submit_work.
    Транзакции проверяются блокчейном (структура reward/work_receipt); невалидные отклоняются.
    """
    data = request.get_json()
    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid transactions format"}), 400
    added = 0
    for i, tx in enumerate(data):
        try:
            blockchain.add_transaction(tx)
            added += 1
        except ValueError as e:
            logger.warning("add_pending_tx invalid tx at index %s: %s", i, e)
            return jsonify({"error": f"Invalid transaction at index {i}", "detail": str(e)}), 400
    return jsonify({"status": "added", "count": added}), 200


if __name__ == "__main__":
    threading.Thread(target=startup_sync, daemon=True).start()
    threading.Thread(target=periodic_sync, daemon=True).start()

    # Шифрование коммуникаций: опциональный TLS (задайте TLS_CERT_FILE и TLS_KEY_FILE)
    ssl_context = None
    cert_file = os.environ.get("TLS_CERT_FILE")
    key_file = os.environ.get("TLS_KEY_FILE")
    if cert_file and key_file and os.path.isfile(cert_file) and os.path.isfile(key_file):
        ssl_context = (cert_file, key_file)
        logger.info("TLS enabled: HTTPS")
    else:
        logger.info("TLS not configured (set TLS_CERT_FILE, TLS_KEY_FILE for HTTPS)")

    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=ssl_context)
