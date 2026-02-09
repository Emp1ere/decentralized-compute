from flask import Flask, request, jsonify, send_from_directory
from blockchain import Blockchain, FEE_PER_WORK_RECEIPT, MAX_PENDING_WORK_PER_CLIENT
from contracts import CONTRACTS  # Исполняемые контракты вместо JSON
import hashlib
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
# Таймаут HTTP-запросов к пиру (секунды); при медленной сети увеличьте (например, 15 или 30)
PEER_REQUEST_TIMEOUT = int(os.environ.get("PEER_REQUEST_TIMEOUT", "15"))
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
        response = requests.get(f"{PEER_URL.rstrip('/')}/pending", timeout=PEER_REQUEST_TIMEOUT, headers=headers)
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
        response = requests.get(f"{PEER_URL.rstrip('/')}/chain", timeout=PEER_REQUEST_TIMEOUT, headers=headers)
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
    Анонимная регистрация (без логина): выдаём client_id и api_key.
    Используется воркером, запущенным без API_KEY/CLIENT_ID. Для сдачи работ на свой аккаунт
    запускайте воркер из дашборда с выбранным вычислителем (тогда API_KEY и CLIENT_ID передаются).
    """
    client_id = str(uuid.uuid4())
    api_key = secrets.token_urlsafe(32)
    api_key_to_client[api_key] = client_id
    blockchain.balances[client_id] = 0
    logger.warning(
        "anonymous_registration: new client_id=%s... (no auth; caller should use dashboard with calculator selected to attribute work to their account)",
        client_id[:8],
    )
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
    В терминах BOINC: выдача одной единицы работы (one result/workunit per request); при необходимости можно
    расширить API (например, max_tasks или duration_sec) по образцу Work Distribution BOINC.
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
    spec = contract.get_task_spec()
    # Уникальный task_seed при каждой выдаче, 64 бит + привязка к client_id — чтобы коллизии
    # между разными клиентами были практически невозможны (proof already used by different client).
    base = uuid.uuid4().int & ((1 << 64) - 1)
    client_bits = int(hashlib.sha256(client_id.encode()).hexdigest()[:16], 16) % (1 << 64)
    spec["task_seed"] = (base ^ client_bits) & ((1 << 64) - 1)
    logger.info("task_issued: contract_id=%s client_id=%s... task_seed=%s", contract.contract_id, client_id[:8], spec["task_seed"])
    return jsonify(spec), 200

@app.route("/submit_work", methods=["POST"])
@limiter.limit("30 per minute")  # Защита от DDoS: не более 30 сдач в минуту на ключ
def submit_work():
    """
    Клиент отправляет результат своей работы. Требуется аутентификация: Authorization: Bearer <api_key>.
    client_id в теле должен совпадать с владельцем api_key.
    """
    logger.info("submit_work request received")
    client_id_from_key = get_client_id_from_auth()
    if client_id_from_key is None:
        logger.warning("submit_work: unauthorized (missing or invalid Bearer)")
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        logger.warning("submit_work_invalid_json")
        return jsonify({"error": "Invalid JSON"}), 400
    client_id = data.get("client_id")
    if client_id != client_id_from_key:
        logger.warning("submit_work: rejected client_id mismatch (body=%s... auth=%s...)", (client_id or "")[:8], (client_id_from_key or "")[:8])
        return jsonify({"error": "client_id does not match authenticated client"}), 403
    contract_id = data.get("contract_id")
    work_units_done = data.get("work_units_done")
    result_data = data.get("result_data")
    nonce = data.get("nonce")  # Nonce для строгой проверки контрактом

    if not all([client_id, contract_id, work_units_done is not None]):
        logger.warning("submit_work: missing data (client_id=%s contract_id=%s work_units_done=%s)", bool(client_id), contract_id, work_units_done)
        return jsonify({"error": "Missing data"}), 400

    # Защита от мошенничества: обязателен nonce для строгой верификации (невозможно подделать результат)
    if nonce is None or nonce == "":
        logger.warning("submit_work: nonce required")
        return jsonify({"error": "nonce required for verification"}), 400

    # Защита от повторной сдачи (replay): проверяем, используется ли proof уже
    # Если proof используется тем же клиентом и для того же контракта — это идемпотентный запрос (OK)
    # Если другим клиентом или для другого контракта — это мошенничество (reject)
    if result_data:
        existing_receipt = blockchain.find_work_receipt_by_proof(result_data)
        if existing_receipt:
            if (existing_receipt["client_id"] == client_id and 
                existing_receipt["contract_id"] == contract_id):
                # Идемпотентность: тот же клиент повторно отправляет тот же proof
                # (например, из-за таймаута или сетевой ошибки)
                logger.info("submit_work: proof already processed (idempotent request) client_id=%s... contract_id=%s", 
                           client_id[:8], contract_id)
                # Получаем reward_amount для ответа
                contract = CONTRACTS.get(contract_id)
                reward_amount = contract.get_reward() if contract else 0
                return jsonify({
                    "status": "success",
                    "reward_issued": reward_amount,
                    "message": "Proof already processed (idempotent request)"
                }), 200
            else:
                # Другой client_id уже записан в цепочке с этим proof (мы не создаём нового клиента —
                # это старая запись в блокчейне; «анонимный» = не в users.json, например от прошлого GET /register).
                existing_cid = existing_receipt["client_id"] or ""
                result_prefix = (result_data[:16] + "...") if result_data and len(result_data) >= 16 else (result_data or "empty")
                is_known_user = False
                try:
                    if auth_find_by_client_id(existing_cid) is not None:
                        is_known_user = True
                except Exception:
                    pass
                if not is_known_user:
                    logger.info(
                        "submit_work: proof already in chain under client_id=%s (that client is not in users.json; "
                        "this is an existing chain entry, we are NOT creating a new client now)",
                        existing_cid[:8],
                    )
                logger.warning(
                    "submit_work: proof already used by different client (same contract) — "
                    "existing_client=%s requested_client=%s contract_id=%s result_data=%s",
                    existing_cid[:8], client_id[:8], contract_id, result_prefix,
                )
                # 409 Conflict: задача уже засчитана другому вычислителю (идемпотентность не применяется).
                hint = ""
                if not is_known_user:
                    hint = " That client_id is already in the chain (from a past run), not created now. To avoid this for new runs, start the worker from the dashboard with your calculator selected (64-bit task_seed makes your proof unique)."
                return jsonify({
                    "error": "Proof already used by another worker for this contract (task already completed)." + hint,
                    "code": "proof_used_other_client",
                    "existing_client_prefix": existing_cid[:8] if existing_cid else None,
                }), 409

    # Находим контракт по contract_id
    contract = CONTRACTS.get(contract_id)
    if not contract:
        logger.warning("submit_work: invalid contract_id=%s", contract_id)
        return jsonify({"error": "Invalid contract ID"}), 400

    # BOINC: validator определяет корректность результата. У нас для астро-контрактов verify() заново
    # выполняет полное вычисление (60k–70k шагов) — может занять 10–15 мин; воркер должен ждать (timeout 900s).
    logger.info("submit_work: starting verification for client_id=%s... contract_id=%s (may take several minutes for large tasks)",
                client_id[:8], contract_id)
    if not contract.verify(client_id, contract_id, work_units_done, result_data, nonce):
        logger.warning("submit_work_verification_failed: client_id=%s... contract_id=%s (balance not updated)", client_id[:8], contract_id)
        return jsonify({"error": "Work verification failed"}), 400
    logger.info("submit_work: verification passed for client_id=%s... contract_id=%s", client_id[:8], contract_id)

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
    
    # Assimilator (BOINC): учёт верифицированного результата — запись в блокчейн (reward + work_receipt; result_data для replay, fee сжигается).
    work_receipt_tx = {
        "type": "work_receipt",
        "client_id": client_id,
        "contract_id": contract_id,
        "work_units": work_units_done,
        "result_data": result_data,
        "fee": FEE_PER_WORK_RECEIPT,  # Экономическая модель: комиссия списывается с клиента после начисления награды
    }
    
    # Критическое исправление: узел, принявший submit_work, всегда создаёт блок сам.
    # Раньше при "не лидер" транзакции отправлялись лидеру через add_pending_tx, но лидер никогда
    # не вызывал mine_pending_transactions (блок создаётся только при submit_work на этом узле),
    # поэтому награда не попадала в цепочку и баланс оставался 0. Теперь блок создаём здесь и пушим пиру.
    
    # Критическое исправление: добавление транзакций и создание блока под одной блокировкой,
    # чтобы не остаться с «сиротой» reward_tx в pending при лимите work_receipt на клиента.
    with _block_creation_lock:
        n_pending = sum(
            1 for t in blockchain.pending_transactions
            if t.get("type") == "work_receipt" and t.get("client_id") == client_id
        )
        if n_pending >= MAX_PENDING_WORK_PER_CLIENT:
            return jsonify({
                "error": "Client already has work in pending; wait for the next block and retry.",
                "code": "pending_limit",
            }), 429
        try:
            blockchain.add_transaction(reward_tx)
            blockchain.add_transaction(work_receipt_tx)
        except ValueError as e:
            logger.warning("submit_work: add_transaction failed: %s", e)
            return jsonify({"error": "Cannot add transaction", "detail": str(e)}), 400
        sync_pending_from_peer()
        new_block = blockchain.mine_pending_transactions(mining_reward_address=None)

    if new_block:
        new_balance = blockchain.get_balance(client_id)
        logger.info("block_created: client_id=%s... reward=%s new_balance=%s block_index=%s",
                    client_id[:8], reward_amount, new_balance, new_block.index)

    # Синхронизация с пиром: отправляем готовый блок
    if new_block and PEER_URL:
        try:
            headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
            response = requests.post(
                f"{PEER_URL.rstrip('/')}/receive_block",
                json=new_block.__dict__,
                timeout=PEER_REQUEST_TIMEOUT,
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
        remaining_volume = max(0, target - total_done)  # оставшийся объём для распределённых вычислителей
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
            "target_total": target,
            "remaining_volume": remaining_volume,
            "free_volume": remaining_volume,  # для совместимости: свободный объём = оставшаяся работа
            "reward_per_task": c.get_reward(),
        })
    return jsonify(out), 200


def _run_worker_container(contract_id, api_key=None, client_id=None, run_once=False):
    """
    Запуск контейнера воркера с CONTRACT_ID (для выбранной задачи).
    Если переданы api_key и client_id, воркер работает от этого аккаунта — награда попадёт на ваш баланс.
    run_once: если True, воркер выполнит одну задачу и выйдет; иначе — цикл до остановки (как в BOINC).
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
    if run_once:
        env["RUN_ONCE"] = "1"
    if api_key and api_key.strip():
        env["API_KEY"] = api_key.strip()
    if client_id and str(client_id).strip():
        env["CLIENT_ID"] = str(client_id).strip()
    logger.info("run_worker starting container contract_id=%s client_id=%s... run_once=%s has_api_key=%s",
                contract_id, (client_id or "")[:8] if client_id else None, run_once, bool(env.get("API_KEY")))
    try:
        import docker as docker_module
        client = docker_module.from_env()
        container = client.containers.run(
            image=worker_image,
            environment=env,
            network=docker_network,
            remove=False,  # Оставляем контейнер после выхода, чтобы можно было снять логи: docker logs <id>
            detach=True,
        )
        # container — объект Container; id можно посмотреть в docker ps -a для снятия логов воркера
        cid = container.id[:12] if hasattr(container, "id") else ""
        logger.info("run_worker started container for contract_id=%s (reward will go to client_id=%s...) container_id=%s — логи: docker logs %s",
                    contract_id, (client_id or "")[:8] if client_id else None, cid, cid or "<id>")
        if run_once:
            return True, "Воркер запущен: выполнит одну задачу и остановится."
        return True, "Воркер запущен: будет брать следующие задачи автоматически до остановки контейнера."
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
    Требуется авторизация. Тело: {"contract_id": "sc-001", "client_id": "опционально для проверки"}.
    Награда начисляется на client_id, соответствующий api_key. Если передан client_id в теле,
    он должен совпадать с ключом — иначе 400 (защита от неверного выбора вычислителя в интерфейсе).
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
    body_client_id = (data.get("client_id") or "").strip() or None
    if body_client_id and body_client_id != client_id:
        logger.warning("run_worker client_id mismatch: body=%s... key_resolves_to=%s...", body_client_id[:8], client_id[:8])
        return jsonify({"error": "client_id does not match this API key (select the correct calculator in Overview)"}), 400
    run_once = data.get("run_once") in (True, "true", "1", 1)
    ok, msg = _run_worker_container(contract_id, api_key=api_key, client_id=client_id, run_once=run_once)
    if ok:
        return jsonify({"status": "started", "message": msg, "contract_id": contract_id, "client_id": client_id}), 202
    if "not set" in msg or "WORKER_IMAGE" in msg:
        return jsonify({"error": "Worker auto-start disabled (WORKER_IMAGE not set)", "detail": msg}), 503
    return jsonify({"error": "Failed to start worker", "detail": msg}), 500


# --- Прогресс воркера для отображения в интерфейсе: client_id -> { contract_id, step, total, updated_at }
_worker_progress = {}
WORKER_PROGRESS_TTL = 300  # 5 минут — считаем прогресс устаревшим, если дольше нет обновлений


@app.route("/worker_progress", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def worker_progress():
    """
    GET: прогресс воркера для текущего вычислителя (по API-ключу). Для отображения в интерфейсе.
    POST: воркер отправляет прогресс (contract_id, step, total). Требуется Authorization.
    """
    if request.method == "POST":
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization"}), 401
        client_id = api_key_to_client.get(auth[7:].strip())
        if client_id is None:
            return jsonify({"error": "Missing or invalid Authorization"}), 401
        data = request.get_json(silent=True) or {}
        contract_id = (data.get("contract_id") or "").strip()
        try:
            step = int(data.get("step", 0))
            total = int(data.get("total", 1))
        except (TypeError, ValueError):
            return jsonify({"error": "step and total must be integers"}), 400
        if total <= 0:
            total = 1
        step = max(0, min(step, total))
        _worker_progress[client_id] = {
            "contract_id": contract_id,
            "step": step,
            "total": total,
            "updated_at": time.time(),
        }
        return jsonify({"ok": True}), 200
    # GET
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"progress": None}), 200
    rec = _worker_progress.get(client_id)
    if not rec:
        return jsonify({"progress": None}), 200
    if time.time() - rec["updated_at"] > WORKER_PROGRESS_TTL:
        _worker_progress.pop(client_id, None)
        return jsonify({"progress": None}), 200
    return jsonify({
        "progress": {
            "contract_id": rec["contract_id"],
            "step": rec["step"],
            "total": rec["total"],
            "updated_at": rec["updated_at"],
        }
    }), 200


@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Веб-интерфейс (дашборд по принципам BOINC)."""
    return send_from_directory(app.static_folder or "static", "dashboard.html")

@app.route("/receive_block", methods=["POST"])
@limiter.limit("120 per minute")  # Синхронизация узлов: больше лимит, чтобы не было 429 при активном обмене блоками
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
                    timeout=PEER_REQUEST_TIMEOUT,
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
