from flask import Flask, request, jsonify, send_from_directory
from blockchain import Blockchain, FEE_PER_WORK_RECEIPT, MAX_PENDING_WORK_PER_CLIENT, MAX_PENDING_TOTAL
from contracts import (
    SYSTEM_CONTRACT_TEMPLATES,
    SUPPORTED_COMPUTATION_TYPES,
    default_difficulty_for,
    verify_contract_result,
)  # Унифицированная верификация и шаблоны миграции контрактов
from contract_market import (
    ContractMarket,
    STATUS_ACTIVE,
    STATUS_CLOSED,
    STATUS_DRAFT,
    STATUS_PAUSED,
    SUPPORTED_BUDGET_CURRENCIES,
)
from onchain_accounting import (
    DEFAULT_CURRENCY as MARKET_DEFAULT_CURRENCY,
    convert_with_rules,
    get_effective_fx_rules,
    get_wallet_amount,
    get_wallet_from_chain,
    is_reward_settled,
    list_audit_events,
    list_contracts_onchain,
    list_withdrawals_from_chain,
    mask_card_number,
    normalize_currency as onchain_normalize_currency,
    now_ts,
)
from fx_oracles import (
    ORACLE_PENALTY_POINTS,
    ORACLE_QUORUM,
    build_oracle_scores,
    calculate_median_rates,
    current_epoch_id,
    detect_outliers,
    get_epoch_finalization,
    get_epoch_submissions,
    get_oracle_public_info,
    normalize_rates_payload,
    verify_submission_signature,
)
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
# Хранилище пользовательских контрактов поставщиков
contract_market = ContractMarket()

# --- Критическое исправление: блокировка при создании блока (защита от race condition) ---
_block_creation_lock = threading.Lock()

# --- Безопасность: аутентификация по API-ключу ---
# api_key -> client_id (ключ выдаётся при регистрации; для постоянных аккаунтов загружаем из auth_storage)
api_key_to_client = {}
auth_load_all = None
auth_create_user = None
auth_verify_login = None
auth_find_by_client_id = None
auth_ensure_user = None
try:
    from auth_storage import (
        load_all_into as auth_load_all,
        create_user as auth_create_user,
        verify_login as auth_verify_login,
        find_by_client_id as auth_find_by_client_id,
        ensure_user as auth_ensure_user,
    )
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


BOOTSTRAP_PROVIDER_LOGIN = os.environ.get("BOOTSTRAP_PROVIDER_LOGIN", "first_provider")
BOOTSTRAP_PROVIDER_PASSWORD = os.environ.get("BOOTSTRAP_PROVIDER_PASSWORD", "first_provider_change_me")
BOOTSTRAP_PROVIDER_NICKNAME = os.environ.get("BOOTSTRAP_PROVIDER_NICKNAME", "Первый поставщик")


def _bootstrap_provider_and_contracts():
    """
    Создаёт/подключает первого поставщика и мигрирует шаблонные контракты
    в пользовательский формат (provider contracts).
    """
    if auth_ensure_user is None:
        logger.warning("bootstrap_provider: auth storage unavailable")
        return None
    provider, err = auth_ensure_user(
        BOOTSTRAP_PROVIDER_LOGIN,
        BOOTSTRAP_PROVIDER_PASSWORD,
        nickname=BOOTSTRAP_PROVIDER_NICKNAME,
    )
    if err:
        logger.warning("bootstrap_provider_failed: %s", err)
        return None
    api_key_to_client[provider["api_key"]] = provider["client_id"]
    seed_leader = sorted(NODE_IDS)[0] if NODE_IDS else NODE_ID
    if NODE_ID == seed_leader:
        created = contract_market.upsert_seed_contracts(
            provider_client_id=provider["client_id"],
            templates=SYSTEM_CONTRACT_TEMPLATES,
        )
        if created:
            logger.info(
                "bootstrap_contracts_seeded: provider=%s created=%s",
                provider["login"],
                len(created),
            )
    else:
        logger.info("bootstrap_contracts_seed_skipped: node_id=%s leader=%s", NODE_ID, seed_leader)
    logger.info(
        "bootstrap_provider_ready: login=%s client_id=%s...",
        provider["login"],
        provider["client_id"][:8],
    )
    return provider


BOOTSTRAP_PROVIDER = _bootstrap_provider_and_contracts()


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
            if not isinstance(peer_pending, list):
                logger.warning("sync_pending: invalid response format from peer")
                return
            # Защита от переполнения: проверяем общий лимит перед добавлением
            current_pending = len(blockchain.pending_transactions)
            if current_pending >= MAX_PENDING_TOTAL:
                logger.debug("sync_pending: local pending full (%s), skipping sync", current_pending)
                return
            # Объединяем транзакции (убираем дубликаты по result_data для work_receipt)
            local_result_data = {tx.get("result_data") for tx in blockchain.pending_transactions if tx.get("type") == "work_receipt" and tx.get("result_data")}
            added_count = 0
            for tx in peer_pending:
                # Проверяем лимит перед каждой попыткой добавления
                if len(blockchain.pending_transactions) >= MAX_PENDING_TOTAL:
                    logger.debug("sync_pending: reached max pending limit (%s), stopping", MAX_PENDING_TOTAL)
                    break
                # Проверяем, нет ли уже такой транзакции
                if tx.get("type") == "work_receipt" and tx.get("result_data"):
                    if tx.get("result_data") in local_result_data:
                        continue  # Уже есть
                # Пытаемся добавить транзакцию (может быть отклонена из-за лимитов)
                try:
                    blockchain.add_transaction(tx)
                    added_count += 1
                except ValueError:
                    pass  # Уже есть или невалидна (не критично)
            logger.debug("sync_pending_completed: local=%s peer=%s added=%s", len(blockchain.pending_transactions), len(peer_pending), added_count)
        else:
            logger.warning("sync_pending: peer returned status %s", response.status_code)
    except requests.Timeout:
        logger.warning("sync_pending: timeout after %ss", PEER_REQUEST_TIMEOUT)
    except requests.RequestException as e:
        logger.warning("sync_pending_failed: %s", e)
    except Exception as e:
        logger.warning("sync_pending_error: %s", e)


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
            if not isinstance(peer_chain, list):
                logger.warning("sync_chain: invalid response format from peer")
                return
            # Пытаемся заменить локальную цепочку на цепочку пира (longest valid chain)
            ok, err = blockchain.replace_chain_from_peer(peer_chain)
            if ok:
                logger.info("sync_chain_replaced: blocks=%s", len(peer_chain))
            else:
                logger.debug("sync_chain_not_replaced: %s", err)
        else:
            logger.warning("sync_chain: peer returned status %s", response.status_code)
    except requests.Timeout:
        logger.warning("sync_chain: timeout after %ss", PEER_REQUEST_TIMEOUT)
    except requests.RequestException as e:
        logger.warning("sync_chain_failed: %s", e)
    except Exception as e:
        logger.warning("sync_chain_error: %s", e)


def startup_sync():
    """
    Начальная синхронизация при старте узла.
    
    Ждём 3 секунды, чтобы пир успел подняться, затем один раз синхронизируемся с пиром
    для получения актуальной цепочки блоков. Это гарантирует, что узел начинает работу
    с актуальным состоянием блокчейна.
    """
    time.sleep(3)  # Ждём, чтобы пир успел подняться
    sync_chain_from_peer()


def periodic_sync():
    """
    Периодическая синхронизация цепочки блоков с пиром.
    
    Выполняется в фоновом потоке каждые SYNC_INTERVAL секунд (по умолчанию 10 секунд).
    Это обеспечивает постоянную актуальность цепочки и быстрое разрешение форков
    при одновременном создании блоков на разных узлах.
    """
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
    if auth_create_user is None:
        return jsonify({"error": "Auth storage not available"}), 503
    user, err = auth_create_user(login, password, nickname)
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
    if auth_verify_login is None:
        return jsonify({"error": "Auth storage not available"}), 503
    user, err = auth_verify_login(login, password)
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
    """
    Подсчёт активных вычислителей по указанному контракту.
    
    Активным считается вычислитель, который получил задачу по контракту и не сдал работу
    в течение ACTIVE_WORKER_TTL секунд (15 минут). Устаревшие записи автоматически удаляются.
    
    Args:
        contract_id: Идентификатор контракта для подсчёта активных вычислителей
    
    Returns:
        int: Количество уникальных активных вычислителей по контракту
    """
    now = time.time()
    cutoff = now - ACTIVE_WORKER_TTL
    seen = set()
    to_del = []
    # Проходим по всем записям активных вычислителей
    for (cid, clid), ts in list(_active_task_takers.items()):
        if ts < cutoff:
            # Запись устарела, помечаем для удаления
            to_del.append((cid, clid))
        elif cid == contract_id:
            # Вычислитель активен по нужному контракту
            seen.add(clid)
    # Удаляем устаревшие записи для освобождения памяти
    for k in to_del:
        _active_task_takers.pop(k, None)
    return len(seen)


def _build_dynamic_task_spec(contract_record):
    """Преобразовать пользовательский контракт в спецификацию задачи для воркера."""
    reward_currency = (contract_record.get("budget_currency") or MARKET_DEFAULT_CURRENCY).upper()
    if reward_currency not in SUPPORTED_BUDGET_CURRENCIES:
        reward_currency = MARKET_DEFAULT_CURRENCY
    return {
        "contract_id": contract_record["contract_id"],
        "work_units_required": int(contract_record["work_units_required"]),
        "difficulty": int(contract_record["difficulty"]),
        "task_name": contract_record.get("task_name") or contract_record["contract_id"],
        "task_description": contract_record.get("task_description", ""),
        "task_category": contract_record.get("task_category", "Пользовательская"),
        "computation_type": contract_record.get("computation_type", "simple_pow"),
        "reward_per_task": int(contract_record.get("reward_per_task", 0)),
        "reward_currency": reward_currency,
        "contract_origin": "provider",
        "provider_client_id": contract_record.get("provider_client_id"),
    }


def _normalized_budget_currency(raw_currency):
    normalized = onchain_normalize_currency(raw_currency or MARKET_DEFAULT_CURRENCY)
    if not normalized:
        return None
    return normalized


def _reward_event_id(*, client_id, contract_id, result_data, nonce):
    payload = f"{client_id}|{contract_id}|{result_data or ''}|{nonce or ''}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _build_reward_settlement_tx(
    *,
    client_id,
    provider_client_id,
    contract_id,
    result_data,
    nonce,
    reward_amount,
    reward_currency,
    work_units_done,
):
    reward_id = _reward_event_id(
        client_id=client_id,
        contract_id=contract_id,
        result_data=result_data,
        nonce=nonce,
    )
    return {
        "type": "contract_reward_settlement",
        "reward_id": reward_id,
        "provider_client_id": provider_client_id,
        "worker_client_id": client_id,
        "contract_id": contract_id,
        "currency": reward_currency,
        "amount": int(reward_amount),
        "work_units": int(work_units_done),
        "created_at": now_ts(),
    }


def _push_block_to_peer(new_block):
    if not new_block or not PEER_URL:
        return
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
            sync_chain_from_peer()
    except requests.RequestException as e:
        logger.warning("push_block_failed: %s", e)


def _append_onchain_events(event_txs):
    if not event_txs:
        return None, None
    try:
        with _block_creation_lock:
            for tx in event_txs:
                blockchain.add_transaction(tx)
            sync_pending_from_peer()
            new_block = blockchain.mine_pending_transactions(mining_reward_address=None)
    except ValueError as e:
        return None, str(e)
    if not new_block:
        return None, "Failed to append on-chain events"
    _push_block_to_peer(new_block)
    return new_block, None


def _oracle_epoch_summary(epoch_id):
    submissions = get_epoch_submissions(blockchain.chain, epoch_id)
    finalization = get_epoch_finalization(blockchain.chain, epoch_id)
    median_rates = calculate_median_rates(submissions) if submissions else None
    outliers = detect_outliers(submissions, median_rates) if submissions and median_rates else {}
    return {
        "epoch_id": epoch_id,
        "oracle_config": get_oracle_public_info(),
        "oracle_scores": list(build_oracle_scores(blockchain.chain).values()),
        "submissions_count": len(submissions),
        "submissions": sorted(list(submissions.values()), key=lambda x: x.get("oracle_id", "")),
        "median_rates_preview": median_rates,
        "outliers_preview": list(outliers.values()),
        "finalization": finalization,
        "is_finalized": finalization is not None,
    }


def _resolve_contract_runtime(contract_id, *, allow_inactive_dynamic=False):
    """
    Получить рантайм-описание пользовательского контракта поставщика.
    allow_inactive_dynamic=True используется в submit_work, чтобы принимать уже выданные задачи.
    """
    dynamic_contract = contract_market.get_contract(contract_id)
    if not dynamic_contract:
        return None
    if (not allow_inactive_dynamic) and (not contract_market.is_assignable(dynamic_contract)):
        return None

    expected_contract_id = dynamic_contract["contract_id"]
    expected_work_units_required = int(dynamic_contract["work_units_required"])
    expected_difficulty = int(dynamic_contract["difficulty"])
    expected_computation_type = dynamic_contract.get("computation_type", "simple_pow")

    def _verify(client_id, runtime_contract_id, work_units_done, result_data, nonce=None):
        return verify_contract_result(
            expected_contract_id=expected_contract_id,
            expected_work_units_required=expected_work_units_required,
            expected_difficulty=expected_difficulty,
            expected_computation_type=expected_computation_type,
            client_id=client_id,
            contract_id=runtime_contract_id,
            work_units_done=work_units_done,
            result_data=result_data,
            nonce=nonce,
        )

    return {
        "kind": "provider",
        "contract_id": dynamic_contract["contract_id"],
        "spec": _build_dynamic_task_spec(dynamic_contract),
        "reward": int(dynamic_contract["reward_per_task"]),
        "verify": _verify,
        "record": dynamic_contract,
    }


def _available_contract_runtimes():
    """Список контрактов, доступных для выдачи задач исполнителям."""
    runtimes = []
    for dynamic_contract in contract_market.list_active_contracts():
        runtimes.append(_resolve_contract_runtime(dynamic_contract["contract_id"], allow_inactive_dynamic=False))
    return [r for r in runtimes if r is not None]


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
        runtime = _resolve_contract_runtime(contract_id, allow_inactive_dynamic=False)
        if not runtime:
            return jsonify({"error": "Unknown contract_id or contract is not active"}), 400
    else:
        candidates = _available_contract_runtimes()
        if not candidates:
            return jsonify({"error": "No available contracts"}), 503
        runtime = random.choice(candidates)
    # Учитываем активного вычислителя по этому контракту
    _active_task_takers[(runtime["contract_id"], client_id)] = time.time()
    spec = dict(runtime["spec"])
    # Уникальный task_seed при каждой выдаче, 64 бит + привязка к client_id — чтобы коллизии
    # между разными клиентами были практически невозможны (proof already used by different client).
    base = uuid.uuid4().int & ((1 << 64) - 1)
    client_bits = int(hashlib.sha256(client_id.encode()).hexdigest()[:16], 16) % (1 << 64)
    spec["task_seed"] = (base ^ client_bits) & ((1 << 64) - 1)
    logger.info(
        "task_issued: contract_id=%s origin=%s client_id=%s... task_seed=%s",
        runtime["contract_id"],
        runtime["kind"],
        client_id[:8],
        spec["task_seed"],
    )
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
    try:
        work_units_done = int(work_units_done)
    except (TypeError, ValueError):
        return jsonify({"error": "work_units_done must be integer"}), 400
    if work_units_done <= 0:
        return jsonify({"error": "work_units_done must be > 0"}), 400

    # Защита от DoS: проверка размера result_data (хеш должен быть 64 символа, максимум 1KB для безопасности)
    if result_data:
        if not isinstance(result_data, str):
            return jsonify({"error": "result_data must be a string"}), 400
        if len(result_data) > 1024:  # Максимум 1KB
            logger.warning("submit_work: result_data too large (%s bytes)", len(result_data))
            return jsonify({"error": "result_data too large (max 1KB)"}), 400

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
                runtime = _resolve_contract_runtime(contract_id, allow_inactive_dynamic=True)
                reward_amount = runtime["reward"] if runtime else 0
                reward_currency = MARKET_DEFAULT_CURRENCY
                provider_client_id = None
                if runtime and runtime.get("record"):
                    reward_currency = (
                        _normalized_budget_currency(runtime["record"].get("budget_currency"))
                        or MARKET_DEFAULT_CURRENCY
                    )
                    provider_client_id = runtime["record"].get("provider_client_id")
                if runtime and provider_client_id and reward_amount > 0:
                    reward_id = _reward_event_id(
                        client_id=client_id,
                        contract_id=contract_id,
                        result_data=result_data,
                        nonce=nonce,
                    )
                    if not is_reward_settled(blockchain.chain, reward_id):
                        settlement_tx = _build_reward_settlement_tx(
                            client_id=client_id,
                            provider_client_id=provider_client_id,
                            contract_id=contract_id,
                            result_data=result_data,
                            nonce=nonce,
                            reward_amount=reward_amount,
                            reward_currency=reward_currency,
                            work_units_done=runtime["spec"].get("work_units_required", 1),
                        )
                        _, settle_err = _append_onchain_events([settlement_tx])
                        if settle_err:
                            return jsonify({"error": settle_err}), 500
                return jsonify({
                    "status": "success",
                    "reward_issued": reward_amount,
                    "reward_currency": reward_currency,
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

    runtime = _resolve_contract_runtime(contract_id, allow_inactive_dynamic=True)
    if not runtime:
        logger.warning("submit_work: invalid contract_id=%s", contract_id)
        return jsonify({"error": "Invalid contract ID"}), 400

    # BOINC: validator определяет корректность результата. У нас для астро-контрактов verify() заново
    # выполняет полное вычисление (60k–70k шагов) — может занять 10–15 мин; воркер должен ждать (timeout 900s).
    logger.info(
        "submit_work: starting verification for client_id=%s... contract_id=%s origin=%s (may take several minutes for large tasks)",
        client_id[:8],
        contract_id,
        runtime["kind"],
    )
    if not runtime["verify"](client_id, contract_id, work_units_done, result_data, nonce):
        logger.warning("submit_work_verification_failed: client_id=%s... contract_id=%s (balance not updated)", client_id[:8], contract_id)
        return jsonify({"error": "Work verification failed"}), 400
    logger.info("submit_work: verification passed for client_id=%s... contract_id=%s", client_id[:8], contract_id)

    reward_amount = int(runtime["reward"])
    reward_currency = MARKET_DEFAULT_CURRENCY
    provider_client_id = None
    if runtime["record"]:
        reward_currency = (
            _normalized_budget_currency(runtime["record"].get("budget_currency"))
            or MARKET_DEFAULT_CURRENCY
        )
        provider_client_id = runtime["record"].get("provider_client_id")
    if not provider_client_id:
        logger.warning("submit_work: provider_client_id missing for contract_id=%s", contract_id)
        return jsonify({"error": "Contract provider is not configured"}), 500
    if reward_amount < FEE_PER_WORK_RECEIPT:
        logger.warning("Contract reward %s less than fee %s", reward_amount, FEE_PER_WORK_RECEIPT)
    logger.info(
        "work_verified: client_id=%s... reward=%s %s contract_id=%s",
        client_id[:8],
        reward_amount,
        reward_currency,
        contract_id,
    )

    # Создаём транзакцию вознаграждения
    reward_from = f"provider_contract:{contract_id}"
    reward_tx = {
        "type": "reward",
        "from": reward_from,
        "to": client_id,
        "amount": reward_amount,
        "contract_id": contract_id,
        "currency": reward_currency,
    }
    if runtime["record"]:
        reward_tx["provider_client_id"] = provider_client_id
    
    # Assimilator (BOINC): учёт верифицированного результата — запись в блокчейн (reward + work_receipt; result_data для replay, fee сжигается).
    work_receipt_tx = {
        "type": "work_receipt",
        "client_id": client_id,
        "contract_id": contract_id,
        "work_units": work_units_done,
        "result_data": result_data,
        "fee": FEE_PER_WORK_RECEIPT,  # Экономическая модель: комиссия списывается с клиента после начисления награды
    }
    reward_settlement_tx = _build_reward_settlement_tx(
        client_id=client_id,
        provider_client_id=provider_client_id,
        contract_id=contract_id,
        result_data=result_data,
        nonce=nonce,
        reward_amount=reward_amount,
        reward_currency=reward_currency,
        work_units_done=work_units_done,
    )
    
    # Критическое исправление: узел, принявший submit_work, всегда создаёт блок сам.
    # Раньше при "не лидер" транзакции отправлялись лидеру через add_pending_tx, но лидер никогда
    # не вызывал mine_pending_transactions (блок создаётся только при submit_work на этом узле),
    # поэтому награда не попадала в цепочку и баланс оставался 0. Теперь блок создаём здесь и пушим пиру.
    
    # Критическое исправление: добавление транзакций и создание блока под одной блокировкой,
    # чтобы не остаться с «сиротой» reward_tx в pending при лимите work_receipt на клиента.
    dynamic_reservation = None
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
        if runtime["kind"] == "provider":
            dynamic_reservation, reserve_err = contract_market.reserve_submission(
                contract_id=contract_id,
                reward_amount=reward_amount,
                work_units_done=work_units_done,
            )
            if reserve_err:
                return jsonify({"error": reserve_err, "code": "provider_contract_budget"}), 409
        try:
            blockchain.add_transaction(reward_tx)
            blockchain.add_transaction(work_receipt_tx)
            blockchain.add_transaction(reward_settlement_tx)
        except ValueError as e:
            if dynamic_reservation:
                contract_market.rollback_submission(contract_id=contract_id, reservation=dynamic_reservation)
            logger.warning("submit_work: add_transaction failed: %s", e)
            return jsonify({"error": "Cannot add transaction", "detail": str(e)}), 400
        sync_pending_from_peer()
        new_block = blockchain.mine_pending_transactions(mining_reward_address=None)
        if dynamic_reservation and not new_block:
            contract_market.rollback_submission(contract_id=contract_id, reservation=dynamic_reservation)

    if new_block:
        new_balance = blockchain.get_balance(client_id)
        logger.info("block_created: client_id=%s... reward=%s new_balance=%s block_index=%s",
                    client_id[:8], reward_amount, new_balance, new_block.index)

    _push_block_to_peer(new_block)

    return jsonify({
        "status": "success", 
        "reward_issued": reward_amount,
        "reward_currency": reward_currency,
    }), 200

@app.route("/me", methods=["GET"])
@limiter.limit("60 per minute")
def me():
    """
    Получение профиля текущего пользователя по API-ключу.
    
    Возвращает информацию о вычислителе: client_id, nickname (если есть постоянный аккаунт),
    login, баланс токенов и количество сданных работ. Используется для отображения профиля
    в интерфейсе и проверки валидности API-ключа.
    
    Returns:
        JSON с полями: client_id, nickname (опционально), login (опционально), balance, submissions_count
    
    Raises:
        401: Если API-ключ отсутствует или неверный
    """
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    out = {"client_id": client_id}
    # Пытаемся получить данные постоянного аккаунта (если есть)
    try:
        profile = auth_find_by_client_id(client_id)
        if profile:
            out["nickname"] = profile.get("nickname") or profile.get("login")
            out["login"] = profile.get("login")
    except Exception:
        pass
    # Получаем баланс из блокчейна
    out["balance"] = blockchain.get_balance(client_id)
    # Фиатный кошелёк on-chain (без отдельного off-chain хранилища)
    wallet_info = get_wallet_from_chain(blockchain.chain, client_id)
    out["fiat_wallet"] = wallet_info.get("balances", {})
    out["fiat_total_rub_estimate"] = wallet_info.get("total_rub_estimate", 0)
    # Подсчитываем количество сданных работ по всей цепочке блоков
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


@app.route("/market/rates", methods=["GET"])
@limiter.limit("120 per minute")
def market_rates():
    """On-chain курсы валют и спред рыночной конвертации."""
    return jsonify(get_effective_fx_rules(blockchain.chain)), 200


@app.route("/market/rates/update", methods=["POST"])
@require_node_secret
@limiter.limit("20 per minute")
def market_rates_update():
    """
    Обновление FX-правил on-chain.
    Защищено X-Node-Secret: изменение возможно только доверенным узлом.
    """
    data = request.get_json(silent=True) or {}
    rates_payload = data.get("rates_to_rub")
    spread_payload = data.get("spread_percent")
    if not isinstance(rates_payload, dict) and spread_payload is None:
        return jsonify({"error": "rates_to_rub or spread_percent is required"}), 400
    tx = {
        "type": "fx_rules_update",
        "rates_to_rub": rates_payload if isinstance(rates_payload, dict) else None,
        "spread_percent": spread_payload,
        "updated_at": now_ts(),
    }
    _, err = _append_onchain_events([tx])
    if err:
        return jsonify({"error": err}), 400
    return jsonify(get_effective_fx_rules(blockchain.chain)), 200


@app.route("/market/fx/oracles", methods=["GET"])
@limiter.limit("120 per minute")
def market_fx_oracles():
    """Публичный статус oracle-пула и текущие on-chain scores."""
    payload = get_oracle_public_info()
    payload["scores"] = list(build_oracle_scores(blockchain.chain).values())
    return jsonify(payload), 200


@app.route("/market/fx/oracle-submit", methods=["POST"])
@limiter.limit("120 per minute")
def market_fx_oracle_submit():
    """Подписанный submit курса от FX-оракула в заданную эпоху."""
    data = request.get_json(silent=True) or {}
    oracle_id = (data.get("oracle_id") or "").strip()
    epoch_id = (data.get("epoch_id") or "").strip() or current_epoch_id()
    rates_payload = data.get("rates_to_rub")
    signature = (data.get("signature") or "").strip()

    if not oracle_id:
        return jsonify({"error": "oracle_id is required"}), 400
    if not epoch_id:
        return jsonify({"error": "epoch_id is required"}), 400
    normalized_rates, normalize_err = normalize_rates_payload(rates_payload)
    if normalize_err:
        return jsonify({"error": normalize_err}), 400

    valid, sign_err = verify_submission_signature(
        oracle_id=oracle_id,
        epoch_id=epoch_id,
        rates_to_rub=normalized_rates,
        signature=signature,
    )
    if not valid:
        return jsonify({"error": sign_err}), 401

    if get_epoch_finalization(blockchain.chain, epoch_id):
        return jsonify({"error": "Epoch already finalized"}), 409
    existing = get_epoch_submissions(blockchain.chain, epoch_id)
    if oracle_id in existing:
        return jsonify({"error": "Oracle already submitted for this epoch"}), 409

    tx = {
        "type": "fx_oracle_submit",
        "oracle_id": oracle_id,
        "epoch_id": epoch_id,
        "rates_to_rub": normalized_rates,
        "signature": signature,
        "submitted_at": now_ts(),
    }
    _, err = _append_onchain_events([tx])
    if err:
        return jsonify({"error": err}), 400
    summary = _oracle_epoch_summary(epoch_id)
    summary["quorum_reached"] = summary["submissions_count"] >= ORACLE_QUORUM
    return jsonify(summary), 201


@app.route("/market/fx/finalize", methods=["POST"])
@require_node_secret
@limiter.limit("30 per minute")
def market_fx_finalize():
    """Финализация эпохи oracle-курсов: медиана, outlier, штрафы, запись on-chain."""
    data = request.get_json(silent=True) or {}
    epoch_id = (data.get("epoch_id") or "").strip() or current_epoch_id()

    existing_final = get_epoch_finalization(blockchain.chain, epoch_id)
    if existing_final:
        return jsonify({"status": "already_finalized", "epoch": _oracle_epoch_summary(epoch_id)}), 200

    submissions = get_epoch_submissions(blockchain.chain, epoch_id)
    if len(submissions) < ORACLE_QUORUM:
        return jsonify(
            {
                "error": "Not enough oracle submissions",
                "epoch_id": epoch_id,
                "submissions_count": len(submissions),
                "required_quorum": ORACLE_QUORUM,
            }
        ), 409

    median_rates = calculate_median_rates(submissions)
    outliers = detect_outliers(submissions, median_rates)
    current_rules = get_effective_fx_rules(blockchain.chain)
    spread_percent = data.get("spread_percent")
    if spread_percent is None:
        spread_percent = current_rules.get("spread_percent")
    txs = [
        {
            "type": "fx_rules_update",
            "rates_to_rub": median_rates,
            "spread_percent": spread_percent,
            "updated_at": now_ts(),
            "meta": {
                "source": "multi_oracle",
                "epoch_id": epoch_id,
                "oracle_count": len(submissions),
                "outliers": sorted(outliers.keys()),
            },
        }
    ]
    for oracle_id in sorted(outliers.keys()):
        txs.append(
            {
                "type": "fx_oracle_penalty",
                "oracle_id": oracle_id,
                "epoch_id": epoch_id,
                "penalty_points": ORACLE_PENALTY_POINTS,
                "reason": "outlier",
                "created_at": now_ts(),
            }
        )
    _, err = _append_onchain_events(txs)
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"status": "finalized", "epoch": _oracle_epoch_summary(epoch_id)}), 200


@app.route("/market/fx/epoch/<epoch_id>", methods=["GET"])
@limiter.limit("120 per minute")
def market_fx_epoch(epoch_id):
    """Подробности oracle-эпохи: submit'ы, preview медианы, финализация."""
    normalized_epoch = (epoch_id or "").strip()
    if not normalized_epoch:
        return jsonify({"error": "epoch_id required"}), 400
    return jsonify(_oracle_epoch_summary(normalized_epoch)), 200


@app.route("/market/wallet", methods=["GET"])
@limiter.limit("120 per minute")
def market_wallet():
    """Фиатный кошелёк текущего пользователя."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    return jsonify(get_wallet_from_chain(blockchain.chain, client_id)), 200


@app.route("/market/wallet/topup", methods=["POST"])
@limiter.limit("30 per minute")
def market_wallet_topup():
    """Пополнение фиатного кошелька (on-chain событие)."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    currency = _normalized_budget_currency(data.get("currency"))
    try:
        amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        amount = 0
    if not currency:
        return jsonify({"error": "Unsupported currency"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    tx = {
        "type": "fiat_topup",
        "client_id": client_id,
        "currency": currency,
        "amount": amount,
        "source": (data.get("source") or "bank_transfer"),
        "created_at": now_ts(),
    }
    _, err = _append_onchain_events([tx])
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"wallet": get_wallet_from_chain(blockchain.chain, client_id)}), 200


@app.route("/market/convert", methods=["POST"])
@limiter.limit("30 per minute")
def market_convert():
    """On-chain конвертация валют внутри кошелька."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    source_currency = _normalized_budget_currency(data.get("from_currency"))
    target_currency = _normalized_budget_currency(data.get("to_currency"))
    try:
        source_amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        source_amount = 0
    if not source_currency or not target_currency:
        return jsonify({"error": "Unsupported currency"}), 400
    if source_currency == target_currency:
        return jsonify({"error": "from_currency and to_currency must differ"}), 400
    if source_amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    wallet_amount = get_wallet_amount(blockchain.chain, client_id, source_currency)
    if wallet_amount < source_amount:
        return jsonify({"error": "Insufficient wallet balance"}), 409
    rules = get_effective_fx_rules(blockchain.chain)
    target_amount, convert_err = convert_with_rules(
        rules=rules,
        from_currency=source_currency,
        to_currency=target_currency,
        amount=source_amount,
    )
    if convert_err:
        return jsonify({"error": convert_err}), 400
    tx = {
        "type": "fiat_conversion",
        "client_id": client_id,
        "from_currency": source_currency,
        "to_currency": target_currency,
        "source_amount": source_amount,
        "target_amount": int(target_amount),
        "spread_percent": float(rules.get("spread_percent", 0)),
        "created_at": now_ts(),
    }
    _, err = _append_onchain_events([tx])
    if err:
        return jsonify({"error": err}), 400
    return jsonify({
        "client_id": client_id,
        "from_currency": source_currency,
        "to_currency": target_currency,
        "source_amount": source_amount,
        "target_amount": int(target_amount),
        "spread_percent": float(rules.get("spread_percent", 0)),
        "balances": get_wallet_from_chain(blockchain.chain, client_id)["balances"],
    }), 200


@app.route("/market/withdrawals", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def market_withdrawals():
    """On-chain заявки на вывод фиатных средств на банковскую карту."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if request.method == "GET":
        limit = request.args.get("limit", 50)
        rows = list_withdrawals_from_chain(blockchain.chain, client_id=client_id, limit=limit)
        return jsonify({"withdrawals": rows}), 200
    data = request.get_json(silent=True) or {}
    currency = _normalized_budget_currency(data.get("currency"))
    try:
        amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        amount = 0
    card_mask = mask_card_number(data.get("card_number"))
    if not currency:
        return jsonify({"error": "Unsupported currency"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400
    if not card_mask:
        return jsonify({"error": "Invalid card number format"}), 400
    wallet_amount = get_wallet_amount(blockchain.chain, client_id, currency)
    if wallet_amount < amount:
        return jsonify({"error": "Insufficient wallet balance"}), 409
    withdrawal_id = f"wd-{uuid.uuid4().hex[:16]}"
    tx = {
        "type": "fiat_withdrawal_request",
        "withdrawal_id": withdrawal_id,
        "client_id": client_id,
        "currency": currency,
        "amount": amount,
        "payout_method": "bank_card",
        "card_mask": card_mask,
        "status": "queued",
        "created_at": now_ts(),
    }
    _, err = _append_onchain_events([tx])
    if err:
        return jsonify({"error": err}), 400
    withdrawal = {
        "withdrawal_id": withdrawal_id,
        "client_id": client_id,
        "currency": currency,
        "amount": amount,
        "card_mask": card_mask,
        "status": "queued",
    }
    return jsonify({"withdrawal": withdrawal, "wallet": get_wallet_from_chain(blockchain.chain, client_id)}), 201


@app.route("/market/audit", methods=["GET"])
@limiter.limit("60 per minute")
def market_audit():
    """On-chain аудит экономических и контрактных событий."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    limit = request.args.get("limit", 200)
    contract_id = (request.args.get("contract_id") or "").strip() or None
    event_type = (request.args.get("event_type") or "").strip() or None
    rows = list_audit_events(
        blockchain.chain,
        client_id=client_id,
        contract_id=contract_id,
        event_type=event_type,
        limit=limit,
    )
    return jsonify({"events": rows}), 200


@app.route("/market/contracts/onchain", methods=["GET"])
@limiter.limit("60 per minute")
def market_contracts_onchain():
    """On-chain слепок контрактов (бюджеты, статусы, settled-метрики)."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    provider_only = request.args.get("provider_only") in ("1", "true", "yes")
    provider_filter = client_id if provider_only else None
    rows = list_contracts_onchain(blockchain.chain, provider_client_id=provider_filter)
    return jsonify({"contracts": rows}), 200


def _provider_contract_error_response(error):
    if error == "Forbidden":
        return jsonify({"error": error}), 403
    if error == "Contract not found":
        return jsonify({"error": error}), 404
    if error == "Insufficient wallet balance":
        return jsonify({"error": error}), 409
    return jsonify({"error": error}), 400


@app.route("/provider/contracts", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def provider_contracts():
    """
    API поставщика контрактов:
    - GET: список своих контрактов
    - POST: создать новый контракт (status=draft по умолчанию)
    """
    provider_client_id = get_client_id_from_auth()
    if provider_client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401

    if request.method == "GET":
        runtime_contracts = contract_market.list_provider_contracts(provider_client_id)
        onchain_rows = list_contracts_onchain(blockchain.chain, provider_client_id=provider_client_id)
        onchain_by_id = {row.get("contract_id"): row for row in onchain_rows}
        for row in runtime_contracts:
            row["onchain"] = onchain_by_id.get(row.get("contract_id"))
        return jsonify(runtime_contracts), 200

    data = request.get_json(silent=True) or {}
    task_name = (data.get("task_name") or "").strip()
    task_description = (data.get("task_description") or "").strip()
    task_category = (data.get("task_category") or "").strip() or "Пользовательская"
    computation_type = (data.get("computation_type") or "simple_pow").strip()

    if not task_name:
        return jsonify({"error": "task_name is required"}), 400
    if computation_type not in SUPPORTED_COMPUTATION_TYPES:
        return jsonify({"error": "Unsupported computation_type"}), 400

    try:
        work_units_required = int(data.get("work_units_required", 1000))
        reward_per_task = int(data.get("reward_per_task", 10))
        target_total_work_units = int(data.get("target_total_work_units", work_units_required * 10))
        difficulty = int(data.get("difficulty", default_difficulty_for(computation_type)))
        initial_budget_tokens = int(data.get("initial_budget_tokens", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Numeric fields must be integers"}), 400
    budget_currency = _normalized_budget_currency(data.get("budget_currency"))
    if not budget_currency:
        return jsonify({"error": "Unsupported budget_currency"}), 400

    if work_units_required <= 0:
        return jsonify({"error": "work_units_required must be > 0"}), 400
    if reward_per_task <= 0:
        return jsonify({"error": "reward_per_task must be > 0"}), 400
    if target_total_work_units < work_units_required:
        return jsonify({"error": "target_total_work_units must be >= work_units_required"}), 400
    if difficulty <= 0 or difficulty > 8:
        return jsonify({"error": "difficulty must be in range 1..8"}), 400
    if initial_budget_tokens < 0:
        return jsonify({"error": "initial_budget_tokens must be >= 0"}), 400

    if initial_budget_tokens > 0:
        provider_amount = get_wallet_amount(blockchain.chain, provider_client_id, budget_currency)
        if provider_amount < initial_budget_tokens:
            return _provider_contract_error_response("Insufficient wallet balance")

    try:
        created = contract_market.create_contract(
            provider_client_id=provider_client_id,
            task_name=task_name,
            task_description=task_description,
            task_category=task_category,
            computation_type=computation_type,
            work_units_required=work_units_required,
            reward_per_task=reward_per_task,
            target_total_work_units=target_total_work_units,
            difficulty=difficulty,
            initial_budget_tokens=initial_budget_tokens,
            budget_currency=budget_currency,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    activate_now = data.get("activate_now") in (True, "true", "1", 1)
    final_status = created.get("status", STATUS_DRAFT)
    if activate_now:
        updated, err = contract_market.set_status(
            contract_id=created["contract_id"],
            provider_client_id=provider_client_id,
            new_status=STATUS_ACTIVE,
        )
        if err:
            return _provider_contract_error_response(err)
        created = updated
        final_status = created.get("status", STATUS_ACTIVE)

    created_ts = now_ts()
    event_txs = [
        {
            "type": "contract_create_event",
            "contract_id": created["contract_id"],
            "provider_client_id": provider_client_id,
            "task_name": task_name,
            "task_category": task_category,
            "computation_type": computation_type,
            "reward_per_task": reward_per_task,
            "budget_currency": budget_currency,
            "status": STATUS_DRAFT,
            "created_at": created_ts,
        }
    ]
    if initial_budget_tokens > 0:
        event_txs.append(
            {
                "type": "contract_budget_fund_event",
                "contract_id": created["contract_id"],
                "provider_client_id": provider_client_id,
                "currency": budget_currency,
                "amount": initial_budget_tokens,
                "created_at": created_ts,
            }
        )
    if final_status != STATUS_DRAFT:
        event_txs.append(
            {
                "type": "contract_status_event",
                "contract_id": created["contract_id"],
                "provider_client_id": provider_client_id,
                "status": final_status,
                "updated_at": created_ts,
            }
        )
    _, append_err = _append_onchain_events(event_txs)
    if append_err:
        contract_market.delete_contract(
            contract_id=created["contract_id"],
            provider_client_id=provider_client_id,
        )
        return jsonify({"error": append_err}), 500
    wallet_info = get_wallet_from_chain(blockchain.chain, provider_client_id)
    return jsonify({"contract": created, "wallet": wallet_info}), 201


@app.route("/provider/contracts/<contract_id>", methods=["GET"])
@limiter.limit("60 per minute")
def provider_contract_details(contract_id):
    """Детали контракта: владелец видит всегда, остальные — только активные."""
    contract = contract_market.get_contract(contract_id)
    if not contract:
        return jsonify({"error": "Contract not found"}), 404
    requester = get_client_id_from_auth()
    if requester == contract.get("provider_client_id") or contract.get("status") == STATUS_ACTIVE:
        onchain_rows = list_contracts_onchain(blockchain.chain)
        onchain = next((row for row in onchain_rows if row.get("contract_id") == contract_id), None)
        payload = dict(contract)
        payload["onchain"] = onchain
        return jsonify(payload), 200
    return jsonify({"error": "Forbidden"}), 403


@app.route("/provider/contracts/<contract_id>/fund", methods=["POST"])
@limiter.limit("20 per minute")
def provider_contract_fund(contract_id):
    """Пополнить бюджет пользовательского контракта."""
    provider_client_id = get_client_id_from_auth()
    if provider_client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    try:
        amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "amount must be integer"}), 400
    contract = contract_market.get_contract(contract_id)
    if not contract:
        return jsonify({"error": "Contract not found"}), 404
    if contract.get("provider_client_id") != provider_client_id:
        return jsonify({"error": "Forbidden"}), 403
    budget_currency = _normalized_budget_currency(contract.get("budget_currency"))
    if not budget_currency:
        return jsonify({"error": "Unsupported budget_currency"}), 400
    request_currency = data.get("currency")
    if request_currency is not None:
        normalized_request_currency = _normalized_budget_currency(request_currency)
        if not normalized_request_currency:
            return jsonify({"error": "Unsupported currency"}), 400
        if normalized_request_currency != budget_currency:
            return jsonify({"error": "Currency mismatch with contract budget"}), 400

    provider_amount = get_wallet_amount(blockchain.chain, provider_client_id, budget_currency)
    if provider_amount < amount:
        return _provider_contract_error_response("Insufficient wallet balance")
    updated, err = contract_market.fund_contract(
        contract_id=contract_id,
        provider_client_id=provider_client_id,
        amount=amount,
    )
    if err:
        return _provider_contract_error_response(err)
    tx = {
        "type": "contract_budget_fund_event",
        "contract_id": contract_id,
        "provider_client_id": provider_client_id,
        "currency": budget_currency,
        "amount": amount,
        "created_at": now_ts(),
    }
    _, append_err = _append_onchain_events([tx])
    if append_err:
        contract_market.refund_contract(
            contract_id=contract_id,
            provider_client_id=provider_client_id,
            amount=amount,
        )
        return jsonify({"error": append_err}), 500
    wallet_info = get_wallet_from_chain(blockchain.chain, provider_client_id)
    return jsonify({"contract": updated, "wallet": wallet_info}), 200


@app.route("/provider/contracts/<contract_id>/status", methods=["POST"])
@limiter.limit("20 per minute")
def provider_contract_status(contract_id):
    """Сменить статус контракта (active/paused/closed)."""
    provider_client_id = get_client_id_from_auth()
    if provider_client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    new_status = (data.get("status") or "").strip()
    current = contract_market.get_contract(contract_id)
    previous_status = current.get("status") if current else None
    updated, err = contract_market.set_status(
        contract_id=contract_id,
        provider_client_id=provider_client_id,
        new_status=new_status,
    )
    if err:
        return _provider_contract_error_response(err)
    tx = {
        "type": "contract_status_event",
        "contract_id": contract_id,
        "provider_client_id": provider_client_id,
        "status": new_status,
        "updated_at": now_ts(),
    }
    _, append_err = _append_onchain_events([tx])
    if append_err:
        if previous_status and previous_status != new_status:
            contract_market.set_status(
                contract_id=contract_id,
                provider_client_id=provider_client_id,
                new_status=previous_status,
            )
        return jsonify({"error": append_err}), 500
    return jsonify(updated), 200


@app.route("/provider/contracts/<contract_id>/refund", methods=["POST"])
@limiter.limit("20 per minute")
def provider_contract_refund(contract_id):
    """Вернуть неиспользованный бюджет поставщику (логическая операция модели)."""
    provider_client_id = get_client_id_from_auth()
    if provider_client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    amount = data.get("amount")
    if amount is not None:
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return jsonify({"error": "amount must be integer"}), 400
    updated, refunded_amount, err = contract_market.refund_contract(
        contract_id=contract_id,
        provider_client_id=provider_client_id,
        amount=amount,
    )
    if err:
        return _provider_contract_error_response(err)
    budget_currency = _normalized_budget_currency(updated.get("budget_currency") if updated else None) or MARKET_DEFAULT_CURRENCY
    if refunded_amount and refunded_amount > 0:
        tx = {
            "type": "contract_budget_refund_event",
            "contract_id": contract_id,
            "provider_client_id": provider_client_id,
            "currency": budget_currency,
            "amount": int(refunded_amount),
            "created_at": now_ts(),
        }
        _, append_err = _append_onchain_events([tx])
        if append_err:
            # rollback refund in runtime storage
            contract_market.fund_contract(
                contract_id=contract_id,
                provider_client_id=provider_client_id,
                amount=int(refunded_amount),
            )
            return jsonify({"error": append_err}), 500
    wallet_info = get_wallet_from_chain(blockchain.chain, provider_client_id)
    return jsonify({"contract": updated, "refunded_amount": refunded_amount, "wallet": wallet_info}), 200


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

@app.route("/explorer/block/<int:index>", methods=["GET"])
@limiter.limit("120 per minute")
def explorer_block(index):
    """Explorer: один блок по индексу (публичный read-only)."""
    if index < 0 or index >= len(blockchain.chain):
        return jsonify({"error": "Block not found"}), 404
    block = blockchain.chain[index]
    return jsonify(block.__dict__), 200


@app.route("/explorer/address/<client_id>", methods=["GET"])
@limiter.limit("60 per minute")
def explorer_address(client_id):
    """Explorer: баланс и список транзакций по client_id (адрес вычислителя)."""
    client_id = (client_id or "").strip()
    if not client_id:
        return jsonify({"error": "client_id required"}), 400
    balance = blockchain.get_balance(client_id)
    transactions = []
    for block in blockchain.chain:
        b_dict = block.__dict__
        for tx in block.transactions:
            involved = False
            if tx.get("type") == "reward" and tx.get("to") == client_id:
                involved = True
            if tx.get("type") == "work_receipt" and tx.get("client_id") == client_id:
                involved = True
            if involved:
                transactions.append({
                    "block_index": block.index,
                    "block_hash": block.hash,
                    "tx": tx,
                })
    transactions.reverse()
    return jsonify({
        "client_id": client_id,
        "balance": balance,
        "transactions": transactions,
    }), 200


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
    onchain_rows = list_contracts_onchain(blockchain.chain)
    onchain_by_id = {row.get("contract_id"): row for row in onchain_rows}
    out = []
    # Публичные контракты поставщиков (только активные)
    for contract_record in contract_market.list_active_contracts():
        cid = contract_record["contract_id"]
        wu_required = int(contract_record["work_units_required"])
        total_done = chain_stats.get(cid, {}).get("total_work_done", 0)
        jobs_count = chain_stats.get(cid, {}).get("jobs_count", 0)
        target = int(contract_record["target_total_work_units"])
        completion_pct = min(100.0, (total_done / target * 100)) if target else 0.0
        remaining_volume = max(0, target - total_done)
        active_workers = _active_workers_count(cid)
        onchain_row = onchain_by_id.get(cid) or {}
        out.append({
            "contract_id": cid,
            "work_units_required": wu_required,
            "difficulty": int(contract_record["difficulty"]),
            "reward": int(contract_record["reward_per_task"]),
            "reward_currency": contract_record.get("budget_currency", MARKET_DEFAULT_CURRENCY),
            "task_name": contract_record.get("task_name", cid),
            "task_description": contract_record.get("task_description", ""),
            "task_category": contract_record.get("task_category", "Пользовательская"),
            "computation_type": contract_record.get("computation_type", "simple_pow"),
            "total_work_done": total_done,
            "jobs_count": jobs_count,
            "completion_pct": round(completion_pct, 1),
            "active_workers": active_workers,
            "target_total": target,
            "remaining_volume": remaining_volume,
            "free_volume": remaining_volume,
            "reward_per_task": int(contract_record["reward_per_task"]),
            "contract_origin": "provider",
            "status": contract_record.get("status", STATUS_DRAFT),
            "provider_client_id": contract_record.get("provider_client_id"),
            "budget_currency": contract_record.get("budget_currency", MARKET_DEFAULT_CURRENCY),
            "budget_tokens_total": int(contract_record.get("budget_tokens_total", 0)),
            "budget_tokens_spent": int(contract_record.get("budget_tokens_spent", 0)),
            "budget_tokens_available": int(contract_record.get("budget_tokens_available", 0)),
            "onchain_budget_total": int(onchain_row.get("budget_total", 0)),
            "onchain_budget_spent": int(onchain_row.get("budget_spent", 0)),
            "onchain_budget_refunded": int(onchain_row.get("budget_refunded", 0)),
            "onchain_budget_available": int(onchain_row.get("budget_available", 0)),
            "onchain_jobs_completed": int(onchain_row.get("jobs_completed", 0)),
        })
    return jsonify(out), 200


def _run_worker_container(contract_id, api_key=None, client_id=None, run_once=False):
    """
    Запуск Docker-контейнера воркера для выполнения задач по указанному контракту.
    
    Воркер запускается с переменными окружения CONTRACT_ID, API_KEY и CLIENT_ID (если переданы).
    Если переданы api_key и client_id, воркер работает от этого аккаунта — награда попадёт на баланс этого вычислителя.
    
    Args:
        contract_id: Идентификатор контракта, для которого запускается воркер
        api_key: API-ключ вычислителя (опционально, для аутентификации воркера)
        client_id: ID вычислителя (опционально, для проверки соответствия ключу)
        run_once: Если True, воркер выполнит одну задачу и выйдет;
                  если False, воркер будет брать задачи в цикле до остановки контейнера (как в BOINC)
    
    Returns:
        tuple: (success: bool, message: str) - результат запуска и сообщение для пользователя
    
    Требования:
        - Доступ к Docker (сокет /var/run/docker.sock)
        - Переменные окружения: WORKER_IMAGE, ORCHESTRATOR_URL_FOR_WORKER, DOCKER_NETWORK
    """
    runtime = _resolve_contract_runtime(contract_id, allow_inactive_dynamic=False)
    if not runtime:
        return False, "Unknown contract_id or contract is not active"
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
    Требуется авторизация. Тело: {"contract_id": "<id_контракта>", "client_id": "опционально для проверки"}.
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
# Используется для отображения прогресса выполнения задачи в реальном времени на вкладке "Профиль"
_worker_progress = {}
WORKER_PROGRESS_TTL = 300  # 5 минут — считаем прогресс устаревшим, если дольше нет обновлений


@app.route("/worker_progress", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def worker_progress():
    """
    Управление прогрессом выполнения задач воркером.
    
    GET: Получение текущего прогресса воркера для вычислителя, определённого по API-ключу.
         Используется для отображения прогресс-бара в интерфейсе на вкладке "Профиль".
    
    POST: Воркер отправляет обновление прогресса (contract_id, step, total).
          Требуется аутентификация через Authorization header.
          Прогресс автоматически удаляется через WORKER_PROGRESS_TTL секунд без обновлений.
    
    Returns:
        GET: JSON с полем "progress" (объект с contract_id, step, total, updated_at) или null
        POST: JSON с полем "ok": true при успешном сохранении
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


@app.route("/explorer")
def explorer():
    """Block Explorer: просмотр блоков и адресов (вычислителей)."""
    return send_from_directory(app.static_folder or "static", "explorer.html")

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
