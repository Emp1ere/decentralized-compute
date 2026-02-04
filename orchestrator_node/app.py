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

# Счётчики для мониторинга (запросы по эндпоинтам и ошибки)
_request_counts = {}
_error_counts = {}

# Инициализируем наш блокчейн
blockchain = Blockchain()

# --- Безопасность: аутентификация по API-ключу ---
# api_key -> client_id (ключ выдаётся один раз при регистрации)
api_key_to_client = {}

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
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "30"))
# Секрет для запросов между узлами (receive_block, receive_chain, add_pending_tx) — опционально
NODE_SECRET = os.environ.get("NODE_SECRET", "")


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

@app.route("/get_task", methods=["GET"])
@limiter.limit("60 per minute")  # Защита от DDoS: не более 60 запросов задач в минуту на ключ
def get_task():
    """
    Клиент запрашивает задачу (смарт-контракт). Требуется аутентификация: Authorization: Bearer <api_key>.
    """
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    contract = random.choice(list(CONTRACTS.values()))
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
    
    # Добавляем транзакции в блокчейн
    blockchain.add_transaction(reward_tx)
    blockchain.add_transaction(work_receipt_tx)

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
    """Для веб-интерфейса: по API-ключу возвращает client_id (без секретов)."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    return jsonify({"client_id": client_id}), 200


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
    except Exception as e:
        logger.exception("metrics_error")
        return jsonify({"error": "metrics failed"}), 500
    body = {
        "chain_length": chain_len,
        "clients_count": num_clients,
        "pending_transactions": pending,
        "request_counts": _request_counts,
        "error_counts": _error_counts,
    }
    return jsonify(body), 200

@app.route("/chain", methods=["GET"])
@limiter.limit("120 per minute")  # Публичный read-only; лимит от DDoS
def get_chain():
    """Посмотреть весь блокчейн (для синхронизации и просмотра)."""
    return jsonify(blockchain.get_chain_json()), 200


@app.route("/contracts", methods=["GET"])
@limiter.limit("60 per minute")
def get_contracts():
    """Список контрактов для веб-интерфейса (вкладка Контракты, по аналогии с BOINC Projects)."""
    out = []
    for cid, c in CONTRACTS.items():
        spec = c.get_task_spec()
        out.append({
            "contract_id": cid,
            "work_units_required": spec["work_units_required"],
            "difficulty": spec["difficulty"],
            "reward": c.get_reward(),
        })
    return jsonify(out), 200


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
