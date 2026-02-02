from flask import Flask, request, jsonify
from blockchain import Blockchain
from contracts import CONTRACTS
import uuid
import random
import os
import requests
import threading
import time

app = Flask(__name__)

# URL второго узла для синхронизации блокчейна (децентрализация)
PEER_URL = os.environ.get("PEER_URL", "")

# Интервал периодической синхронизации с пиром (секунды)
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", 30))


def sync_chain_from_peer():
    """
    Запросить у пира полную цепочку и заменить локальную, если у пира длиннее и она валидна.
    Основа начальной синхронизации при старте и разрешения конфликтов (longest chain).
    """
    if not PEER_URL:
        return  # Нет пира — нечего синхронизировать
    try:
        r = requests.get(f"{PEER_URL.rstrip('/')}/chain", timeout=5)  # GET /chain у пира
        if r.status_code != 200:
            return  # Пир недоступен или ошибка — пропускаем
        peer_chain = r.json()  # Цепочка как список блоков (словарей)
        ok, err = blockchain.replace_chain_from_peer(peer_chain)  # Замена только если длиннее и валидна
        if ok:
            print(f"[Sync] Replaced local chain with peer chain (length {len(peer_chain)})")
        elif err and "not longer" not in err:
            print(f"[Sync] Peer chain rejected: {err}")  # Не печатаем, если просто «не длиннее»
    except Exception as e:
        print(f"[Sync] Failed to fetch peer chain: {e}")


def startup_sync():
    """
    Синхронизация с пиром при старте узла: ждём, пока пир поднимется, затем подтягиваем его цепочку.
    Узел, запущенный позже, получает актуальное состояние сети.
    """
    time.sleep(3)  # Даём пиру время подняться (в docker-compose node_2 зависит от node_1)
    sync_chain_from_peer()  # Один раз запрашиваем цепочку и принимаем, если длиннее


def periodic_sync():
    """
    Периодически запрашивать цепочку у пира и принимать более длинную валидную.
    Компенсирует расхождения при сбоях и «догоняет» сеть.
    """
    while True:
        time.sleep(SYNC_INTERVAL)  # Интервал между проверками (по умолчанию 30 сек)
        sync_chain_from_peer()  # Подтягиваем цепочку пира, если она длиннее


def mining_loop():
    """
    Консенсус PoW: любой узел может майнить. При наличии pending tx ищем nonce;
    первый найденный валидный блок добавляется в цепочку и отправляется пиру.
    """
    while True:
        time.sleep(1)  # Пауза, чтобы не нагружать CPU впустую
        if not blockchain.pending_transactions:
            continue  # Пустая очередь — майнить нечего
        new_block = blockchain.mine_pending_transactions(mining_reward_address=None)  # PoW без доп. награды за блок
        if new_block and PEER_URL:
            try:
                requests.post(
                    f"{PEER_URL.rstrip('/')}/receive_block",
                    json=new_block.__dict__,
                    timeout=5,
                )  # Рассылаем блок пиру; тот примет его и очистит свой pending (консенсус)
            except Exception:
                pass  # Ошибка сети при отправке блока — не критично

# Инициализируем блокчейн
blockchain = Blockchain()

# --- API Эндпоинты ---

@app.route("/register", methods=["GET"])
def register_client():
    """Регистрация клиента: выдаём уникальный ID и инициализируем баланс."""
    client_id = str(uuid.uuid4())  # Уникальный идентификатор как «адрес кошелька»
    blockchain.balances[client_id] = 0  # Начальный баланс ноль
    return jsonify({"client_id": client_id}), 200

@app.route("/get_task", methods=["GET"])
def get_task():
    """Выдача задачи: случайный исполняемый контракт возвращает минимальную спецификацию для воркера."""
    contract = random.choice(list(CONTRACTS.values()))  # Выбираем контракт из реестра
    return jsonify(contract.get_task_spec()), 200  # Только contract_id, work_units_required, difficulty

@app.route("/submit_work", methods=["POST"])
def submit_work():
    """Приём результата работы: исполняемый контракт проверяет выполнение и определяет вознаграждение."""
    data = request.json  # client_id, contract_id, work_units_done, result_data, nonce (опционально)
    client_id = data.get("client_id")
    contract_id = data.get("contract_id")
    work_units_done = data.get("work_units_done")
    result_data = data.get("result_data")
    nonce = data.get("nonce")  # Nonce решения для строгой проверки хеша

    if not all([client_id, contract_id, work_units_done is not None]):
        return jsonify({"error": "Missing data"}), 400

    contract = CONTRACTS.get(contract_id)  # Берём исполняемый контракт по id
    if not contract:
        return jsonify({"error": "Invalid contract ID"}), 400

    # Исполняемая проверка: контракт верифицирует работу (объём + результат, при наличии nonce — хеш)
    if not contract.verify(client_id, contract_id, work_units_done, result_data, nonce):
        return jsonify({
            "status": "pending",
            "message": "Work not verified (insufficient work or invalid result)."
        }), 200

    # Контракт определяет размер вознаграждения
    reward_amount = contract.get_reward()

    reward_tx = {
        "type": "reward",
        "from": "system_contract",
        "to": client_id,
        "amount": reward_amount,
        "contract_id": contract_id,
    }
    work_receipt_tx = {
        "type": "work_receipt",
        "client_id": client_id,
        "contract_id": contract_id,
        "work_units": work_units_done,
    }
    blockchain.add_transaction(reward_tx)  # В очередь; майнить будет любой узел (PoW), не один оркестратор
    blockchain.add_transaction(work_receipt_tx)
    if PEER_URL:
        try:
            requests.post(
                f"{PEER_URL.rstrip('/')}/add_pending_tx",
                json={"transactions": [reward_tx, work_receipt_tx]},
                timeout=5,
            )  # Пир получает те же tx и тоже будет майнить — конкуренция за блок (консенсус PoW)
        except Exception:
            pass
    return jsonify({"status": "success", "reward_issued": reward_amount}), 200  # Блок создаст mining_loop

@app.route("/get_balance/<client_id>", methods=["GET"])
def get_balance(client_id):
    """
    Получить баланс клиента
    """
    balance = blockchain.get_balance(client_id)
    return jsonify({"client_id": client_id, "balance": balance}), 200

@app.route("/chain", methods=["GET"])
def get_chain():
    """
    Посмотреть весь блокчейн
    """
    return jsonify(blockchain.get_chain_json()), 200


@app.route("/add_pending_tx", methods=["POST"])
def add_pending_tx():
    """
    Консенсус PoW: принять транзакции от пира в очередь; оба узла майнят один и тот же pending.
    """
    data = request.get_json()  # Тело: { "transactions": [ tx1, tx2, ... ] }
    if not data or "transactions" not in data:
        return jsonify({"error": "No transactions"}), 400
    for tx in data["transactions"]:
        blockchain.add_transaction(tx)  # Добавляем в локальную очередь для майнинга
    return jsonify({"accepted": True}), 200


@app.route("/receive_block", methods=["POST"])
def receive_block():
    """
    Принять блок от другого узла (консенсус PoW: первый валидный блок принимается, pending очищается).
    """
    data = request.get_json()
    if not data:
        return jsonify({"accepted": False, "error": "No JSON"}), 400
    ok, err = blockchain.add_block_from_peer(data)
    if ok:
        return jsonify({"accepted": True}), 200
    return jsonify({"accepted": False, "error": err}), 400


@app.route("/receive_chain", methods=["POST"])
def receive_chain():
    """
    Принять полную цепочку от пира (разрешение конфликтов, broadcast цепочки).
    Принимаем только если цепочка валидна и длиннее локальной (longest valid chain).
    """
    data = request.get_json()  # Тело запроса — список блоков (как из GET /chain)
    if not data or not isinstance(data, list):
        return jsonify({"accepted": False, "error": "No chain or invalid format"}), 400
    ok, err = blockchain.replace_chain_from_peer(data)  # Валидация + замена, если длиннее
    if ok:
        return jsonify({"accepted": True, "length": len(data)}), 200
    return jsonify({"accepted": False, "error": err}), 400


if __name__ == "__main__":
    t_startup = threading.Thread(target=startup_sync, daemon=True)
    t_startup.start()
    t_periodic = threading.Thread(target=periodic_sync, daemon=True)
    t_periodic.start()
    t_mining = threading.Thread(target=mining_loop, daemon=True)  # Консенсус PoW: майнит любой узел
    t_mining.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
