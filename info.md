PoC: Система Распределенных Вычислений на БлокчейнеВ этом документе описана архитектура и реализация Proof-of-Concept (PoC) для системы распределенных вычислений, использующей собственный блокчейн и смарт-контракты для вознаграждения участников.1. Обзор АрхитектурыСистема состоит из двух основных сервисов, которые будут развернуты в Docker-контейнерах:Оркестратор (Orchestrator Node):Роль: Центральный узел управления (в PoC).Компоненты:Веб-сервер (Flask): Предоставляет API для клиентов.Блокчейн (Python Class): Упрощенная реализация блокчейна.Реестр Смарт-контрактов: Хранит "контракты" на вычисления.Система Вознаграждений: Управляет балансами клиентов и создает транзакции.Задачи:Регистрация ("аутентификация") новых клиентов.Выдача вычислительных задач (смарт-контрактов).Прием и упрощенная верификация результатов.Запись транзакций вознаграждения в блокчейн.Клиент (Client Worker):Роль: Вычислительный узел (воркер).Компоненты:Python-скрипт: Основная логика воркера.Задачи:Авторизация на Оркестраторе (получение client_id).Запрос задачи (смарт-контракта).Выполнение вычислений (имитация работы).Подсчет "работы" (Proof-of-Computation).Отправка результата и получение вознаграждения.Упрощения в этом PoC:Консенсус: Мы не используем сложный консенсус (как PoW или PoS). Оркестратор является единственным "майнером" (Proof-of-Authority).Верификация Работы: Мы доверяем клиенту, что он выполнил работу. В реальной системе это самая сложная часть (требуются ZK-SNARKs, TEE или избыточные вычисления).Сеть: Взаимодействие идет через HTTP API, а не через P2P-протокол.Смарт-контракт: Это не исполняемый код (как в Ethereum), а декларативный JSON, описывающий условия ("работа" -> "вознаграждение").Аутентификация: Упрощена до выдачи уникального ID.2. Структура ПроектаДля развертывания вам понадобится создать следующую структуру папок и файлов:distributed-compute-project/
├── orchestrator_node/
│   ├── blockchain.py
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
├── client_worker/
│   ├── worker.py
│   ├── requirements.txt
│   └── Dockerfile
└── docker-compose.yml
3. Шаг 1: Код Оркестратора и БлокчейнаСоздайте папку orchestrator_node и файлы внутри нее.orchestrator_node/blockchain.py(Реализация простого блокчейна)import hashlib
import time
import json

class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        # Упрощенный майнинг (Proof-of-Work)
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print(f"Block Mined! Hash: {self.hash}")


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []
        self.difficulty = 2 # Просто для демонстрации PoW
        self.balances = {} # Балансы клиентов

    def create_genesis_block(self):
        return Block(0, time.time(), [], "0")

    def get_last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        # Транзакция = {"from": "system", "to": client_id, "amount": 10}
        #           ИЛИ {"type": "work_receipt", "client_id": ..., "work_units": ...}
        self.pending_transactions.append(transaction)
        return self.get_last_block().index + 1

    def mine_pending_transactions(self, mining_reward_address=None):
        if not self.pending_transactions and mining_reward_address is None:
            print("No pending transactions to mine.")
            return None
        
        # В PoC майнером выступает сам оркестратор
        if mining_reward_address:
             self.pending_transactions.append({
                 "from": "network", 
                 "to": mining_reward_address, 
                 "amount": 1 # Награда за майнинг (если бы он был)
            })

        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=list(self.pending_transactions),
            previous_hash=self.get_last_block().hash
        )

        new_block.mine_block(self.difficulty)
        
        print(f"Adding new block {new_block.index} to the chain.")
        self.chain.append(new_block)

        # Обновляем балансы на основе транзакций
        for tx in self.pending_transactions:
            if tx.get("type") == "reward":
                client_id = tx["to"]
                amount = tx["amount"]
                self.balances[client_id] = self.balances.get(client_id, 0) + amount
                print(f"Updated balance for {client_id}: {self.balances[client_id]}")

        self.pending_transactions = []
        return new_block

    def get_balance(self, client_id):
        return self.balances.get(client_id, 0)

    def get_chain_json(self):
        return [block.__dict__ for block in self.chain]

orchestrator_node/app.py(Flask-сервер, API и управление)from flask import Flask, request, jsonify
from blockchain import Blockchain
import uuid
import random

app = Flask(__name__)

# Инициализируем наш блокчейн
blockchain = Blockchain()

# Реестр "Смарт-контрактов"
# Это декларативные контракты, определяющие работу
SMART_CONTRACTS = [
    {
        "contract_id": "sc-001",
        "task_type": "simple-hash-pow",
        "description": "Find a hash starting with 3 zeros.",
        "work_units_required": 1000, # Количество "вычислительных операций"
        "reward": 10 # Вознаграждение в токенах
    },
    {
        "contract_id": "sc-002",
        "task_type": "complex-hash-pow",
        "description": "Find a hash starting with 4 zeros.",
        "work_units_required": 5000,
        "reward": 50
    }
]

# --- API Эндпоинты ---

@app.route("/register", methods=["GET"])
def register_client():
    """
    (Пункт 5) Упрощенная авторизация/регистрация клиента.
    Выдаем ему ID, который будет его "адресом кошелька".
    """
    client_id = str(uuid.uuid4())
    # Инициализируем баланс
    blockchain.balances[client_id] = 0
    print(f"New client registered: {client_id}")
    return jsonify({"client_id": client_id}), 200

@app.route("/get_task", methods=["GET"])
def get_task():
    """
    (Пункт 2) Клиент запрашивает "смарт-контракт" (задачу)
    """
    # Выдаем случайный контракт из реестра
    contract = random.choice(SMART_CONTRACTS)
    print(f"Issuing task {contract['contract_id']} to a client.")
    return jsonify(contract), 200

@app.route("/submit_work", methods=["POST"])
def submit_work():
    """
    (Пункты 6, 7) Клиент отправляет результат своей работы
    """
    data = request.json
    client_id = data.get("client_id")
    contract_id = data.get("contract_id")
    work_units_done = data.get("work_units_done")
    result_data = data.get("result_data") # Результат вычислений

    if not all([client_id, contract_id, work_units_done is not None]):
        return jsonify({"error": "Missing data"}), 400

    # 1. Находим контракт, по которому отчитывается клиент
    contract = next((c for c in SMART_CONTRACTS if c["contract_id"] == contract_id), None)
    
    if not contract:
        return jsonify({"error": "Invalid contract ID"}), 400

    # 2. (УПРОЩЕНИЕ) Верификация работы
    # В реальной системе здесь была бы сложная проверка `result_data`
    # Мы просто доверяем, что клиент выполнил `work_units_done`
    
    print(f"Received work submission from {client_id} for {contract_id}.")
    print(f"Client claims {work_units_done} units of work. Result: {result_data}")

    # 3. Проверяем, достаточно ли работы для вознаграждения
    if work_units_done >= contract["work_units_required"]:
        reward_amount = contract["reward"]
        
        print(f"Work verified. Issuing reward of {reward_amount} to {client_id}.")

        # 4. Создаем транзакцию вознаграждения
        reward_tx = {
            "type": "reward",
            "from": "system_contract",
            "to": client_id,
            "amount": reward_amount,
            "contract_id": contract_id
        }
        
        # 5. Создаем "квитанцию" о работе
        work_receipt_tx = {
            "type": "work_receipt",
            "client_id": client_id,
            "contract_id": contract_id,
            "work_units": work_units_done
        }
        
        blockchain.add_transaction(reward_tx)
        blockchain.add_transaction(work_receipt_tx)

        # 6. "Майним" блок, чтобы транзакции попали в блокчейн
        # В PoC мы делаем это немедленно.
        blockchain.mine_pending_transactions(mining_reward_address="orchestrator_wallet")

        return jsonify({
            "status": "success", 
            "reward_issued": reward_amount
        }), 200
    else:
        return jsonify({
            "status": "pending",
            "message": f"Not enough work done. {work_units_done} / {contract['work_units_required']}"
        }), 200

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


if __name__ == "__main__":
    # 0.0.0.0 нужен для Docker
    app.run(host="0.0.0.0", port=5000, debug=True)

orchestrator_node/requirements.txtFlask
orchestrator_node/DockerfileFROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Порт, на котором слушает Flask
EXPOSE 5000

# Запускаем наш сервер-оркестратор
CMD ["python", "app.py"]
4. Шаг 2: Код Клиента-ВычислителяСоздайте папку client_worker и файлы внутри нее.client_worker/worker.py(Логика клиента, который выполняет вычисления)import requests
import time
import hashlib
import os

# Адрес оркестратора (имя сервиса из docker-compose)
ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator_node:5000")

class ClientWorker:
    def __init__(self):
        self.client_id = None
        self.register()

    def register(self):
        """ (Пункт 5) "Авторизация" на сервере """
        try:
            response = requests.get(f"{ORCHESTRATOR_URL}/register")
            response.raise_for_status()
            data = response.json()
            self.client_id = data["client_id"]
            print(f"Successfully registered. My Client ID: {self.client_id}")
        except Exception as e:
            print(f"Error registering: {e}")
            time.sleep(5)
            self.register() # Повторная попытка

    def fetch_task(self):
        """ Запрос "смарт-контракта" (задачи) """
        try:
            response = requests.get(f"{ORCHESTRATOR_URL}/get_task")
            response.raise_for_status()
            task_data = response.json()
            print(f"Fetched new task: {task_data['description']}")
            return task_data
        except Exception as e:
            print(f"Error fetching task: {e}")
            return None

    def perform_computation(self, task):
        """
        (Пункт 3, 6) Выполнение вычислений и подсчет "работы"
        """
        print(f"Starting computation for {task['contract_id']}...")
        
        work_units_done = 0
        target_work = task["work_units_required"]
        
        # Имитируем вычисления
        # В данном случае, мы "майним" хэши, как в PoW
        # Каждая попытка хэширования = 1 "единица работы"
        
        start_time = time.time()
        
        # Определяем сложность "майнинга" из описания контракта
        difficulty = 0
        if "3 zeros" in task["description"]:
            difficulty = 3
        elif "4 zeros" in task["description"]:
            difficulty = 4
        else:
            difficulty = 2
            
        target_hash_prefix = "0" * difficulty
        
        final_result = None

        while work_units_done < target_work:
            work_units_done += 1
            nonce = str(work_units_done)
            text = f"{self.client_id}-{task['contract_id']}-{nonce}"
            
            # Это и есть "вычислительная работа"
            hash_result = hashlib.sha256(text.encode()).hexdigest()
            
            if hash_result.startswith(target_hash_prefix):
                # Мы нашли "решение" во время выполнения работы
                final_result = hash_result
                print(f"Found a solution hash: {hash_result}")
                # Мы могли бы остановиться, но контракт требует `target_work`
                # Продолжаем работать, чтобы выполнить "объем"
            
            if work_units_done % 500 == 0:
                print(f"Work progress: {work_units_done} / {target_work} units")

        end_time = time.time()
        print(f"Computation finished in {end_time - start_time:.2f}s.")
        
        return work_units_done, final_result or "dummy_result_data"

    def submit_work(self, task, work_done, result_data):
        """ (Пункт 7) Отправка результатов для получения вознаграждения """
        payload = {
            "client_id": self.client_id,
            "contract_id": task["contract_id"],
            "work_units_done": work_done,
            "result_data": result_data
        }
        
        try:
            print("Submitting work...")
            response = requests.post(f"{ORCHESTRATOR_URL}/submit_work", json=payload)
            response.raise_for_status()
            print(f"Submission response: {response.json()}")
        except Exception as e:
            print(f"Error submitting work: {e}")

    def check_balance(self):
        try:
            response = requests.get(f"{ORCHESTRATOR_URL}/get_balance/{self.client_id}")
            response.raise_for_status()
            print(f"Current Balance: {response.json()['balance']}")
        except Exception as e:
            print(f"Error checking balance: {e}")

    def run(self):
        """ Главный цикл работы клиента """
        if not self.client_id:
            print("Client not registered. Exiting.")
            return

        while True:
            task = self.fetch_task()
            if task:
                work_done, result = self.perform_computation(task)
                self.submit_work(task, work_done, result)
                self.check_balance()
            
            print("Waiting for 10s before next task...")
            time.sleep(10)

if __name__ == "__main__":
    # (Пункт 4) Клиент запускается (будет в Docker)
    print("Starting Client Worker...")
    worker = ClientWorker()
    worker.run()

client_worker/requirements.txtrequests
client_worker/DockerfileFROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Запускаем нашего клиента-вычислителя
CMD ["python", "worker.py"]
5. Шаг 3: Развертывание Тестовой Среды (Docker Compose)Создайте файл docker-compose.yml в корневой папке distributed-compute-project/.docker-compose.ymlversion: '3.8'

services:
  
  # 1. Оркестратор / Узел Блокчейна
  orchestrator_node:
    build:
      context: ./orchestrator_node
    ports:
      - "5000:5000" # Пробрасываем порт API наружу
    container_name: orchestrator_node
    # restart: unless-stopped # можно включить для стабильности

  # 2. Клиент-Вычислитель 1
  client_worker_1:
    build:
      context: ./client_worker
    container_name: client_worker_1
    environment:
      # Клиент находит оркестратор по имени сервиса
      - ORCHESTRATOR_URL=http://orchestrator_node:5000
    depends_on:
      - orchestrator_node # Ждем, пока запустится оркестратор
    # restart: unless-stopped

  # 3. Клиент-Вычислитель 2 (для имитации распределенности)
  client_worker_2:
    build:
      context: ./client_worker
    container_name: client_worker_2
    environment:
      - ORCHESTRATOR_URL=http://orchestrator_node:5000
    depends_on:
      - orchestrator_node
    # restart: unless-stopped

  # 4. Клиент-Вычислитель 3
  client_worker_3:
    build:
      context: ./client_worker
    container_name: client_worker_3
    environment:
      - ORCHESTRATOR_URL=http://orchestrator_node:5000
    depends_on:
      - orchestrator_node
    # restart: unless-stopped

6. Шаг 4: Запуск и Проверка СистемыУбедитесь, что у вас установлен Docker и Docker Compose.Откройте терминал в корневой папке distributed-compute-project/.Выполните команду для сборки и запуска всех контейнеров:docker-compose up --build
Наблюдайте за логами. Вы увидите логи от всех 4-х контейнеров (orchestrator_node, client_worker_1, client_worker_2, client_worker_3).Логи Оркестратора будут показывать:New client registered: ...Issuing task sc-001...Received work submission from ...Work verified. Issuing reward of 10...Block Mined! Hash: 00...Updated balance for ...Логи Клиентов будут показывать:Successfully registered. My Client ID: ...Fetched new task: Simple-hash-pow...Starting computation...Work progress: 500 / 1000 unitsComputation finished...Submitting work...Submission response: {'status': 'success', 'reward_issued': 10}Current Balance: 10 (или 20, 30 и т.д. по мере выполнения)Проверка через браузер или curl:Пока система работает, вы можете взаимодействовать с API оркестратора:Посмотреть весь блокчейн:Откройте в браузере http://localhost:5000/chainВы увидите JSON со всеми блоками и транзакциями (вознаграждения и квитанции о работе).Проверить баланс клиента (возьмите ID из логов):# Замените <CLIENT_ID> на ID из логов
curl http://localhost:5000/get_balance/<CLIENT_ID> 
Остановка системы:Нажмите Ctrl+C в терминале, где запущен docker-compose.