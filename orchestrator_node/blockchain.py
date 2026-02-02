# Консенсус: Proof-of-Work (PoW). Блок принимается только если его хеш удовлетворяет сложности (leading zeros).
# Любой узел может майнить; первый найденный валидный блок распространяется и принимается сетью.
import hashlib
import time
import json


class Block:
    def __init__(self, index, timestamp, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()  # Хеш блока для проверки целостности и PoW

    def calculate_hash(self):
        # Каноническая сериализация блока для детерминированного хеша
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        # Proof-of-Work: подбор nonce до тех пор, пока хеш не начнётся с difficulty нулей
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []  # Очередь транзакций, общая для всех узлов (распространяется по сети)
        self.difficulty = 2  # Сложность PoW: число ведущих нулей в хеше блока
        self.balances = {}

    def create_genesis_block(self):
        # Одинаковый genesis у всех узлов — основа консенсуса
        return Block(0, 0, [], "0")

    def get_last_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        # Добавление транзакции в очередь; майнить будет любой узел (PoW), не один «авторитет»
        self.pending_transactions.append(transaction)
        return self.get_last_block().index + 1

    def mine_pending_transactions(self, mining_reward_address=None):
        # Майнинг по консенсусу PoW: любой узел вызывает этот метод при наличии pending tx
        if not self.pending_transactions and mining_reward_address is None:
            return None
        # Опциональная награда за блок (при PoA была; при чистом PoW можно не добавлять)
        if mining_reward_address:
            self.pending_transactions.append({
                "from": "network",
                "to": mining_reward_address,
                "amount": 1
            })
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=list(self.pending_transactions),
            previous_hash=self.get_last_block().hash
        )
        new_block.mine_block(self.difficulty)  # PoW: подбор nonce до валидного хеша
        self.chain.append(new_block)
        for tx in self.pending_transactions:
            if tx.get("type") == "reward":
                client_id = tx["to"]
                amount = tx["amount"]
                self.balances[client_id] = self.balances.get(client_id, 0) + amount
        self.pending_transactions = []
        return new_block

    def add_block_from_peer(self, block_dict):
        """
        Принять блок от другого узла (консенсус PoW: первый валидный блок принимается).
        Проверяет индекс, previous_hash, хеш и PoW; обновляет балансы; очищает pending.
        """
        last = self.get_last_block()
        if block_dict["index"] != len(self.chain):
            return False, "wrong index"
        if block_dict["previous_hash"] != last.hash:
            return False, "previous_hash mismatch"
        block = Block(
            block_dict["index"],
            block_dict["timestamp"],
            block_dict["transactions"],
            block_dict["previous_hash"],
            block_dict.get("nonce", 0),
        )
        if block.hash != block_dict.get("hash"):
            return False, "hash mismatch"
        if block.hash[: self.difficulty] != "0" * self.difficulty:
            return False, "PoW invalid"  # Хеш блока должен удовлетворять сложности PoW
        self.chain.append(block)
        for tx in block.transactions:
            if tx.get("type") == "reward":
                client_id = tx["to"]
                amount = tx["amount"]
                self.balances[client_id] = self.balances.get(client_id, 0) + amount
        self.pending_transactions = []  # Консенсус: пир выиграл раунд — не майним те же tx повторно
        return True, None

    def get_balance(self, client_id):
        return self.balances.get(client_id, 0)

    def get_chain_json(self):
        return [block.__dict__ for block in self.chain]

    def replace_chain_from_peer(self, chain_list):
        """
        Заменить локальную цепочку на цепочку от пира, если она длиннее и валидна.
        Правило «longest valid chain» — основа разрешения конфликтов в децентрализованной сети.
        """
        # Пустой или не список — отказ
        if not chain_list or not isinstance(chain_list, list):
            return False, "empty or invalid chain list"
        # Genesis должен быть один: index=0, previous_hash="0"
        g = chain_list[0]
        if g.get("index") != 0 or g.get("previous_hash") != "0":
            return False, "invalid genesis"
        new_chain = []
        prev_hash = "0"
        for i, d in enumerate(chain_list):
            # Каждый блок должен следовать за предыдущим по индексу и previous_hash
            if d.get("index") != i or d.get("previous_hash") != prev_hash:
                return False, f"index or previous_hash mismatch at block {i}"
            # Восстанавливаем объект Block из словаря пира
            block = Block(
                d["index"],
                d["timestamp"],
                d["transactions"],
                d["previous_hash"],
                d.get("nonce", 0),
            )
            # Хеш блока должен совпадать с переданным (целостность)
            if block.hash != d.get("hash"):
                return False, f"hash mismatch at block {i}"
            # Proof-of-Work: хеш должен начинаться с difficulty нулей
            if block.hash[: self.difficulty] != "0" * self.difficulty:
                return False, f"PoW invalid at block {i}"
            new_chain.append(block)
            prev_hash = block.hash
        # Принимаем только если цепочка пира длиннее — правило «longest chain»
        if len(new_chain) <= len(self.chain):
            return False, "peer chain not longer"
        self.chain = new_chain  # Подменяем локальную цепочку на цепочку пира
        self.pending_transactions = []  # Очищаем pending, чтобы не дублировать транзакции
        self.balances = {}  # Пересчитываем балансы с нуля по принятой цепочке
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("type") == "reward":  # Учитываем только награды клиентам
                    client_id = tx["to"]
                    amount = tx["amount"]
                    self.balances[client_id] = self.balances.get(client_id, 0) + amount
        return True, None  # Успешная замена цепочки