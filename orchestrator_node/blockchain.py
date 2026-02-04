# Консенсус: Proof-of-Useful-Work (PoUW)
# Блок создаётся при верифицированной полезной работе (контракт verify + reward/work_receipt в блоке).
# Хеш блока используется только для целостности, без перебора nonce (difficulty=0).
#
# Экономическая модель: токены создаются наградой за верифицированную работу; комиссия за квитанцию
# сжигается (уменьшает эффективное предложение). Защита от спама: лимит pending по клиенту и общий.
import hashlib
import time
import json
import logging
import os

logger = logging.getLogger("blockchain")

# --- Экономическая модель и защита от спама ---
# Комиссия за квитанцию о работе (списывается с клиента в блоке, «сжигается»)
FEE_PER_WORK_RECEIPT = int(os.environ.get("FEE_PER_WORK_RECEIPT", "1"))
# Максимум транзакций в очереди pending (защита от спама)
MAX_PENDING_TOTAL = int(os.environ.get("MAX_PENDING_TOTAL", "500"))
# У одного клиента в pending не более N квитанций (защита от спама с одного аккаунта)
MAX_PENDING_WORK_PER_CLIENT = int(os.environ.get("MAX_PENDING_WORK_PER_CLIENT", "1"))


def _is_valid_reward_tx(tx):
    """
    Проверка структуры транзакции вознаграждения: type, to (непустая строка), amount (число >= 0).
    Защита от некорректных данных и отрицательных сумм.
    """
    if not isinstance(tx, dict):
        return False
    if tx.get("type") != "reward":
        return False
    to_addr = tx.get("to")
    if not isinstance(to_addr, str) or not to_addr.strip():
        return False
    amount = tx.get("amount")
    if not isinstance(amount, (int, float)) or amount < 0:
        return False
    return True


def _is_valid_work_receipt_tx(tx):
    """Проверка структуры квитанции о работе: type, client_id, contract_id, work_units; fee опционально (число >= 0)."""
    if not isinstance(tx, dict):
        return False
    if tx.get("type") != "work_receipt":
        return False
    if not isinstance(tx.get("client_id"), str) or not tx.get("client_id"):
        return False
    if not isinstance(tx.get("contract_id"), str) or not tx.get("contract_id"):
        return False
    wu = tx.get("work_units")
    if wu is None or (not isinstance(wu, (int, float))) or wu < 0:
        return False
    fee = tx.get("fee", 0)
    if fee is not None and (not isinstance(fee, (int, float)) or fee < 0):
        return False
    return True


def _apply_block_transactions(transactions, balances):
    """
    Применить транзакции блока к словарю балансов (экономическая модель).
    Сначала начисляются reward, затем списывается комиссия за work_receipt (fee сжигается).
    """
    for tx in transactions:
        if _is_valid_reward_tx(tx):
            to_addr = tx["to"]
            amount = int(tx["amount"]) if isinstance(tx["amount"], float) else tx["amount"]
            balances[to_addr] = balances.get(to_addr, 0) + amount
    for tx in transactions:
        if tx.get("type") == "work_receipt":
            fee = tx.get("fee") or 0
            if isinstance(fee, (int, float)) and fee > 0:
                cid = tx.get("client_id")
                if cid:
                    balances[cid] = max(0, balances.get(cid, 0) - int(fee))


class Block:
    """Блок в блокчейне: индекс, время, транзакции, хеш предыдущего блока, nonce, хеш блока."""
    def __init__(self, index, timestamp, transactions, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()  # Хеш для целостности (PoUW: без перебора nonce)

    def calculate_hash(self):
        """Вычисление хеша блока из всех полей."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        """Метод оставлен для совместимости; при PoUW не вызывается (difficulty=0)."""
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        logger.debug("Block completed: hash=%s", self.hash[:16] + "...")


class Blockchain:
    """Блокчейн с консенсусом Proof-of-Useful-Work (PoUW)."""
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions = []  # Очередь транзакций для упаковки в блок
        self.difficulty = 0  # PoUW: не используется для валидации (блок создаётся при полезной работе)
        self.balances = {}  # Балансы клиентов (пересчитываются из транзакций reward)

    def create_genesis_block(self):
        """Создание genesis-блока с фиксированным временем (чтобы у всех узлов был одинаковый genesis)."""
        return Block(0, 0, [], "0")  # Фиксированное время 0 для одинакового genesis на всех узлах

    def get_last_block(self):
        """Получить последний блок в цепочке."""
        return self.chain[-1]

    def add_transaction(self, transaction):
        """
        Добавить транзакцию в очередь pending (будет упакована в блок при submit_work).
        Проверяет структуру и лимиты от спама: не более MAX_PENDING_TOTAL транзакций,
        у одного client_id не более MAX_PENDING_WORK_PER_CLIENT квитанций в pending.
        """
        if not isinstance(transaction, dict) or transaction.get("type") not in ("reward", "work_receipt"):
            raise ValueError("Invalid transaction: must be dict with type 'reward' or 'work_receipt'")
        if transaction.get("type") == "reward" and not _is_valid_reward_tx(transaction):
            raise ValueError("Invalid reward transaction: need 'to' (non-empty str) and 'amount' (number >= 0)")
        if transaction.get("type") == "work_receipt" and not _is_valid_work_receipt_tx(transaction):
            raise ValueError("Invalid work_receipt: need client_id, contract_id, work_units (number >= 0)")

        # Защита от спама: общий лимит pending
        if len(self.pending_transactions) >= MAX_PENDING_TOTAL:
            raise ValueError(f"Pending queue full (max {MAX_PENDING_TOTAL})")

        # Защита от спама: у одного клиента не более N квитанций в pending
        if transaction.get("type") == "work_receipt":
            cid = transaction.get("client_id")
            n = sum(1 for t in self.pending_transactions if t.get("type") == "work_receipt" and t.get("client_id") == cid)
            if n >= MAX_PENDING_WORK_PER_CLIENT:
                raise ValueError(f"Client {cid[:8]}... already has {MAX_PENDING_WORK_PER_CLIENT} work_receipt(s) in pending")

        self.pending_transactions.append(transaction)
        return self.get_last_block().index + 1

    def mine_pending_transactions(self, mining_reward_address=None):
        """
        PoUW: упаковка pending транзакций в блок (без перебора nonce).
        Блок создаётся при верифицированной полезной работе (submit_work).
        """
        if not self.pending_transactions and mining_reward_address is None:
            logger.debug("No pending transactions to mine")
            return None
        
        # Опциональная награда за блок (если передана)
        if mining_reward_address:
             self.pending_transactions.append({
                 "from": "network", 
                 "to": mining_reward_address, 
                 "amount": 1
            })

        # Создаём блок с текущими pending транзакциями
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=list(self.pending_transactions),
            previous_hash=self.get_last_block().hash
        )
        # PoUW: не вызываем mine_block (difficulty=0, хеш уже вычислен в __init__)

        logger.info("Adding block index=%s to chain", new_block.index)
        self.chain.append(new_block)

        # Экономическая модель: начисление reward и списание комиссии за work_receipt
        for tx in self.pending_transactions:
            if tx.get("type") == "reward" and not _is_valid_reward_tx(tx):
                logger.warning("Skipping invalid reward tx in mine_pending: %s", tx)
        _apply_block_transactions(self.pending_transactions, self.balances)

        self.pending_transactions = []
        return new_block

    def add_block_from_peer(self, block_dict):
        """
        Принять блок от другого узла (децентрализованная синхронизация).
        Проверяет целостность (индекс, previous_hash, хеш) и обновляет балансы.
        Идемпотентность: если блок уже есть в цепочке — возвращаем True (для распространения в 3+ узлах).
        """
        # Уже есть столько же или больше блоков — идемпотентный приём (горизонтальное масштабирование)
        if block_dict["index"] < len(self.chain):
            return True, None
        last = self.get_last_block()
        # Тот же блок уже на конце цепочки (например, мы его создали или получили по другому пути)
        if block_dict["index"] == len(self.chain) and last.hash == block_dict.get("hash"):
            return True, None
        # Проверка индекса: блок должен быть следующим в цепочке
        if block_dict["index"] != len(self.chain):
            return False, "wrong index"
        # Проверка previous_hash: блок должен ссылаться на последний блок
        if block_dict["previous_hash"] != last.hash:
            return False, "previous_hash mismatch"
        # Создаём объект Block из данных пира
        block = Block(
            block_dict["index"],
            block_dict["timestamp"],
            block_dict["transactions"],
            block_dict["previous_hash"],
            block_dict.get("nonce", 0),
        )
        # Проверка хеша: пересчитанный хеш должен совпадать с полученным
        if block.hash != block_dict.get("hash"):
            return False, "hash mismatch"
        # PoUW: проверка PoW (leading zeros) убрана — проверяем только целостность
        # Проверка транзакций в блоке: все reward должны быть валидными (защита от подделки пира)
        for tx in block.transactions:
            if tx.get("type") == "reward" and not _is_valid_reward_tx(tx):
                return False, "invalid reward transaction in block"
        self.chain.append(block)
        _apply_block_transactions(block.transactions, self.balances)
        logger.info("Sync added block index=%s from peer", block.index)
        return True, None

    def replace_chain_from_peer(self, chain_list):
        """
        Заменить локальную цепочку на цепочку пира, если она валидна и длиннее (longest valid chain).
        Проверяет все блоки, пересчитывает балансы из транзакций.
        PoUW: проверка PoW для каждого блока убрана — проверяем только целостность.
        """
        if not chain_list:
            return False, "empty chain"
        # Проверка genesis: первый блок должен быть валидным
        genesis = chain_list[0]
        if genesis.get("index") != 0 or genesis.get("previous_hash") != "0":
            return False, "invalid genesis"
        # Проверка всех блоков: индекс, previous_hash, хеш
        new_chain = []
        for i, block_dict in enumerate(chain_list):
            if block_dict.get("index") != i:
                return False, f"wrong index at block {i}"
            if i > 0:
                prev_hash = new_chain[-1].hash
                if block_dict.get("previous_hash") != prev_hash:
                    return False, f"previous_hash mismatch at block {i}"
            block = Block(
                block_dict["index"],
                block_dict["timestamp"],
                block_dict["transactions"],
                block_dict["previous_hash"],
                block_dict.get("nonce", 0),
            )
            if block.hash != block_dict.get("hash"):
                return False, f"hash mismatch at block {i}"
            # PoUW: проверка PoW (leading zeros) убрана — проверяем только целостность
            new_chain.append(block)
        # Если цепочка пира короче или равна нашей, не заменяем
        if len(new_chain) <= len(self.chain):
            return False, "chain not longer"
        # Проверка: все reward-транзакции в цепочке должны быть валидными
        for bi, block in enumerate(new_chain):
            for tx in block.transactions:
                if tx.get("type") == "reward" and not _is_valid_reward_tx(tx):
                    return False, f"invalid reward transaction in block {bi}"
        self.chain = new_chain
        self.pending_transactions = []
        self.balances = {}
        for block in self.chain:
            _apply_block_transactions(block.transactions, self.balances)
        logger.info("Sync replaced chain: %s blocks", len(self.chain))
        return True, None

    def get_balance(self, client_id):
        """Получить баланс клиента (из пересчитанных балансов)."""
        return self.balances.get(client_id, 0)

    def get_used_proof_ids(self):
        """
        Защита от мошенничества (replay): возвращает множество уже использованных
        доказательств работы (result_data) — по цепочке и по текущим pending.
        Один и тот же результат нельзя сдать дважды для получения двойного вознаграждения.
        """
        used = set()
        for block in self.chain:
            for tx in block.transactions:
                if tx.get("type") == "work_receipt" and tx.get("result_data"):
                    used.add(tx["result_data"])
        for tx in self.pending_transactions:
            if tx.get("type") == "work_receipt" and tx.get("result_data"):
                used.add(tx["result_data"])
        return used

    def get_chain_json(self):
        """Получить всю цепочку в формате JSON (для синхронизации и просмотра)."""
        return [block.__dict__ for block in self.chain]
