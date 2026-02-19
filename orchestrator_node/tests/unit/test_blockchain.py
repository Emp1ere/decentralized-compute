# Unit-тесты блокчейна: приём блока, замена цепочки, used proofs, валидация транзакций
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from blockchain import (
    Blockchain,
    Block,
    FEE_PER_WORK_RECEIPT,
    MAX_PENDING_TOTAL,
    MAX_PENDING_WORK_PER_CLIENT,
)


class TestBlockchain:
    def test_genesis(self):
        bc = Blockchain()
        assert len(bc.chain) == 1
        assert bc.chain[0].index == 0
        assert bc.chain[0].previous_hash == "0"

    def test_add_transaction_and_mine(self):
        bc = Blockchain()
        bc.add_transaction({"type": "reward", "from": "sys", "to": "client1", "amount": 10})
        block = bc.mine_pending_transactions(mining_reward_address=None)
        assert block is not None
        assert len(bc.chain) == 2
        assert bc.get_balance("client1") == 10

    def test_add_block_from_peer_idempotent(self):
        bc = Blockchain()
        last = bc.get_last_block()
        block_dict = {
            "index": 0,
            "timestamp": 0,
            "transactions": [],
            "previous_hash": "0",
            "nonce": 0,
            "hash": last.hash,
        }
        ok, err = bc.add_block_from_peer(block_dict)
        assert ok is True
        assert err is None
        assert len(bc.chain) == 1  # не добавили дубликат

    def test_add_block_from_peer_wrong_index(self):
        bc = Blockchain()
        block_dict = {
            "index": 5,
            "timestamp": 1,
            "transactions": [],
            "previous_hash": bc.get_last_block().hash,
            "nonce": 0,
            "hash": "x",
        }
        ok, err = bc.add_block_from_peer(block_dict)
        assert ok is False
        assert "index" in err.lower()

    def test_get_used_proof_ids_empty(self):
        bc = Blockchain()
        assert bc.get_used_proof_ids() == set()

    def test_get_used_proof_ids_after_work_receipt(self):
        bc = Blockchain()
        bc.add_transaction({
            "type": "work_receipt",
            "client_id": "c1",
            "contract_id": "sc-001",
            "work_units": 1000,
            "attempt_id": 1,
            "artifact_manifest_hash": "a" * 64,
            "result_data": "proof_hash_123",
        })
        bc.mine_pending_transactions(None)
        used = bc.get_used_proof_ids()
        assert "proof_hash_123" in used

    def test_replace_chain_from_peer_longer(self):
        bc = Blockchain()
        bc.add_transaction({"type": "reward", "from": "s", "to": "c1", "amount": 5})
        bc.mine_pending_transactions(None)
        chain_json = [b.__dict__ for b in bc.chain]
        # Ещё один блок в цепочке пира (удлинённая копия)
        last = bc.get_last_block()
        new_block = Block(
            len(bc.chain),
            1,
            [{"type": "reward", "from": "s", "to": "c2", "amount": 3}],
            last.hash,
        )
        chain_json.append(new_block.__dict__)
        bc2 = Blockchain()
        ok, err = bc2.replace_chain_from_peer(chain_json)
        assert ok is True
        assert len(bc2.chain) == 3
        assert bc2.get_balance("c1") == 5
        assert bc2.get_balance("c2") == 3

    def test_add_transaction_rejects_invalid_type(self):
        bc = Blockchain()
        with pytest.raises(ValueError, match="type"):
            bc.add_transaction({"type": "unknown"})
        with pytest.raises(ValueError):
            bc.add_transaction({})

    def test_add_transaction_rejects_invalid_reward(self):
        bc = Blockchain()
        with pytest.raises(ValueError, match="reward"):
            bc.add_transaction({"type": "reward", "to": "c1"})  # no amount
        with pytest.raises(ValueError):
            bc.add_transaction({"type": "reward", "to": "c1", "amount": -1})
        with pytest.raises(ValueError):
            bc.add_transaction({"type": "reward", "to": "", "amount": 10})

    def test_add_transaction_rejects_invalid_work_receipt(self):
        bc = Blockchain()
        with pytest.raises(ValueError, match="work_receipt"):
            bc.add_transaction({"type": "work_receipt", "client_id": "c1"})  # no contract_id, work_units
        with pytest.raises(ValueError):
            bc.add_transaction({"type": "work_receipt", "client_id": "c1", "contract_id": "sc-001", "work_units": -1})

    def test_add_block_from_peer_rejects_invalid_reward_tx(self):
        bc = Blockchain()
        last = bc.get_last_block()
        invalid_block = Block(
            1,
            1,
            [{"type": "reward", "to": "c1"}],  # no amount - invalid
            last.hash,
        )
        ok, err = bc.add_block_from_peer(invalid_block.__dict__)
        assert ok is False
        assert "invalid reward" in err.lower()
        assert len(bc.chain) == 1

    def test_replace_chain_rejects_invalid_reward_tx(self):
        bc = Blockchain()
        chain_json = [bc.chain[0].__dict__]
        bad_block = Block(1, 1, [{"type": "reward", "amount": 10}], bc.get_last_block().hash)  # no "to"
        chain_json.append(bad_block.__dict__)
        bc2 = Blockchain()
        ok, err = bc2.replace_chain_from_peer(chain_json)
        assert ok is False
        assert "invalid reward" in err.lower()

    def test_mine_pending_skips_invalid_reward_tx(self):
        bc = Blockchain()
        bc.pending_transactions = [
            {"type": "reward", "from": "s", "to": "c1", "amount": 10},
            {"type": "reward", "to": "c2", "amount": -5},  # invalid, skipped
        ]
        block = bc.mine_pending_transactions(None)
        assert block is not None
        assert bc.get_balance("c1") == 10
        assert bc.get_balance("c2") == 0  # invalid tx not applied

    def test_fee_deducted_from_balance(self):
        bc = Blockchain()
        bc.add_transaction({"type": "reward", "from": "s", "to": "c1", "amount": 10})
        bc.add_transaction({
            "type": "work_receipt",
            "client_id": "c1",
            "contract_id": "sc-001",
            "work_units": 1000,
            "attempt_id": 1,
            "artifact_manifest_hash": "b" * 64,
            "result_data": "x",
            "fee": 1,
        })
        bc.mine_pending_transactions(None)
        assert bc.get_balance("c1") == 9  # 10 - 1 fee

    def test_spam_limit_one_work_receipt_per_client_in_pending(self):
        bc = Blockchain()
        bc.add_transaction({
            "type": "work_receipt",
            "client_id": "c1",
            "contract_id": "sc-001",
            "work_units": 1000,
            "attempt_id": 1,
            "artifact_manifest_hash": "c" * 64,
            "result_data": "a",
        })
        with pytest.raises(ValueError, match="already has"):
            bc.add_transaction({
                "type": "work_receipt",
                "client_id": "c1",
                "contract_id": "sc-001",
                "work_units": 1000,
                "attempt_id": 2,
                "artifact_manifest_hash": "d" * 64,
                "result_data": "b",
            })
