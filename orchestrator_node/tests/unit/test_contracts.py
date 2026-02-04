# Unit-тесты контрактов: верификация и спецификация задачи
import hashlib
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from contracts import CONTRACTS, SimpleHashPoW, ComplexHashPoW


class TestSimpleHashPoW:
    def test_get_task_spec(self):
        c = SimpleHashPoW()
        spec = c.get_task_spec()
        assert spec["contract_id"] == "sc-001"
        assert spec["work_units_required"] == 1000
        assert spec["difficulty"] == 3

    def test_verify_success(self):
        c = SimpleHashPoW()
        client_id = "test-client"
        contract_id = "sc-001"
        # Найдём валидный nonce для префикса "000"
        for nonce in range(1, 5000):
            text = f"{client_id}-{contract_id}-{nonce}"
            h = hashlib.sha256(text.encode()).hexdigest()
            if h.startswith("000"):
                assert c.verify(client_id, contract_id, 1000, h, str(nonce)) is True
                assert c.get_reward() == 10
                return
        pytest.fail("No valid nonce found in range")

    def test_verify_fail_wrong_contract(self):
        c = SimpleHashPoW()
        assert c.verify("cid", "sc-002", 1000, "000abc", "1") is False

    def test_verify_fail_insufficient_work(self):
        c = SimpleHashPoW()
        assert c.verify("cid", "sc-001", 999, "000abc", "1") is False

    def test_verify_fail_no_nonce(self):
        c = SimpleHashPoW()
        assert c.verify("cid", "sc-001", 1000, "000abc", None) is False
        assert c.verify("cid", "sc-001", 1000, "000abc", "") is False

    def test_verify_fail_hash_mismatch(self):
        c = SimpleHashPoW()
        # result_data не совпадает с hash(client_id-contract_id-nonce)
        assert c.verify("cid", "sc-001", 1000, "0000000000000000", "1") is False


class TestComplexHashPoW:
    def test_get_task_spec(self):
        c = ComplexHashPoW()
        spec = c.get_task_spec()
        assert spec["contract_id"] == "sc-002"
        assert spec["work_units_required"] == 5000
        assert spec["difficulty"] == 4

    def test_get_reward(self):
        assert ComplexHashPoW().get_reward() == 50


class TestCONTRACTS:
    def test_registry(self):
        assert "sc-001" in CONTRACTS
        assert "sc-002" in CONTRACTS
        assert CONTRACTS["sc-001"].work_units_required == 1000
        assert CONTRACTS["sc-002"].work_units_required == 5000
