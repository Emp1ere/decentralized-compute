# Интеграционные тесты API оркестратора (Flask test client)
import hashlib
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from app import app, blockchain


@pytest.fixture
def client():
    app.config["TESTING"] = True
    try:
        app.config["RATELIMIT_ENABLED"] = False  # Отключаем лимитер в тестах
    except Exception:
        pass
    with app.test_client() as c:
        yield c


@pytest.fixture
def auth_headers(client):
    """Регистрация и заголовки с api_key."""
    r = client.get("/register")
    assert r.status_code == 200
    data = r.get_json()
    api_key = data["api_key"]
    client_id = data["client_id"]
    return {"Authorization": f"Bearer {api_key}"}, client_id


def _solve_pow(client_id, contract_id, difficulty, max_iter=1_500_000):
    """Найти nonce и хеш для simple_pow-контракта."""
    for n in range(1, max_iter):
        text = f"{client_id}-{contract_id}-{n}"
        h = hashlib.sha256(text.encode()).hexdigest()
        if h.startswith("0" * difficulty):
            return h, str(n)
    return None, None


def test_register(client):
    r = client.get("/register")
    assert r.status_code == 200
    data = r.get_json()
    assert "client_id" in data
    assert "api_key" in data
    assert len(data["api_key"]) > 10


def test_get_task_requires_auth(client):
    r = client.get("/get_task")
    assert r.status_code == 401


def test_get_task_success(client, auth_headers):
    headers, _ = auth_headers
    contracts_res = client.get("/contracts")
    assert contracts_res.status_code == 200
    available_ids = {c["contract_id"] for c in contracts_res.get_json()}
    assert available_ids
    r = client.get("/get_task", headers=headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "contract_id" in data
    assert "work_units_required" in data
    assert "difficulty" in data
    assert data["contract_id"] in available_ids


def test_get_task_by_contract_id(client, auth_headers):
    headers, _ = auth_headers
    contracts_res = client.get("/contracts")
    assert contracts_res.status_code == 200
    contracts_list = contracts_res.get_json()
    assert contracts_list
    picked_contract_id = contracts_list[0]["contract_id"]

    r = client.get("/get_task", headers=headers, query_string={"contract_id": picked_contract_id})
    assert r.status_code == 200
    data = r.get_json()
    assert data["contract_id"] == picked_contract_id
    r2 = client.get("/get_task", headers=headers, query_string={"contract_id": "unknown"})
    assert r2.status_code == 400


def test_submit_work_requires_auth(client):
    r = client.post("/submit_work", json={"client_id": "x", "contract_id": "sc-001", "work_units_done": 1000})
    assert r.status_code == 401


def test_submit_work_success(client, auth_headers):
    """Проверяем сдачу работы для любого доступного simple_pow контракта."""
    headers, client_id = auth_headers
    contracts_res = client.get("/contracts")
    assert contracts_res.status_code == 200
    contracts_list = contracts_res.get_json()
    # Берём задачу среди доступных simple_pow, чтобы тест был быстрым
    simple_pow_ids = [c["contract_id"] for c in contracts_list if c.get("computation_type") == "simple_pow"]
    assert simple_pow_ids, "Need at least one simple_pow contract"
    contract_id = random.choice(simple_pow_ids)
    r = client.get("/get_task", headers=headers, query_string={"contract_id": contract_id})
    assert r.status_code == 200
    task = r.get_json()
    assert task["contract_id"] == contract_id
    difficulty = task["difficulty"]
    target_work = task["work_units_required"]
    # Находим валидный nonce (с большим запасом, чтобы тест не флапал)
    result_data, solution_nonce = _solve_pow(client_id, contract_id, difficulty)
    assert result_data is not None, f"Valid hash not found for {contract_id} (difficulty {difficulty})"
    r = client.post(
        "/submit_work",
        headers=headers,
        json={
            "client_id": client_id,
            "contract_id": contract_id,
            "work_units_done": target_work,
            "result_data": result_data,
            "nonce": solution_nonce,
        },
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("status") == "success"
    assert "reward_issued" in data


def test_get_balance_requires_auth(client):
    r = client.get("/get_balance/some-id")
    assert r.status_code == 401


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    data = r.get_json()
    assert "chain_length" in data
    assert "clients_count" in data
    assert "pending_transactions" in data


def test_chain(client):
    r = client.get("/chain")
    assert r.status_code == 200
    chain = r.get_json()
    assert isinstance(chain, list)
    assert len(chain) >= 1
    assert chain[0]["index"] == 0


def test_contracts_with_stats(client):
    r = client.get("/contracts")
    assert r.status_code == 200
    list_ = r.get_json()
    assert isinstance(list_, list)
    assert len(list_) >= 1
    c = list_[0]
    assert "contract_id" in c
    assert "total_work_done" in c
    assert "jobs_count" in c
    assert "completion_pct" in c
    assert "active_workers" in c
    assert "free_volume" in c
    assert "reward_per_task" in c


def test_provider_contract_flow(client, auth_headers):
    headers, client_id = auth_headers
    # 1) Поставщик создаёт и сразу активирует пользовательский контракт
    create_res = client.post(
        "/provider/contracts",
        headers=headers,
        json={
            "task_name": "Provider PoW demo",
            "task_description": "User-defined contract for integration test",
            "task_category": "Пользовательская",
            "computation_type": "simple_pow",
            "work_units_required": 200,
            "reward_per_task": 3,
            "target_total_work_units": 400,
            "difficulty": 2,
            "initial_budget_tokens": 6,
            "activate_now": True,
        },
    )
    assert create_res.status_code == 201
    contract = create_res.get_json()
    assert contract["status"] == "active"
    contract_id = contract["contract_id"]

    # 2) Контракт должен появиться в публичном списке /contracts
    contracts_res = client.get("/contracts")
    assert contracts_res.status_code == 200
    public_ids = {c["contract_id"] for c in contracts_res.get_json()}
    assert contract_id in public_ids

    # 3) Исполнитель берёт задачу по этому контракту и сдаёт работу (первый раз)
    task_res = client.get("/get_task", headers=headers, query_string={"contract_id": contract_id})
    assert task_res.status_code == 200
    task = task_res.get_json()
    result_hash, nonce = _solve_pow(client_id, contract_id, task["difficulty"])
    assert result_hash is not None
    submit_res = client.post(
        "/submit_work",
        headers=headers,
        json={
            "client_id": client_id,
            "contract_id": contract_id,
            "work_units_done": task["work_units_required"],
            "result_data": result_hash,
            "nonce": nonce,
        },
    )
    assert submit_res.status_code == 200
    assert submit_res.get_json().get("reward_issued") == 3

    # 4) Вторая сдача от другого исполнителя закрывает контракт (и бюджет, и target объём)
    second_reg = client.get("/register")
    assert second_reg.status_code == 200
    second_data = second_reg.get_json()
    second_client_id = second_data["client_id"]
    second_headers = {"Authorization": f"Bearer {second_data['api_key']}"}

    task_res_2 = client.get("/get_task", headers=second_headers, query_string={"contract_id": contract_id})
    assert task_res_2.status_code == 200
    task_2 = task_res_2.get_json()
    result_hash_2, nonce_2 = _solve_pow(second_client_id, contract_id, task_2["difficulty"])
    assert result_hash_2 is not None
    submit_res_2 = client.post(
        "/submit_work",
        headers=second_headers,
        json={
            "client_id": second_client_id,
            "contract_id": contract_id,
            "work_units_done": task_2["work_units_required"],
            "result_data": result_hash_2,
            "nonce": nonce_2,
        },
    )
    assert submit_res_2.status_code == 200

    contract_res = client.get(f"/provider/contracts/{contract_id}", headers=headers)
    assert contract_res.status_code == 200
    updated = contract_res.get_json()
    assert updated["status"] == "closed"
    assert updated["budget_tokens_available"] == 0
