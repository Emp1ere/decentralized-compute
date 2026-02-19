# Интеграционные тесты API оркестратора (Flask test client)
import hashlib
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
from app import app, blockchain
from fx_oracles import current_epoch_id, get_oracle_registry, sign_submission


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


def _register_worker(client):
    reg = client.get("/register")
    assert reg.status_code == 200
    payload = reg.get_json()
    return {"Authorization": f"Bearer {payload['api_key']}"}, payload["client_id"]


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
    assert "job_id" in data
    assert data["job_id"].startswith("job-")
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
    assert "job_id" in task
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
            "job_id": task["job_id"],
            "work_units_done": target_work,
            "result_data": result_data,
            "nonce": solution_nonce,
        },
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data.get("status") == "success"
    assert "reward_issued" in data


def test_job_status_endpoint(client, auth_headers):
    headers, _ = auth_headers
    task_res = client.get("/get_task", headers=headers)
    assert task_res.status_code == 200
    task = task_res.get_json()
    job_id = task.get("job_id")
    assert job_id
    status_res = client.get(f"/job/{job_id}", headers=headers)
    assert status_res.status_code == 200
    payload = status_res.get_json()
    assert payload["job_id"] == job_id
    assert payload["status"] in {"issued", "expired", "completed_submitted", "reward_settled", "rejected"}


def test_agent_task_and_heartbeat(client, auth_headers):
    headers, _ = auth_headers
    task_res = client.post("/agent/get_task", headers=headers, json={})
    assert task_res.status_code == 200
    task = task_res.get_json()
    assert task.get("job_id")

    hb_res = client.post(f"/agent/job/{task['job_id']}/heartbeat", headers=headers, json={})
    assert hb_res.status_code == 200
    hb_payload = hb_res.get_json()
    assert hb_payload["job_id"] == task["job_id"]
    assert hb_payload["status"] in {"issued", "completed_local", "completed_submitted"}

    ack_res = client.post(
        f"/agent/job/{task['job_id']}/complete_ack",
        headers=headers,
        json={"result_data": "abc123", "nonce": "42"},
    )
    assert ack_res.status_code == 200
    ack_payload = ack_res.get_json()
    assert ack_payload["status"] == "completed_local"


def test_agent_get_task_adaptive_profile_defaults_to_balanced_for_non_md(client, auth_headers):
    headers, _ = auth_headers
    contracts_res = client.get("/contracts")
    assert contracts_res.status_code == 200
    contracts_list = contracts_res.get_json()
    simple_pow_ids = [c["contract_id"] for c in contracts_list if c.get("computation_type") == "simple_pow"]
    assert simple_pow_ids
    task_res = client.post(
        "/agent/get_task",
        headers=headers,
        json={"contract_id": simple_pow_ids[0], "scheduler_profile": "adaptive"},
    )
    assert task_res.status_code == 200
    task = task_res.get_json()
    assert task.get("scheduler_profile_effective") == "balanced"


def test_agent_get_task_capability_matching(client, auth_headers):
    headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=headers,
        json={
            "sector_name": "MD policy sector",
            "organization_name": "Policy org",
            "compute_domain": "molecular_dynamics",
            "description": "Capabilities matching test",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]
    topup_res = client.post(
        "/market/wallet/topup",
        headers=headers,
        json={"currency": "RUB", "amount": 20},
    )
    assert topup_res.status_code == 200
    create_res = client.post(
        "/provider/contracts",
        headers=headers,
        json={
            "sector_id": sector_id,
            "task_name": "Capability-gated benchmark",
            "task_description": "Should require higher capabilities",
            "task_category": "Пользовательская",
            "computation_type": "simple_pow",
            "work_units_required": 500,
            "reward_per_task": 5,
            "target_total_work_units": 5000,
            "difficulty": 2,
            "budget_currency": "RUB",
            "initial_budget_tokens": 10,
            "activate_now": True,
            "benchmark_meta": {
                "requirements": {
                    "min_cpu_cores": 8,
                    "min_ram_gb": 16,
                    "require_gpu": True,
                }
            },
        },
    )
    assert create_res.status_code == 201
    contract_id = (create_res.get_json().get("contract") or create_res.get_json())["contract_id"]

    too_small = client.post(
        "/agent/get_task",
        headers=headers,
        json={
            "contract_id": contract_id,
            "device_capabilities": {"cpu_cores": 4, "ram_gb": 8, "has_gpu": False},
        },
    )
    assert too_small.status_code == 400
    assert "does not match device capabilities" in (too_small.get_json().get("error") or "")

    match_res = client.post(
        "/agent/get_task",
        headers=headers,
        json={
            "contract_id": contract_id,
            "device_capabilities": {"cpu_cores": 12, "ram_gb": 32, "has_gpu": True},
        },
    )
    assert match_res.status_code == 200
    assert match_res.get_json().get("job_id")


def test_jobs_my_list(client, auth_headers):
    headers, _ = auth_headers
    task_res = client.get("/get_task", headers=headers)
    assert task_res.status_code == 200
    jobs_res = client.get("/jobs/my?limit=10", headers=headers)
    assert jobs_res.status_code == 200
    payload = jobs_res.get_json()
    assert isinstance(payload.get("jobs"), list)
    assert any(j.get("job_id") == task_res.get_json().get("job_id") for j in payload["jobs"])


def test_get_balance_requires_auth(client):
    r = client.get("/get_balance/some-id")
    assert r.status_code == 401


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_download_desktop_agent(client):
    r = client.get("/download/desktop-agent")
    assert r.status_code == 200
    assert "application/zip" in (r.headers.get("Content-Type") or "")


def test_agent_version(client):
    r = client.get("/agent/version")
    assert r.status_code == 200
    payload = r.get_json()
    assert "latest_version" in payload
    assert "download_url" in payload


def test_agent_devices_flow(client, auth_headers):
    headers, _ = auth_headers
    register_res = client.post(
        "/agent/devices/register",
        headers=headers,
        json={
            "device_id": "dev-test-001",
            "device_name": "Test Device",
            "agent_version": "0.2.0",
            "device_capabilities": {"cpu_cores": 8, "ram_gb": 16, "has_gpu": False},
        },
    )
    assert register_res.status_code == 200
    rec = register_res.get_json()
    assert rec["device_id"] == "dev-test-001"
    assert rec.get("capabilities", {}).get("cpu_cores") == 8

    hb_res = client.post(
        "/agent/devices/heartbeat",
        headers=headers,
        json={"device_id": "dev-test-001", "agent_version": "0.2.1"},
    )
    assert hb_res.status_code == 200
    hb = hb_res.get_json()
    assert hb["agent_version"] == "0.2.1"
    assert "status_reason" in hb

    list_res = client.get("/agent/devices/my", headers=headers)
    assert list_res.status_code == 200
    rows = list_res.get_json()["devices"]
    assert any(r.get("device_id") == "dev-test-001" for r in rows)

    disable_res = client.post(
        "/agent/devices/dev-test-001/disable",
        headers=headers,
        json={"is_disabled": True},
    )
    assert disable_res.status_code == 200
    assert disable_res.get_json()["is_disabled"] is True


def test_metrics(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    data = r.get_json()
    assert "chain_length" in data
    assert "clients_count" in data
    assert "pending_transactions" in data
    assert "slo" in data
    assert "validation_latency_avg_seconds" in (data.get("slo") or {})


def test_chain(client):
    r = client.get("/chain")
    assert r.status_code == 200
    chain = r.get_json()
    assert isinstance(chain, list)
    assert len(chain) >= 1
    assert chain[0]["index"] == 0


def test_explorer_address_includes_settlement_and_prefix_resolve(client, auth_headers):
    headers, target_id = auth_headers
    contracts_res = client.get("/contracts")
    assert contracts_res.status_code == 200
    contracts_list = contracts_res.get_json()
    simple_pow_ids = [c["contract_id"] for c in contracts_list if c.get("computation_type") == "simple_pow"]
    assert simple_pow_ids
    contract_id = simple_pow_ids[0]
    task_res = client.get("/get_task", headers=headers, query_string={"contract_id": contract_id})
    assert task_res.status_code == 200
    task = task_res.get_json()
    result_hash, nonce = _solve_pow(target_id, contract_id, task["difficulty"])
    assert result_hash is not None
    submit_res = client.post(
        "/submit_work",
        headers=headers,
        json={
            "client_id": target_id,
            "contract_id": contract_id,
            "job_id": task.get("job_id"),
            "work_units_done": task["work_units_required"],
            "result_data": result_hash,
            "nonce": nonce,
        },
    )
    assert submit_res.status_code == 200

    full_res = client.get(f"/explorer/address/{target_id}")
    assert full_res.status_code == 200
    full_payload = full_res.get_json()
    assert full_payload["client_id"] == target_id
    assert isinstance(full_payload.get("fiat_wallet"), dict)
    assert "chain_points" in full_payload
    tx_types = {item["tx"].get("type") for item in full_payload.get("transactions", [])}
    assert "work_receipt" in tx_types
    assert "contract_reward_settlement" in tx_types

    prefix = target_id[:13]
    prefix_res = client.get(f"/explorer/address/{prefix}")
    assert prefix_res.status_code == 200
    prefix_payload = prefix_res.get_json()
    assert prefix_payload["client_id"] == target_id
    assert prefix_payload.get("resolved_from") == prefix


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
    sector_res = client.post(
        "/provider/sectors",
        headers=headers,
        json={
            "sector_name": "Astro BOINC sector",
            "organization_name": "Test institute",
            "compute_domain": "astrophysics",
            "description": "Integration test sector",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]
    topup_res = client.post(
        "/market/wallet/topup",
        headers=headers,
        json={"currency": "RUB", "amount": 12},
    )
    assert topup_res.status_code == 200
    # 1) Поставщик создаёт и сразу активирует пользовательский контракт
    create_res = client.post(
        "/provider/contracts",
        headers=headers,
        json={
            "sector_id": sector_id,
            "task_name": "Provider PoW demo",
            "task_description": "User-defined contract for integration test",
            "task_category": "Пользовательская",
            "computation_type": "simple_pow",
            "work_units_required": 200,
            "reward_per_task": 3,
            "target_total_work_units": 400,
            "difficulty": 2,
            "initial_budget_tokens": 6,
            "budget_currency": "RUB",
            "benchmark_meta": {
                "runner": {"engine": "python_cli", "command_template": "python --version"},
                "input_format": "none",
            },
            "activate_now": True,
        },
    )
    assert create_res.status_code == 201
    create_data = create_res.get_json()
    contract = create_data.get("contract", create_data)
    assert contract["status"] == "active"
    assert (contract.get("benchmark_meta") or {}).get("runner", {}).get("engine") == "python_cli"
    contract_id = contract["contract_id"]
    provider_list_res = client.get(
        "/provider/contracts",
        headers=headers,
        query_string={"sector_id": sector_id},
    )
    assert provider_list_res.status_code == 200
    provider_rows = provider_list_res.get_json()
    created_row = next((row for row in provider_rows if row.get("contract_id") == contract_id), None)
    assert created_row is not None
    assert created_row.get("completion_pct") is not None

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


def test_provider_task_classes_catalog_and_auto_policy(client, auth_headers):
    headers, _ = auth_headers
    classes_res = client.get("/provider/task-classes", headers=headers)
    assert classes_res.status_code == 200
    classes_payload = classes_res.get_json()
    classes = classes_payload.get("task_classes") or []
    assert any(row.get("task_class") == "scientific_simulation" for row in classes)
    assert any(row.get("task_class") == "biomedical_modeling" for row in classes)
    assert any(row.get("task_class") == "ai_training" for row in classes)
    assert any(row.get("task_class") == "data_analytics" for row in classes)

    sector_res = client.post(
        "/provider/sectors",
        headers=headers,
        json={
            "sector_name": "Bio sector",
            "organization_name": "Bio lab",
            "compute_domain": "protein",
            "description": "Auto task-class test",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]
    topup_res = client.post(
        "/market/wallet/topup",
        headers=headers,
        json={"currency": "USD", "amount": 20},
    )
    assert topup_res.status_code == 200

    create_res = client.post(
        "/provider/contracts",
        headers=headers,
        json={
            "sector_id": sector_id,
            "task_name": "Protein structure fold",
            "task_description": "3D protein structure search",
            "task_category": "biomed",
            "computation_type": "molecular_dynamics_benchpep",
            "work_units_required": 120,
            "reward_per_task": 4,
            "target_total_work_units": 240,
            "difficulty": 2,
            "initial_budget_tokens": 8,
            "budget_currency": "USD",
            "activate_now": True,
        },
    )
    assert create_res.status_code == 201
    contract = (create_res.get_json().get("contract") or create_res.get_json())
    decentralized_meta = (contract.get("benchmark_meta") or {}).get("decentralized_policy") or {}
    assert decentralized_meta.get("task_class") == "biomedical_modeling"
    assert decentralized_meta.get("validation_policy", {}).get("mode") == "challengeable"
    assert decentralized_meta.get("escrow_policy", {}).get("enabled") is True


def test_replicated_validation_requires_quorum(client, auth_headers):
    provider_headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=provider_headers,
        json={
            "sector_name": "Replicated sector",
            "organization_name": "Replication lab",
            "compute_domain": "verification",
            "description": "Quorum flow test",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]

    topup_res = client.post(
        "/market/wallet/topup",
        headers=provider_headers,
        json={"currency": "RUB", "amount": 20},
    )
    assert topup_res.status_code == 200

    create_res = client.post(
        "/provider/contracts",
        headers=provider_headers,
        json={
            "sector_id": sector_id,
            "task_name": "Replicated PoW",
            "task_description": "Needs 2 replicated submissions",
            "task_category": "Verification",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 3,
            "target_total_work_units": 400,
            "difficulty": 2,
            "initial_budget_tokens": 12,
            "budget_currency": "RUB",
            "activate_now": True,
            "validation_policy": {"mode": "replicated", "replication_factor": 2},
        },
    )
    assert create_res.status_code == 201
    contract_id = (create_res.get_json().get("contract") or create_res.get_json())["contract_id"]

    worker1_headers, worker1_id = _register_worker(client)
    worker2_headers, worker2_id = _register_worker(client)

    task1 = client.get("/get_task", headers=worker1_headers, query_string={"contract_id": contract_id})
    task2 = client.get("/get_task", headers=worker2_headers, query_string={"contract_id": contract_id})
    assert task1.status_code == 200
    assert task2.status_code == 200
    payload1 = task1.get_json()
    payload2 = task2.get_json()
    assert payload1.get("replication_factor") == 2
    assert payload1.get("replication_group_id")
    assert payload2.get("replication_group_id") == payload1.get("replication_group_id")

    hash1, nonce1 = _solve_pow(worker1_id, contract_id, payload1["difficulty"])
    hash2, nonce2 = _solve_pow(worker2_id, contract_id, payload2["difficulty"])
    assert hash1 is not None
    assert hash2 is not None

    submit1 = client.post(
        "/submit_work",
        headers=worker1_headers,
        json={
            "client_id": worker1_id,
            "contract_id": contract_id,
            "job_id": payload1["job_id"],
            "work_units_done": payload1["work_units_required"],
            "result_data": hash1,
            "nonce": nonce1,
        },
    )
    assert submit1.status_code == 202
    assert submit1.get_json().get("status") == "pending_validation"

    submit2 = client.post(
        "/submit_work",
        headers=worker2_headers,
        json={
            "client_id": worker2_id,
            "contract_id": contract_id,
            "job_id": payload2["job_id"],
            "work_units_done": payload2["work_units_required"],
            "result_data": hash2,
            "nonce": nonce2,
        },
    )
    assert submit2.status_code == 200
    assert submit2.get_json().get("status") == "success"


def test_replication_m_of_n_threshold_allows_early_resolution(client, auth_headers):
    provider_headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=provider_headers,
        json={
            "sector_name": "M-of-N sector",
            "organization_name": "Quorum lab",
            "compute_domain": "validation",
            "description": "M-of-N early quorum",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]
    topup_res = client.post(
        "/market/wallet/topup",
        headers=provider_headers,
        json={"currency": "RUB", "amount": 30},
    )
    assert topup_res.status_code == 200
    create_res = client.post(
        "/provider/contracts",
        headers=provider_headers,
        json={
            "sector_id": sector_id,
            "task_name": "M of N PoW",
            "task_description": "3 replicas, threshold 2",
            "task_category": "Validation",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 3,
            "target_total_work_units": 400,
            "difficulty": 2,
            "initial_budget_tokens": 12,
            "budget_currency": "RUB",
            "activate_now": True,
            "validation_policy": {"mode": "replicated", "replication_factor": 3, "quorum_threshold": 2},
        },
    )
    assert create_res.status_code == 201
    contract_id = (create_res.get_json().get("contract") or create_res.get_json())["contract_id"]

    w1_headers, w1_id = _register_worker(client)
    w2_headers, w2_id = _register_worker(client)

    t1 = client.get("/get_task", headers=w1_headers, query_string={"contract_id": contract_id})
    t2 = client.get("/get_task", headers=w2_headers, query_string={"contract_id": contract_id})
    assert t1.status_code == 200
    assert t2.status_code == 200
    p1 = t1.get_json()
    p2 = t2.get_json()
    assert p1.get("replication_factor") == 3
    assert p1.get("quorum_threshold") == 2

    h1, n1 = _solve_pow(w1_id, contract_id, p1["difficulty"])
    h2, n2 = _solve_pow(w2_id, contract_id, p2["difficulty"])
    assert h1 is not None and h2 is not None

    s1 = client.post(
        "/submit_work",
        headers=w1_headers,
        json={
            "client_id": w1_id,
            "contract_id": contract_id,
            "job_id": p1["job_id"],
            "attempt_id": 1,
            "work_units_done": p1["work_units_required"],
            "result_data": h1,
            "nonce": n1,
        },
    )
    assert s1.status_code == 202
    s2 = client.post(
        "/submit_work",
        headers=w2_headers,
        json={
            "client_id": w2_id,
            "contract_id": contract_id,
            "job_id": p2["job_id"],
            "attempt_id": 1,
            "work_units_done": p2["work_units_required"],
            "result_data": h2,
            "nonce": n2,
        },
    )
    assert s2.status_code == 200


def test_submit_work_attempt_manifest_replay_guard(client, auth_headers):
    headers, client_id = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=headers,
        json={
            "sector_name": "Replay sector",
            "organization_name": "Replay lab",
            "compute_domain": "validation",
            "description": "Replay guard test",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]
    topup_res = client.post(
        "/market/wallet/topup",
        headers=headers,
        json={"currency": "RUB", "amount": 20},
    )
    assert topup_res.status_code == 200
    create_res = client.post(
        "/provider/contracts",
        headers=headers,
        json={
            "sector_id": sector_id,
            "task_name": "Replay replicated PoW",
            "task_description": "Replay guard should trigger on same attempt",
            "task_category": "Validation",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 2,
            "target_total_work_units": 200,
            "difficulty": 2,
            "initial_budget_tokens": 6,
            "budget_currency": "RUB",
            "activate_now": True,
            "validation_policy": {"mode": "replicated", "replication_factor": 2, "quorum_threshold": 2},
        },
    )
    assert create_res.status_code == 201
    contract_id = (create_res.get_json().get("contract") or create_res.get_json())["contract_id"]

    task_res = client.get("/get_task", headers=headers, query_string={"contract_id": contract_id})
    assert task_res.status_code == 200
    task = task_res.get_json()
    result_hash, nonce = _solve_pow(client_id, contract_id, task["difficulty"])
    assert result_hash is not None
    first = client.post(
        "/submit_work",
        headers=headers,
        json={
            "client_id": client_id,
            "contract_id": contract_id,
            "job_id": task["job_id"],
            "attempt_id": 1,
            "work_units_done": task["work_units_required"],
            "result_data": result_hash,
            "nonce": nonce,
            "output_artifacts": [{"name": "r.txt", "sha256": "a" * 64, "uri": "s3://bucket/r.txt", "size_bytes": 1}],
        },
    )
    assert first.status_code == 202
    assert first.get_json().get("code") == "replication.pending"
    second = client.post(
        "/submit_work",
        headers=headers,
        json={
            "client_id": client_id,
            "contract_id": contract_id,
            "job_id": task["job_id"],
            "attempt_id": 1,
            "work_units_done": task["work_units_required"],
            "result_data": result_hash,
            "nonce": nonce,
            "output_artifacts": [{"name": "r.txt", "sha256": "a" * 64, "uri": "s3://bucket/r.txt", "size_bytes": 1}],
        },
    )
    assert second.status_code == 409
    assert second.get_json().get("code") == "replay.attempt_detected"


def test_challengeable_escrow_and_dispute_resolution(client, auth_headers):
    provider_headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=provider_headers,
        json={
            "sector_name": "Challenge sector",
            "organization_name": "Dispute lab",
            "compute_domain": "challenge",
            "description": "Challenge + escrow lifecycle",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]

    topup_provider = client.post(
        "/market/wallet/topup",
        headers=provider_headers,
        json={"currency": "RUB", "amount": 20},
    )
    assert topup_provider.status_code == 200

    create_res = client.post(
        "/provider/contracts",
        headers=provider_headers,
        json={
            "sector_id": sector_id,
            "task_name": "Challengeable PoW",
            "task_description": "Escrow should remain locked during challenge window",
            "task_category": "Verification",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 4,
            "target_total_work_units": 300,
            "difficulty": 2,
            "initial_budget_tokens": 12,
            "budget_currency": "RUB",
            "activate_now": True,
            "validation_policy": {
                "mode": "challengeable",
                "replication_factor": 1,
                "challenge_window_seconds": 300,
            },
            "escrow_policy": {
                "enabled": True,
                "worker_collateral": 2,
                "penalty_percent_on_reject": 50,
            },
        },
    )
    assert create_res.status_code == 201
    contract_id = (create_res.get_json().get("contract") or create_res.get_json())["contract_id"]

    worker_headers, worker_id = _register_worker(client)
    topup_worker = client.post(
        "/market/wallet/topup",
        headers=worker_headers,
        json={"currency": "RUB", "amount": 10},
    )
    assert topup_worker.status_code == 200

    task_res = client.get("/get_task", headers=worker_headers, query_string={"contract_id": contract_id})
    assert task_res.status_code == 200
    task = task_res.get_json()
    job_id = task["job_id"]
    result_hash, nonce = _solve_pow(worker_id, contract_id, task["difficulty"])
    assert result_hash is not None

    submit_res = client.post(
        "/submit_work",
        headers=worker_headers,
        json={
            "client_id": worker_id,
            "contract_id": contract_id,
            "job_id": job_id,
            "work_units_done": task["work_units_required"],
            "result_data": result_hash,
            "nonce": nonce,
        },
    )
    assert submit_res.status_code == 200
    assert submit_res.get_json().get("challenge_window_open") is True

    challenger_headers, _ = _register_worker(client)
    open_challenge_res = client.post(
        f"/job/{job_id}/challenge",
        headers=challenger_headers,
        json={"reason": "need manual review"},
    )
    assert open_challenge_res.status_code == 201
    challenge_id = open_challenge_res.get_json()["challenge"]["challenge_id"]

    resolve_res = client.post(
        f"/challenges/{challenge_id}/resolve",
        headers=provider_headers,
        json={"decision": "reject_worker"},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.get_json()["challenge"]["decision"] == "reject_worker"

    job_status_res = client.get(f"/job/{job_id}", headers=worker_headers)
    assert job_status_res.status_code == 200
    assert job_status_res.get_json().get("status") == "rejected"


def test_validator_verdict_reputation_and_compliance_stubs(client, auth_headers):
    provider_headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=provider_headers,
        json={
            "sector_name": "Validator sector",
            "organization_name": "Validation lab",
            "compute_domain": "validation",
            "description": "Validator verdict path",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]
    topup_res = client.post(
        "/market/wallet/topup",
        headers=provider_headers,
        json={"currency": "RUB", "amount": 20},
    )
    assert topup_res.status_code == 200
    create_res = client.post(
        "/provider/contracts",
        headers=provider_headers,
        json={
            "sector_id": sector_id,
            "task_name": "Validator PoW",
            "task_description": "Need replication group for verdict",
            "task_category": "Validation",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 2,
            "target_total_work_units": 300,
            "difficulty": 2,
            "initial_budget_tokens": 10,
            "budget_currency": "RUB",
            "activate_now": True,
            "validation_policy": {"mode": "replicated", "replication_factor": 2},
        },
    )
    assert create_res.status_code == 201
    contract_id = (create_res.get_json().get("contract") or create_res.get_json())["contract_id"]

    worker_headers, _ = _register_worker(client)
    task_res = client.get("/get_task", headers=worker_headers, query_string={"contract_id": contract_id})
    assert task_res.status_code == 200
    group_id = task_res.get_json().get("replication_group_id")
    assert group_id

    validator_headers, validator_id = _register_worker(client)
    admit_res = client.post(
        "/network/governance/validators/admit",
        headers=provider_headers,
        json={"validator_client_id": validator_id, "meta": {"role": "validator"}},
    )
    assert admit_res.status_code == 201
    verdict_res = client.post(
        f"/replication/{group_id}/verdict",
        headers=validator_headers,
        json={"decision": "accept", "reason": "artifacts look consistent", "weight": 2},
    )
    assert verdict_res.status_code == 201
    summary = verdict_res.get_json().get("summary") or {}
    assert summary.get("accept_weight", 0) >= 2

    rep_res = client.get(f"/reputation/validator/{validator_id}", headers=validator_headers)
    assert rep_res.status_code == 200
    assert rep_res.get_json().get("score", 0) >= 1

    compliance_res = client.post(
        "/compliance/evaluate",
        headers=validator_headers,
        json={"amount": 2500, "currency": "USD", "country_code": "US"},
    )
    assert compliance_res.status_code == 200
    payload = compliance_res.get_json()
    assert payload.get("status") == "active"
    assert "kyc" in payload and "aml" in payload and "jurisdiction" in payload and "gate" in payload


def test_market_currency_budget_and_withdrawal_flow(client, auth_headers):
    provider_headers, provider_client_id = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=provider_headers,
        json={
            "sector_name": "Finance sector",
            "organization_name": "Market Lab",
            "compute_domain": "market",
            "description": "USD payout integration",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]

    # 1) Поставщик пополняет USD-кошелёк и создаёт контракт с бюджетом в USD.
    topup_provider = client.post(
        "/market/wallet/topup",
        headers=provider_headers,
        json={"currency": "USD", "amount": 20},
    )
    assert topup_provider.status_code == 200

    create_res = client.post(
        "/provider/contracts",
        headers=provider_headers,
        json={
            "sector_id": sector_id,
            "task_name": "USD contract",
            "task_description": "Market economy test",
            "task_category": "Finance",
            "computation_type": "simple_pow",
            "work_units_required": 150,
            "reward_per_task": 5,
            "target_total_work_units": 300,
            "difficulty": 2,
            "initial_budget_tokens": 10,
            "budget_currency": "USD",
            "activate_now": True,
        },
    )
    assert create_res.status_code == 201
    created_data = create_res.get_json()
    contract = created_data.get("contract", created_data)
    contract_id = contract["contract_id"]
    assert contract["budget_currency"] == "USD"

    # 2) Отдельный исполнитель выполняет задачу и получает доход в USD.
    worker_reg = client.get("/register")
    assert worker_reg.status_code == 200
    worker_data = worker_reg.get_json()
    worker_client_id = worker_data["client_id"]
    worker_headers = {"Authorization": f"Bearer {worker_data['api_key']}"}

    task_res = client.get("/get_task", headers=worker_headers, query_string={"contract_id": contract_id})
    assert task_res.status_code == 200
    task = task_res.get_json()
    result_hash, nonce = _solve_pow(worker_client_id, contract_id, task["difficulty"])
    assert result_hash is not None
    submit_res = client.post(
        "/submit_work",
        headers=worker_headers,
        json={
            "client_id": worker_client_id,
            "contract_id": contract_id,
            "work_units_done": task["work_units_required"],
            "result_data": result_hash,
            "nonce": nonce,
        },
    )
    assert submit_res.status_code == 200
    submit_payload = submit_res.get_json()
    assert submit_payload.get("reward_issued") == 5
    assert submit_payload.get("reward_currency") == "USD"

    # 3) Проверяем USD-баланс исполнителя и вывод на карту без криптовалют.
    wallet_res = client.get("/market/wallet", headers=worker_headers)
    assert wallet_res.status_code == 200
    wallet = wallet_res.get_json()
    assert wallet["balances"]["USD"] == 5

    withdraw_res = client.post(
        "/market/withdrawals",
        headers=worker_headers,
        json={
            "currency": "USD",
            "amount": 3,
            "card_number": "1234567812345678",
        },
    )
    assert withdraw_res.status_code == 201
    withdraw_payload = withdraw_res.get_json()
    assert withdraw_payload["withdrawal"]["status"] == "queued"
    assert withdraw_payload["withdrawal"]["currency"] == "USD"
    assert withdraw_payload["wallet"]["balances"]["USD"] == 2

    # 4) Проверяем аудит и on-chain сводку контракта.
    audit_res = client.get("/market/audit?limit=200", headers=worker_headers)
    assert audit_res.status_code == 200
    events = audit_res.get_json()["events"]
    assert any(e["tx"].get("type") == "contract_reward_settlement" for e in events)
    assert any(e["tx"].get("type") == "fiat_withdrawal_request" for e in events)

    provider_onchain_res = client.get("/market/contracts/onchain?provider_only=1", headers=provider_headers)
    assert provider_onchain_res.status_code == 200
    onchain_contracts = provider_onchain_res.get_json()["contracts"]
    assert any(c.get("contract_id") == contract_id for c in onchain_contracts)


def test_provider_sectors_crud_minimum(client, auth_headers):
    headers, _ = auth_headers
    create_res = client.post(
        "/provider/sectors",
        headers=headers,
        json={
            "sector_name": "Research sector",
            "organization_name": "Lab",
            "compute_domain": "simulation",
            "description": "For contract grouping",
        },
    )
    assert create_res.status_code == 201
    created = create_res.get_json()
    assert created["sector_id"].startswith("sec-")
    assert created["sector_name"] == "Research sector"

    list_res = client.get("/provider/sectors", headers=headers)
    assert list_res.status_code == 200
    rows = list_res.get_json()
    assert any(s.get("sector_id") == created["sector_id"] for s in rows)


def test_provider_contract_requires_sector(client, auth_headers):
    headers, _ = auth_headers
    create_res = client.post(
        "/provider/contracts",
        headers=headers,
        json={
            "task_name": "No sector contract",
            "task_description": "Should fail",
            "task_category": "Test",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 1,
            "target_total_work_units": 100,
            "difficulty": 1,
            "initial_budget_tokens": 0,
            "budget_currency": "RUB",
            "activate_now": False,
        },
    )
    assert create_res.status_code == 400
    assert "sector_id is required" in (create_res.get_json().get("error") or "")


def test_provider_contract_create_forbidden_for_non_owner_sector(client, auth_headers):
    owner_headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=owner_headers,
        json={
            "sector_name": "Owner-only sector",
            "organization_name": "Owner org",
            "compute_domain": "restricted",
            "description": "Only sector creator can create contracts here",
        },
    )
    assert sector_res.status_code == 201
    sector_id = sector_res.get_json()["sector_id"]

    another_user = client.get("/register")
    assert another_user.status_code == 200
    another_headers = {"Authorization": f"Bearer {another_user.get_json()['api_key']}"}

    create_res = client.post(
        "/provider/contracts",
        headers=another_headers,
        json={
            "sector_id": sector_id,
            "task_name": "Should be forbidden",
            "task_description": "Non-owner sector contract create",
            "task_category": "Test",
            "computation_type": "simple_pow",
            "work_units_required": 100,
            "reward_per_task": 1,
            "target_total_work_units": 100,
            "difficulty": 1,
            "initial_budget_tokens": 0,
            "budget_currency": "RUB",
            "activate_now": False,
        },
    )
    assert create_res.status_code == 403
    assert "forbidden" in (create_res.get_json().get("error") or "").lower()


def test_provider_contracts_list_forbidden_for_foreign_sector_filter(client, auth_headers):
    owner_headers, _ = auth_headers
    sector_res = client.post(
        "/provider/sectors",
        headers=owner_headers,
        json={
            "sector_name": "Private owner sector",
            "organization_name": "Owner org",
            "compute_domain": "private",
            "description": "Should not be listed by foreign account",
        },
    )
    assert sector_res.status_code == 201
    foreign_sector_id = sector_res.get_json()["sector_id"]

    another_user = client.get("/register")
    assert another_user.status_code == 200
    another_headers = {"Authorization": f"Bearer {another_user.get_json()['api_key']}"}

    list_res = client.get(
        "/provider/contracts",
        headers=another_headers,
        query_string={"sector_id": foreign_sector_id},
    )
    assert list_res.status_code == 403
    assert "forbidden" in (list_res.get_json().get("error") or "").lower()


def test_market_rates_update_is_stored_onchain(client, auth_headers):
    headers, _ = auth_headers
    update_res = client.post(
        "/market/rates/update",
        json={
            "rates_to_rub": {"USD": 100.0, "EUR": 110.0, "RUB": 1.0},
            "spread_percent": 2.0,
        },
    )
    assert update_res.status_code == 200
    rates = update_res.get_json()
    assert rates["rates_to_rub"]["USD"] == 100.0
    assert rates["spread_percent"] == 2.0

    get_res = client.get("/market/rates", headers=headers)
    assert get_res.status_code == 200
    current = get_res.get_json()
    assert current["rates_to_rub"]["USD"] == 100.0
    assert current["spread_percent"] == 2.0


def test_multi_oracle_fx_finalize_flow(client):
    registry = get_oracle_registry()
    epoch_id = current_epoch_id()
    oracle_ids = sorted(list(registry.keys()))[:3]
    payloads = [
        {"RUB": 1.0, "USD": 95.0, "EUR": 101.0},
        {"RUB": 1.0, "USD": 96.0, "EUR": 100.0},
        {"RUB": 1.0, "USD": 94.5, "EUR": 102.0},
    ]
    for oracle_id, rates in zip(oracle_ids, payloads):
        signature = sign_submission(registry[oracle_id], epoch_id, rates)
        submit_res = client.post(
            "/market/fx/oracle-submit",
            json={
                "oracle_id": oracle_id,
                "epoch_id": epoch_id,
                "rates_to_rub": rates,
                "signature": signature,
            },
        )
        assert submit_res.status_code == 201

    finalize_res = client.post("/market/fx/finalize", json={"epoch_id": epoch_id})
    assert finalize_res.status_code == 200
    finalized = finalize_res.get_json()
    assert finalized["status"] == "finalized"
    epoch_info = finalized["epoch"]
    assert epoch_info["is_finalized"] is True
    assert epoch_info["finalization"] is not None
    assert epoch_info["finalization"]["meta"]["source"] == "multi_oracle"
    assert epoch_info["finalization"]["meta"]["epoch_id"] == epoch_id

    rates_res = client.get("/market/rates")
    assert rates_res.status_code == 200
    rates = rates_res.get_json()
    assert rates["rates_to_rub"]["USD"] > 0
    assert rates["rates_to_rub"]["EUR"] > 0
