from flask import Flask, request, jsonify, send_from_directory, send_file
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
from device_registry import (
    register_or_update_device,
    heartbeat_device,
    list_devices_for_client,
    set_device_disabled,
)
from decentralized_fiat_policy import (
    build_policy_bundle,
    list_task_class_profiles,
    sanitize_validation_policy,
    sanitize_escrow_policy,
)
from decentralized_runtime_store import (
    add_validator_verdict,
    enforce_dispute_deadlines,
    export_runtime_state,
    governance_ack_rollout,
    governance_admit_node,
    governance_admit_validator,
    governance_finalize_rollout,
    governance_is_validator_admitted,
    governance_propose_rollout,
    governance_snapshot,
    bump_reputation,
    check_and_register_replay,
    create_dispute,
    acquire_replication_group,
    create_escrow_hold,
    get_challenge,
    get_dispute,
    get_escrow_hold_by_job,
    get_open_challenge_by_job,
    get_reputation,
    open_challenge,
    penalize_escrow_hold,
    merge_runtime_state,
    register_replication_submission,
    release_escrow_hold,
    resolve_challenge,
    runtime_snapshot,
    summarize_validator_verdicts,
    transition_dispute,
)
from validation_codes import PENALTY_CODES, error_payload
from compliance_core import (
    evaluate_aml_risk,
    evaluate_jurisdiction,
    evaluate_kyc_tier,
    evaluate_withdrawal_gate,
)
from simulated_compliance_provider import (
    evaluate_or_create_case as simulated_compliance_case,
    list_cases as simulated_list_cases,
    list_webhook_events as simulated_list_webhook_events,
    process_cases as simulated_process_cases,
    get_case as simulated_get_case,
)
import hashlib
import uuid
import os
import io
import zipfile
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
auth_find_by_api_key = None
auth_ensure_user = None
try:
    from auth_storage import (
        load_all_into as auth_load_all,
        create_user as auth_create_user,
        verify_login as auth_verify_login,
        find_by_client_id as auth_find_by_client_id,
        find_by_api_key as auth_find_by_api_key,
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

# --- Lifecycle выдачи задач (job assignments) ---
# Важно: это runtime-состояние в памяти для безопасного введения job_id без ломки совместимости.
_job_assignments = {}  # job_id -> assignment dict
_job_assignments_lock = threading.Lock()
JOB_TTL_SECONDS = int(os.environ.get("JOB_TTL_SECONDS", "3600"))
JOB_REASSIGN_COOLDOWN_SECONDS = int(os.environ.get("JOB_REASSIGN_COOLDOWN_SECONDS", "30"))
JOB_MAX_REASSIGN_ATTEMPTS = int(os.environ.get("JOB_MAX_REASSIGN_ATTEMPTS", "3"))
JOB_STATUSES_FINAL = {"reward_settled", "rejected", "expired", "reassigned"}


def _expire_job_assignments(now_ts_value=None):
    """Пометить просроченные assignment'ы как expired."""
    now_value = now_ts_value if now_ts_value is not None else time.time()
    with _job_assignments_lock:
        for assignment in _job_assignments.values():
            if assignment.get("status") in JOB_STATUSES_FINAL:
                continue
            expires_at = float(assignment.get("expires_at", 0) or 0)
            if expires_at and expires_at <= now_value:
                assignment["status"] = "expired"
                assignment["expired_at"] = now_value
                assignment["updated_at"] = now_value


def _create_job_assignment(*, client_id, contract_id, task_seed, parent_job_id=None, reassign_count=0):
    """Создать assignment для выданной задачи."""
    now_value = time.time()
    job_id = f"job-{uuid.uuid4().hex[:16]}"
    assignment = {
        "job_id": job_id,
        "client_id": client_id,
        "contract_id": contract_id,
        "task_seed": int(task_seed),
        "status": "issued",
        "assigned_at": now_value,
        "updated_at": now_value,
        "expires_at": now_value + JOB_TTL_SECONDS,
        "result_data": None,
        "nonce": None,
        "reward_id": None,
        "parent_job_id": parent_job_id,
        "reassign_count": int(reassign_count),
    }
    with _job_assignments_lock:
        _job_assignments[job_id] = assignment
    return assignment


def _get_job_assignment(job_id):
    if not job_id:
        return None
    _expire_job_assignments()
    with _job_assignments_lock:
        assignment = _job_assignments.get(job_id)
        if not assignment:
            return None
        return dict(assignment)


def _update_job_assignment(job_id, **updates):
    if not job_id:
        return None
    with _job_assignments_lock:
        assignment = _job_assignments.get(job_id)
        if not assignment:
            return None
        assignment.update(updates)
        assignment["updated_at"] = time.time()
        return dict(assignment)


def _task_requirements_from_runtime(runtime):
    """Извлечь требования задачи из benchmark_meta."""
    spec = (runtime or {}).get("spec") or {}
    benchmark_meta = spec.get("benchmark_meta") if isinstance(spec.get("benchmark_meta"), dict) else {}
    raw = benchmark_meta.get("requirements") if isinstance(benchmark_meta.get("requirements"), dict) else {}
    try:
        min_cpu_cores = int(raw.get("min_cpu_cores", 0) or 0)
    except (TypeError, ValueError):
        min_cpu_cores = 0
    try:
        min_ram_gb = float(raw.get("min_ram_gb", 0) or 0.0)
    except (TypeError, ValueError):
        min_ram_gb = 0.0
    return {
        "min_cpu_cores": min_cpu_cores,
        "min_ram_gb": min_ram_gb,
        "require_gpu": bool(raw.get("require_gpu", False)),
        "required_engine": (
            ((benchmark_meta.get("runner") or {}).get("engine") if isinstance(benchmark_meta.get("runner"), dict) else None)
            or (benchmark_meta.get("engine") or "")
        ).strip(),
    }


def _matches_task_requirements(runtime, device_capabilities):
    """
    Policy matching v1:
    - фильтруем контракты, которые устройство заведомо не тянет.
    - если capabilities не переданы, сохраняем backward compatibility (не режем кандидатов).
    """
    caps = device_capabilities if isinstance(device_capabilities, dict) else {}
    if not caps:
        return True
    req = _task_requirements_from_runtime(runtime)
    cpu_cores = int(caps.get("cpu_cores", 0) or 0)
    ram_gb = float(caps.get("ram_gb", 0) or 0.0)
    has_gpu = bool(caps.get("has_gpu", False))
    supported_engines = caps.get("supported_engines")
    if not isinstance(supported_engines, list):
        supported_engines = []
    if req["min_cpu_cores"] and cpu_cores < req["min_cpu_cores"]:
        return False
    if req["min_ram_gb"] and ram_gb < req["min_ram_gb"]:
        return False
    if req["require_gpu"] and not has_gpu:
        return False
    if req["required_engine"] and supported_engines and req["required_engine"] not in supported_engines:
        return False
    return True


def _runtime_rank_score(runtime, scheduler_profile):
    """
    Rank-политика v1 (аналог упрощённого ClassAd rank):
    - eco: предпочитает лёгкие chunk-и;
    - performance: предпочитает более крупные chunk-и;
    - balanced: компромисс reward/объём.
    """
    spec = (runtime or {}).get("spec") or {}
    work_units = max(1, int(spec.get("work_units_required", 1) or 1))
    reward = max(0, int(spec.get("reward_per_task", 0) or 0))
    profile = (scheduler_profile or "balanced").strip().lower()
    if profile == "eco":
        return reward - (work_units / 200.0)
    if profile == "performance":
        return reward + (work_units / 200.0)
    return reward - (work_units / 1000.0)


def _is_md_heavy_runtime(runtime):
    """
    Выделяем heavy-MD контракты для adaptive policy.
    Это позволяет не включать performance-гиперагрессивно для всех типов задач.
    """
    spec = (runtime or {}).get("spec") or {}
    ctype = str(spec.get("computation_type") or "").strip().lower()
    if ctype.startswith("molecular_dynamics"):
        return True
    return ctype == "molecular_dynamics_benchpep"


def _is_client_degraded(client_id, *, lookback_seconds=2 * 3600):
    """
    Детектор деградации по assignment-истории клиента:
    если за последнее окно много expired/reassigned/rejected, снижаем профиль.
    """
    now_value = time.time()
    bad_statuses = {"expired", "reassigned", "rejected"}
    considered = 0
    bad = 0
    with _job_assignments_lock:
        for row in _job_assignments.values():
            if row.get("client_id") != client_id:
                continue
            updated = float(row.get("updated_at", 0) or 0)
            if now_value - updated > lookback_seconds:
                continue
            considered += 1
            if (row.get("status") or "").strip() in bad_statuses:
                bad += 1
    # Гарантируем, что единичные случайные ошибки не переключают профиль.
    return considered >= 3 and bad / max(1, considered) >= 0.4


def _resolve_effective_scheduler_profile(
    *,
    requested_profile,
    runtime,
    client_id,
    device_capabilities,
):
    """
    Adaptive policy:
    - default performance для MD-heavy задач;
    - автоматический downgrade до balanced при деградации клиента/слабом железе.
    """
    profile = (requested_profile or "adaptive").strip().lower()
    if profile in {"eco", "balanced", "performance"}:
        return profile
    # Для не-MD задач adaptive ведёт себя консервативно.
    if not _is_md_heavy_runtime(runtime):
        return "balanced"
    caps = device_capabilities if isinstance(device_capabilities, dict) else {}
    cpu_cores = int(caps.get("cpu_cores", 0) or 0)
    ram_gb = float(caps.get("ram_gb", 0) or 0.0)
    if (cpu_cores and cpu_cores < 8) or (ram_gb and ram_gb < 16):
        return "balanced"
    if _is_client_degraded(client_id):
        return "balanced"
    return "performance"


def _issue_task_for_client(
    client_id,
    *,
    contract_id=None,
    sector_id=None,
    device_capabilities=None,
    scheduler_profile="adaptive",
):
    """Выдать задачу клиенту и зарегистрировать assignment с policy matching/ranking."""
    if contract_id:
        runtime = _resolve_contract_runtime(contract_id, allow_inactive_dynamic=False)
        if not runtime:
            return None, "Unknown contract_id or contract is not active"
        if sector_id and runtime.get("record") and runtime["record"].get("sector_id") != sector_id:
            return None, "contract_id does not belong to the selected sector"
        if not _matches_task_requirements(runtime, device_capabilities):
            return None, "Selected contract does not match device capabilities"
        effective_profile = _resolve_effective_scheduler_profile(
            requested_profile=scheduler_profile,
            runtime=runtime,
            client_id=client_id,
            device_capabilities=device_capabilities,
        )
    else:
        candidates = _available_contract_runtimes()
        if sector_id:
            candidates = [
                r for r in candidates
                if (r.get("record") or {}).get("sector_id") == sector_id
            ]
        candidates = [r for r in candidates if _matches_task_requirements(r, device_capabilities)]
        if not candidates:
            return None, "No available contracts for current device capabilities"
        ranked = sorted(
            candidates,
            key=lambda r: _runtime_rank_score(
                r,
                _resolve_effective_scheduler_profile(
                    requested_profile=scheduler_profile,
                    runtime=r,
                    client_id=client_id,
                    device_capabilities=device_capabilities,
                ),
            ),
            reverse=True,
        )
        runtime = ranked[0]
        effective_profile = _resolve_effective_scheduler_profile(
            requested_profile=scheduler_profile,
            runtime=runtime,
            client_id=client_id,
            device_capabilities=device_capabilities,
        )
    _active_task_takers[(runtime["contract_id"], client_id)] = time.time()
    spec = dict(runtime["spec"])
    validation_policy, escrow_policy = _runtime_policies(runtime)
    replication_mode = validation_policy.get("mode") in {"replicated", "challengeable"}
    replication_factor = int(validation_policy.get("replication_factor", 1) or 1)
    quorum_threshold = int(validation_policy.get("quorum_threshold", replication_factor) or replication_factor)
    replication_group_id = None
    if replication_mode and replication_factor > 1:
        group = acquire_replication_group(
            contract_id=runtime["contract_id"],
            client_id=client_id,
            replication_factor=replication_factor,
            quorum_threshold=quorum_threshold,
        )
        spec["task_seed"] = int(group["task_seed"])
        replication_group_id = group["group_id"]
    else:
        base = uuid.uuid4().int & ((1 << 64) - 1)
        client_bits = int(hashlib.sha256(client_id.encode()).hexdigest()[:16], 16) % (1 << 64)
        spec["task_seed"] = (base ^ client_bits) & ((1 << 64) - 1)

    escrow_collateral = int(escrow_policy.get("worker_collateral", 0) or 0)
    reward_currency = _normalized_budget_currency(spec.get("reward_currency")) or MARKET_DEFAULT_CURRENCY
    if escrow_policy.get("enabled") and escrow_collateral > 0:
        wallet_amount = get_wallet_amount(blockchain.chain, client_id, reward_currency)
        if wallet_amount < escrow_collateral:
            return None, (
                f"Insufficient wallet balance for escrow collateral: "
                f"required {escrow_collateral} {reward_currency}"
            )

    assignment = _create_job_assignment(
        client_id=client_id,
        contract_id=runtime["contract_id"],
        task_seed=spec["task_seed"],
    )
    # Сохраняем профиль планировщика в assignment для UX/диагностики в профиле пользователя.
    _update_job_assignment(
        assignment["job_id"],
        scheduler_profile_requested=(scheduler_profile or "adaptive"),
        scheduler_profile_effective=effective_profile,
        replication_group_id=replication_group_id,
        replication_factor=replication_factor if replication_mode else 1,
        quorum_threshold=quorum_threshold if replication_mode else 1,
    )
    if escrow_policy.get("enabled") and escrow_collateral > 0:
        provider_client_id = (runtime.get("record") or {}).get("provider_client_id")
        hold = create_escrow_hold(
            job_id=assignment["job_id"],
            contract_id=runtime["contract_id"],
            provider_client_id=provider_client_id,
            worker_client_id=client_id,
            currency=reward_currency,
            amount=escrow_collateral,
        )
        if hold:
            _, hold_err = _append_onchain_events([_build_escrow_hold_tx(hold)])
            if hold_err:
                _update_job_assignment(assignment["job_id"], status="rejected")
                return None, f"Failed to reserve escrow collateral: {hold_err}"
            _update_job_assignment(
                assignment["job_id"],
                escrow_hold_id=hold.get("hold_id"),
                escrow_status=hold.get("status"),
                escrow_amount=int(hold.get("amount", 0)),
                escrow_currency=hold.get("currency"),
            )
    spec["job_id"] = assignment["job_id"]
    spec["job_ttl_seconds"] = JOB_TTL_SECONDS
    # Возвращаем effective-профиль для наблюдаемости и отладки adaptive-логики.
    spec["scheduler_profile_effective"] = effective_profile
    if replication_group_id:
        spec["replication_group_id"] = replication_group_id
        spec["replication_factor"] = replication_factor
        spec["quorum_threshold"] = quorum_threshold
    return spec, None


def _sync_jobs_from_peer():
    """Синхронизировать assignment'ы задач с пиром."""
    if not PEER_URL:
        return
    try:
        headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
        response = requests.get(
            f"{PEER_URL.rstrip('/')}/jobs/snapshot",
            timeout=PEER_REQUEST_TIMEOUT,
            headers=headers,
        )
        if response.status_code != 200:
            return
        peer_rows = response.json()
        if not isinstance(peer_rows, list):
            return
        with _job_assignments_lock:
            for row in peer_rows:
                if not isinstance(row, dict):
                    continue
                job_id = (row.get("job_id") or "").strip()
                if not job_id:
                    continue
                local = _job_assignments.get(job_id)
                peer_updated = float(row.get("updated_at", 0) or 0)
                local_updated = float((local or {}).get("updated_at", 0) or 0)
                if (not local) or (peer_updated > local_updated):
                    _job_assignments[job_id] = dict(row)
    except requests.RequestException:
        return

def get_client_id_from_auth():
    """Из заголовка Authorization: Bearer <api_key> возвращаем client_id или None."""
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    client_id = api_key_to_client.get(token)
    if client_id is not None:
        return client_id
    # Если ключ пришёл на другой узел (после логина/регистрации на пиру),
    # подтягиваем соответствие из users.json и кэшируем локально.
    if auth_find_by_api_key is not None:
        profile = auth_find_by_api_key(token)
        if profile and profile.get("client_id"):
            client_id = profile["client_id"]
            api_key_to_client[token] = client_id
            return client_id
    return None

def rate_limit_key():
    """Ключ для лимитов: по API-ключу для авторизованных, иначе по IP (защита от DDoS)."""
    # Для тестов используем уникальный ключ на запрос, чтобы лимитер не ломал
    # изоляцию тест-кейсов и не создавал флапающие 429.
    if app.config.get("TESTING"):
        return f"test-{time.time_ns()}"
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
DESKTOP_AGENT_LATEST_VERSION = os.environ.get("DESKTOP_AGENT_LATEST_VERSION", "0.2.0")

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

NETWORK_PROTOCOL_VERSION = os.environ.get("NETWORK_PROTOCOL_VERSION", "1.0")
SUPPORTED_PROTOCOL_VERSIONS = [
    value.strip()
    for value in os.environ.get("SUPPORTED_PROTOCOL_VERSIONS", NETWORK_PROTOCOL_VERSION).split(",")
    if value.strip()
]
if NETWORK_PROTOCOL_VERSION not in SUPPORTED_PROTOCOL_VERSIONS:
    SUPPORTED_PROTOCOL_VERSIONS.append(NETWORK_PROTOCOL_VERSION)
GOVERNANCE_ADMISSION_TOKEN = os.environ.get("GOVERNANCE_ADMISSION_TOKEN", "")
COMPLIANCE_ENFORCEMENT_MODE = os.environ.get("COMPLIANCE_ENFORCEMENT_MODE", "shadow").strip().lower()
COMPLIANCE_PROVIDER_MODE = os.environ.get("COMPLIANCE_PROVIDER_MODE", "deterministic").strip().lower()
COMPLIANCE_REVIEW_BLOCK_WITHDRAWAL_MIN_AMOUNT = int(
    os.environ.get("COMPLIANCE_REVIEW_BLOCK_WITHDRAWAL_MIN_AMOUNT", "500")
)
COMPLIANCE_REVIEW_BLOCK_CONVERT_MIN_AMOUNT = int(
    os.environ.get("COMPLIANCE_REVIEW_BLOCK_CONVERT_MIN_AMOUNT", "1000")
)


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
        # В тестах отключаем требование node-secret, чтобы интеграционные сценарии
        # проверяли бизнес-логику, а не инфраструктурную конфигурацию окружения.
        if app.config.get("TESTING"):
            return f(*args, **kwargs)
        if not NODE_SECRET:
            # Fail-closed для удалённых сред: без NODE_SECRET служебные эндпоинты
            # разрешены только локально (loopback) для dev-сценариев.
            remote_addr = (request.remote_addr or "").strip()
            if remote_addr not in ("127.0.0.1", "::1"):
                logger.error("node_secret_missing_for_remote_request: path=%s remote_addr=%s", request.path, remote_addr or "unknown")
                return jsonify({"error": "NODE_SECRET is required for remote node synchronization endpoints"}), 503
            return f(*args, **kwargs)
        if request.headers.get("X-Node-Secret") != NODE_SECRET:
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
        _sync_jobs_from_peer()
        _sync_runtime_from_peer()
        enforce_dispute_deadlines()
        if COMPLIANCE_PROVIDER_MODE == "simulated":
            simulated_process_cases()


def _sync_runtime_from_peer():
    """Синхронизировать runtime state (replication/challenge/dispute/governance) с пиром."""
    if not PEER_URL:
        return
    try:
        headers = {"X-Node-Secret": NODE_SECRET} if NODE_SECRET else {}
        response = requests.get(
            f"{PEER_URL.rstrip('/')}/runtime/snapshot",
            timeout=PEER_REQUEST_TIMEOUT,
            headers=headers,
        )
        if response.status_code != 200:
            return
        remote_state = response.json()
        changed = merge_runtime_state(remote_state)
        if changed:
            logger.info("sync_runtime_merged: changed=%s", changed)
    except requests.RequestException:
        return


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
    computation_type = contract_record.get("computation_type", "simple_pow")
    is_heavy = computation_type in {
        "cosmological",
        "supernova",
        "mhd",
        "radiative",
        "gravitational_waves",
        "molecular_dynamics_benchpep",
    }
    task_profile = {
        "mode": "heavy" if is_heavy else "standard",
        "recommended_heartbeat_seconds": 10 if is_heavy else 20,
        "recommended_submit_timeout_seconds": 1800 if is_heavy else 900,
        "recommended_checkpoint_interval_seconds": 30 if is_heavy else 60,
    }
    benchmark_meta = contract_record.get("benchmark_meta", {}) if isinstance(contract_record.get("benchmark_meta"), dict) else {}
    policy_meta = benchmark_meta.get("decentralized_policy", {}) if isinstance(benchmark_meta.get("decentralized_policy"), dict) else {}
    validation_policy = sanitize_validation_policy(policy_meta.get("validation_policy"))
    escrow_policy = sanitize_escrow_policy(policy_meta.get("escrow_policy"))
    task_class = str(policy_meta.get("task_class") or "").strip() or None
    task_class_source = str(policy_meta.get("task_class_source") or "").strip() or None
    validation_style = str(policy_meta.get("validation_style") or "").strip() or None
    return {
        "contract_id": contract_record["contract_id"],
        "sector_id": contract_record.get("sector_id"),
        "sector_name": contract_record.get("sector_name"),
        "work_units_required": int(contract_record["work_units_required"]),
        "difficulty": int(contract_record["difficulty"]),
        "task_name": contract_record.get("task_name") or contract_record["contract_id"],
        "task_description": contract_record.get("task_description", ""),
        "task_category": contract_record.get("task_category", "Пользовательская"),
        "computation_type": computation_type,
        "reward_per_task": int(contract_record.get("reward_per_task", 0)),
        "reward_currency": reward_currency,
        "contract_origin": "provider",
        "provider_client_id": contract_record.get("provider_client_id"),
        "task_profile": task_profile,
        "benchmark_meta": benchmark_meta,
        # Stage 1 migration fields: explicit policy payload for agent/validator pipeline.
        "validation_policy": validation_policy,
        "escrow_policy": escrow_policy,
        "task_class": task_class,
        "task_class_source": task_class_source,
        "validation_style": validation_style,
    }


def _normalized_budget_currency(raw_currency):
    normalized = onchain_normalize_currency(raw_currency or MARKET_DEFAULT_CURRENCY)
    if not normalized:
        return None
    return normalized


def _reward_event_id(*, client_id, contract_id, result_data, nonce):
    payload = f"{client_id}|{contract_id}|{result_data or ''}|{nonce or ''}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _artifact_manifest_hash(output_artifacts):
    normalized = []
    for item in output_artifacts or []:
        if not isinstance(item, dict):
            continue
        normalized.append(
            (
                str(item.get("name") or "").strip(),
                str(item.get("sha256") or "").strip().lower(),
                str(item.get("uri") or "").strip(),
                int(item.get("size_bytes", 0) or 0),
            )
        )
    normalized.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    payload = "|".join(f"{name}:{sha256}:{uri}:{size}" for name, sha256, uri, size in normalized)
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


def _runtime_policies(runtime):
    spec = (runtime or {}).get("spec") or {}
    validation_policy = spec.get("validation_policy") if isinstance(spec.get("validation_policy"), dict) else {}
    escrow_policy = spec.get("escrow_policy") if isinstance(spec.get("escrow_policy"), dict) else {}
    return sanitize_validation_policy(validation_policy), sanitize_escrow_policy(escrow_policy)


def _build_escrow_hold_tx(hold):
    return {
        "type": "contract_worker_escrow_hold",
        "hold_id": hold.get("hold_id"),
        "job_id": hold.get("job_id"),
        "contract_id": hold.get("contract_id"),
        "provider_client_id": hold.get("provider_client_id"),
        "worker_client_id": hold.get("worker_client_id"),
        "currency": hold.get("currency"),
        "amount": int(hold.get("amount", 0)),
        "created_at": now_ts(),
    }


def _build_escrow_release_tx(hold):
    return {
        "type": "contract_worker_escrow_release",
        "hold_id": hold.get("hold_id"),
        "worker_client_id": hold.get("worker_client_id"),
        "currency": hold.get("currency"),
        "amount": int(hold.get("amount", 0)),
        "created_at": now_ts(),
    }


def _build_escrow_penalty_tx(hold):
    return {
        "type": "contract_worker_escrow_penalty",
        "hold_id": hold.get("hold_id"),
        "contract_id": hold.get("contract_id"),
        "provider_client_id": hold.get("provider_client_id"),
        "worker_client_id": hold.get("worker_client_id"),
        "currency": hold.get("currency"),
        "penalty_amount": int(hold.get("penalty_amount", 0)),
        "created_at": now_ts(),
    }


def _try_release_escrow_for_job(job_id):
    hold = release_escrow_hold(job_id)
    if not hold or hold.get("status") != "released":
        return None, None
    tx = _build_escrow_release_tx(hold)
    _, err = _append_onchain_events([tx])
    return hold, err


def _try_penalize_escrow_for_job(job_id, *, penalty_percent):
    hold = penalize_escrow_hold(job_id, penalty_percent=penalty_percent)
    if not hold or hold.get("status") != "penalized":
        return None, None
    if int(hold.get("penalty_amount", 0)) <= 0:
        return hold, None
    tx = _build_escrow_penalty_tx(hold)
    _, err = _append_onchain_events([tx])
    return hold, err


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


def _withdrawal_usage(client_id):
    rows = list_withdrawals_from_chain(blockchain.chain, client_id=client_id, limit=1000)
    now_value = now_ts()
    day_start = now_value - 24 * 3600
    month_start = now_value - 30 * 24 * 3600
    daily_used = 0
    monthly_used = 0
    for row in rows:
        status = (row.get("status") or "").strip()
        if status == "rejected":
            continue
        amount = int(row.get("amount", 0) or 0)
        created_at = int(row.get("created_at", 0) or 0)
        if created_at >= day_start:
            daily_used += amount
        if created_at >= month_start:
            monthly_used += amount
    return daily_used, monthly_used


def _stage3_observability_metrics():
    runtime = runtime_snapshot()
    latencies = []
    settlement_delays = []
    with _job_assignments_lock:
        rows = [dict(v) for v in _job_assignments.values()]
    for row in rows:
        assigned = float(row.get("assigned_at", 0) or 0)
        validation_finished = float(row.get("validation_finished_at", 0) or 0)
        updated = float(row.get("updated_at", 0) or 0)
        if assigned and validation_finished and validation_finished >= assigned:
            latencies.append(validation_finished - assigned)
        if assigned and updated and row.get("status") in {"reward_settled", "rejected"} and updated >= assigned:
            settlement_delays.append(updated - assigned)
    avg_validation_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
    avg_settlement_delay = (sum(settlement_delays) / len(settlement_delays)) if settlement_delays else 0.0

    events = list_audit_events(blockchain.chain, limit=5000)
    reward_total = 0
    penalty_total = 0
    for row in events:
        tx = row.get("tx") or {}
        if tx.get("type") == "contract_reward_settlement":
            reward_total += int(tx.get("amount", 0) or 0)
        if tx.get("type") == "contract_worker_escrow_penalty":
            penalty_total += int(tx.get("penalty_amount", 0) or 0)
    denom = reward_total + penalty_total
    fraud_loss_ratio = (penalty_total / denom) if denom > 0 else 0.0

    resolved_jobs = 0
    for row in rows:
        if row.get("status") in {"reward_settled", "rejected"}:
            resolved_jobs += 1
    challenge_rate = (
        float(runtime.get("challenges_total", 0) or 0) / float(resolved_jobs)
        if resolved_jobs > 0
        else 0.0
    )
    return {
        "validation_latency_avg_seconds": round(avg_validation_latency, 3),
        "challenge_rate": round(challenge_rate, 4),
        "settlement_delay_avg_seconds": round(avg_settlement_delay, 3),
        "fraud_loss_ratio": round(fraud_loss_ratio, 6),
        "runtime_snapshot": runtime,
    }


def _compliance_bundle(*, client_id, amount, currency, country_code=None, operation="withdrawal"):
    daily_used, monthly_used = _withdrawal_usage(client_id)
    kyc = evaluate_kyc_tier(client_id=client_id)
    aml = evaluate_aml_risk(client_id=client_id, amount=amount, currency=currency)
    jurisdiction = evaluate_jurisdiction(client_id=client_id, country_code=country_code)
    provider_case = None
    if COMPLIANCE_PROVIDER_MODE == "simulated":
        provider_case = simulated_compliance_case(
            client_id=client_id,
            operation=(operation or "withdrawal").strip().lower(),
            amount=amount,
            currency=currency,
            country_code=country_code,
            kyc_tier=kyc.get("kyc_tier", "tier0_unverified"),
        )
        case_status = (provider_case.get("status") or "").strip().lower() if isinstance(provider_case, dict) else ""
        if case_status in {"allow", "review", "reject"}:
            aml["decision"] = case_status
            aml["risk_score"] = int(provider_case.get("risk_score", aml.get("risk_score", 0)) or 0)
            aml["provider_reason"] = provider_case.get("decision_reason")
            aml["status"] = "simulated-provider"
        else:
            aml["decision"] = "review"
            aml["provider_reason"] = "provider_pending"
            aml["status"] = "simulated-provider-pending"
    gate = evaluate_withdrawal_gate(
        kyc_result=kyc,
        aml_result=aml,
        jurisdiction_result=jurisdiction,
        amount=amount,
        daily_used=daily_used,
        monthly_used=monthly_used,
    )
    return {
        "kyc": kyc,
        "aml": aml,
        "jurisdiction": jurisdiction,
        "gate": gate,
        "provider_case": provider_case,
        "provider_mode": COMPLIANCE_PROVIDER_MODE,
    }


def _is_compliance_blocked_for_operation(*, operation, amount, gate_decision):
    normalized_operation = (operation or "").strip().lower()
    decision = (gate_decision or "").strip().lower()
    if COMPLIANCE_ENFORCEMENT_MODE == "shadow":
        return False
    if decision == "reject":
        return normalized_operation in {"withdrawal", "convert"}
    if decision != "review":
        return False
    if COMPLIANCE_ENFORCEMENT_MODE == "hard":
        return normalized_operation in {"withdrawal", "convert"}
    # adaptive mode: block review only for high-risk/high-amount operations.
    if normalized_operation == "withdrawal":
        return int(amount or 0) >= COMPLIANCE_REVIEW_BLOCK_WITHDRAWAL_MIN_AMOUNT
    if normalized_operation == "convert":
        return int(amount or 0) >= COMPLIANCE_REVIEW_BLOCK_CONVERT_MIN_AMOUNT
    return False


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
    _expire_job_assignments()
    contract_id = (request.args.get("contract_id") or "").strip() or None
    sector_id = (request.args.get("sector_id") or "").strip() or None
    scheduler_profile = (request.args.get("scheduler_profile") or "adaptive").strip().lower()
    spec, issue_err = _issue_task_for_client(
        client_id,
        contract_id=contract_id,
        sector_id=sector_id,
        scheduler_profile=scheduler_profile,
    )
    if issue_err:
        code = 400 if contract_id else 503
        if "selected sector" in issue_err:
            code = 400
        return jsonify({"error": issue_err}), code
    logger.info(
        "task_issued: contract_id=%s client_id=%s... task_seed=%s job_id=%s sector_id=%s",
        spec["contract_id"],
        client_id[:8],
        spec["task_seed"],
        spec["job_id"],
        sector_id,
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
    _expire_job_assignments()
    client_id = data.get("client_id")
    if client_id != client_id_from_key:
        logger.warning("submit_work: rejected client_id mismatch (body=%s... auth=%s...)", (client_id or "")[:8], (client_id_from_key or "")[:8])
        return jsonify({"error": "client_id does not match authenticated client"}), 403
    contract_id = data.get("contract_id")
    work_units_done = data.get("work_units_done")
    result_data = data.get("result_data")
    nonce = data.get("nonce")  # Nonce для строгой проверки контрактом
    job_id = (data.get("job_id") or "").strip() or None
    attempt_id = data.get("attempt_id", 1)
    output_artifacts = data.get("output_artifacts")

    if not all([client_id, contract_id, work_units_done is not None]):
        logger.warning("submit_work: missing data (client_id=%s contract_id=%s work_units_done=%s)", bool(client_id), contract_id, work_units_done)
        return jsonify({"error": "Missing data"}), 400
    try:
        work_units_done = int(work_units_done)
    except (TypeError, ValueError):
        return jsonify({"error": "work_units_done must be integer"}), 400
    try:
        attempt_id = int(attempt_id)
    except (TypeError, ValueError):
        return jsonify({"error": "attempt_id must be integer"}), 400
    if attempt_id <= 0:
        return jsonify({"error": "attempt_id must be > 0"}), 400
    if work_units_done <= 0:
        return jsonify({"error": "work_units_done must be > 0"}), 400

    assignment = None
    if job_id:
        assignment = _get_job_assignment(job_id)
        if not assignment:
            return jsonify(error_payload(code_key="JOB_NOT_FOUND", message="Unknown job_id")), 404
        if assignment.get("client_id") != client_id:
            return jsonify(error_payload(code_key="JOB_FORBIDDEN", message="job_id belongs to another client")), 403
        if assignment.get("contract_id") != contract_id:
            return jsonify(error_payload(code_key="JOB_CONTRACT_MISMATCH", message="job_id contract mismatch")), 400
        if assignment.get("status") == "expired":
            return jsonify(error_payload(code_key="JOB_EXPIRED", message="job_id expired, request a new task")), 409
        if assignment.get("status") == "rejected":
            return jsonify(error_payload(code_key="JOB_ALREADY_REJECTED", message="job_id already rejected")), 409
        if assignment.get("status") == "reassigned":
            return jsonify(error_payload(code_key="JOB_ALREADY_REASSIGNED", message="job_id already reassigned")), 409
        existing_result = assignment.get("result_data")
        if existing_result and result_data and existing_result != result_data:
            return jsonify(error_payload(code_key="JOB_ALREADY_USED_OTHER_PROOF", message="job_id already used with another proof")), 409
        if assignment.get("status") == "reward_settled":
            return jsonify({
                "status": "success",
                "message": "Job already settled (idempotent request)",
                "reward_issued": 0,
            }), 200
        if assignment.get("status") == "challenge_window_open":
            return jsonify({
                "status": "success",
                "message": "Job already settled and waiting for challenge window finalization",
                "reward_issued": 0,
                "challenge_window_open": True,
            }), 200

    # Защита от DoS: проверка размера result_data (хеш должен быть 64 символа, максимум 1KB для безопасности)
    if result_data:
        if not isinstance(result_data, str):
            return jsonify({"error": "result_data must be a string"}), 400
        if len(result_data) > 1024:  # Максимум 1KB
            logger.warning("submit_work: result_data too large (%s bytes)", len(result_data))
            return jsonify({"error": "result_data too large (max 1KB)"}), 400
    # Artifact contract v1: валидируем структуру артефактов, чтобы тяжёлые раннеры сдавали
    # воспроизводимые ссылки/хеши результатов (а не только result_data string).
    if output_artifacts is None:
        output_artifacts = []
    if not isinstance(output_artifacts, list):
        return jsonify({"error": "output_artifacts must be an array"}), 400
    if len(output_artifacts) > 32:
        return jsonify({"error": "too many output_artifacts (max 32)"}), 400
    normalized_artifacts = []
    for item in output_artifacts:
        if not isinstance(item, dict):
            return jsonify({"error": "each output_artifact must be an object"}), 400
        name = str(item.get("name") or "").strip()
        sha256 = str(item.get("sha256") or "").strip().lower()
        uri = str(item.get("uri") or "").strip()
        try:
            size_bytes = int(item.get("size_bytes", 0) or 0)
        except (TypeError, ValueError):
            return jsonify({"error": "output_artifact.size_bytes must be integer"}), 400
        if not name or len(name) > 256:
            return jsonify({"error": "output_artifact.name is required (max 256)"}), 400
        if not sha256 or len(sha256) != 64:
            return jsonify({"error": "output_artifact.sha256 must be 64 hex chars"}), 400
        if size_bytes < 0:
            return jsonify({"error": "output_artifact.size_bytes must be >= 0"}), 400
        normalized_artifacts.append(
            {
                "name": name,
                "sha256": sha256,
                "uri": uri,
                "size_bytes": size_bytes,
            }
        )
    artifact_manifest_hash = _artifact_manifest_hash(normalized_artifacts)
    if job_id:
        replay_seed = f"{job_id}|{attempt_id}|{artifact_manifest_hash}"
        replay_key = hashlib.sha256(replay_seed.encode()).hexdigest()
        is_replay, replay_row = check_and_register_replay(
            replay_key=replay_key,
            job_id=job_id,
            attempt_id=attempt_id,
            artifact_manifest_hash=artifact_manifest_hash,
        )
        if is_replay:
            return jsonify(
                error_payload(
                    code_key="REPLAY_ATTEMPT",
                    message="Replay attempt detected for this job attempt and artifact manifest",
                    extra={"replay": replay_row},
                )
            ), 409

    # Защита от мошенничества: обязателен nonce для строгой верификации (невозможно подделать результат)
    if nonce is None or nonce == "":
        logger.warning("submit_work: nonce required")
        return jsonify(error_payload(code_key="NONCE_REQUIRED", message="nonce required for verification")), 400

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
                    if assignment:
                        _update_job_assignment(
                            job_id,
                            status="reward_settled",
                            result_data=result_data,
                            nonce=str(nonce),
                            reward_id=reward_id,
                        )
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
                if assignment:
                    _update_job_assignment(job_id, status="rejected")
                return jsonify(
                    error_payload(
                        code_key="PROOF_USED_OTHER_CLIENT",
                        message="Proof already used by another worker for this contract (task already completed)." + hint,
                        extra={"existing_client_prefix": existing_cid[:8] if existing_cid else None},
                    )
                ), 409

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
    if assignment:
        _update_job_assignment(
            job_id,
            status="completed_submitted",
            result_data=result_data,
            nonce=str(nonce),
            validation_started_at=time.time(),
        )
    if not runtime["verify"](client_id, contract_id, work_units_done, result_data, nonce):
        logger.warning("submit_work_verification_failed: client_id=%s... contract_id=%s (balance not updated)", client_id[:8], contract_id)
        if assignment:
            _, escrow_policy = _runtime_policies(runtime)
            if escrow_policy.get("enabled") and int(escrow_policy.get("penalty_percent_on_reject", 0) or 0) > 0:
                _try_penalize_escrow_for_job(
                    job_id,
                    penalty_percent=int(escrow_policy.get("penalty_percent_on_reject", 0) or 0),
                )
                _update_job_assignment(
                    job_id,
                    penalty_code=PENALTY_CODES["VERIFICATION_REJECT"],
                    penalty_reason="Failed deterministic verification",
                )
            bump_reputation(actor_id=client_id, role="worker", delta=-5, reason="verification_failed")
            _update_job_assignment(job_id, status="rejected", validation_finished_at=time.time())
        return jsonify(error_payload(code_key="VERIFICATION_FAILED", message="Work verification failed")), 400
    logger.info("submit_work: verification passed for client_id=%s... contract_id=%s", client_id[:8], contract_id)

    validation_policy, escrow_policy = _runtime_policies(runtime)
    validation_mode = validation_policy.get("mode")
    replication_factor = int(validation_policy.get("replication_factor", 1) or 1)
    quorum_threshold = int(validation_policy.get("quorum_threshold", replication_factor) or replication_factor)
    if (
        assignment
        and validation_mode in {"replicated", "challengeable"}
        and replication_factor > 1
        and assignment.get("replication_group_id")
    ):
        replication_decision = register_replication_submission(
            group_id=assignment.get("replication_group_id"),
            job_id=assignment.get("job_id"),
            client_id=client_id,
            result_data=result_data,
            artifact_manifest_hash=artifact_manifest_hash,
            attempt_id=attempt_id,
        )
        decision_status = (replication_decision.get("status") or "").strip()
        if decision_status == "pending":
            _update_job_assignment(
                job_id,
                status="awaiting_replication",
                replication_status="pending",
                replication_quorum_threshold=quorum_threshold,
            )
            return jsonify(
                {
                    "status": "pending_validation",
                    "replication": replication_decision,
                    "message": "Waiting for replicated submissions",
                    "code": "replication.pending",
                }
            ), 202
        if decision_status == "disputed":
            dispute = create_dispute(
                job_id=assignment.get("job_id"),
                contract_id=assignment.get("contract_id"),
                opened_by=client_id,
                reason="Replication quorum not reached",
                review_deadline_seconds=max(300, int(validation_policy.get("challenge_window_seconds", 0) or 3600)),
                appeal_deadline_seconds=3600,
            )
            if escrow_policy.get("enabled") and int(escrow_policy.get("penalty_percent_on_reject", 0) or 0) > 0:
                _try_penalize_escrow_for_job(
                    job_id,
                    penalty_percent=int(escrow_policy.get("penalty_percent_on_reject", 0) or 0),
                )
                _update_job_assignment(
                    job_id,
                    penalty_code=PENALTY_CODES["REPLICATION_REJECT"],
                    penalty_reason="Replication disputed and rejected",
                )
            bump_reputation(actor_id=client_id, role="worker", delta=-3, reason="replication_disputed")
            _update_job_assignment(
                job_id,
                status="rejected",
                replication_status="disputed",
                reject_reason="Replication dispute detected",
                reject_code="replication.disputed",
                dispute_id=dispute.get("dispute_id") if isinstance(dispute, dict) else None,
            )
            return jsonify(error_payload(
                code_key="REPLICATION_DISPUTED",
                message="Replication dispute detected. Open challenge to resolve.",
                extra={"replication": replication_decision, "dispute": dispute},
            )), 409
        if decision_status == "rejected":
            if escrow_policy.get("enabled") and int(escrow_policy.get("penalty_percent_on_reject", 0) or 0) > 0:
                _try_penalize_escrow_for_job(
                    job_id,
                    penalty_percent=int(escrow_policy.get("penalty_percent_on_reject", 0) or 0),
                )
                _update_job_assignment(
                    job_id,
                    penalty_code=PENALTY_CODES["REPLICATION_REJECT"],
                    penalty_reason="Replication quorum winner differs",
                )
            bump_reputation(actor_id=client_id, role="worker", delta=-2, reason="replication_rejected")
            _update_job_assignment(
                job_id,
                status="rejected",
                replication_status="rejected",
                reject_reason="Result rejected by replication quorum",
                reject_code="replication.rejected",
            )
            return jsonify(error_payload(
                code_key="REPLICATION_REJECTED",
                message="Result rejected by replicated validation consensus",
                extra={"replication": replication_decision},
            )), 409
        _update_job_assignment(
            job_id,
            replication_status="accepted",
            replication_winner_manifest_hash=replication_decision.get("winner_manifest_hash"),
            validation_finished_at=time.time(),
        )
        bump_reputation(actor_id=client_id, role="worker", delta=2, reason="replication_accepted")

    if assignment and validation_mode not in {"replicated", "challengeable"}:
        _update_job_assignment(job_id, validation_finished_at=time.time())

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

    # Транзакция point-награды (legacy): для рыночных контрактов не используем,
    # чтобы награда начислялась только в валютный кошелёк через settlement.
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
        "attempt_id": int(attempt_id),
        "result_data": result_data,
        "artifact_manifest_hash": artifact_manifest_hash,
        "fee": FEE_PER_WORK_RECEIPT,  # Экономическая модель: комиссия списывается с клиента после начисления награды
        "output_artifacts": normalized_artifacts,
    }
    reward_id = _reward_event_id(
        client_id=client_id,
        contract_id=contract_id,
        result_data=result_data,
        nonce=nonce,
    )
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
            # Для provider-контрактов награда идёт только в fiat-кошелёк
            # (contract_reward_settlement), а не в chain points.
            if runtime["kind"] != "provider":
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

    challenge_window_seconds = int(validation_policy.get("challenge_window_seconds", 0) or 0)
    release_after_success = not (
        validation_policy.get("mode") == "challengeable" and challenge_window_seconds > 0
    )

    if new_block:
        new_balance = blockchain.get_balance(client_id)
        logger.info("block_created: client_id=%s... reward=%s new_balance=%s block_index=%s",
                    client_id[:8], reward_amount, new_balance, new_block.index)
        if assignment:
            next_status = "reward_settled" if release_after_success else "challenge_window_open"
            updates = {"status": next_status, "reward_id": reward_id}
            if not release_after_success:
                updates["challenge_deadline_at"] = now_ts() + challenge_window_seconds
            _update_job_assignment(job_id, **updates)

    _push_block_to_peer(new_block)

    if assignment and escrow_policy.get("enabled"):
        if release_after_success:
            _, release_err = _try_release_escrow_for_job(job_id)
            if release_err:
                return jsonify({"error": f"Failed to release escrow: {release_err}"}), 500
        else:
            _update_job_assignment(job_id, escrow_status="held")

    return jsonify({
        "status": "success", 
        "reward_issued": reward_amount,
        "reward_currency": reward_currency,
        "challenge_window_open": bool(assignment and not release_after_success),
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
    country_code = (data.get("country_code") or "").strip() or None
    compliance = _compliance_bundle(
        client_id=client_id,
        amount=source_amount,
        currency=source_currency,
        country_code=country_code,
        operation="convert",
    )
    if _is_compliance_blocked_for_operation(
        operation="convert",
        amount=source_amount,
        gate_decision=(compliance.get("gate") or {}).get("decision"),
    ):
        return jsonify(
            {
                "error": "Conversion blocked by compliance policy",
                "compliance": {
                    **compliance,
                    "enforcement_mode": COMPLIANCE_ENFORCEMENT_MODE,
                    "operation": "convert",
                },
            }
        ), 409
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
        "compliance": {
            **compliance,
            "enforcement_mode": COMPLIANCE_ENFORCEMENT_MODE,
            "operation": "convert",
        },
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
    country_code = (data.get("country_code") or "").strip() or None
    compliance = _compliance_bundle(
        client_id=client_id,
        amount=amount,
        currency=currency,
        country_code=country_code,
        operation="withdrawal",
    )
    gate_result = compliance.get("gate") or {}
    if _is_compliance_blocked_for_operation(
        operation="withdrawal",
        amount=amount,
        gate_decision=gate_result.get("decision"),
    ):
        return jsonify(
            {
                "error": "Withdrawal blocked by compliance policy",
                "compliance": {
                    **compliance,
                    "enforcement_mode": COMPLIANCE_ENFORCEMENT_MODE,
                    "operation": "withdrawal",
                },
            }
        ), 409
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
    return jsonify(
        {
            "withdrawal": withdrawal,
            "wallet": get_wallet_from_chain(blockchain.chain, client_id),
            "compliance": {
                **compliance,
                "enforcement_mode": COMPLIANCE_ENFORCEMENT_MODE,
                "operation": "withdrawal",
            },
        }
    ), 201


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
    if error == "Sector not found":
        return jsonify({"error": error}), 404
    if error == "Insufficient wallet balance":
        return jsonify({"error": error}), 409
    if "sector_id is required" in (error or ""):
        return jsonify({"error": error}), 400
    return jsonify({"error": error}), 400


@app.route("/provider/sectors", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def provider_sectors():
    """API секторов поставщика: список и создание."""
    owner_client_id = get_client_id_from_auth()
    if owner_client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if request.method == "GET":
        rows = contract_market.list_owner_sectors(owner_client_id)
        return jsonify(rows), 200

    data = request.get_json(silent=True) or {}
    sector_name = (data.get("sector_name") or "").strip()
    organization_name = (data.get("organization_name") or "").strip()
    compute_domain = (data.get("compute_domain") or "").strip()
    description = (data.get("description") or "").strip()
    if not sector_name:
        return jsonify({"error": "sector_name is required"}), 400
    try:
        created = contract_market.create_sector(
            owner_client_id=owner_client_id,
            sector_name=sector_name,
            organization_name=organization_name,
            compute_domain=compute_domain,
            description=description,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(created), 201


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
        sector_id_filter = (request.args.get("sector_id") or "").strip() or None
        if sector_id_filter:
            sector = contract_market.get_sector(sector_id_filter)
            if not sector:
                return jsonify({"error": "Sector not found"}), 404
            if sector.get("owner_client_id") != provider_client_id:
                return jsonify({"error": "Forbidden"}), 403
        runtime_contracts = contract_market.list_provider_contracts(
            provider_client_id,
            sector_id=sector_id_filter,
        )
        chain_stats = blockchain.get_contract_stats()
        onchain_rows = list_contracts_onchain(blockchain.chain, provider_client_id=provider_client_id)
        onchain_by_id = {row.get("contract_id"): row for row in onchain_rows}
        for row in runtime_contracts:
            cid = row.get("contract_id")
            stats = chain_stats.get(cid, {})
            target = int(row.get("target_total_work_units") or 0)
            total_done = int(stats.get("total_work_done", 0))
            completion_pct = min(100.0, (total_done / target * 100)) if target else 0.0
            row["total_work_done"] = total_done
            row["jobs_count"] = int(stats.get("jobs_count", 0))
            row["completion_pct"] = round(completion_pct, 1)
            row["active_workers"] = _active_workers_count(cid)
            row["remaining_volume"] = max(0, target - total_done)
            row["free_volume"] = row["remaining_volume"]
            row["onchain"] = onchain_by_id.get(row.get("contract_id"))
        return jsonify(runtime_contracts), 200

    data = request.get_json(silent=True) or {}
    sector_id = (data.get("sector_id") or "").strip() or None
    task_name = (data.get("task_name") or "").strip()
    task_description = (data.get("task_description") or "").strip()
    task_category = (data.get("task_category") or "").strip() or "Пользовательская"
    computation_type = (data.get("computation_type") or "simple_pow").strip()
    benchmark_meta = data.get("benchmark_meta")
    if benchmark_meta is None:
        benchmark_meta = {}
    if not isinstance(benchmark_meta, dict):
        return jsonify({"error": "benchmark_meta must be an object"}), 400
    # Stage 2: task-class policy presets with optional manual override.
    policy_bundle = build_policy_bundle(
        requested_task_class=data.get("task_class"),
        computation_type=computation_type,
        task_name=task_name,
        task_category=task_category,
        benchmark_meta=benchmark_meta,
        raw_validation_policy=data.get("validation_policy"),
        raw_escrow_policy=data.get("escrow_policy"),
    )
    validation_policy = policy_bundle["validation_policy"]
    escrow_policy = policy_bundle["escrow_policy"]
    policy_bucket = benchmark_meta.get("decentralized_policy")
    if not isinstance(policy_bucket, dict):
        policy_bucket = {}
    policy_bucket["task_class"] = policy_bundle["task_class"]
    policy_bucket["task_class_source"] = policy_bundle["task_class_source"]
    policy_bucket["validation_style"] = policy_bundle["validation_style"]
    policy_bucket["validation_policy"] = validation_policy
    policy_bucket["escrow_policy"] = escrow_policy
    benchmark_meta["decentralized_policy"] = policy_bucket

    if not sector_id:
        return jsonify({"error": "sector_id is required: create/select sector first"}), 400

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
            sector_id=sector_id,
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
            benchmark_meta=benchmark_meta,
        )
    except ValueError as exc:
        return _provider_contract_error_response(str(exc))

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
            "sector_id": created.get("sector_id"),
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


@app.route("/provider/task-classes", methods=["GET"])
@limiter.limit("60 per minute")
def provider_task_classes():
    """Каталог поддерживаемых классов задач и рекомендуемых policy-профилей."""
    provider_client_id = get_client_id_from_auth()
    if provider_client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    return jsonify({"task_classes": list_task_class_profiles()}), 200


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
    return jsonify({"status": "ok", "protocol_version": NETWORK_PROTOCOL_VERSION}), 200


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
        stage3_slo = _stage3_observability_metrics()
        governance = governance_snapshot()
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
        "protocol_version": NETWORK_PROTOCOL_VERSION,
        "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
        "slo": stage3_slo,
        "governance": governance,
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

    known_client_ids = set(blockchain.balances.keys())
    party_fields = ("to", "from", "client_id", "provider_client_id", "worker_client_id")
    for block in blockchain.chain:
        for tx in block.transactions:
            for field in party_fields:
                value = tx.get(field)
                if isinstance(value, str) and value:
                    known_client_ids.add(value)

    resolved_client_id = client_id
    if client_id not in known_client_ids:
        matches = sorted(cid for cid in known_client_ids if cid.startswith(client_id))
        if len(matches) == 1:
            resolved_client_id = matches[0]
        elif len(matches) > 1:
            return jsonify({
                "error": "Ambiguous client_id prefix",
                "matches": matches[:10],
            }), 400

    chain_points = blockchain.get_balance(resolved_client_id)
    wallet_info = get_wallet_from_chain(blockchain.chain, resolved_client_id)
    transactions = []
    for block in blockchain.chain:
        for tx in block.transactions:
            involved = any(tx.get(field) == resolved_client_id for field in party_fields)
            if involved:
                transactions.append({
                    "block_index": block.index,
                    "block_hash": block.hash,
                    "tx": tx,
                })
    transactions.reverse()
    payload = {
        "client_id": resolved_client_id,
        "balance": chain_points,
        "chain_points": chain_points,
        "fiat_wallet": wallet_info.get("balances", {}),
        "fiat_total_rub_estimate": wallet_info.get("total_rub_estimate", 0),
        "transactions": transactions,
    }
    if resolved_client_id != client_id:
        payload["resolved_from"] = client_id
    return jsonify(payload), 200


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
            "sector_id": contract_record.get("sector_id"),
            "sector_name": contract_record.get("sector_name"),
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
    client_id = get_client_id_from_auth()
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


@app.route("/job/<job_id>", methods=["GET"])
@limiter.limit("120 per minute")
def job_status(job_id):
    """Статус assignment'а задачи (для воркера/приложения)."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    assignment = _get_job_assignment((job_id or "").strip())
    if not assignment:
        return jsonify({"error": "Job not found"}), 404
    if assignment.get("client_id") != client_id:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(assignment), 200


@app.route("/job/<job_id>/challenge", methods=["POST"])
@limiter.limit("30 per minute")
def job_open_challenge(job_id):
    """Открыть спор по уже засчитанной задаче в challengeable-режиме."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    assignment = _get_job_assignment((job_id or "").strip())
    if not assignment:
        return jsonify(error_payload(code_key="JOB_NOT_FOUND", message="Job not found")), 404
    if assignment.get("status") not in {"challenge_window_open", "reward_settled", "challenged"}:
        return jsonify(error_payload(code_key="CHALLENGE_DISABLED", message="Job is not in challenge state")), 409
    runtime = _resolve_contract_runtime(assignment.get("contract_id"), allow_inactive_dynamic=True)
    if not runtime:
        return jsonify({"error": "Contract runtime not found"}), 404
    validation_policy, _ = _runtime_policies(runtime)
    if validation_policy.get("mode") != "challengeable":
        return jsonify(error_payload(code_key="CHALLENGE_DISABLED", message="Challenge is disabled for this contract")), 409
    deadline_at = int(assignment.get("challenge_deadline_at", 0) or 0)
    if deadline_at and now_ts() > deadline_at:
        return jsonify(error_payload(code_key="CHALLENGE_WINDOW_EXPIRED", message="Challenge window expired")), 409
    data = request.get_json(silent=True) or {}
    reason = (data.get("reason") or "").strip() or "manual_challenge"
    remaining_window = max(0, deadline_at - now_ts()) if deadline_at else int(
        validation_policy.get("challenge_window_seconds", 0) or 0
    )
    challenge, open_err = open_challenge(
        job_id=assignment.get("job_id"),
        contract_id=assignment.get("contract_id"),
        opened_by=client_id,
        reason=reason,
        window_seconds=remaining_window,
    )
    if open_err:
        return jsonify(error_payload(code_key="CHALLENGE_ALREADY_OPEN", message=open_err)), 409
    dispute = create_dispute(
        job_id=assignment.get("job_id"),
        contract_id=assignment.get("contract_id"),
        opened_by=client_id,
        reason=reason,
        review_deadline_seconds=max(300, remaining_window or 3600),
        appeal_deadline_seconds=3600,
    )
    if dispute:
        transition_dispute(
            dispute_id=dispute.get("dispute_id"),
            event="start_review",
            actor_id=client_id,
            payload={"source": "job_open_challenge"},
        )
    _update_job_assignment(
        assignment.get("job_id"),
        status="challenged",
        challenge_id=challenge.get("challenge_id"),
        dispute_id=(dispute or {}).get("dispute_id"),
    )
    return jsonify({"challenge": challenge, "dispute": dispute}), 201


@app.route("/job/<job_id>/challenge/finalize", methods=["POST"])
@limiter.limit("30 per minute")
def job_finalize_challenge_window(job_id):
    """Финализировать challenge-window: release escrow, если споров нет."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    assignment = _get_job_assignment((job_id or "").strip())
    if not assignment:
        return jsonify({"error": "Job not found"}), 404
    if assignment.get("status") not in {"challenge_window_open", "challenged"}:
        return jsonify({"error": "Job is not in challenge-window state"}), 409
    runtime = _resolve_contract_runtime(assignment.get("contract_id"), allow_inactive_dynamic=True)
    if not runtime:
        return jsonify({"error": "Contract runtime not found"}), 404
    provider_client_id = (runtime.get("record") or {}).get("provider_client_id")
    if client_id not in {assignment.get("client_id"), provider_client_id}:
        return jsonify({"error": "Forbidden"}), 403
    open_chg = get_open_challenge_by_job(assignment.get("job_id"))
    if open_chg:
        return jsonify({"error": "Open challenge exists", "challenge": open_chg}), 409
    deadline_at = int(assignment.get("challenge_deadline_at", 0) or 0)
    if deadline_at and now_ts() < deadline_at:
        return jsonify({"error": "Challenge window is still open"}), 409
    hold = get_escrow_hold_by_job(assignment.get("job_id"))
    if hold and hold.get("status") == "held":
        _, release_err = _try_release_escrow_for_job(assignment.get("job_id"))
        if release_err:
            return jsonify({"error": release_err}), 500
    updated = _update_job_assignment(assignment.get("job_id"), status="reward_settled", escrow_status="released")
    return jsonify({"status": "finalized", "job": updated}), 200


@app.route("/challenges/<challenge_id>/resolve", methods=["POST"])
@limiter.limit("30 per minute")
def challenge_resolve(challenge_id):
    """Решение спора поставщиком контракта."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    challenge = get_challenge((challenge_id or "").strip())
    if not challenge:
        return jsonify(error_payload(code_key="JOB_NOT_FOUND", message="Challenge not found")), 404
    assignment = _get_job_assignment(challenge.get("job_id"))
    if not assignment:
        return jsonify({"error": "Job not found"}), 404
    runtime = _resolve_contract_runtime(assignment.get("contract_id"), allow_inactive_dynamic=True)
    if not runtime:
        return jsonify({"error": "Contract runtime not found"}), 404
    provider_client_id = (runtime.get("record") or {}).get("provider_client_id")
    if client_id != provider_client_id:
        return jsonify({"error": "Only contract provider can resolve challenge"}), 403
    data = request.get_json(silent=True) or {}
    decision = (data.get("decision") or "").strip().lower()
    resolved, resolve_err = resolve_challenge(
        challenge_id=challenge.get("challenge_id"),
        resolved_by=client_id,
        decision=decision,
    )
    if resolve_err:
        return jsonify({"error": resolve_err}), 409
    _, escrow_policy = _runtime_policies(runtime)
    if decision == "accept_worker":
        _, release_err = _try_release_escrow_for_job(assignment.get("job_id"))
        if release_err:
            return jsonify({"error": release_err}), 500
        bump_reputation(actor_id=assignment.get("client_id"), role="worker", delta=2, reason="challenge_accept")
        _update_job_assignment(assignment.get("job_id"), status="reward_settled", escrow_status="released")
    if decision == "reject_worker":
        _, penalty_err = _try_penalize_escrow_for_job(
            assignment.get("job_id"),
            penalty_percent=int(escrow_policy.get("penalty_percent_on_reject", 0) or 0),
        )
        if penalty_err:
            return jsonify({"error": penalty_err}), 500
        bump_reputation(actor_id=assignment.get("client_id"), role="worker", delta=-4, reason="challenge_reject")
        _update_job_assignment(
            assignment.get("job_id"),
            status="rejected",
            escrow_status="penalized",
            penalty_code=PENALTY_CODES["CHALLENGE_REJECT"],
            penalty_reason="Challenge resolved against worker",
            reject_code="challenge.reject_worker",
            reject_reason="Challenge resolved against worker",
        )
    bump_reputation(actor_id=client_id, role="validator", delta=1, reason="challenge_resolve")
    # Sync dispute machine if dispute_id is known.
    dispute_id = assignment.get("dispute_id")
    if dispute_id:
        transition_dispute(
            dispute_id=dispute_id,
            event="resolve_accept" if decision == "accept_worker" else "resolve_reject",
            actor_id=client_id,
            payload={"challenge_id": challenge_id},
        )
    return jsonify({"challenge": resolved, "dispute_id": dispute_id}), 200


@app.route("/replication/<group_id>/verdict", methods=["POST"])
@limiter.limit("30 per minute")
def replication_add_verdict(group_id):
    """Independent validator verdict for replication group arbitration."""
    validator_id = get_client_id_from_auth()
    if validator_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if not governance_is_validator_admitted(validator_client_id=validator_id):
        return jsonify({"error": "Validator is not admitted by governance"}), 403
    data = request.get_json(silent=True) or {}
    decision = (data.get("decision") or "").strip().lower()
    reason = (data.get("reason") or "").strip()
    verdict, err = add_validator_verdict(
        group_id=(group_id or "").strip(),
        validator_client_id=validator_id,
        decision=decision,
        reason=reason,
        weight=int(data.get("weight", 1) or 1),
    )
    if err:
        return jsonify({"error": err}), 400
    bump_reputation(actor_id=validator_id, role="validator", delta=1, reason="validator_verdict_submitted")
    summary = summarize_validator_verdicts((group_id or "").strip())
    return jsonify({"verdict": verdict, "summary": summary}), 201


@app.route("/replication/<group_id>/verdicts", methods=["GET"])
@limiter.limit("60 per minute")
def replication_verdicts(group_id):
    validator_id = get_client_id_from_auth()
    if validator_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    return jsonify(summarize_validator_verdicts((group_id or "").strip())), 200


@app.route("/reputation/<role>/<actor_id>", methods=["GET"])
@limiter.limit("60 per minute")
def reputation_get(role, actor_id):
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    return jsonify(get_reputation(actor_id=(actor_id or "").strip(), role=(role or "").strip().lower())), 200


@app.route("/disputes/<dispute_id>", methods=["GET"])
@limiter.limit("60 per minute")
def dispute_get(dispute_id):
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    enforce_dispute_deadlines()
    row = get_dispute((dispute_id or "").strip())
    if not row:
        return jsonify({"error": "Dispute not found"}), 404
    return jsonify(row), 200


@app.route("/disputes/<dispute_id>/event", methods=["POST"])
@limiter.limit("30 per minute")
def dispute_event(dispute_id):
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    enforce_dispute_deadlines()
    data = request.get_json(silent=True) or {}
    event = (data.get("event") or "").strip()
    updated, err = transition_dispute(
        dispute_id=(dispute_id or "").strip(),
        event=event,
        actor_id=requester,
        payload=data.get("payload") if isinstance(data.get("payload"), dict) else {},
    )
    if err:
        return jsonify({"error": err}), 409
    return jsonify(updated), 200


@app.route("/compliance/evaluate", methods=["POST"])
@limiter.limit("30 per minute")
def compliance_evaluate():
    """
    Stage-3 preparation endpoint: unified KYC/AML/Jurisdiction evaluation interface.
    Current behavior is stub-only and non-blocking.
    """
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    target_client_id = (data.get("client_id") or requester).strip()
    try:
        amount = int(data.get("amount", 0) or 0)
    except (TypeError, ValueError):
        amount = 0
    currency = (data.get("currency") or "RUB").strip().upper()
    country_code = (data.get("country_code") or "").strip() or None
    operation = (data.get("operation") or "withdrawal").strip().lower()
    compliance = _compliance_bundle(
        client_id=target_client_id,
        amount=amount,
        currency=currency,
        country_code=country_code,
        operation=operation,
    )
    gate = compliance.get("gate") or {}
    blocked = _is_compliance_blocked_for_operation(
        operation=operation,
        amount=amount,
        gate_decision=gate.get("decision"),
    )
    return jsonify(
        {
            **compliance,
            "gate": gate,
            "operation": operation,
            "blocked": blocked,
            "enforcement_mode": COMPLIANCE_ENFORCEMENT_MODE,
            "status": "active",
        }
    ), 200


@app.route("/compliance/provider/cases", methods=["GET"])
@limiter.limit("60 per minute")
def compliance_provider_cases():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if COMPLIANCE_PROVIDER_MODE != "simulated":
        return jsonify({"error": "Simulated provider is disabled"}), 409
    simulated_process_cases()
    status = (request.args.get("status") or "").strip() or None
    limit = request.args.get("limit", 100)
    rows = simulated_list_cases(limit=limit, status=status)
    return jsonify({"cases": rows, "provider_mode": COMPLIANCE_PROVIDER_MODE}), 200


@app.route("/compliance/provider/cases/<case_id>", methods=["GET"])
@limiter.limit("60 per minute")
def compliance_provider_case(case_id):
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if COMPLIANCE_PROVIDER_MODE != "simulated":
        return jsonify({"error": "Simulated provider is disabled"}), 409
    simulated_process_cases()
    row = simulated_get_case((case_id or "").strip())
    if not row:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"case": row, "provider_mode": COMPLIANCE_PROVIDER_MODE}), 200


@app.route("/compliance/provider/webhooks", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def compliance_provider_webhooks():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    if COMPLIANCE_PROVIDER_MODE != "simulated":
        return jsonify({"error": "Simulated provider is disabled"}), 409
    if request.method == "POST":
        events = simulated_process_cases()
        return jsonify({"dispatched": events, "count": len(events)}), 200
    limit = request.args.get("limit", 100)
    rows = simulated_list_webhook_events(limit=limit)
    return jsonify({"events": rows}), 200


@app.route("/network/governance/info", methods=["GET"])
@limiter.limit("60 per minute")
def governance_info():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    return jsonify(
        {
            "node_id": NODE_ID,
            "protocol_version": NETWORK_PROTOCOL_VERSION,
            "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
            "governance": governance_snapshot(),
        }
    ), 200


@app.route("/network/governance/admission", methods=["POST"])
@limiter.limit("30 per minute")
def governance_admission():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    if GOVERNANCE_ADMISSION_TOKEN:
        if str(data.get("admission_token") or "").strip() != GOVERNANCE_ADMISSION_TOKEN:
            return jsonify({"error": "Invalid admission token"}), 403
    node_id = (data.get("node_id") or "").strip()
    rec, err = governance_admit_node(
        node_id=node_id,
        admitted_by=requester,
        node_meta=data.get("meta") if isinstance(data.get("meta"), dict) else {},
    )
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"node": rec, "governance": governance_snapshot()}), 201


@app.route("/network/governance/validators/admit", methods=["POST"])
@limiter.limit("30 per minute")
def governance_admit_validator_endpoint():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    if GOVERNANCE_ADMISSION_TOKEN:
        if str(data.get("admission_token") or "").strip() != GOVERNANCE_ADMISSION_TOKEN:
            return jsonify({"error": "Invalid admission token"}), 403
    validator_client_id = (data.get("validator_client_id") or "").strip()
    rec, err = governance_admit_validator(
        validator_client_id=validator_client_id,
        admitted_by=requester,
        validator_meta=data.get("meta") if isinstance(data.get("meta"), dict) else {},
    )
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"validator": rec, "governance": governance_snapshot()}), 201


@app.route("/network/governance/rollout/propose", methods=["POST"])
@limiter.limit("30 per minute")
def governance_rollout_propose():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    version = (data.get("protocol_version") or "").strip()
    if version not in SUPPORTED_PROTOCOL_VERSIONS:
        return jsonify({"error": "Unsupported protocol_version"}), 400
    try:
        required_acks = int(data.get("required_acks", max(1, len(NODE_IDS))) or max(1, len(NODE_IDS)))
    except (TypeError, ValueError):
        required_acks = max(1, len(NODE_IDS))
    rollout, err = governance_propose_rollout(
        protocol_version=version,
        proposed_by=requester,
        required_acks=required_acks,
    )
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"rollout": rollout}), 201


@app.route("/network/governance/rollout/ack", methods=["POST"])
@limiter.limit("30 per minute")
def governance_rollout_ack():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    rollout, err = governance_ack_rollout(node_id=NODE_ID)
    if err:
        return jsonify({"error": err}), 409
    return jsonify({"rollout": rollout, "acked_by": requester, "node_id": NODE_ID}), 200


@app.route("/network/governance/rollout/finalize", methods=["POST"])
@limiter.limit("30 per minute")
def governance_rollout_finalize():
    requester = get_client_id_from_auth()
    if requester is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    rollout, err = governance_finalize_rollout(finalized_by=requester)
    if err:
        return jsonify({"error": err}), 409
    return jsonify({"rollout": rollout}), 200


@app.route("/jobs/snapshot", methods=["GET"])
@require_node_secret
def jobs_snapshot():
    """Снимок assignment'ов для синхронизации между узлами."""
    _expire_job_assignments()
    with _job_assignments_lock:
        rows = [dict(v) for v in _job_assignments.values()]
    return jsonify(rows), 200


@app.route("/runtime/snapshot", methods=["GET"])
@require_node_secret
def runtime_state_snapshot():
    """Снимок runtime state для синхронизации между оркестраторами."""
    return jsonify(export_runtime_state()), 200


@app.route("/jobs/my", methods=["GET"])
@limiter.limit("120 per minute")
def jobs_my():
    """Список assignment'ов текущего вычислителя для диагностики desktop-агента."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    _expire_job_assignments()
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(500, limit))
    with _job_assignments_lock:
        rows = [
            dict(v)
            for v in _job_assignments.values()
            if v.get("client_id") == client_id
        ]
    rows.sort(key=lambda x: float(x.get("updated_at", 0) or 0), reverse=True)
    return jsonify({"jobs": rows[:limit]}), 200


@app.route("/job/<job_id>/reassign", methods=["POST"])
@limiter.limit("60 per minute")
def job_reassign(job_id):
    """Переиздать просроченную задачу тому же/другому клиенту."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    source = _get_job_assignment((job_id or "").strip())
    if not source:
        return jsonify({"error": "Job not found"}), 404
    if source.get("client_id") != client_id:
        return jsonify({"error": "Forbidden"}), 403
    if source.get("status") != "expired":
        return jsonify({"error": "Only expired jobs can be reassigned"}), 409
    expired_at = float(source.get("expired_at", 0) or 0)
    if expired_at and (time.time() - expired_at) < JOB_REASSIGN_COOLDOWN_SECONDS:
        wait_for = int(JOB_REASSIGN_COOLDOWN_SECONDS - (time.time() - expired_at))
        return jsonify({"error": f"Reassign cooldown active, retry in {max(1, wait_for)}s"}), 409
    current_reassign_count = int(source.get("reassign_count", 0) or 0)
    if current_reassign_count >= JOB_MAX_REASSIGN_ATTEMPTS:
        return jsonify({"error": "Max reassignment attempts reached"}), 409
    spec, issue_err = _issue_task_for_client(
        client_id,
        contract_id=source.get("contract_id"),
        sector_id=None,
    )
    if issue_err:
        return jsonify({"error": issue_err}), 409
    _update_job_assignment(source.get("job_id"), status="reassigned", reassigned_to=spec.get("job_id"))
    _update_job_assignment(
        spec.get("job_id"),
        parent_job_id=source.get("job_id"),
        reassign_count=current_reassign_count + 1,
    )
    return jsonify(spec), 200


@app.route("/agent/get_task", methods=["POST"])
@limiter.limit("60 per minute")
def agent_get_task():
    """Desktop-agent: взять задачу по сектору/контракту."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    contract_id = (data.get("contract_id") or "").strip() or None
    sector_id = (data.get("sector_id") or "").strip() or None
    scheduler_profile = (data.get("scheduler_profile") or "adaptive").strip().lower()
    device_capabilities = data.get("device_capabilities") if isinstance(data.get("device_capabilities"), dict) else {}
    spec, issue_err = _issue_task_for_client(
        client_id,
        contract_id=contract_id,
        sector_id=sector_id,
        device_capabilities=device_capabilities,
        scheduler_profile=scheduler_profile,
    )
    if issue_err:
        code = 400 if contract_id else 503
        if "selected sector" in issue_err:
            code = 400
        return jsonify({"error": issue_err}), code
    return jsonify(spec), 200


@app.route("/agent/job/<job_id>/heartbeat", methods=["POST"])
@limiter.limit("120 per minute")
def agent_job_heartbeat(job_id):
    """Desktop-agent: продлить lease задачи."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    assignment = _get_job_assignment((job_id or "").strip())
    if not assignment:
        return jsonify({"error": "Job not found"}), 404
    if assignment.get("client_id") != client_id:
        return jsonify({"error": "Forbidden"}), 403
    if assignment.get("status") in JOB_STATUSES_FINAL:
        return jsonify({"error": f"Job is {assignment.get('status')}"}), 409
    updated = _update_job_assignment(
        assignment.get("job_id"),
        expires_at=time.time() + JOB_TTL_SECONDS,
    )
    return jsonify(updated), 200


@app.route("/agent/version", methods=["GET"])
def agent_version():
    """Публичная версия desktop-агента для автообновления."""
    return jsonify(
        {
            "latest_version": DESKTOP_AGENT_LATEST_VERSION,
            "download_url": "/download/desktop-agent",
        }
    ), 200


@app.route("/agent/devices/register", methods=["POST"])
@limiter.limit("120 per minute")
def agent_devices_register():
    """Desktop-agent: регистрация/обновление устройства."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    rec, err = register_or_update_device(
        client_id=client_id,
        device_id=(data.get("device_id") or "").strip() or None,
        device_name=(data.get("device_name") or "").strip() or None,
        agent_version=(data.get("agent_version") or "").strip() or None,
        capabilities=data.get("device_capabilities") if isinstance(data.get("device_capabilities"), dict) else None,
    )
    if err:
        return jsonify({"error": err}), 400 if err != "Forbidden" else 403
    return jsonify(rec), 200


@app.route("/agent/devices/heartbeat", methods=["POST"])
@limiter.limit("240 per minute")
def agent_devices_heartbeat():
    """Desktop-agent: heartbeat устройства."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    rec, err = heartbeat_device(
        client_id=client_id,
        device_id=(data.get("device_id") or "").strip(),
        agent_version=(data.get("agent_version") or "").strip() or None,
        capabilities=data.get("device_capabilities") if isinstance(data.get("device_capabilities"), dict) else None,
    )
    if err:
        status = 404
        if err == "Forbidden":
            status = 403
        if err == "device_id is required":
            status = 400
        if err == "Device is disabled":
            status = 409
        return jsonify({"error": err}), status
    return jsonify(rec), 200


@app.route("/agent/devices/my", methods=["GET"])
@limiter.limit("120 per minute")
def agent_devices_my():
    """Список устройств текущего вычислителя."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    rows = list_devices_for_client(client_id)
    return jsonify({"devices": rows}), 200


@app.route("/agent/devices/<device_id>/disable", methods=["POST"])
@limiter.limit("60 per minute")
def agent_devices_disable(device_id):
    """Включить/выключить устройство вычислителя."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    data = request.get_json(silent=True) or {}
    rec, err = set_device_disabled(
        client_id=client_id,
        device_id=(device_id or "").strip(),
        is_disabled=bool(data.get("is_disabled", True)),
    )
    if err:
        return jsonify({"error": err}), 404 if err == "Device not found" else 403
    return jsonify(rec), 200


@app.route("/agent/job/<job_id>/complete_ack", methods=["POST"])
@limiter.limit("120 per minute")
def agent_job_complete_ack(job_id):
    """Desktop-agent: локальное подтверждение завершения вычисления до submit_work."""
    client_id = get_client_id_from_auth()
    if client_id is None:
        return jsonify({"error": "Missing or invalid Authorization (Bearer api_key)"}), 401
    assignment = _get_job_assignment((job_id or "").strip())
    if not assignment:
        return jsonify({"error": "Job not found"}), 404
    if assignment.get("client_id") != client_id:
        return jsonify({"error": "Forbidden"}), 403
    if assignment.get("status") in JOB_STATUSES_FINAL:
        return jsonify({"error": f"Job is {assignment.get('status')}"}), 409
    data = request.get_json(silent=True) or {}
    result_preview = (data.get("result_data") or "")[:64] or None
    nonce_preview = (str(data.get("nonce")) if data.get("nonce") is not None else None)
    updated = _update_job_assignment(
        assignment.get("job_id"),
        status="completed_local",
        result_data=result_preview,
        nonce=nonce_preview,
    )
    return jsonify(updated), 200


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
        client_id = get_client_id_from_auth()
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


@app.route("/download/desktop-agent", methods=["GET"])
def download_desktop_agent():
    """Скачать desktop-агент как zip-архив."""
    app_dir = os.path.dirname(os.path.abspath(__file__))
    desktop_candidates = [
        os.path.join(os.path.dirname(app_dir), "desktop_agent"),
        os.path.join(app_dir, "desktop_agent"),
    ]
    shared_candidates = [
        os.path.join(os.path.dirname(app_dir), "shared"),
        os.path.join(app_dir, "shared"),
    ]
    desktop_dir = next((path for path in desktop_candidates if os.path.isdir(path)), "")
    shared_dir = next((path for path in shared_candidates if os.path.isdir(path)), "")
    if not desktop_dir:
        return jsonify({"error": "Desktop agent bundle not found on server"}), 404
    if not shared_dir:
        return jsonify({"error": "Shared module bundle not found on server"}), 404

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(desktop_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for file_name in files:
                if file_name.endswith((".pyc", ".pyo")):
                    continue
                abs_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(abs_path, desktop_dir)
                zf.write(abs_path, arcname=os.path.join("desktop_agent", rel_path))
        for root, dirs, files in os.walk(shared_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for file_name in files:
                if file_name.endswith((".pyc", ".pyo")):
                    continue
                abs_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(abs_path, shared_dir)
                zf.write(abs_path, arcname=os.path.join("shared", rel_path))
    archive.seek(0)
    return send_file(
        archive,
        mimetype="application/zip",
        as_attachment=True,
        download_name="desktop_agent.zip",
    )


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
    prev_last_index = blockchain.get_last_block().index if blockchain.chain else -1
    ok, err = blockchain.add_block_from_peer(data)
    if ok:
        # Важно: пересылаем дальше только реально новый блок.
        # Иначе дубликаты (ok=True для идемпотентности) начинают "пинг-понг"
        # между узлами и забивают /receive_block до 429.
        current_last_index = blockchain.get_last_block().index if blockchain.chain else -1
        is_new_block = current_last_index > prev_last_index
        if PEER_URL and is_new_block:
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

    debug_mode = os.environ.get("FLASK_DEBUG", "false").strip().lower() in ("1", "true", "yes", "on")
    if debug_mode:
        logger.warning("FLASK_DEBUG is enabled (use only for local development)")
    if not NODE_SECRET and not debug_mode:
        logger.error("NODE_SECRET is not set; remote synchronization endpoints are disabled. Set NODE_SECRET for non-local environments.")
        raise RuntimeError("NODE_SECRET must be set when FLASK_DEBUG is disabled")
    app.run(host="0.0.0.0", port=5000, debug=debug_mode, ssl_context=ssl_context)
