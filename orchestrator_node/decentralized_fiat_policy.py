"""
Policy helpers for decentralized-compute + fiat settlement migration.

Stage 1 goals:
- keep existing fiat ledger unchanged;
- formalize validation/replication policy in contract metadata;
- formalize escrow/penalty policy for future settlement workflow.
"""

from copy import deepcopy


DEFAULT_VALIDATION_POLICY = {
    "mode": "deterministic",  # deterministic | replicated | challengeable
    "replication_factor": 1,
    "quorum_threshold": 1,  # M in M-of-N
    "challenge_window_seconds": 0,
}

DEFAULT_ESCROW_POLICY = {
    "enabled": False,
    "worker_collateral": 0,  # fiat units in contract currency
    "penalty_percent_on_reject": 0,  # 0..100
}

TASK_CLASS_PROFILES = {
    # Climate, astrophysics, fluid/MHD and similar long-running simulations.
    "scientific_simulation": {
        "title": "Scientific simulation",
        "domains": ["climate", "astrophysics", "mhd", "radiative", "gravitational_waves"],
        "validation_policy": {
            "mode": "challengeable",
            "replication_factor": 2,
            "challenge_window_seconds": 2 * 3600,
        },
        "escrow_policy": {
            "enabled": True,
            "worker_collateral": 5,
            "penalty_percent_on_reject": 25,
        },
        "validation_style": "tolerance_or_invariant",
    },
    # Molecular dynamics and protein structure prediction workloads.
    "biomedical_modeling": {
        "title": "Biomedical modeling",
        "domains": ["molecular_dynamics", "protein_structure"],
        "validation_policy": {
            "mode": "challengeable",
            "replication_factor": 2,
            "challenge_window_seconds": 4 * 3600,
        },
        "escrow_policy": {
            "enabled": True,
            "worker_collateral": 8,
            "penalty_percent_on_reject": 30,
        },
        "validation_style": "stochastic_or_metric",
    },
    # Deep learning / training / inference with framework pipelines.
    "ai_training": {
        "title": "AI training",
        "domains": ["deep_learning", "llm", "distributed_training"],
        "validation_policy": {
            "mode": "challengeable",
            "replication_factor": 2,
            "challenge_window_seconds": 6 * 3600,
        },
        "escrow_policy": {
            "enabled": True,
            "worker_collateral": 10,
            "penalty_percent_on_reject": 35,
        },
        "validation_style": "metric_and_reproducibility",
    },
    # Monte-Carlo/risk/quant and signal processing pipelines.
    "data_analytics": {
        "title": "Data analytics and risk",
        "domains": ["financial_simulation", "risk_analysis", "signal_processing"],
        "validation_policy": {
            "mode": "replicated",
            "replication_factor": 2,
            "challenge_window_seconds": 0,
        },
        "escrow_policy": {
            "enabled": True,
            "worker_collateral": 4,
            "penalty_percent_on_reject": 20,
        },
        "validation_style": "deterministic_or_tolerance",
    },
    # Deterministic quick checks / baseline workloads.
    "deterministic_baseline": {
        "title": "Deterministic baseline",
        "domains": ["pow", "sanity", "smoke_test"],
        "validation_policy": {
            "mode": "deterministic",
            "replication_factor": 1,
            "challenge_window_seconds": 0,
        },
        "escrow_policy": {
            "enabled": False,
            "worker_collateral": 0,
            "penalty_percent_on_reject": 0,
        },
        "validation_style": "bitwise_or_hash_match",
    },
}


def _to_int(value, fallback):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _to_bool(value, fallback):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"1", "true", "yes"}:
            return True
        if low in {"0", "false", "no"}:
            return False
    return fallback


def sanitize_validation_policy(raw_policy):
    """
    Normalize validation policy with safe defaults.
    Non-breaking: unknown/invalid values fallback to deterministic mode.
    """
    policy = deepcopy(DEFAULT_VALIDATION_POLICY)
    if not isinstance(raw_policy, dict):
        return policy
    mode = str(raw_policy.get("mode", policy["mode"])).strip().lower()
    if mode not in {"deterministic", "replicated", "challengeable"}:
        mode = "deterministic"
    replication_factor = max(1, min(5, _to_int(raw_policy.get("replication_factor"), policy["replication_factor"])))
    quorum_threshold = max(1, min(replication_factor, _to_int(raw_policy.get("quorum_threshold"), replication_factor)))
    challenge_window_seconds = max(0, min(7 * 24 * 3600, _to_int(raw_policy.get("challenge_window_seconds"), 0)))
    if mode == "deterministic":
        replication_factor = 1
        quorum_threshold = 1
        challenge_window_seconds = 0
    policy["mode"] = mode
    policy["replication_factor"] = replication_factor
    policy["quorum_threshold"] = quorum_threshold
    policy["challenge_window_seconds"] = challenge_window_seconds
    return policy


def sanitize_escrow_policy(raw_policy):
    """
    Normalize escrow/penalty policy for fiat workflow.
    Stage 1 stores policy only (execution path is introduced in later stages).
    """
    policy = deepcopy(DEFAULT_ESCROW_POLICY)
    if not isinstance(raw_policy, dict):
        return policy
    enabled = _to_bool(raw_policy.get("enabled"), False)
    worker_collateral = max(0, min(10_000_000, _to_int(raw_policy.get("worker_collateral"), 0)))
    penalty_percent = max(0, min(100, _to_int(raw_policy.get("penalty_percent_on_reject"), 0)))
    if not enabled:
        worker_collateral = 0
        penalty_percent = 0
    policy["enabled"] = enabled
    policy["worker_collateral"] = worker_collateral
    policy["penalty_percent_on_reject"] = penalty_percent
    return policy


def list_task_class_profiles():
    rows = []
    for class_id, profile in TASK_CLASS_PROFILES.items():
        rows.append(
            {
                "task_class": class_id,
                "title": profile.get("title"),
                "domains": list(profile.get("domains") or []),
                "validation_style": profile.get("validation_style"),
                "recommended_validation_policy": sanitize_validation_policy(profile.get("validation_policy")),
                "recommended_escrow_policy": sanitize_escrow_policy(profile.get("escrow_policy")),
            }
        )
    rows.sort(key=lambda x: x["task_class"])
    return rows


def _auto_task_class(*, computation_type, task_name, task_category, benchmark_meta):
    ctype = str(computation_type or "").strip().lower()
    name = str(task_name or "").strip().lower()
    category = str(task_category or "").strip().lower()
    hints = f"{name} {category}"
    meta = benchmark_meta if isinstance(benchmark_meta, dict) else {}
    domain_hint = str(meta.get("domain") or meta.get("science_domain") or "").strip().lower()

    if ctype == "simple_pow":
        return "deterministic_baseline"
    if ctype in {"cosmological", "supernova", "mhd", "radiative", "gravitational_waves"}:
        return "scientific_simulation"
    if ctype == "molecular_dynamics_benchpep":
        return "biomedical_modeling"
    if "protein" in hints or "protein" in domain_hint or "biomed" in hints:
        return "biomedical_modeling"
    if "llm" in hints or "deep learning" in hints or "training" in hints or "neural" in hints:
        return "ai_training"
    if "finance" in hints or "risk" in hints or "signal" in hints or "analytics" in hints:
        return "data_analytics"
    return "scientific_simulation"


def resolve_task_class(
    *,
    requested_task_class,
    computation_type,
    task_name,
    task_category,
    benchmark_meta,
):
    normalized = str(requested_task_class or "").strip().lower()
    if normalized in TASK_CLASS_PROFILES:
        return normalized, "explicit"
    detected = _auto_task_class(
        computation_type=computation_type,
        task_name=task_name,
        task_category=task_category,
        benchmark_meta=benchmark_meta,
    )
    return detected, "auto"


def build_policy_bundle(
    *,
    requested_task_class,
    computation_type,
    task_name,
    task_category,
    benchmark_meta,
    raw_validation_policy,
    raw_escrow_policy,
):
    task_class, source = resolve_task_class(
        requested_task_class=requested_task_class,
        computation_type=computation_type,
        task_name=task_name,
        task_category=task_category,
        benchmark_meta=benchmark_meta,
    )
    profile = TASK_CLASS_PROFILES.get(task_class, {})
    has_validation_override = isinstance(raw_validation_policy, dict) and bool(raw_validation_policy)
    has_escrow_override = isinstance(raw_escrow_policy, dict) and bool(raw_escrow_policy)
    validation_base = raw_validation_policy if has_validation_override else profile.get("validation_policy")
    escrow_base = raw_escrow_policy if has_escrow_override else profile.get("escrow_policy")
    return {
        "task_class": task_class,
        "task_class_source": source,
        "validation_style": profile.get("validation_style"),
        "validation_policy": sanitize_validation_policy(validation_base),
        "escrow_policy": sanitize_escrow_policy(escrow_base),
    }
