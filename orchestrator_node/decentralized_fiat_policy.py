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
    "challenge_window_seconds": 0,
}

DEFAULT_ESCROW_POLICY = {
    "enabled": False,
    "worker_collateral": 0,  # fiat units in contract currency
    "penalty_percent_on_reject": 0,  # 0..100
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
    challenge_window_seconds = max(0, min(7 * 24 * 3600, _to_int(raw_policy.get("challenge_window_seconds"), 0)))
    if mode == "deterministic":
        replication_factor = 1
        challenge_window_seconds = 0
    policy["mode"] = mode
    policy["replication_factor"] = replication_factor
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
