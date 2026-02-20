"""
Multi-oracle FX utilities:
- HMAC-подписи submit'ов оракулов;
- эпохи, кворум, медиана;
- детекция outlier;
- репутация (штрафы).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import statistics
import time
from typing import Dict, Iterable, Optional, Tuple

SUPPORTED_CURRENCIES = ("RUB", "USD", "EUR")

DEFAULT_ORACLE_SECRETS = {
    "oracle-1": "dev-oracle-secret-1",
    "oracle-2": "dev-oracle-secret-2",
    "oracle-3": "dev-oracle-secret-3",
    "oracle-4": "dev-oracle-secret-4",
    "oracle-5": "dev-oracle-secret-5",
}

ORACLE_EPOCH_SECONDS = int(os.environ.get("FX_ORACLE_EPOCH_SECONDS", "300"))
ORACLE_QUORUM = int(os.environ.get("FX_ORACLE_QUORUM", "3"))
ORACLE_OUTLIER_THRESHOLD_PERCENT = float(os.environ.get("FX_ORACLE_OUTLIER_THRESHOLD_PERCENT", "5.0"))
ORACLE_PENALTY_POINTS = int(os.environ.get("FX_ORACLE_PENALTY_POINTS", "10"))
ORACLE_REQUIRE_COMMIT_REVEAL = (os.environ.get("FX_ORACLE_REQUIRE_COMMIT_REVEAL", "0").strip() == "1")
_DEFAULT_COMMIT_WINDOW_SECONDS = max(1, ORACLE_EPOCH_SECONDS // 2)
ORACLE_COMMIT_WINDOW_SECONDS = int(
    os.environ.get("FX_ORACLE_COMMIT_WINDOW_SECONDS", str(_DEFAULT_COMMIT_WINDOW_SECONDS))
)
ORACLE_COMMIT_WINDOW_SECONDS = max(1, min(ORACLE_EPOCH_SECONDS - 1, ORACLE_COMMIT_WINDOW_SECONDS))
ORACLE_REVEAL_WINDOW_SECONDS = max(1, ORACLE_EPOCH_SECONDS - ORACLE_COMMIT_WINDOW_SECONDS)


def _load_registry() -> Dict[str, str]:
    raw = os.environ.get("ORACLE_SECRETS_JSON", "").strip()
    if not raw:
        return dict(DEFAULT_ORACLE_SECRETS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return dict(DEFAULT_ORACLE_SECRETS)
    if not isinstance(parsed, dict):
        return dict(DEFAULT_ORACLE_SECRETS)
    cleaned = {}
    for oracle_id, secret in parsed.items():
        if not isinstance(oracle_id, str) or not isinstance(secret, str):
            continue
        oid = oracle_id.strip()
        sec = secret.strip()
        if oid and sec:
            cleaned[oid] = sec
    if not cleaned:
        return dict(DEFAULT_ORACLE_SECRETS)
    return cleaned


def get_oracle_registry() -> Dict[str, str]:
    return _load_registry()


def get_oracle_public_info() -> dict:
    registry = get_oracle_registry()
    return {
        "oracle_ids": sorted(registry.keys()),
        "oracle_count": len(registry),
        "epoch_seconds": ORACLE_EPOCH_SECONDS,
        "quorum": ORACLE_QUORUM,
        "require_commit_reveal": ORACLE_REQUIRE_COMMIT_REVEAL,
        "commit_window_seconds": ORACLE_COMMIT_WINDOW_SECONDS,
        "reveal_window_seconds": ORACLE_REVEAL_WINDOW_SECONDS,
        "outlier_threshold_percent": ORACLE_OUTLIER_THRESHOLD_PERCENT,
        "penalty_points": ORACLE_PENALTY_POINTS,
    }


def current_epoch_id(ts: Optional[int] = None) -> str:
    unix_ts = int(ts or time.time())
    slot = unix_ts // max(1, ORACLE_EPOCH_SECONDS)
    return f"fx-{slot}"


def epoch_time_bounds(epoch_id: str, ts: Optional[int] = None) -> Optional[dict]:
    if not isinstance(epoch_id, str):
        return None
    epoch = epoch_id.strip().lower()
    if not epoch.startswith("fx-"):
        return None
    try:
        slot = int(epoch.split("-", 1)[1])
    except (TypeError, ValueError):
        return None
    now_value = int(ts or time.time())
    start_ts = int(slot * ORACLE_EPOCH_SECONDS)
    end_ts = int(start_ts + ORACLE_EPOCH_SECONDS)
    commit_end_ts = int(start_ts + ORACLE_COMMIT_WINDOW_SECONDS)
    reveal_end_ts = int(commit_end_ts + ORACLE_REVEAL_WINDOW_SECONDS)
    if reveal_end_ts > end_ts:
        reveal_end_ts = end_ts
    phase = "closed"
    if now_value < commit_end_ts:
        phase = "commit"
    elif now_value < reveal_end_ts:
        phase = "reveal"
    return {
        "epoch_id": epoch_id,
        "start_ts": start_ts,
        "commit_end_ts": commit_end_ts,
        "reveal_end_ts": reveal_end_ts,
        "end_ts": end_ts,
        "phase": phase,
        "now_ts": now_value,
    }


def normalize_rates_payload(rates_to_rub) -> Tuple[Optional[dict], Optional[str]]:
    if not isinstance(rates_to_rub, dict):
        return None, "rates_to_rub must be object"
    normalized = {}
    for currency in SUPPORTED_CURRENCIES:
        raw = rates_to_rub.get(currency)
        if raw is None:
            return None, f"Missing rate for {currency}"
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return None, f"Invalid rate for {currency}"
        if value <= 0:
            return None, f"Rate for {currency} must be > 0"
        normalized[currency] = value
    return normalized, None


def build_signature_payload(epoch_id: str, rates_to_rub: dict) -> str:
    canonical_rates = {c: float(rates_to_rub[c]) for c in SUPPORTED_CURRENCIES}
    return f"{epoch_id}|{json.dumps(canonical_rates, sort_keys=True, separators=(',', ':'))}"


def sign_submission(secret: str, epoch_id: str, rates_to_rub: dict) -> str:
    payload = build_signature_payload(epoch_id, rates_to_rub)
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def verify_submission_signature(
    *,
    oracle_id: str,
    epoch_id: str,
    rates_to_rub: dict,
    signature: str,
) -> Tuple[bool, Optional[str]]:
    registry = get_oracle_registry()
    secret = registry.get(oracle_id)
    if not secret:
        return False, "Unknown oracle_id"
    if not isinstance(signature, str) or not signature.strip():
        return False, "signature is required"
    normalized_rates, err = normalize_rates_payload(rates_to_rub)
    if err:
        return False, err
    expected = sign_submission(secret, epoch_id, normalized_rates)
    if not hmac.compare_digest(expected, signature.strip()):
        return False, "Invalid oracle signature"
    return True, None


def _iter_oracle_txs(chain: Iterable):
    for block in chain:
        block_index = int(getattr(block, "index", 0))
        ts = int(getattr(block, "timestamp", 0) or 0)
        for tx in list(getattr(block, "transactions", []) or []):
            if not isinstance(tx, dict):
                continue
            tx_type = tx.get("type")
            if tx_type in (
                "fx_oracle_commit",
                "fx_oracle_submit",
                "fx_oracle_penalty",
                "fx_epoch_finalized",
                "fx_rules_update",
            ):
                yield block_index, ts, tx


def build_commit_hash(*, oracle_id: str, epoch_id: str, rates_to_rub: dict, nonce: str) -> str:
    canonical_rates = {c: float(rates_to_rub[c]) for c in SUPPORTED_CURRENCIES}
    payload = {
        "oracle_id": str(oracle_id or "").strip(),
        "epoch_id": str(epoch_id or "").strip(),
        "rates_to_rub": canonical_rates,
        "nonce": str(nonce or "").strip(),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def get_epoch_commits(chain: Iterable, epoch_id: str) -> Dict[str, dict]:
    commits = {}
    for block_index, ts, tx in _iter_oracle_txs(chain):
        if tx.get("type") != "fx_oracle_commit":
            continue
        if tx.get("epoch_id") != epoch_id:
            continue
        oracle_id = tx.get("oracle_id")
        commit_hash = (tx.get("commit_hash") or "").strip().lower()
        if not isinstance(oracle_id, str) or not oracle_id:
            continue
        if len(commit_hash) != 64 or any(ch not in "0123456789abcdef" for ch in commit_hash):
            continue
        commits[oracle_id] = {
            "oracle_id": oracle_id,
            "epoch_id": epoch_id,
            "commit_hash": commit_hash,
            "committed_at": int(tx.get("committed_at", ts or int(time.time()))),
            "block_index": block_index,
        }
    return commits


def get_epoch_submissions(chain: Iterable, epoch_id: str) -> Dict[str, dict]:
    submissions = {}
    for block_index, ts, tx in _iter_oracle_txs(chain):
        if tx.get("type") != "fx_oracle_submit":
            continue
        if tx.get("epoch_id") != epoch_id:
            continue
        oracle_id = tx.get("oracle_id")
        if not isinstance(oracle_id, str) or not oracle_id:
            continue
        rates, err = normalize_rates_payload(tx.get("rates_to_rub"))
        if err:
            continue
        submissions[oracle_id] = {
            "oracle_id": oracle_id,
            "epoch_id": epoch_id,
            "rates_to_rub": rates,
            "signature": tx.get("signature"),
            "submitted_at": int(tx.get("submitted_at", ts or int(time.time()))),
            "block_index": block_index,
        }
    return submissions


def get_epoch_finalization(chain: Iterable, epoch_id: str) -> Optional[dict]:
    found = None
    for block_index, ts, tx in _iter_oracle_txs(chain):
        tx_type = tx.get("type")
        if tx_type not in ("fx_epoch_finalized", "fx_rules_update"):
            continue
        meta = tx.get("meta") or {}
        if not isinstance(meta, dict):
            continue
        if meta.get("source") != "multi_oracle":
            continue
        if meta.get("epoch_id") != epoch_id:
            continue
        rates, err = normalize_rates_payload(tx.get("rates_to_rub"))
        if err:
            continue
        found = {
            "epoch_id": epoch_id,
            "rates_to_rub": rates,
            "spread_percent": tx.get("spread_percent"),
            "meta": meta,
            "finalized_at": int(tx.get("updated_at", ts or int(time.time()))),
            "block_index": block_index,
            "tx_type": tx_type,
        }
    return found


def get_latest_finalization(chain: Iterable) -> Optional[dict]:
    latest = None
    for block_index, ts, tx in _iter_oracle_txs(chain):
        tx_type = tx.get("type")
        if tx_type not in ("fx_epoch_finalized", "fx_rules_update"):
            continue
        meta = tx.get("meta") or {}
        if not isinstance(meta, dict) or meta.get("source") != "multi_oracle":
            continue
        epoch_id = meta.get("epoch_id")
        if not isinstance(epoch_id, str) or not epoch_id:
            continue
        rates, err = normalize_rates_payload(tx.get("rates_to_rub"))
        if err:
            continue
        row = {
            "epoch_id": epoch_id,
            "rates_to_rub": rates,
            "spread_percent": tx.get("spread_percent"),
            "meta": meta,
            "finalized_at": int(tx.get("updated_at", ts or int(time.time()))),
            "block_index": block_index,
            "tx_type": tx_type,
        }
        if latest is None or int(row.get("block_index", 0)) >= int(latest.get("block_index", 0)):
            latest = row
    return latest


def calculate_median_rates(submissions: Dict[str, dict]) -> dict:
    rates = {}
    for currency in SUPPORTED_CURRENCIES:
        series = [float(sub["rates_to_rub"][currency]) for sub in submissions.values()]
        rates[currency] = float(statistics.median(series))
    return rates


def calculate_weighted_median_rates(submissions: Dict[str, dict], oracle_scores: Dict[str, dict]) -> dict:
    rates = {}
    for currency in SUPPORTED_CURRENCIES:
        weighted_series = []
        for oracle_id, sub in submissions.items():
            score_row = oracle_scores.get(oracle_id) or {}
            weight = int(score_row.get("score", 100) or 100)
            weight = max(1, weight)
            weighted_series.append((float(sub["rates_to_rub"][currency]), weight))
        weighted_series.sort(key=lambda x: x[0])
        total_weight = sum(weight for _, weight in weighted_series) or 1
        acc = 0
        selected = weighted_series[-1][0]
        for value, weight in weighted_series:
            acc += weight
            if acc >= total_weight / 2.0:
                selected = value
                break
        rates[currency] = float(selected)
    return rates


def detect_outliers(submissions: Dict[str, dict], median_rates: dict) -> Dict[str, dict]:
    outliers = {}
    threshold = float(ORACLE_OUTLIER_THRESHOLD_PERCENT)
    for oracle_id, submission in submissions.items():
        max_deviation = 0.0
        for currency in SUPPORTED_CURRENCIES:
            median_value = float(median_rates[currency])
            value = float(submission["rates_to_rub"][currency])
            if median_value <= 0:
                continue
            deviation = abs(value - median_value) / median_value * 100.0
            if deviation > max_deviation:
                max_deviation = deviation
        if max_deviation > threshold:
            outliers[oracle_id] = {
                "oracle_id": oracle_id,
                "max_deviation_percent": round(max_deviation, 4),
            }
    return outliers


def calculate_confidence_score(*, submissions: Dict[str, dict], selected_rates: dict, outliers: Dict[str, dict], quorum: int) -> float:
    if not submissions or not selected_rates:
        return 0.0
    deviations = []
    for sub in submissions.values():
        for currency in SUPPORTED_CURRENCIES:
            base = float(selected_rates.get(currency, 0) or 0)
            if base <= 0:
                continue
            value = float(sub["rates_to_rub"][currency])
            deviations.append(abs(value - base) / base * 100.0)
    avg_dev = (sum(deviations) / len(deviations)) if deviations else 100.0
    outlier_ratio = float(len(outliers)) / float(max(1, len(submissions)))
    quorum_bonus = min(20.0, max(0.0, (len(submissions) - int(quorum)) * 3.0))
    score = 100.0 - (avg_dev * 5.0) - (outlier_ratio * 35.0) + quorum_bonus
    if score < 0:
        return 0.0
    if score > 100:
        return 100.0
    return round(score, 2)


def calculate_volatility_score(*, previous_rates: Optional[dict], current_rates: dict) -> float:
    if not previous_rates:
        return 0.0
    changes = []
    for currency in SUPPORTED_CURRENCIES:
        prev = float(previous_rates.get(currency, 0) or 0)
        cur = float(current_rates.get(currency, 0) or 0)
        if prev <= 0 or cur <= 0:
            continue
        changes.append(abs(cur - prev) / prev * 100.0)
    if not changes:
        return 0.0
    avg_change = sum(changes) / len(changes)
    # Нормализуем в диапазон 0..100 (10% среднего изменения = 100 баллов волатильности).
    normalized = min(100.0, (avg_change / 10.0) * 100.0)
    return round(normalized, 2)


def build_oracle_scores(chain: Iterable) -> Dict[str, dict]:
    registry = get_oracle_registry()
    scores = {
        oracle_id: {
            "oracle_id": oracle_id,
            "score": 100,
            "penalties": 0,
        }
        for oracle_id in registry.keys()
    }
    for _, _, tx in _iter_oracle_txs(chain):
        if tx.get("type") != "fx_oracle_penalty":
            continue
        oracle_id = tx.get("oracle_id")
        if oracle_id not in scores:
            continue
        points = tx.get("penalty_points")
        try:
            points = int(points)
        except (TypeError, ValueError):
            points = ORACLE_PENALTY_POINTS
        points = max(1, points)
        scores[oracle_id]["score"] = max(0, int(scores[oracle_id]["score"]) - points)
        scores[oracle_id]["penalties"] = int(scores[oracle_id]["penalties"]) + 1
    return scores
