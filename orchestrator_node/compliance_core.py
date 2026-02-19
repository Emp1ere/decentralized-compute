import os
from typing import Dict, Optional


KYC_LIMITS = {
    "tier0_unverified": {"daily_withdrawal": 300, "monthly_withdrawal": 3000},
    "tier1_basic": {"daily_withdrawal": 500, "monthly_withdrawal": 5000},
    "tier2_verified": {"daily_withdrawal": 5000, "monthly_withdrawal": 50000},
}


def evaluate_kyc_tier(*, client_id: str) -> Dict:
    tier2_ids = {
        value.strip()
        for value in str(os.environ.get("COMPLIANCE_TIER2_CLIENT_IDS", "")).split(",")
        if value.strip()
    }
    tier1_ids = {
        value.strip()
        for value in str(os.environ.get("COMPLIANCE_TIER1_CLIENT_IDS", "")).split(",")
        if value.strip()
    }
    if client_id in tier2_ids:
        tier = "tier2_verified"
    elif client_id in tier1_ids:
        tier = "tier1_basic"
    else:
        tier = "tier0_unverified"
    return {
        "client_id": client_id,
        "kyc_tier": tier,
        "allowed_limits": dict(KYC_LIMITS[tier]),
        "status": "deterministic-policy",
    }


def evaluate_aml_risk(*, client_id: str, amount: int, currency: str) -> Dict:
    normalized_amount = max(0, int(amount or 0))
    risk_score = min(100, normalized_amount // 250)
    if normalized_amount >= 20_000:
        risk_score = min(100, risk_score + 20)
    if (currency or "RUB").upper() in {"USD", "EUR"}:
        risk_score = min(100, risk_score + 5)
    return {
        "client_id": client_id,
        "amount": normalized_amount,
        "currency": (currency or "RUB").upper(),
        "risk_score": risk_score,
        "decision": "allow" if risk_score < 50 else ("review" if risk_score < 80 else "reject"),
        "status": "deterministic-policy",
    }


def evaluate_jurisdiction(*, client_id: str, country_code: Optional[str] = None) -> Dict:
    cc = (country_code or "UNSET").upper()
    blocked = {value.strip().upper() for value in os.environ.get("COMPLIANCE_BLOCKED_COUNTRIES", "BLOCKED").split(",") if value.strip()}
    return {
        "client_id": client_id,
        "country_code": cc,
        "payout_allowed": cc not in blocked,
        "status": "deterministic-policy",
    }


def evaluate_withdrawal_gate(
    *,
    kyc_result: Dict,
    aml_result: Dict,
    jurisdiction_result: Dict,
    amount: int,
    daily_used: int,
    monthly_used: int,
) -> Dict:
    normalized_amount = max(0, int(amount or 0))
    limits = (kyc_result or {}).get("allowed_limits") or {"daily_withdrawal": 0, "monthly_withdrawal": 0}
    daily_limit = max(0, int(limits.get("daily_withdrawal", 0) or 0))
    monthly_limit = max(0, int(limits.get("monthly_withdrawal", 0) or 0))
    reasons = []
    decision = "allow"

    if not bool((jurisdiction_result or {}).get("payout_allowed", False)):
        decision = "reject"
        reasons.append("jurisdiction_blocked")
    if (aml_result or {}).get("decision") == "reject":
        decision = "reject"
        reasons.append("aml_reject")
    if decision != "reject" and (aml_result or {}).get("decision") == "review":
        decision = "review"
        reasons.append("aml_review")
    if normalized_amount + int(daily_used or 0) > daily_limit:
        if decision != "reject":
            decision = "review"
        reasons.append("daily_limit_exceeded")
    if normalized_amount + int(monthly_used or 0) > monthly_limit:
        if decision != "reject":
            decision = "review"
        reasons.append("monthly_limit_exceeded")

    return {
        "decision": decision,
        "reasons": reasons,
        "daily_limit": daily_limit,
        "monthly_limit": monthly_limit,
        "daily_used": int(daily_used or 0),
        "monthly_used": int(monthly_used or 0),
    }
