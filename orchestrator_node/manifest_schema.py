"""
Схема manifest.json (ТЗ раздел 7).

Формат: runner, entry_point, args, data_dir, output_dir, resources,
parallelism, verification, environment, network_whitelist, timeout_hours,
budget_usd, region_preference.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

VERIFICATION_TYPES = ("exact", "metric", "statistical", "tee")

VERIFICATION_EXACT = "exact"  # SHA-256
VERIFICATION_METRIC = "metric"  # ±tolerance
VERIFICATION_STATISTICAL = "statistical"  # KS, Mann-Whitney
VERIFICATION_TEE = "tee"  # SGX

REDUNDANCY_BY_VERIFICATION = {
    VERIFICATION_EXACT: 3,  # 2/3
    VERIFICATION_METRIC: 3,
    VERIFICATION_STATISTICAL: 3,
    VERIFICATION_TEE: 5,
}


def manifest_schema() -> Dict[str, Any]:
    """Схема полей manifest.json."""
    return {
        "runner": "string (docker image or 'python'|'external')",
        "entry_point": "string",
        "args": "list[str]",
        "data_dir": "string (path)",
        "output_dir": "string (path)",
        "resources": {"cpus": "int", "memory_gb": "float", "gpu": "bool"},
        "parallelism": "int",
        "verification": {
            "type": "exact|metric|statistical|tee",
            "tolerance": "float (for metric)",
            "test": "string (for statistical: ks|mann_whitney)",
        },
        "environment": "dict",
        "network_whitelist": "list[str]",
        "timeout_hours": "float",
        "budget_usd": "float",
        "region_preference": "list[str] (RU|EU|US|CN)",
    }


def validate_manifest(manifest: Dict[str, Any]) -> Optional[str]:
    """
    Валидация manifest. Возвращает None при успехе, иначе строку ошибки.
    """
    if not isinstance(manifest, dict):
        return "manifest must be object"
    runner = manifest.get("runner")
    if not runner or not isinstance(runner, str):
        return "runner is required"
    verification = manifest.get("verification")
    if verification and isinstance(verification, dict):
        vtype = verification.get("type")
        if vtype and vtype not in VERIFICATION_TYPES:
            return f"verification.type must be one of {VERIFICATION_TYPES}"
    return None
