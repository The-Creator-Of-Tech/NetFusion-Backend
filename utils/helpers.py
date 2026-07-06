"""Generic helper utilities."""

import re
import uuid

from core.constants import (
    DEFAULT_RISK_LEVEL,
    HIGH_RISK_PROTOCOLS,
    RISK_HOST_SCORE_HIGH,
    RISK_HOST_SCORE_MEDIUM,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_LOW,
    RISK_LEVEL_MEDIUM,
)

from utils.network import normalize_mac


def compact_fields(item, keys):
    if isinstance(item, dict):
        return {key: item.get(key) for key in keys if item.get(key) is not None}
    return {"value": str(item)}


def compact_list(items, keys, limit=6):
    if not items:
        return []
    return [compact_fields(item, keys) for item in items[:limit]]


def sanitize_filename(filename):
    """Sanitize filename for safe file creation."""
    filename = re.sub(r"[^\w\s-]", "", filename)
    filename = re.sub(r"[\s]+", "_", filename)
    filename = filename[:50]
    filename = f"{filename}_{uuid.uuid4().hex[:8]}.pdf"
    return filename


def ensure_asset_mac_aliases(asset: dict):
    if not asset:
        return asset

    mac = asset.get("mac")
    mac_address = asset.get("macAddress")

    normalized_mac = normalize_mac(mac) if mac else None
    normalized_address = normalize_mac(mac_address) if mac_address else None

    resolved_mac = normalized_mac or normalized_address
    if normalized_mac and normalized_address and normalized_mac != normalized_address:
        resolved_mac = normalized_address

    if resolved_mac:
        asset["mac"] = resolved_mac
        asset["macAddress"] = resolved_mac
    else:
        asset["mac"] = None
        asset["macAddress"] = None

    return asset


def determine_risk_level(session):
    if not session:
        return DEFAULT_RISK_LEVEL

    alerts = session.get("alerts", []) or []
    iocs = session.get("iocs", []) or []
    risk_hosts = session.get("riskRanking", []) or session.get("risk_ranking", []) or []
    analysis = session.get("analysis", {}) or {}
    protocols = analysis.get("protocols", {}) or {}

    has_high = False
    has_medium = False

    for item in alerts:
        severity = str(item.get("severity", "")).lower() if isinstance(item, dict) else "info"
        if "high" in severity or "critical" in severity:
            has_high = True
        elif "medium" in severity:
            has_medium = True

    for item in iocs:
        severity = str(item.get("severity", "")).lower() if isinstance(item, dict) else "info"
        if "high" in severity or "critical" in severity:
            has_high = True
        elif "medium" in severity:
            has_medium = True

    for host in risk_hosts:
        score = host.get("score", 0)
        if score >= RISK_HOST_SCORE_HIGH:
            has_high = True
        elif score >= RISK_HOST_SCORE_MEDIUM:
            has_medium = True

    if any(proto in protocols for proto in HIGH_RISK_PROTOCOLS):
        has_high = True

    if has_high:
        return RISK_LEVEL_HIGH
    if has_medium:
        return RISK_LEVEL_MEDIUM
    return RISK_LEVEL_LOW
