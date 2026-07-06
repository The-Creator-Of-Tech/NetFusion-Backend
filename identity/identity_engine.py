"""
Identity Engine — pure device identity resolution from packet evidence.

Responsibilities:
  Evidence  →  Best Device Identity

This module has no knowledge of FastAPI, routes, or Prisma.
It receives raw packet dicts and returns structured identity results.
"""

from core.constants import HOSTNAME_IDENTITY_SOURCES, IDENTITY_CONFIDENCE
from utils.network import extract_ip_from_text


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def normalize_identity_value(value: str):
    """Strip and return a non-empty string, or None."""
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None


def infer_reverse_dns(packet: dict):
    """Return a reverse-DNS name from dns_ptr or .in-addr.arpa / .ip6.arpa queries."""
    dns_ptr = normalize_identity_value(packet.get("dns_ptr"))
    if dns_ptr:
        return dns_ptr
    dns_query = normalize_identity_value(packet.get("dns_query"))
    if dns_query and (
        dns_query.endswith(".in-addr.arpa") or dns_query.endswith(".ip6.arpa")
    ):
        return dns_query
    return None


def build_identity_candidate(source: str, value: str, confidence: int):
    """Build a single identity candidate dict, or None if value is empty."""
    value = normalize_identity_value(value)
    if not value:
        return None
    return {
        "source": source,
        "name": value,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Evidence merging
# ---------------------------------------------------------------------------

def merge_identity_evidence(existing: list, incoming: list):
    """
    Merge two identity evidence lists.
    Deduplicates by (name, source), keeps the highest-confidence entry.
    Returns a list sorted by (-confidence, source).
    """
    if not incoming:
        return existing or []
    merged = {}
    for item in (existing or []) + incoming:
        if not isinstance(item, dict):
            continue
        name = normalize_identity_value(item.get("name"))
        source = item.get("source")
        confidence = item.get("confidence", 0)
        if not name or not source:
            continue
        key = f"{name.lower()}|{source}"
        current = merged.get(key)
        if not current or confidence > current.get("confidence", 0):
            merged[key] = {
                "source": source,
                "name": name,
                "confidence": confidence,
            }
    return sorted(
        merged.values(),
        key=lambda item: (-item["confidence"], item["source"]),
    )


# ---------------------------------------------------------------------------
# Value selection
# ---------------------------------------------------------------------------

def choose_best_identity_value(
    existing_value: str,
    new_value: str,
    existing_evidence: list,
    new_evidence: list,
):
    """
    Return whichever of existing_value / new_value has higher confidence
    according to the supplied evidence lists.
    """
    existing_value = normalize_identity_value(existing_value)
    new_value = normalize_identity_value(new_value)
    if not new_value:
        return existing_value
    if not existing_value:
        return new_value

    def max_confidence(value, evidence_list):
        best = 0
        for item in (evidence_list or []):
            if not isinstance(item, dict):
                continue
            if normalize_identity_value(item.get("name")) == value:
                best = max(best, int(item.get("confidence", 0)))
        return best

    existing_conf = max_confidence(existing_value, existing_evidence)
    new_conf = max_confidence(new_value, new_evidence)
    return new_value if new_conf > existing_conf else existing_value


# ---------------------------------------------------------------------------
# Core resolution
# ---------------------------------------------------------------------------

def resolve_device_identity(packet: dict):
    """
    Resolve the best device identity from a single packet dict.

    Returns:
        {
            "deviceName": str | None,
            "hostname":   str | None,
            "identityEvidence": [ {source, name, confidence}, ... ]
        }
    """
    candidates = [
        build_identity_candidate("manual",             packet.get("manual_name"),        IDENTITY_CONFIDENCE["manual"]),
        build_identity_candidate("dhcp_hostname",      packet.get("dhcp_hostname"),       IDENTITY_CONFIDENCE["dhcp_hostname"]),
        build_identity_candidate("bootp_hostname",     packet.get("bootp_hostname"),      IDENTITY_CONFIDENCE["bootp_hostname"]),
        build_identity_candidate("http_host",          packet.get("http_host"),           IDENTITY_CONFIDENCE["http_host"]),
        build_identity_candidate("nbns_name",          packet.get("nbns_name"),           IDENTITY_CONFIDENCE["nbns_name"]),
        build_identity_candidate("nbns_netbios_name",  packet.get("nbns_netbios_name"),   IDENTITY_CONFIDENCE["nbns_netbios_name"]),
        build_identity_candidate("mdns_name",          packet.get("mdns_name"),           IDENTITY_CONFIDENCE["mdns_name"]),
        build_identity_candidate("llmnr_name",         packet.get("llmnr_name"),          IDENTITY_CONFIDENCE["llmnr_name"]),
        build_identity_candidate("dns_ptr",            packet.get("dns_ptr"),             IDENTITY_CONFIDENCE["dns_ptr"]),
        build_identity_candidate("reverse_dns",        infer_reverse_dns(packet),         IDENTITY_CONFIDENCE["reverse_dns"]),
        build_identity_candidate("dns_query",          packet.get("dns_query"),           IDENTITY_CONFIDENCE["dns_query"]),
        build_identity_candidate("nmap_name",          packet.get("nmap_name"),           IDENTITY_CONFIDENCE["nmap_name"]),
    ]
    candidates = [c for c in candidates if c]

    # Deduplicate by name (keep highest confidence)
    unique_candidates = {}
    for candidate in candidates:
        key = candidate["name"].lower()
        existing = unique_candidates.get(key)
        if not existing or candidate["confidence"] > existing["confidence"]:
            unique_candidates[key] = candidate

    ordered = sorted(
        unique_candidates.values(),
        key=lambda item: (-item["confidence"], item["source"]),
    )

    device_name = None
    hostname = None
    for candidate in ordered:
        if not device_name:
            device_name = candidate["name"]
        if not hostname and candidate["source"] in HOSTNAME_IDENTITY_SOURCES:
            hostname = candidate["name"]
    if not hostname:
        hostname = device_name

    result = {
        "deviceName": device_name,
        "hostname": hostname,
        "identityEvidence": ordered,
    }
    if ordered:
        print(
            f"=== IDENTITY RESOLVED === "
            f"deviceName={device_name} hostname={hostname} evidence={ordered}"
        )
    return result


# ---------------------------------------------------------------------------
# Multi-packet helpers
# ---------------------------------------------------------------------------

def select_best_device_name_from_packets(packets: list):
    """
    Scan a list of enriched packets and return the highest-priority device name.
    Priority order mirrors IDENTITY_CONFIDENCE ranking.
    """
    if not packets:
        return None

    priority_getters = [
        lambda p: normalize_identity_value(p.get("manual_name")),
        lambda p: normalize_identity_value(p.get("dhcp_hostname")),
        lambda p: normalize_identity_value(p.get("nbns_name") or p.get("nbns_netbios_name")),
        lambda p: normalize_identity_value(p.get("mdns_name")),
        lambda p: normalize_identity_value(p.get("llmnr_name")),
        lambda p: normalize_identity_value(p.get("nmap_name")),
        lambda p: infer_reverse_dns(p),
        lambda p: normalize_identity_value(p.get("hostname")),
    ]

    for getter in priority_getters:
        for packet in packets:
            value = getter(packet)
            if value:
                return value

    return None


def select_best_hostname_from_packets(packets: list):
    """Return the first non-empty hostname found in a list of enriched packets."""
    if not packets:
        return None
    for packet in packets:
        hostname = normalize_identity_value(packet.get("hostname"))
        if hostname:
            return hostname
    return None
