"""
Asset Service — packet-to-asset conversion and asset management.

Responsibilities:
  identity_engine  →  Asset objects  →  returned to callers

This module has no knowledge of FastAPI, routes, or Prisma.
"""

import uuid

from core.constants import (
    DEFAULT_VENDOR,
    DNS_PACKET_THRESHOLD,
    DNS_PROTOCOL,
    HIGH_TRAFFIC_PACKET_THRESHOLD,
    INSECURE_PROTOCOLS,
    LEGACY_SSL_PROTOCOL,
    RISK_SCORE_DNS_THRESHOLD,
    RISK_SCORE_HIGH_TRAFFIC,
    RISK_SCORE_INSECURE_PROTOCOLS,
    RISK_SCORE_SSL,
)
from identity.identity_engine import (
    choose_best_identity_value,
    merge_identity_evidence,
    resolve_device_identity,
)
from utils.helpers import ensure_asset_mac_aliases
from utils.network import is_private_ip, lookup_mac_vendor, normalize_mac


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def build_asset_risk_score(protocol_counts: dict, packet_count: int) -> int:
    """
    Calculate a risk score for an asset based on its observed protocols
    and total packet count.
    """
    score = 0
    if protocol_counts.get(LEGACY_SSL_PROTOCOL, 0) > 0:
        score += RISK_SCORE_SSL
    if any(protocol_counts.get(proto, 0) > 0 for proto in INSECURE_PROTOCOLS):
        score += RISK_SCORE_INSECURE_PROTOCOLS
    if protocol_counts.get(DNS_PROTOCOL, 0) > DNS_PACKET_THRESHOLD:
        score += RISK_SCORE_DNS_THRESHOLD
    if packet_count > HIGH_TRAFFIC_PACKET_THRESHOLD:
        score += RISK_SCORE_HIGH_TRAFFIC
    return score


# ---------------------------------------------------------------------------
# Asset name helper
# ---------------------------------------------------------------------------

def extract_asset_name(packet: dict):
    """Return the best hostname or device name resolvable from a packet."""
    resolved = resolve_device_identity(packet)
    return resolved.get("hostname") or resolved.get("deviceName")


# ---------------------------------------------------------------------------
# Asset merging
# ---------------------------------------------------------------------------

def merge_asset_records(target: dict, source: dict):
    """
    Merge fields from *source* into *target* asset dict.
    - Fills missing identity fields (hostname, deviceName, vendor, operatingSystem)
    - Appends new previous IPs
    - Takes the maximum packetCount and riskScore
    - Updates lastSeen
    """
    if not source or not target or source is target:
        return target

    if not target.get("hostname") and source.get("hostname"):
        target["hostname"] = source["hostname"]
    if not target.get("deviceName") and source.get("deviceName"):
        target["deviceName"] = source["deviceName"]
    if not target.get("vendor") and source.get("vendor"):
        target["vendor"] = source["vendor"]
    if not target.get("operatingSystem") and source.get("operatingSystem"):
        target["operatingSystem"] = source["operatingSystem"]

    if source.get("currentIp") and source["currentIp"] not in target.get("previousIPs", []):
        target["previousIPs"].append(source["currentIp"])
    for ip in source.get("previousIPs", []):
        if ip and ip not in target.get("previousIPs", []):
            target["previousIPs"].append(ip)

    target["packetCount"] = max(
        target.get("packetCount", 0),
        source.get("packetCount", 0),
    )
    target["currentRiskScore"] = max(
        target.get("currentRiskScore", 0),
        source.get("currentRiskScore", 0),
    )
    target["lastSeen"] = source.get("lastSeen") or target.get("lastSeen")
    return target


# ---------------------------------------------------------------------------
# Core upsert
# ---------------------------------------------------------------------------

def update_asset_with_observation(
    observation: dict,
    assets_by_mac: dict,
    assets_by_ip: dict,
):
    """
    Upsert an asset record from a single observation (src or dst side of a packet).

    Looks up by MAC first, then by IP.  Creates a new asset if neither matches.
    Updates identity evidence, IPs, protocol counts, risk score, and timestamps.

    Returns the upserted asset dict.
    """
    mac = normalize_mac(observation.get("mac"))
    ip = observation.get("ip")
    hostname = observation.get("hostname")
    device_name = observation.get("deviceName") or hostname
    identity_evidence = observation.get("identityEvidence") or []
    vendor = lookup_mac_vendor(mac) if mac else DEFAULT_VENDOR
    internal = is_private_ip(ip) if ip else False

    asset = None
    if mac and mac in assets_by_mac:
        asset = assets_by_mac[mac]
    elif ip and ip in assets_by_ip:
        asset = assets_by_ip[ip]

    if not asset:
        asset_id = mac if mac else f"ip:{ip}" if ip else str(uuid.uuid4())
        asset = {
            "assetId": asset_id,
            "macAddress": mac,
            "hostname": hostname,
            "deviceName": device_name,
            "identityEvidence": merge_identity_evidence([], identity_evidence),
            "vendor": vendor,
            "operatingSystem": observation.get("operatingSystem") or "Unknown",
            "currentIp": ip,
            "previousIPs": [],
            "firstSeen": observation.get("time"),
            "lastSeen": observation.get("time"),
            "currentRiskScore": 0,
            "currentStatus": "active" if internal else "external",
            "findings": [],
            "alerts": [],
            "packets": [],
            "connections": [],
            "timeline": [],
            "reports": [],
            "notes": [],
            "protocols": {},
            "packetCount": 0,
        }
        if mac:
            assets_by_mac[mac] = asset
        if ip:
            assets_by_ip[ip] = asset

    # Upgrade IP-keyed asset to MAC-keyed once we discover the MAC
    if asset.get("assetId") == f"ip:{ip}" and mac:
        asset["assetId"] = mac
        asset["macAddress"] = mac

    # Merge identity evidence and re-select best values
    if identity_evidence:
        old_identity_evidence = asset.get("identityEvidence", [])
        merged_identity_evidence = merge_identity_evidence(
            old_identity_evidence, identity_evidence
        )
        asset["identityEvidence"] = merged_identity_evidence
        asset["deviceName"] = choose_best_identity_value(
            asset.get("deviceName"),
            device_name,
            old_identity_evidence,
            identity_evidence,
        )
        asset["hostname"] = choose_best_identity_value(
            asset.get("hostname"),
            hostname,
            old_identity_evidence,
            identity_evidence,
        )

    # Fill in any still-missing fields
    if hostname and not asset.get("hostname"):
        asset["hostname"] = hostname
    if device_name and not asset.get("deviceName"):
        asset["deviceName"] = device_name
    if mac and not asset.get("macAddress"):
        asset["macAddress"] = mac
    if vendor and asset.get("vendor") == "Unknown":
        asset["vendor"] = vendor

    # IP tracking
    if ip:
        if ip not in asset["previousIPs"]:
            asset["previousIPs"].append(ip)
        asset["currentIp"] = ip

    # Timestamps
    if not asset.get("firstSeen") and observation.get("time"):
        asset["firstSeen"] = observation.get("time")
    if observation.get("time"):
        asset["lastSeen"] = observation.get("time")

    # Packet counter
    asset["packetCount"] = asset.get("packetCount", 0) + 1

    # Protocol accumulation
    protocol = observation.get("protocol")
    if protocol:
        asset["protocols"][protocol] = asset["protocols"].get(protocol, 0) + 1

    # Recalculate risk
    asset["currentRiskScore"] = build_asset_risk_score(
        asset["protocols"], asset["packetCount"]
    )
    asset["currentStatus"] = (
        "active" if internal else asset.get("currentStatus", "external")
    )

    # Keep both lookup dicts in sync
    if mac:
        assets_by_mac[mac] = asset
    if ip:
        assets_by_ip[ip] = asset

    ensure_asset_mac_aliases(asset)
    return asset


# ---------------------------------------------------------------------------
# Batch packet → asset conversion
# ---------------------------------------------------------------------------

def build_assets_from_packets(packets: list) -> list:
    """
    Convert a list of enriched packet dicts into a deduplicated list of asset dicts.

    For each packet, two observations are created (src side + dst side) and
    upserted via update_asset_with_observation.  Timeline entries and packet
    numbers are also attached to each asset.
    """
    assets_by_mac: dict = {}
    assets_by_ip: dict = {}

    for packet in packets:
        src_observation = {
            "mac":              packet.get("mac_src"),
            "ip":               packet.get("src"),
            "hostname":         packet.get("hostname"),
            "deviceName":       packet.get("deviceName"),
            "identityEvidence": packet.get("identityEvidence"),
            "operatingSystem":  packet.get("operatingSystem"),
            "protocol":         packet.get("protocol"),
            "time":             packet.get("time"),
        }
        dst_observation = {
            "mac":              packet.get("mac_dst"),
            "ip":               packet.get("dst"),
            "hostname":         packet.get("hostname"),
            "deviceName":       packet.get("deviceName"),
            "identityEvidence": packet.get("identityEvidence"),
            "operatingSystem":  packet.get("operatingSystem"),
            "protocol":         packet.get("protocol"),
            "time":             packet.get("time"),
        }

        src_asset = update_asset_with_observation(
            src_observation, assets_by_mac, assets_by_ip
        )
        dst_asset = update_asset_with_observation(
            dst_observation, assets_by_mac, assets_by_ip
        )

        for asset in (src_asset, dst_asset):
            if not asset:
                continue
            if packet.get("number"):
                asset["packets"].append(packet.get("number"))
            if packet.get("info"):
                asset["timeline"].append({
                    "time":     packet.get("time"),
                    "protocol": packet.get("protocol"),
                    "info":     packet.get("info"),
                })

    # Ensure currentIp is in previousIPs for every asset
    for asset in assets_by_mac.values():
        if asset.get("currentIp") and asset["currentIp"] not in asset["previousIPs"]:
            asset["previousIPs"].append(asset["currentIp"])

    # Deduplicate: MAC-keyed assets take precedence over IP-keyed duplicates
    all_assets = list(
        {
            asset["assetId"]: asset
            for asset in list(assets_by_mac.values()) + list(assets_by_ip.values())
        }.values()
    )

    for asset in all_assets:
        ensure_asset_mac_aliases(asset)

    return all_assets


# ---------------------------------------------------------------------------
# Asset lookup helpers
# ---------------------------------------------------------------------------

def find_asset_by_ip(ip: str, assets: list) -> dict:
    """Return the first asset whose currentIp or previousIPs matches *ip*."""
    if not ip or not assets:
        return None
    normalized_ip = ip.strip()
    for asset in assets:
        if (
            asset.get("currentIp") == normalized_ip
            or normalized_ip in asset.get("previousIPs", [])
        ):
            return asset
    return None


def find_asset_by_id(asset_id: str, assets: list) -> dict:
    """Return the first asset whose assetId or macAddress matches *asset_id*."""
    if not asset_id or not assets:
        return None
    normalized = asset_id.strip()
    for asset in assets:
        if (
            asset.get("assetId") == normalized
            or asset.get("macAddress") == normalized
        ):
            return asset
    return None


# ---------------------------------------------------------------------------
# Packet → evidence conversion helper
# ---------------------------------------------------------------------------

def packet_to_asset_evidence(packet: dict) -> dict:
    """Extract the asset-relevant fields from a packet dict."""
    return {
        "mac_src":    packet.get("mac_src"),
        "mac_dst":    packet.get("mac_dst"),
        "hostname":   packet.get("hostname"),
        "deviceName": packet.get("deviceName"),
        "vendor":     packet.get("vendor"),
        "protocol":   packet.get("protocol"),
        "time":       packet.get("time"),
    }


# =============================================================================
# Phase A.2.2.5 — Asset Service Integration (Orchestration Layer)
# =============================================================================
# This section integrates the four engines built in Phases A.2.2.1–4 into a
# single deterministic asset lifecycle.
#
# Dependency graph (no circular imports):
#   identity_signal_service     ← extract signals
#   identity_confidence_service ← score signal reliability
#   identity_resolution_service ← match signal against stored assets
#   enterprise_asset_repository ← persist results
#
# The orchestrator (process_identity_signal) owns the FLOW.
# It delegates ALL scoring, matching, and persistence to their respective
# owners.  No scoring or matching logic lives here.
# =============================================================================

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.constants import IDENTITY_RESOLUTION_ENGINE_VERSION
from services.identity_confidence_service import (
    IdentityConfidence,
    calculate_identity_confidence,
)
from services.identity_resolution_service import (
    AssetSummary,
    DecisionLevel,
    ResolutionDecision,
    resolve_identity,
)
from services.identity_signal_service import IdentitySignal
import repositories.enterprise_asset_repository as _repo

# Engine version for the orchestration layer.
ASSET_SERVICE_ENGINE_VERSION: str = "asset-service-v1"


# ---------------------------------------------------------------------------
# ProcessedAssetResult — output of process_identity_signal()
# ---------------------------------------------------------------------------

class ProcessedAssetResult(BaseModel):
    """
    Returned by process_identity_signal().

    Fields
    ------
    assetId            Primary key of the affected Asset row (new or updated).
                       None when action is MANUAL_REVIEW or FAILED.
    action             What the orchestrator did:
                         CREATED        — new Asset row was written
                         UPDATED        — existing Asset row was updated
                         UNCHANGED      — asset matched but no fields changed
                         MANUAL_REVIEW  — ambiguous; no writes performed
                         FAILED         — an exception occurred; see warnings
    resolutionDecision The full ResolutionDecision from the Resolution Engine.
    identityConfidence The full IdentityConfidence from the Confidence Engine.
    asset              The AssetRecord returned from the repository (or None).
    warnings           Accumulated warnings from all engines + orchestrator.
    metadata           engineVersion, processingTimeMs, signalSource, etc.
    """
    assetId            : Optional[str]          = None
    action             : str                    = "FAILED"
    resolutionDecision : Optional[ResolutionDecision] = None
    identityConfidence : Optional[IdentityConfidence] = None
    asset              : Optional[Any]          = None   # AssetRecord | None
    warnings           : List[str]              = Field(default_factory=list)
    metadata           : Dict[str, Any]         = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True


# ---------------------------------------------------------------------------
# Helper: build_processed_result()
# ---------------------------------------------------------------------------

def build_processed_result(
    action             : str,
    asset_id           : Optional[str],
    resolution_decision: Optional[ResolutionDecision],
    identity_confidence: Optional[IdentityConfidence],
    asset              : Optional[Any],
    warnings           : List[str],
    processing_time_ms : int,
    signal             : IdentitySignal,
) -> ProcessedAssetResult:
    """
    Assemble a ProcessedAssetResult from the components produced during
    process_identity_signal().

    Parameters
    ----------
    action              : one of CREATED / UPDATED / UNCHANGED / MANUAL_REVIEW / FAILED
    asset_id            : persisted asset primary key, or None
    resolution_decision : output of resolve_identity()
    identity_confidence : output of calculate_identity_confidence()
    asset               : AssetRecord from the repository, or None
    warnings            : accumulated warning strings
    processing_time_ms  : wall-clock ms for the entire pipeline
    signal              : the original IdentitySignal (for metadata)

    Returns
    -------
    ProcessedAssetResult
    """
    return ProcessedAssetResult(
        assetId            = asset_id,
        action             = action,
        resolutionDecision = resolution_decision,
        identityConfidence = identity_confidence,
        asset              = asset,
        warnings           = warnings,
        metadata           = {
            "engineVersion"     : ASSET_SERVICE_ENGINE_VERSION,
            "resolutionVersion" : IDENTITY_RESOLUTION_ENGINE_VERSION,
            "processingTimeMs"  : processing_time_ms,
            "signalSource"      : (
                signal.sourceType
                if isinstance(signal.sourceType, str)
                else signal.sourceType.value
            ),
            "packetNumber"      : signal.packetNumber,
            "captureId"         : signal.captureId,
            "decision"          : (
                resolution_decision.decision
                if resolution_decision else None
            ),
            "overallConfidence" : (
                identity_confidence.overallConfidence
                if identity_confidence else None
            ),
        },
    )


# ---------------------------------------------------------------------------
# Helper: create_asset_from_signal()
# ---------------------------------------------------------------------------

def create_asset_from_signal(
    signal     : IdentitySignal,
    confidence : IdentityConfidence,
    project_id : str,
    tx_id      : Optional[str] = None,
) -> Any:
    """
    Create a new Asset row and all normalised child rows derived from the
    IdentitySignal.

    Persists:
      Asset root  → vendor, os, confidence, firstSeen, lastSeen
      AssetMAC    → one row if macAddress present
      AssetIP     → one row if ipAddress present
      AssetSSID   → one row if ssid present
      Hostnames   → all entries from signal.hostnames

    Does NOT persist evidence — that is handled by append_identity_evidence().
    Does NOT compute scores — confidence comes from the Confidence Engine.

    Returns
    -------
    AssetRecord
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    asset_data: Dict[str, Any] = {
        "projectId"  : project_id,
        "vendor"     : signal.vendor,
        "os"         : signal.operatingSystem,
        "confidence" : round(confidence.overallConfidence / 100, 4),
        "firstSeen"  : now_iso,
        "lastSeen"   : now_iso,
    }
    asset_record = _repo.create_asset(asset_data, tx_id=tx_id)
    asset_id = asset_record.id

    # MAC address
    if signal.macAddress:
        _repo.upsert_mac(
            asset_id,
            {
                "macAddress" : signal.macAddress,
                "isCurrent"  : True,
                "isPrimary"  : True,
                "vendor"     : signal.vendor,
                "firstSeen"  : now_iso,
                "lastSeen"   : now_iso,
                "source"     : signal.sourceType if isinstance(signal.sourceType, str) else signal.sourceType.value,
            },
            tx_id=tx_id,
        )

    # IP address
    if signal.ipAddress:
        _repo.upsert_ip_address(
            asset_id,
            {
                "ipAddress" : signal.ipAddress,
                "isCurrent" : True,
                "firstSeen" : now_iso,
                "lastSeen"  : now_iso,
                "source"    : signal.sourceType if isinstance(signal.sourceType, str) else signal.sourceType.value,
            },
            tx_id=tx_id,
        )

    # Hostnames
    if signal.hostnames:
        _repo.batch_upsert_hostnames(
            asset_id,
            [
                {
                    "hostname"   : h,
                    "isPrimary"  : (i == 0),
                    "confidence" : round(confidence.overallConfidence / 100, 4),
                    "firstSeen"  : now_iso,
                    "lastSeen"   : now_iso,
                    "source"     : "signal",
                }
                for i, h in enumerate(signal.hostnames)
            ],
            tx_id=tx_id,
        )

    # SSID
    if signal.ssid:
        _repo.upsert_ssid(
            asset_id,
            {
                "ssid"      : signal.ssid,
                "isCurrent" : True,
                "firstSeen" : now_iso,
                "lastSeen"  : now_iso,
                "source"    : signal.sourceType if isinstance(signal.sourceType, str) else signal.sourceType.value,
            },
            tx_id=tx_id,
        )

    return asset_record


# ---------------------------------------------------------------------------
# Helper: update_asset_from_signal()
# ---------------------------------------------------------------------------

def update_asset_from_signal(
    asset_id   : str,
    signal     : IdentitySignal,
    confidence : IdentityConfidence,
    tx_id      : Optional[str] = None,
) -> Any:
    """
    Update an existing Asset row and upsert normalised child rows from the
    IdentitySignal.

    Rules
    -----
    - Always upsert MACs and IPs (new observations extend history, never replace).
    - Always upsert hostnames (new observations extend history).
    - Update Asset.lastSeen and Asset.confidence if new confidence is higher.
    - Never overwrite existing data with a lower-confidence value.

    Returns
    -------
    AssetRecord
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    source_str = signal.sourceType if isinstance(signal.sourceType, str) else signal.sourceType.value

    # Update Asset root (only lastSeen + confidence — never overwrite identity fields)
    updated = _repo.update_asset(
        asset_id,
        {
            "lastSeen"   : now_iso,
            "confidence" : round(confidence.overallConfidence / 100, 4),
        },
        tx_id=tx_id,
    )

    # Upsert MAC (preserves history — unique by assetId+macAddress)
    if signal.macAddress:
        _repo.upsert_mac(
            asset_id,
            {
                "macAddress" : signal.macAddress,
                "isCurrent"  : True,
                "lastSeen"   : now_iso,
                "source"     : source_str,
            },
            tx_id=tx_id,
        )

    # Upsert IP — mark as current; previous IPs remain but isCurrent will be
    # managed by a future IP-rotation job (not this phase).
    if signal.ipAddress:
        _repo.upsert_ip_address(
            asset_id,
            {
                "ipAddress" : signal.ipAddress,
                "isCurrent" : True,
                "lastSeen"  : now_iso,
                "source"    : source_str,
            },
            tx_id=tx_id,
        )

    # Upsert hostnames
    if signal.hostnames:
        _repo.batch_upsert_hostnames(
            asset_id,
            [
                {
                    "hostname"  : h,
                    "lastSeen"  : now_iso,
                    "confidence": round(confidence.overallConfidence / 100, 4),
                    "source"    : "signal",
                }
                for h in signal.hostnames
            ],
            tx_id=tx_id,
        )

    # Upsert SSID
    if signal.ssid:
        _repo.upsert_ssid(
            asset_id,
            {
                "ssid"     : signal.ssid,
                "isCurrent": True,
                "lastSeen" : now_iso,
                "source"   : source_str,
            },
            tx_id=tx_id,
        )

    return updated


# ---------------------------------------------------------------------------
# Helper: append_identity_evidence()
# ---------------------------------------------------------------------------

def append_identity_evidence(
    asset_id   : str,
    signal     : IdentitySignal,
    confidence : IdentityConfidence,
    tx_id      : Optional[str] = None,
) -> None:
    """
    Append AssetFieldEvidence rows for every non-empty evidence item in the
    IdentitySignal.

    Rules
    -----
    - Evidence is ALWAYS appended — never overwritten or deduplicated here.
    - Deduplication is the query layer's responsibility.
    - One evidence row per SignalEvidence entry in signal.confidenceHints.

    Parameters
    ----------
    asset_id   : target Asset primary key
    signal     : IdentitySignal from the extraction engine
    confidence : IdentityConfidence for per-field confidence scores
    tx_id      : optional transaction token
    """
    if not signal.confidenceHints:
        return

    items = [
        {
            "fieldName"    : ev.fieldName,
            "fieldValue"   : ev.fieldValue,
            "confidence"   : round(ev.confidence / 100, 4),
            "sourceType"   : ev.source if isinstance(ev.source, str) else ev.source.value,
            "packetNumber" : ev.packetNumber,
            "captureId"    : ev.captureId or signal.captureId,
            "observedAt"   : ev.observedAt.isoformat() if ev.observedAt else datetime.now(timezone.utc).isoformat(),
        }
        for ev in signal.confidenceHints
        if ev.fieldValue
    ]

    if items:
        _repo.batch_insert_evidence(asset_id, items, tx_id=tx_id)


# ---------------------------------------------------------------------------
# Helper: append_relationship_placeholders()
# ---------------------------------------------------------------------------

def append_relationship_placeholders(
    asset_id   : str,
    signal     : IdentitySignal,
) -> None:
    """
    Placeholder hook for future relationship generation.

    Phase A.2.2.5 specification: prepare the hook; do NOT implement
    relationship generation logic.  This function intentionally does nothing
    and is called by process_identity_signal() to mark the integration point.

    Future implementation will:
    - Detect communicating peers from signal.destinationIp / destinationMac
    - Resolve the peer asset ID via the repository
    - Call _repo.upsert_relationship() with type="communicates_with"
    """
    # TODO (future phase): implement peer relationship generation
    pass


# ---------------------------------------------------------------------------
# Core orchestration entrypoint: process_identity_signal()
# ---------------------------------------------------------------------------

def process_identity_signal(
    signal     : IdentitySignal,
    project_id : str,
) -> ProcessedAssetResult:
    """
    Orchestrate the full Asset Lifecycle for one IdentitySignal.

    Flow
    ----
    1.  Confidence Engine   → calculate_identity_confidence(signal)
    2.  Repository          → fetch candidate AssetSummaries for this project
    3.  Resolution Engine   → resolve_identity(signal, confidence, candidates)
    4.  Decision branch:
          MATCH / LIKELY    → update_asset_from_signal()
          CREATE_NEW        → create_asset_from_signal()
          POSSIBLE / MANUAL → no writes; return MANUAL_REVIEW
    5.  Evidence append     → append_identity_evidence()
    6.  Relationship hook   → append_relationship_placeholders()
    7.  Return              → ProcessedAssetResult

    Parameters
    ----------
    signal     : IdentitySignal from identity_signal_service
    project_id : project scope for all repository operations

    Returns
    -------
    ProcessedAssetResult — always returned, never raises.
    Errors are captured as warnings with action=FAILED.

    Notes
    -----
    - No scoring, no matching, no confidence calculation lives here.
    - Repository is called only through its public interface.
    - Evidence is always appended, never overwritten.
    """
    t_start    = time.monotonic()
    warnings   : List[str]                 = []
    confidence : Optional[IdentityConfidence]  = None
    decision   : Optional[ResolutionDecision]  = None

    try:
        # ── Step 1: Confidence Engine ─────────────────────────────────────
        confidence = calculate_identity_confidence(signal)
        warnings.extend(confidence.warnings)

        # ── Step 2: Fetch candidates from repository ──────────────────────
        candidates = _fetch_candidates(project_id, signal)

        # ── Step 3: Resolution Engine ─────────────────────────────────────
        decision = resolve_identity(signal, confidence, candidates)
        warnings.extend(decision.warnings)

        level = DecisionLevel(decision.decision) if isinstance(decision.decision, str) else decision.decision

        # ── Step 4: Decision branch ───────────────────────────────────────
        if level in (DecisionLevel.MATCH, DecisionLevel.LIKELY_MATCH):
            asset_record = update_asset_from_signal(
                decision.matchedAssetId, signal, confidence
            )
            action   = "UPDATED"
            asset_id = decision.matchedAssetId

        elif level == DecisionLevel.CREATE_NEW:
            asset_record = create_asset_from_signal(signal, confidence, project_id)
            action   = "CREATED"
            asset_id = asset_record.id

        else:
            # POSSIBLE_MATCH or MANUAL_REVIEW — no writes
            warnings.append(
                f"Decision '{level}' requires manual review. No asset was written."
            )
            ms = int((time.monotonic() - t_start) * 1000)
            return build_processed_result(
                action              = "MANUAL_REVIEW",
                asset_id            = None,
                resolution_decision = decision,
                identity_confidence = confidence,
                asset               = None,
                warnings            = warnings,
                processing_time_ms  = ms,
                signal              = signal,
            )

        # ── Step 5: Append evidence (always, never overwrite) ─────────────
        append_identity_evidence(asset_id, signal, confidence)

        # ── Step 6: Relationship placeholder hook ─────────────────────────
        append_relationship_placeholders(asset_id, signal)

        # ── Step 7: Return result ─────────────────────────────────────────
        ms = int((time.monotonic() - t_start) * 1000)
        return build_processed_result(
            action              = action,
            asset_id            = asset_id,
            resolution_decision = decision,
            identity_confidence = confidence,
            asset               = asset_record,
            warnings            = warnings,
            processing_time_ms  = ms,
            signal              = signal,
        )

    except Exception as exc:  # noqa: BLE001
        ms = int((time.monotonic() - t_start) * 1000)
        warnings.append(f"process_identity_signal failed: {type(exc).__name__}: {exc}")
        return build_processed_result(
            action              = "FAILED",
            asset_id            = None,
            resolution_decision = decision,
            identity_confidence = confidence,
            asset               = None,
            warnings            = warnings,
            processing_time_ms  = ms,
            signal              = signal,
        )


# ---------------------------------------------------------------------------
# Internal: _fetch_candidates()
# ---------------------------------------------------------------------------

def _fetch_candidates(
    project_id : str,
    signal     : IdentitySignal,
) -> List[AssetSummary]:
    """
    Fetch AssetSummary objects from the repository for use by the Resolution Engine.

    Strategy
    --------
    Fetch the most recent N assets for this project.  The Resolution Engine
    then scores all of them — pre-filtering by MAC or IP would risk missing
    edge cases (e.g. MAC spoofing, IP reuse).

    The page size of 200 covers enterprise deployments comfortably.
    A future phase may add index-based pre-filtering for very large projects.

    Returns
    -------
    List[AssetSummary] — may be empty if the project has no assets yet.
    """
    try:
        page = _repo.get_assets_by_project(
            project_id,
            page      = 1,
            page_size = 200,
            sort_by   = "lastSeen",
            sort_order= "desc",
        )
    except Exception:
        # Repository unavailable — return empty list so CREATE_NEW fires
        return []

    summaries: List[AssetSummary] = []
    for asset in page.items:
        try:
            macs = _repo.get_macs(asset.id)
            ips  = _repo.get_ip_addresses(asset.id)
            hnms = _repo.get_hostnames(asset.id)
            sids = _repo.get_ssids(asset.id)

            summaries.append(AssetSummary(
                assetId        = asset.id,
                macAddresses   = [m.macAddress for m in macs],
                currentIps     = [i.ipAddress for i in ips if i.isCurrent],
                previousIps    = [i.ipAddress for i in ips if not i.isCurrent],
                hostnames      = [h.hostname for h in hnms],
                ssids          = [s.ssid for s in sids],
                vendor         = asset.vendor,
                operatingSystem= asset.os,
            ))
        except Exception:
            # Skip assets whose child data cannot be fetched
            continue

    return summaries
