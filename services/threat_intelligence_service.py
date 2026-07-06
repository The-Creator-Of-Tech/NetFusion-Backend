"""
Threat Intelligence Engine
===========================
Phase A4.4.4 — Deterministic, immutable threat actor, campaign, and mapping
management for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model ThreatActor, ThreatCampaign, ThreatMapping, and ThreatStatistics as
  immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_threat_actor, build_threat_campaign, build_threat_mapping,
    build_threat_statistics.
- Expose validation functions:
    validate_threat_actor, validate_threat_campaign, validate_threat_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  MitreTechnique, CVERecord, and IOCRecord objects into ThreatMapping objects
  without executing AI.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No HTTP. No MISP. No VirusTotal. No AbuseIPDB. No AlienVault OTX.
- No TAXII. No STIX download. No database. No frontend. No AI execution.
- Provider-agnostic.

Out of scope
------------
- External threat feed fetching, live lookups, automated scoring via ML.
- Streaming, retry/failover, HTTP, websocket.
- Actual AI execution.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import THREAT_INTELLIGENCE_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("threat_intelligence_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_THREAT_NS = uuid.UUID("6ba7b880-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class ThreatSeverityEnum(str, Enum):
    """Severity classification for a threat actor or campaign."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatConfidenceEnum(str, Enum):
    """Confidence classification for a threat intelligence object."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    VERIFIED = "VERIFIED"


class ThreatTypeEnum(str, Enum):
    """Type classification for a threat intelligence object."""
    THREAT_ACTOR   = "THREAT_ACTOR"
    CAMPAIGN       = "CAMPAIGN"
    MALWARE        = "MALWARE"
    TOOL           = "TOOL"
    VULNERABILITY  = "VULNERABILITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ThreatIntelligenceError(Exception):
    """Base class for all Threat Intelligence Engine errors."""


class InvalidThreatActorError(ThreatIntelligenceError):
    """Raised when a ThreatActor fails validation."""


class InvalidCampaignError(ThreatIntelligenceError):
    """Raised when a ThreatCampaign fails validation."""


class InvalidThreatMappingError(ThreatIntelligenceError):
    """Raised when a ThreatMapping fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class ThreatActor(BaseModel):
    """
    One immutable threat actor record.

    Identity
    --------
    actorKey : SHA256(name.upper())[:32]
    actorId  : UUIDv5(_THREAT_NS, actorKey)

    Fields
    ------
    actorId            : deterministic UUID derived from actorKey.
    actorKey           : 32-char SHA-256 identity key.
    name               : canonical threat actor name (non-empty).
    aliases            : sorted tuple of alternate names (lowercase).
    description        : human-readable description.
    country            : ISO-3166-1 alpha-2 country code or empty string.
    motivation         : motivation string (e.g. "espionage", "financial").
    confidence         : ThreatConfidenceEnum — confidence in this actor record.
    relatedTechniques  : sorted tuple of MITRE ATT&CK technique ID strings.
    relatedCVEs        : sorted tuple of CVE ID strings associated with actor.
    relatedIOCs        : sorted tuple of IOC value strings linked to actor.
    createdAt          : ISO-8601 timestamp (caller-supplied for determinism).
    """
    actorId           : str
    actorKey          : str
    name              : str
    aliases           : Tuple[str, ...]
    description       : str
    country           : str
    motivation        : str
    confidence        : ThreatConfidenceEnum
    relatedTechniques : Tuple[str, ...]
    relatedCVEs       : Tuple[str, ...]
    relatedIOCs       : Tuple[str, ...]
    createdAt         : str

    class Config:
        frozen = True


class ThreatCampaign(BaseModel):
    """
    One immutable threat campaign record.

    Identity
    --------
    campaignKey : SHA256(name.upper())[:32]
    campaignId  : UUIDv5(_THREAT_NS, campaignKey)

    Fields
    ------
    campaignId         : deterministic UUID derived from campaignKey.
    campaignKey        : 32-char SHA-256 identity key.
    name               : canonical campaign name (non-empty).
    description        : human-readable description.
    startDate          : ISO-8601 start date string (may be empty).
    endDate            : ISO-8601 end date string (may be empty).
    threatActors       : sorted tuple of ThreatActor actorId strings linked.
    relatedTechniques  : sorted tuple of MITRE ATT&CK technique ID strings.
    relatedCVEs        : sorted tuple of CVE ID strings associated with campaign.
    relatedIOCs        : sorted tuple of IOC value strings linked to campaign.
    confidence         : ThreatConfidenceEnum — confidence in this campaign record.
    createdAt          : ISO-8601 timestamp (caller-supplied for determinism).
    """
    campaignId        : str
    campaignKey       : str
    name              : str
    description       : str
    startDate         : str
    endDate           : str
    threatActors      : Tuple[str, ...]
    relatedTechniques : Tuple[str, ...]
    relatedCVEs       : Tuple[str, ...]
    relatedIOCs       : Tuple[str, ...]
    confidence        : ThreatConfidenceEnum
    createdAt         : str

    class Config:
        frozen = True


class ThreatMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to threat actors
    and campaigns.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(actorIds) + sorted(campaignIds))[:32]
    mappingId          : UUIDv5(_THREAT_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(actorIds) +
                                sorted(campaignIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    mappingFingerprint : deterministic 32-char content fingerprint.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    actors             : sorted tuple of ThreatActor objects matched
                         (sorted by actorId ASC).
    campaigns          : sorted tuple of ThreatCampaign objects matched
                         (sorted by campaignId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    mappingFingerprint : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    actors             : Tuple[ThreatActor, ...]
    campaigns          : Tuple[ThreatCampaign, ...]
    confidence         : float
    createdAt          : str

    class Config:
        frozen = True


class ThreatStatistics(BaseModel):
    """
    Aggregate statistics over a collection of ThreatActor, ThreatCampaign,
    and ThreatMapping objects.

    Fields
    ------
    totalActors       : count of distinct ThreatActor actorIds.
    totalCampaigns    : count of distinct ThreatCampaign campaignIds.
    mappedFindings    : count of distinct non-empty findingIds across all mappings.
    mappedAlerts      : count of distinct non-empty alertIds across all mappings.
    mappedReasoning   : count of distinct non-empty reasoningIds across all mappings.
    averageConfidence : mean mapping.confidence across all mappings (0.0 if empty).
    actorCountries    : sorted tuple of distinct non-empty country strings from actors.
    campaignCounts    : dict mapping campaignName → count of mappings that reference
                        that campaign (by campaignId).
    """
    totalActors       : int
    totalCampaigns    : int
    mappedFindings    : int
    mappedAlerts      : int
    mappedReasoning   : int
    averageConfidence : float
    actorCountries    : Tuple[str, ...]
    campaignCounts    : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers (internal)
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5(key: str) -> str:
    """UUIDv5(_THREAT_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_THREAT_NS, key))


def _norm(s: str) -> str:
    """Strip a string; return empty string if None."""
    return s.strip() if s else ""


def _norm_lower(s: str) -> str:
    """Lowercase and strip a string."""
    return s.strip().lower() if s else ""


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings (case-preserved)."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _norm_lower_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, lowercase, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip().lower() for s in items if s and s.strip()}))


def _norm_upper_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, uppercase, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip().upper() for s in items if s and s.strip()}))


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


# ---------------------------------------------------------------------------
# Public key derivation functions (named per spec)
# ---------------------------------------------------------------------------

def actorKey(name: str) -> str:
    """
    actorKey = SHA256(name.upper())[:32]

    Identical name always produces the same key regardless of caller.
    """
    return _sha256_32(name.strip().upper())


def campaignKey(name: str) -> str:
    """
    campaignKey = SHA256(name.upper())[:32]

    Identical name always produces the same key regardless of caller.
    """
    return _sha256_32(name.strip().upper())


def mappingKey(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    actor_ids   : Tuple[str, ...],
    campaign_ids: Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(actorIds) + sorted(campaignIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    ID collections sorted before joining for order-independence.
    """
    sorted_actors    = "\x01".join(sorted(actor_ids))
    sorted_campaigns = "\x01".join(sorted(campaign_ids))
    return _sha256_32(
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_actors,
        sorted_campaigns,
    )


def mappingFingerprint(
    m_key       : str,
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    actor_ids   : Tuple[str, ...],
    campaign_ids: Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(actorIds) +
                                sorted(campaignIds))[:32]
    """
    sorted_actors    = "\x01".join(sorted(actor_ids))
    sorted_campaigns = "\x01".join(sorted(campaign_ids))
    return _sha256_32(
        m_key,
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_actors,
        sorted_campaigns,
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_threat_actor(
    name       : str,
    confidence : ThreatConfidenceEnum,
    created_at : str,
) -> None:
    """
    Validate ThreatActor construction parameters.

    Checks
    ------
    - name is non-empty.
    - confidence is a valid ThreatConfidenceEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidThreatActorError : if any rule is violated.
    """
    errors: List[str] = []

    if not name or not name.strip():
        errors.append("name must not be empty.")

    if not isinstance(confidence, ThreatConfidenceEnum):
        errors.append(
            f"confidence must be a ThreatConfidenceEnum member; got {confidence!r}."
        )

    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_threat_actor", "errors": errors},
        )
        raise InvalidThreatActorError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_threat_campaign(
    name       : str,
    confidence : ThreatConfidenceEnum,
    created_at : str,
) -> None:
    """
    Validate ThreatCampaign construction parameters.

    Checks
    ------
    - name is non-empty.
    - confidence is a valid ThreatConfidenceEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidCampaignError : if any rule is violated.
    """
    errors: List[str] = []

    if not name or not name.strip():
        errors.append("name must not be empty.")

    if not isinstance(confidence, ThreatConfidenceEnum):
        errors.append(
            f"confidence must be a ThreatConfidenceEnum member; got {confidence!r}."
        )

    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_threat_campaign", "errors": errors},
        )
        raise InvalidCampaignError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_threat_mapping(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    confidence  : float,
    created_at  : str,
) -> None:
    """
    Validate ThreatMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidThreatMappingError : if any rule is violated.
    """
    errors: List[str] = []

    has_source = any(
        s and s.strip()
        for s in (finding_id, alert_id, reasoning_id)
    )
    if not has_source:
        errors.append(
            "At least one of findingId, alertId, or reasoningId must be non-empty."
        )

    if not isinstance(confidence, (int, float)) or not (0.0 <= float(confidence) <= 100.0):
        errors.append(
            f"confidence={confidence!r} must be a float in [0.0, 100.0]."
        )

    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_threat_mapping", "errors": errors},
        )
        raise InvalidThreatMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_threat_actor()
# ===========================================================================

def build_threat_actor(
    name               : str,
    confidence         : ThreatConfidenceEnum,
    created_at         : str,
    aliases            : Optional[List[str]] = None,
    description        : str                 = "",
    country            : str                 = "",
    motivation         : str                 = "",
    related_techniques : Optional[List[str]] = None,
    related_cves       : Optional[List[str]] = None,
    related_iocs       : Optional[List[str]] = None,
    validate           : bool                = True,
) -> ThreatActor:
    """
    Build an immutable ThreatActor.

    actorKey = SHA256(name.upper())[:32]
    actorId  = UUIDv5(_THREAT_NS, actorKey)

    Parameters
    ----------
    name               : canonical threat actor name (non-empty).
    confidence         : ThreatConfidenceEnum — confidence in this actor record.
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    aliases            : alternate names (deduped + lowercase + sorted).
    description        : human-readable description (may be empty).
    country            : ISO-3166-1 alpha-2 or free-form country string.
    motivation         : motivation string (may be empty).
    related_techniques : MITRE ATT&CK technique IDs (deduped + uppercase + sorted).
    related_cves       : CVE ID strings (deduped + uppercase + sorted).
    related_iocs       : IOC value strings (deduped + sorted).
    validate           : if True, run validate_threat_actor() first.

    Returns
    -------
    ThreatActor (frozen / immutable)

    Raises
    ------
    InvalidThreatActorError : if validate=True and validation fails.
    """
    if validate:
        validate_threat_actor(name, confidence, created_at)

    a_key = actorKey(name)
    a_id  = _uuid5(a_key)

    return ThreatActor(
        actorId           = a_id,
        actorKey          = a_key,
        name              = name.strip(),
        aliases           = _norm_lower_strings(aliases),
        description       = description,
        country           = _norm(country),
        motivation        = _norm_lower(motivation),
        confidence        = confidence,
        relatedTechniques = _norm_upper_strings(related_techniques),
        relatedCVEs       = _norm_upper_strings(related_cves),
        relatedIOCs       = _norm_strings(related_iocs),
        createdAt         = created_at,
    )


# ===========================================================================
# Builder: build_threat_campaign()
# ===========================================================================

def build_threat_campaign(
    name               : str,
    confidence         : ThreatConfidenceEnum,
    created_at         : str,
    description        : str                 = "",
    start_date         : str                 = "",
    end_date           : str                 = "",
    threat_actors      : Optional[List[str]] = None,
    related_techniques : Optional[List[str]] = None,
    related_cves       : Optional[List[str]] = None,
    related_iocs       : Optional[List[str]] = None,
    validate           : bool                = True,
) -> ThreatCampaign:
    """
    Build an immutable ThreatCampaign.

    campaignKey = SHA256(name.upper())[:32]
    campaignId  = UUIDv5(_THREAT_NS, campaignKey)

    Parameters
    ----------
    name               : canonical campaign name (non-empty).
    confidence         : ThreatConfidenceEnum — confidence in this campaign record.
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    description        : human-readable description (may be empty).
    start_date         : ISO-8601 start date (may be empty).
    end_date           : ISO-8601 end date (may be empty).
    threat_actors      : actorId strings of linked ThreatActors
                         (deduped + sorted).
    related_techniques : MITRE ATT&CK technique IDs (deduped + uppercase + sorted).
    related_cves       : CVE ID strings (deduped + uppercase + sorted).
    related_iocs       : IOC value strings (deduped + sorted).
    validate           : if True, run validate_threat_campaign() first.

    Returns
    -------
    ThreatCampaign (frozen / immutable)

    Raises
    ------
    InvalidCampaignError : if validate=True and validation fails.
    """
    if validate:
        validate_threat_campaign(name, confidence, created_at)

    c_key = campaignKey(name)
    c_id  = _uuid5(c_key)

    return ThreatCampaign(
        campaignId        = c_id,
        campaignKey       = c_key,
        name              = name.strip(),
        description       = description,
        startDate         = _norm(start_date),
        endDate           = _norm(end_date),
        threatActors      = _norm_strings(threat_actors),
        relatedTechniques = _norm_upper_strings(related_techniques),
        relatedCVEs       = _norm_upper_strings(related_cves),
        relatedIOCs       = _norm_strings(related_iocs),
        confidence        = confidence,
        createdAt         = created_at,
    )


# ===========================================================================
# Builder: build_threat_mapping()
# ===========================================================================

def build_threat_mapping(
    actors       : List[ThreatActor],
    campaigns    : List[ThreatCampaign],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> ThreatMapping:
    """
    Build an immutable ThreatMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(actorIds) + sorted(campaignIds))[:32]
    mappingId          = UUIDv5(_THREAT_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(actorIds) +
                                sorted(campaignIds))[:32]

    Parameters
    ----------
    actors       : list of ThreatActor objects to link.
    campaigns    : list of ThreatCampaign objects to link.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_threat_mapping() first.

    Returns
    -------
    ThreatMapping (frozen / immutable)

    Raises
    ------
    InvalidThreatMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_threat_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: by actorId ASC
    sorted_actors: Tuple[ThreatActor, ...] = tuple(
        sorted(actors or [], key=lambda a: a.actorId)
    )

    # Deterministic ordering: by campaignId ASC
    sorted_campaigns: Tuple[ThreatCampaign, ...] = tuple(
        sorted(campaigns or [], key=lambda c: c.campaignId)
    )

    # Collect IDs for key computation
    actor_ids    : Tuple[str, ...] = tuple(a.actorId    for a in sorted_actors)
    campaign_ids : Tuple[str, ...] = tuple(c.campaignId for c in sorted_campaigns)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, actor_ids, campaign_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(
        m_key, finding_id, alert_id, reasoning_id, actor_ids, campaign_ids
    )

    return ThreatMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        mappingFingerprint = m_fp,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        actors             = sorted_actors,
        campaigns          = sorted_campaigns,
        confidence         = round(clamped_conf, 4),
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_threat_statistics()
# ===========================================================================

def build_threat_statistics(
    actors    : List[ThreatActor],
    campaigns : List[ThreatCampaign],
    mappings  : List[ThreatMapping],
) -> ThreatStatistics:
    """
    Compute ThreatStatistics over lists of ThreatActor, ThreatCampaign,
    and ThreatMapping objects.

    Deterministic: canonical sort (by actorId / campaignId / mappingId ASC)
    before accumulation so all counts and floating-point sums are identical
    across every run regardless of input ordering.

    Parameters
    ----------
    actors    : list of ThreatActor objects (may contain duplicates by actorId).
    campaigns : list of ThreatCampaign objects (may contain duplicates by campaignId).
    mappings  : list of ThreatMapping objects.

    Returns
    -------
    ThreatStatistics (frozen / immutable)
    """
    # Deduplicate actors by actorId — canonical sort, first occurrence wins
    ordered_actors: List[ThreatActor] = sorted(actors or [], key=lambda a: a.actorId)
    seen_actor_ids: dict = {}
    for a in ordered_actors:
        if a.actorId not in seen_actor_ids:
            seen_actor_ids[a.actorId] = a

    # Deduplicate campaigns by campaignId — canonical sort, first occurrence wins
    ordered_campaigns: List[ThreatCampaign] = sorted(campaigns or [], key=lambda c: c.campaignId)
    seen_campaign_ids: dict = {}
    for c in ordered_campaigns:
        if c.campaignId not in seen_campaign_ids:
            seen_campaign_ids[c.campaignId] = c

    total_actors    = len(seen_actor_ids)
    total_campaigns = len(seen_campaign_ids)

    # actorCountries: sorted distinct non-empty countries from deduplicated actors
    actor_countries: Tuple[str, ...] = tuple(sorted({
        a.country for a in seen_actor_ids.values() if a.country
    }))

    if not mappings:
        # campaignCounts: each campaign → 0 mappings (no mappings provided)
        campaign_counts: Dict[str, int] = {
            c.name: 0
            for c in sorted(seen_campaign_ids.values(), key=lambda x: x.name)
        }
        return ThreatStatistics(
            totalActors       = total_actors,
            totalCampaigns    = total_campaigns,
            mappedFindings    = 0,
            mappedAlerts      = 0,
            mappedReasoning   = 0,
            averageConfidence = 0.0,
            actorCountries    = actor_countries,
            campaignCounts    = campaign_counts,
        )

    # Canonical order for deterministic accumulation
    ordered_mappings: List[ThreatMapping] = sorted(mappings, key=lambda m: m.mappingId)

    # Distinct non-empty source IDs
    distinct_finding_ids   = {m.findingId   for m in ordered_mappings if m.findingId}
    distinct_alert_ids     = {m.alertId     for m in ordered_mappings if m.alertId}
    distinct_reasoning_ids = {m.reasoningId for m in ordered_mappings if m.reasoningId}

    n        = len(ordered_mappings)
    avg_conf = round(sum(m.confidence for m in ordered_mappings) / n, 4)

    # campaignCounts: campaignName → count of mappings referencing that campaign
    # Build lookup: campaignId → campaignName from the deduplicated campaign set
    cid_to_name: Dict[str, str] = {
        cid: c.name for cid, c in seen_campaign_ids.items()
    }
    campaign_counts_raw: Dict[str, int] = {}
    # Start all known campaigns at 0
    for c in sorted(seen_campaign_ids.values(), key=lambda x: x.name):
        campaign_counts_raw[c.name] = 0
    # Count mappings that reference each campaign
    for m in ordered_mappings:
        for c in m.campaigns:
            cname = cid_to_name.get(c.campaignId, c.name)
            campaign_counts_raw[cname] = campaign_counts_raw.get(cname, 0) + 1

    # Sort campaign_counts by name for determinism
    campaign_counts = dict(sorted(campaign_counts_raw.items()))

    return ThreatStatistics(
        totalActors       = total_actors,
        totalCampaigns    = total_campaigns,
        mappedFindings    = len(distinct_finding_ids),
        mappedAlerts      = len(distinct_alert_ids),
        mappedReasoning   = len(distinct_reasoning_ids),
        averageConfidence = avg_conf,
        actorCountries    = actor_countries,
        campaignCounts    = campaign_counts,
    )


# ===========================================================================
# Integration Helpers — transform-only
# ===========================================================================
# These are pure transformation helpers.
# They accept objects from other engine services and return ThreatMapping
# or reference-enriched ThreatActor / ThreatCampaign objects.
# No external lookups.  No AI execution.  No network.
# Duck-typed inputs — avoids import cycles with other service modules.
# ===========================================================================

def mitre_to_threat_reference(
    technique   : Any,
    actor       : ThreatActor,
) -> ThreatActor:
    """
    Create a deterministic reference between a MitreTechnique and a
    ThreatActor by returning a new ThreatActor that includes the technique's
    mitreId in its relatedTechniques tuple.

    Rules
    -----
    - If the technique's mitreId is already in actor.relatedTechniques,
      the original actor is returned unchanged (idempotent).
    - Otherwise, a new ThreatActor is built from the existing actor's fields
      plus the new mitreId inserted in uppercase sorted order.
    - actorKey and actorId are stable — identity never changes.
    - No validation is re-run; validate=False is used internally.

    Parameters
    ----------
    technique : MitreTechnique object from mitre_attack_service (duck-typed).
    actor     : Existing ThreatActor to extend.

    Returns
    -------
    ThreatActor (frozen / immutable) — either the original (if already linked)
    or a new actor with the technique mitreId added.
    """
    mitre_id = _norm(_norm(getattr(technique, "mitreId", ""))).upper()
    if not mitre_id:
        return actor

    if mitre_id in actor.relatedTechniques:
        return actor

    _log.debug(
        "mitre_to_threat_reference",
        extra={"actorId": actor.actorId, "mitreId": mitre_id},
    )

    new_techniques = tuple(sorted(set(actor.relatedTechniques) | {mitre_id}))
    return ThreatActor(
        actorId           = actor.actorId,
        actorKey          = actor.actorKey,
        name              = actor.name,
        aliases           = actor.aliases,
        description       = actor.description,
        country           = actor.country,
        motivation        = actor.motivation,
        confidence        = actor.confidence,
        relatedTechniques = new_techniques,
        relatedCVEs       = actor.relatedCVEs,
        relatedIOCs       = actor.relatedIOCs,
        createdAt         = actor.createdAt,
    )


def cve_to_threat_reference(
    cve_record : Any,
    actor      : ThreatActor,
) -> ThreatActor:
    """
    Create a deterministic reference between a CVERecord and a ThreatActor
    by returning a new ThreatActor that includes the CVE ID in its
    relatedCVEs tuple.

    Rules
    -----
    - If the cve_record.cveId is already in actor.relatedCVEs, the original
      actor is returned unchanged (idempotent).
    - Otherwise, a new ThreatActor is built with the CVE ID added in
      uppercase sorted order.
    - actorKey and actorId are stable — identity never changes.

    Parameters
    ----------
    cve_record : CVERecord object from cve_intelligence_service (duck-typed).
    actor      : Existing ThreatActor to extend.

    Returns
    -------
    ThreatActor (frozen / immutable)
    """
    cve_id = _norm(getattr(cve_record, "cveId", "")).upper()
    if not cve_id:
        return actor

    if cve_id in actor.relatedCVEs:
        return actor

    _log.debug(
        "cve_to_threat_reference",
        extra={"actorId": actor.actorId, "cveId": cve_id},
    )

    new_cves = tuple(sorted(set(actor.relatedCVEs) | {cve_id}))
    return ThreatActor(
        actorId           = actor.actorId,
        actorKey          = actor.actorKey,
        name              = actor.name,
        aliases           = actor.aliases,
        description       = actor.description,
        country           = actor.country,
        motivation        = actor.motivation,
        confidence        = actor.confidence,
        relatedTechniques = actor.relatedTechniques,
        relatedCVEs       = new_cves,
        relatedIOCs       = actor.relatedIOCs,
        createdAt         = actor.createdAt,
    )


def ioc_to_threat_reference(
    ioc_record : Any,
    actor      : ThreatActor,
) -> ThreatActor:
    """
    Create a deterministic reference between an IOCRecord and a ThreatActor
    by returning a new ThreatActor that includes the IOC value in its
    relatedIOCs tuple.

    Rules
    -----
    - If the ioc_record.value is already in actor.relatedIOCs, the original
      actor is returned unchanged (idempotent).
    - Otherwise, a new ThreatActor is built with the IOC value added in
      sorted order (case-preserved).
    - actorKey and actorId are stable — identity never changes.

    Parameters
    ----------
    ioc_record : IOCRecord object from ioc_intelligence_service (duck-typed).
    actor      : Existing ThreatActor to extend.

    Returns
    -------
    ThreatActor (frozen / immutable)
    """
    ioc_value = _norm(getattr(ioc_record, "value", ""))
    if not ioc_value:
        return actor

    if ioc_value in actor.relatedIOCs:
        return actor

    _log.debug(
        "ioc_to_threat_reference",
        extra={"actorId": actor.actorId, "iocValue": ioc_value},
    )

    new_iocs = tuple(sorted(set(actor.relatedIOCs) | {ioc_value}))
    return ThreatActor(
        actorId           = actor.actorId,
        actorKey          = actor.actorKey,
        name              = actor.name,
        aliases           = actor.aliases,
        description       = actor.description,
        country           = actor.country,
        motivation        = actor.motivation,
        confidence        = actor.confidence,
        relatedTechniques = actor.relatedTechniques,
        relatedCVEs       = actor.relatedCVEs,
        relatedIOCs       = new_iocs,
        createdAt         = actor.createdAt,
    )


def finding_to_threat_mapping(
    finding    : Any,
    actors     : List[ThreatActor],
    campaigns  : List[ThreatCampaign],
    created_at : str,
    confidence : float = 0.0,
    validate   : bool  = True,
) -> ThreatMapping:
    """
    Convert a Finding (from finding_service) into a ThreatMapping.

    Rules
    -----
    - findingId  = finding.findingId
    - alertId    = "" (no alert source)
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    finding    : Finding object from finding_service (duck-typed).
    actors     : list of ThreatActor objects to map.
    campaigns  : list of ThreatCampaign objects to map.
    created_at : ISO-8601 timestamp.
    confidence : 0.0–100.0 caller-assessed confidence.
    validate   : if True, run validate_threat_mapping().

    Returns
    -------
    ThreatMapping (frozen / immutable)
    """
    _log.debug(
        "finding_to_threat_mapping",
        extra={
            "findingId"    : finding.findingId,
            "actorCount"   : len(actors),
            "campaignCount": len(campaigns),
        },
    )
    return build_threat_mapping(
        actors       = actors,
        campaigns    = campaigns,
        created_at   = created_at,
        finding_id   = finding.findingId,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def alert_to_threat_mapping(
    alert      : Any,
    actors     : List[ThreatActor],
    campaigns  : List[ThreatCampaign],
    created_at : str,
    confidence : float = 0.0,
    validate   : bool  = True,
) -> ThreatMapping:
    """
    Convert an Alert (from alert_service) into a ThreatMapping.

    Rules
    -----
    - findingId  = alert.findingId  (Alert always has a source findingId)
    - alertId    = alert.alertId
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    alert      : Alert object from alert_service (duck-typed).
    actors     : list of ThreatActor objects to map.
    campaigns  : list of ThreatCampaign objects to map.
    created_at : ISO-8601 timestamp.
    confidence : 0.0–100.0 caller-assessed confidence.
    validate   : if True, run validate_threat_mapping().

    Returns
    -------
    ThreatMapping (frozen / immutable)
    """
    _log.debug(
        "alert_to_threat_mapping",
        extra={
            "alertId"      : alert.alertId,
            "findingId"    : alert.findingId,
            "actorCount"   : len(actors),
            "campaignCount": len(campaigns),
        },
    )
    return build_threat_mapping(
        actors       = actors,
        campaigns    = campaigns,
        created_at   = created_at,
        finding_id   = alert.findingId,
        alert_id     = alert.alertId,
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def reasoning_to_threat_mapping(
    reasoning  : Any,
    actors     : List[ThreatActor],
    campaigns  : List[ThreatCampaign],
    created_at : str,
    finding_id : str  = "",
    alert_id   : str  = "",
    validate   : bool = True,
) -> ThreatMapping:
    """
    Convert a ReasoningResult (from reasoning_service) into a ThreatMapping.

    Rules
    -----
    - reasoningId = reasoning.reasoningId
    - confidence  = reasoning.overallConfidence (already 0–100)
    - findingId and alertId are optional caller-supplied context linkages.

    Parameters
    ----------
    reasoning  : ReasoningResult object from reasoning_service (duck-typed).
    actors     : list of ThreatActor objects to map.
    campaigns  : list of ThreatCampaign objects to map.
    created_at : ISO-8601 timestamp.
    finding_id : optional finding ID for context linkage (may be empty).
    alert_id   : optional alert ID for context linkage (may be empty).
    validate   : if True, run validate_threat_mapping().

    Returns
    -------
    ThreatMapping (frozen / immutable)
    """
    _log.debug(
        "reasoning_to_threat_mapping",
        extra={
            "reasoningId"  : reasoning.reasoningId,
            "confidence"   : reasoning.overallConfidence,
            "actorCount"   : len(actors),
            "campaignCount": len(campaigns),
        },
    )
    return build_threat_mapping(
        actors       = actors,
        campaigns    = campaigns,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = reasoning.reasoningId,
        confidence   = reasoning.overallConfidence,
        validate     = validate,
    )


# ===========================================================================
# Part 2 — Threat Actor Operations
# ===========================================================================

def add_threat_actor(
    collection : List[ThreatActor],
    new_actor  : ThreatActor,
) -> List[ThreatActor]:
    """
    Return a new list with new_actor added, deduplicating by actorId.

    Rules
    -----
    - If an actor with the same actorId already exists, the existing actor
      is kept (first-write-wins — identity is stable).
    - Otherwise new_actor is appended and the list is sorted by actorId ASC.
    - Input list is never mutated.

    Returns
    -------
    New sorted List[ThreatActor].
    """
    existing_ids = {a.actorId for a in collection}
    if new_actor.actorId in existing_ids:
        _log.debug(
            "threat_actor_duplicate_skipped",
            extra={"actorId": new_actor.actorId},
        )
        return list(sorted(collection, key=lambda a: a.actorId))

    result = list(collection) + [new_actor]
    result.sort(key=lambda a: a.actorId)
    _log.info(
        "actor_created",
        extra={"actorId": new_actor.actorId, "actorName": new_actor.name},
    )
    return result


def update_threat_actor(
    collection   : List[ThreatActor],
    updated_actor: ThreatActor,
) -> List[ThreatActor]:
    """
    Return a new list where the actor matching updated_actor.actorId is replaced.

    Rules
    -----
    - Match is by actorId — actorKey and actorId are stable (never recomputed).
    - If no matching actor is found, the list is returned unchanged.
    - Input list is never mutated.

    Returns
    -------
    New sorted List[ThreatActor].
    """
    replaced = False
    result: List[ThreatActor] = []
    for a in collection:
        if a.actorId == updated_actor.actorId:
            result.append(updated_actor)
            replaced = True
        else:
            result.append(a)

    if replaced:
        result.sort(key=lambda a: a.actorId)
        _log.info(
            "actor_updated",
            extra={"actorId": updated_actor.actorId, "actorName": updated_actor.name},
        )
    return result


def remove_threat_actor(
    collection : List[ThreatActor],
    actor_id   : str,
) -> List[ThreatActor]:
    """
    Return a new list with the actor matching actor_id removed.

    Rules
    -----
    - Match is by actorId (exact, case-sensitive).
    - If no match, the original list is returned unchanged.
    - Input list is never mutated.

    Returns
    -------
    New List[ThreatActor] with the matching actor excluded.
    """
    result = [a for a in collection if a.actorId != actor_id]
    if len(result) < len(collection):
        _log.info(
            "actor_removed",
            extra={"actorId": actor_id},
        )
    return result


def merge_threat_actors(
    base    : List[ThreatActor],
    incoming: List[ThreatActor],
) -> List[ThreatActor]:
    """
    Merge two ThreatActor collections deterministically.

    Rules
    -----
    - Deduplication is by actorId.
    - For a collision (same actorId), the actor from *base* is kept.
    - Result is sorted by actorId ASC.
    - Input lists are never mutated.
    - Zero randomness: canonical sort before any iteration.

    Returns
    -------
    New merged and sorted List[ThreatActor].
    """
    ordered_base     = sorted(base,     key=lambda a: a.actorId)
    ordered_incoming = sorted(incoming, key=lambda a: a.actorId)

    merged: Dict[str, ThreatActor] = {}
    for a in ordered_base:
        merged[a.actorId] = a
    for a in ordered_incoming:
        if a.actorId not in merged:
            merged[a.actorId] = a

    result = sorted(merged.values(), key=lambda a: a.actorId)
    _log.info(
        "merge_completed",
        extra={
            "type"         : "threat_actors",
            "baseCount"    : len(base),
            "incomingCount": len(incoming),
            "resultCount"  : len(result),
        },
    )
    return result


# ===========================================================================
# Part 2 — Campaign Operations
# ===========================================================================

def add_campaign(
    collection   : List[ThreatCampaign],
    new_campaign : ThreatCampaign,
) -> List[ThreatCampaign]:
    """
    Return a new list with new_campaign added, deduplicating by campaignId.

    Rules
    -----
    - If a campaign with the same campaignId already exists, the existing
      campaign is kept (first-write-wins — identity is stable).
    - Otherwise new_campaign is appended and the list is sorted by campaignId ASC.
    - Input list is never mutated.

    Returns
    -------
    New sorted List[ThreatCampaign].
    """
    existing_ids = {c.campaignId for c in collection}
    if new_campaign.campaignId in existing_ids:
        _log.debug(
            "threat_campaign_duplicate_skipped",
            extra={"campaignId": new_campaign.campaignId},
        )
        return list(sorted(collection, key=lambda c: c.campaignId))

    result = list(collection) + [new_campaign]
    result.sort(key=lambda c: c.campaignId)
    _log.info(
        "campaign_created",
        extra={"campaignId": new_campaign.campaignId, "campaignName": new_campaign.name},
    )
    return result


def update_campaign(
    collection       : List[ThreatCampaign],
    updated_campaign : ThreatCampaign,
) -> List[ThreatCampaign]:
    """
    Return a new list where the campaign matching updated_campaign.campaignId
    is replaced.

    Rules
    -----
    - Match is by campaignId — campaignKey and campaignId are stable.
    - If no matching campaign is found, the list is returned unchanged.
    - Input list is never mutated.

    Returns
    -------
    New sorted List[ThreatCampaign].
    """
    replaced = False
    result: List[ThreatCampaign] = []
    for c in collection:
        if c.campaignId == updated_campaign.campaignId:
            result.append(updated_campaign)
            replaced = True
        else:
            result.append(c)

    if replaced:
        result.sort(key=lambda c: c.campaignId)
        _log.info(
            "campaign_updated",
            extra={"campaignId": updated_campaign.campaignId, "campaignName": updated_campaign.name},
        )
    return result


def remove_campaign(
    collection  : List[ThreatCampaign],
    campaign_id : str,
) -> List[ThreatCampaign]:
    """
    Return a new list with the campaign matching campaign_id removed.

    Rules
    -----
    - Match is by campaignId (exact, case-sensitive).
    - If no match, the original list is returned unchanged.
    - Input list is never mutated.

    Returns
    -------
    New List[ThreatCampaign] with the matching campaign excluded.
    """
    result = [c for c in collection if c.campaignId != campaign_id]
    if len(result) < len(collection):
        _log.info(
            "campaign_removed",
            extra={"campaignId": campaign_id},
        )
    return result


def merge_campaigns(
    base    : List[ThreatCampaign],
    incoming: List[ThreatCampaign],
) -> List[ThreatCampaign]:
    """
    Merge two ThreatCampaign collections deterministically.

    Rules
    -----
    - Deduplication is by campaignId.
    - For a collision (same campaignId), the campaign from *base* is kept.
    - Result is sorted by campaignId ASC.
    - Input lists are never mutated.
    - Zero randomness: canonical sort before any iteration.

    Returns
    -------
    New merged and sorted List[ThreatCampaign].
    """
    ordered_base     = sorted(base,     key=lambda c: c.campaignId)
    ordered_incoming = sorted(incoming, key=lambda c: c.campaignId)

    merged: Dict[str, ThreatCampaign] = {}
    for c in ordered_base:
        merged[c.campaignId] = c
    for c in ordered_incoming:
        if c.campaignId not in merged:
            merged[c.campaignId] = c

    result = sorted(merged.values(), key=lambda c: c.campaignId)
    _log.info(
        "merge_completed",
        extra={
            "type"         : "campaigns",
            "baseCount"    : len(base),
            "incomingCount": len(incoming),
            "resultCount"  : len(result),
        },
    )
    return result


# ===========================================================================
# Part 2 — Mapping Operations
# ===========================================================================

def add_threat_mapping(
    collection  : List[ThreatMapping],
    new_mapping : ThreatMapping,
) -> List[ThreatMapping]:
    """
    Return a new list with new_mapping added, deduplicating by mappingId.

    Rules
    -----
    - If a mapping with the same mappingId already exists, the existing
      mapping is kept (first-write-wins / idempotent).
    - Otherwise new_mapping is appended and the list is sorted by mappingId ASC.
    - Input list is never mutated.

    Returns
    -------
    New sorted List[ThreatMapping].
    """
    existing_ids = {m.mappingId for m in collection}
    if new_mapping.mappingId in existing_ids:
        _log.debug(
            "threat_mapping_duplicate_skipped",
            extra={"mappingId": new_mapping.mappingId},
        )
        return list(sorted(collection, key=lambda m: m.mappingId))

    result = list(collection) + [new_mapping]
    result.sort(key=lambda m: m.mappingId)
    _log.info(
        "mapping_created",
        extra={"mappingId": new_mapping.mappingId},
    )
    return result


def remove_threat_mapping(
    collection  : List[ThreatMapping],
    mapping_id  : str,
) -> List[ThreatMapping]:
    """
    Return a new list with the mapping matching mapping_id removed.

    Rules
    -----
    - Match is by mappingId (exact, case-sensitive).
    - If no match, the original list is returned unchanged.
    - Input list is never mutated.

    Returns
    -------
    New List[ThreatMapping] with the matching mapping excluded.
    """
    result = [m for m in collection if m.mappingId != mapping_id]
    if len(result) < len(collection):
        _log.info(
            "mapping_removed",
            extra={"mappingId": mapping_id},
        )
    return result


def merge_threat_mappings(
    base    : List[ThreatMapping],
    incoming: List[ThreatMapping],
) -> List[ThreatMapping]:
    """
    Merge two ThreatMapping collections deterministically.

    Rules
    -----
    - Deduplication is by mappingId.
    - For a collision (same mappingId), the mapping from *base* is kept.
    - Result is sorted by mappingId ASC.
    - Input lists are never mutated.
    - Zero randomness: canonical sort before any iteration.

    Returns
    -------
    New merged and sorted List[ThreatMapping].
    """
    ordered_base     = sorted(base,     key=lambda m: m.mappingId)
    ordered_incoming = sorted(incoming, key=lambda m: m.mappingId)

    merged: Dict[str, ThreatMapping] = {}
    for m in ordered_base:
        merged[m.mappingId] = m
    for m in ordered_incoming:
        if m.mappingId not in merged:
            merged[m.mappingId] = m

    result = sorted(merged.values(), key=lambda m: m.mappingId)
    _log.info(
        "merge_completed",
        extra={
            "type"         : "threat_mappings",
            "baseCount"    : len(base),
            "incomingCount": len(incoming),
            "resultCount"  : len(result),
        },
    )
    return result


# ===========================================================================
# Part 2 — Search Utilities
# ===========================================================================

def find_threat_actor(
    collection : List[ThreatActor],
    actor_id   : Optional[str] = None,
    actor_key  : Optional[str] = None,
) -> Optional[ThreatActor]:
    """
    Find a single ThreatActor by actorId or actorKey.

    Rules
    -----
    - actor_id takes priority over actor_key when both are supplied.
    - Lookup is exact case-sensitive match.
    - Returns the first match in deterministic actorId ASC order.
    - Returns None if no match or no criteria supplied.
    - Input list is never mutated.

    Parameters
    ----------
    collection : list of ThreatActor objects to search.
    actor_id   : actorId to match (exact).
    actor_key  : actorKey to match (exact).

    Returns
    -------
    First matching ThreatActor, or None.
    """
    ordered = sorted(collection, key=lambda a: a.actorId)

    if actor_id is not None:
        target = actor_id.strip()
        for a in ordered:
            if a.actorId == target:
                return a
        return None

    if actor_key is not None:
        target = actor_key.strip()
        for a in ordered:
            if a.actorKey == target:
                return a
        return None

    return None


def find_campaign(
    collection  : List[ThreatCampaign],
    campaign_id : Optional[str] = None,
    campaign_key: Optional[str] = None,
) -> Optional[ThreatCampaign]:
    """
    Find a single ThreatCampaign by campaignId or campaignKey.

    Rules
    -----
    - campaign_id takes priority over campaign_key when both are supplied.
    - Lookup is exact case-sensitive match.
    - Returns the first match in deterministic campaignId ASC order.
    - Returns None if no match or no criteria supplied.
    - Input list is never mutated.

    Parameters
    ----------
    collection   : list of ThreatCampaign objects to search.
    campaign_id  : campaignId to match (exact).
    campaign_key : campaignKey to match (exact).

    Returns
    -------
    First matching ThreatCampaign, or None.
    """
    ordered = sorted(collection, key=lambda c: c.campaignId)

    if campaign_id is not None:
        target = campaign_id.strip()
        for c in ordered:
            if c.campaignId == target:
                return c
        return None

    if campaign_key is not None:
        target = campaign_key.strip()
        for c in ordered:
            if c.campaignKey == target:
                return c
        return None

    return None


def find_threat_mapping(
    collection : List[ThreatMapping],
    mapping_id : Optional[str] = None,
) -> Optional[ThreatMapping]:
    """
    Find a single ThreatMapping by mappingId.

    Rules
    -----
    - Lookup is exact case-sensitive match against mappingId.
    - Returns the first match in deterministic mappingId ASC order.
    - Returns None if no match or no criteria supplied.
    - Input list is never mutated.

    Parameters
    ----------
    collection : list of ThreatMapping objects to search.
    mapping_id : mappingId to match (exact).

    Returns
    -------
    First matching ThreatMapping, or None.
    """
    if mapping_id is None:
        return None

    ordered = sorted(collection, key=lambda m: m.mappingId)
    target  = mapping_id.strip()
    for m in ordered:
        if m.mappingId == target:
            return m
    return None


# ===========================================================================
# Part 2 — Sorting
# ===========================================================================

# Confidence order for deterministic sorting (higher = more confident)
_CONFIDENCE_ORDER: Dict[ThreatConfidenceEnum, int] = {
    ThreatConfidenceEnum.VERIFIED : 4,
    ThreatConfidenceEnum.HIGH     : 3,
    ThreatConfidenceEnum.MEDIUM   : 2,
    ThreatConfidenceEnum.LOW      : 1,
}

_VALID_ACTOR_SORT_KEYS = frozenset({
    "name", "confidence", "country", "createdAt",
})

_VALID_CAMPAIGN_SORT_KEYS = frozenset({
    "name", "confidence", "createdAt", "startDate",
})

_VALID_MAPPING_SORT_KEYS = frozenset({
    "confidence", "createdAt", "mappingId",
})


def sort_threat_actors(
    actors    : List[ThreatActor],
    by        : str  = "name",
    ascending : bool = True,
) -> List[ThreatActor]:
    """
    Return a new sorted list of ThreatActor objects.

    Parameters
    ----------
    by        : "name" (default) | "confidence" | "country" | "createdAt"
    ascending : True = ascending (default for name/country/createdAt).

    Tie-breaking is always by actorId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted List[ThreatActor] — input is not mutated.
    """
    if by not in _VALID_ACTOR_SORT_KEYS:
        raise ValueError(
            f"sort_threat_actors: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_ACTOR_SORT_KEYS)}"
        )

    def _key(a: ThreatActor) -> tuple:
        if by == "confidence":
            primary = _CONFIDENCE_ORDER.get(a.confidence, 0)
        elif by == "name":
            primary = a.name.lower()
        elif by == "country":
            primary = a.country.lower()
        else:  # createdAt
            primary = a.createdAt
        return (primary, a.actorId)

    return sorted(actors, key=_key, reverse=not ascending)


def sort_campaigns(
    campaigns : List[ThreatCampaign],
    by        : str  = "name",
    ascending : bool = True,
) -> List[ThreatCampaign]:
    """
    Return a new sorted list of ThreatCampaign objects.

    Parameters
    ----------
    by        : "name" (default) | "confidence" | "createdAt" | "startDate"
    ascending : True = ascending (default).

    Tie-breaking is always by campaignId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted List[ThreatCampaign] — input is not mutated.
    """
    if by not in _VALID_CAMPAIGN_SORT_KEYS:
        raise ValueError(
            f"sort_campaigns: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_CAMPAIGN_SORT_KEYS)}"
        )

    def _key(c: ThreatCampaign) -> tuple:
        if by == "confidence":
            primary = _CONFIDENCE_ORDER.get(c.confidence, 0)
        elif by == "name":
            primary = c.name.lower()
        elif by == "startDate":
            primary = c.startDate
        else:  # createdAt
            primary = c.createdAt
        return (primary, c.campaignId)

    return sorted(campaigns, key=_key, reverse=not ascending)


def sort_threat_mappings(
    mappings  : List[ThreatMapping],
    by        : str  = "confidence",
    ascending : bool = False,
) -> List[ThreatMapping]:
    """
    Return a new sorted list of ThreatMapping objects.

    Parameters
    ----------
    by        : "confidence" (default) | "createdAt" | "mappingId"
    ascending : False = descending — highest confidence first (default).

    Tie-breaking is always by mappingId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted List[ThreatMapping] — input is not mutated.
    """
    if by not in _VALID_MAPPING_SORT_KEYS:
        raise ValueError(
            f"sort_threat_mappings: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: ThreatMapping) -> tuple:
        if by == "confidence":
            primary = m.confidence
        elif by == "createdAt":
            primary = m.createdAt
        else:  # mappingId
            primary = m.mappingId
        return (primary, m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Part 2 — Filtering
# ===========================================================================

def filter_threat_actors(
    actors            : List[ThreatActor],
    country           : Optional[str]               = None,
    confidence        : Optional[ThreatConfidenceEnum] = None,
    related_technique : Optional[str]               = None,
    related_cve       : Optional[str]               = None,
    related_ioc       : Optional[str]               = None,
) -> List[ThreatActor]:
    """
    Filter ThreatActor objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    country           : keep only actors whose country matches (case-insensitive).
    confidence        : keep only actors with this ThreatConfidenceEnum.
    related_technique : keep only actors that have this technique ID in
                        relatedTechniques (case-insensitive; stored uppercase).
    related_cve       : keep only actors that have this CVE ID in relatedCVEs
                        (case-insensitive; stored uppercase).
    related_ioc       : keep only actors that have this IOC value in relatedIOCs
                        (case-sensitive; stored as-is).

    Returns
    -------
    New filtered List[ThreatActor] sorted by actorId ASC — input not mutated.
    """
    norm_country   = _norm(country).lower()              if country           is not None else None
    norm_technique = _norm(related_technique or "").upper() if related_technique is not None else None
    norm_cve       = _norm(related_cve or "").upper()       if related_cve       is not None else None
    norm_ioc       = _norm(related_ioc or "")               if related_ioc       is not None else None

    result: List[ThreatActor] = []
    for a in sorted(actors, key=lambda x: x.actorId):
        if norm_country   is not None and a.country.lower() != norm_country:
            continue
        if confidence     is not None and a.confidence != confidence:
            continue
        if norm_technique is not None and norm_technique not in a.relatedTechniques:
            continue
        if norm_cve       is not None and norm_cve not in a.relatedCVEs:
            continue
        if norm_ioc       is not None and norm_ioc not in a.relatedIOCs:
            continue
        result.append(a)

    return result


def filter_campaigns(
    campaigns         : List[ThreatCampaign],
    confidence        : Optional[ThreatConfidenceEnum] = None,
    related_technique : Optional[str]               = None,
    related_cve       : Optional[str]               = None,
    related_ioc       : Optional[str]               = None,
    threat_actor_id   : Optional[str]               = None,
) -> List[ThreatCampaign]:
    """
    Filter ThreatCampaign objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    confidence        : keep only campaigns with this ThreatConfidenceEnum.
    related_technique : keep only campaigns with this technique ID in
                        relatedTechniques (case-insensitive; stored uppercase).
    related_cve       : keep only campaigns with this CVE ID in relatedCVEs
                        (case-insensitive; stored uppercase).
    related_ioc       : keep only campaigns with this IOC value in relatedIOCs.
    threat_actor_id   : keep only campaigns whose threatActors tuple contains
                        this actorId (exact match).

    Returns
    -------
    New filtered List[ThreatCampaign] sorted by campaignId ASC — input not mutated.
    """
    norm_technique = _norm(related_technique or "").upper() if related_technique is not None else None
    norm_cve       = _norm(related_cve or "").upper()       if related_cve       is not None else None
    norm_ioc       = _norm(related_ioc or "")               if related_ioc       is not None else None
    norm_actor_id  = _norm(threat_actor_id or "")           if threat_actor_id   is not None else None

    result: List[ThreatCampaign] = []
    for c in sorted(campaigns, key=lambda x: x.campaignId):
        if confidence     is not None and c.confidence != confidence:
            continue
        if norm_technique is not None and norm_technique not in c.relatedTechniques:
            continue
        if norm_cve       is not None and norm_cve not in c.relatedCVEs:
            continue
        if norm_ioc       is not None and norm_ioc not in c.relatedIOCs:
            continue
        if norm_actor_id  is not None and norm_actor_id not in c.threatActors:
            continue
        result.append(c)

    return result


def filter_threat_mappings(
    mappings          : List[ThreatMapping],
    finding_id        : Optional[str]   = None,
    alert_id          : Optional[str]   = None,
    reasoning_id      : Optional[str]   = None,
    min_confidence    : Optional[float] = None,
    max_confidence    : Optional[float] = None,
    threat_actor_id   : Optional[str]   = None,
    campaign_id       : Optional[str]   = None,
) -> List[ThreatMapping]:
    """
    Filter ThreatMapping objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    finding_id      : keep only mappings with this findingId (exact).
    alert_id        : keep only mappings with this alertId (exact).
    reasoning_id    : keep only mappings with this reasoningId (exact).
    min_confidence  : keep only mappings with confidence >= min_confidence.
    max_confidence  : keep only mappings with confidence <= max_confidence.
    threat_actor_id : keep only mappings whose actors tuple contains an actor
                      with this actorId (exact match).
    campaign_id     : keep only mappings whose campaigns tuple contains a
                      campaign with this campaignId (exact match).

    Returns
    -------
    New filtered List[ThreatMapping] sorted by mappingId ASC — input not mutated.
    """
    result: List[ThreatMapping] = []

    for m in sorted(mappings, key=lambda x: x.mappingId):
        if finding_id     is not None and m.findingId   != finding_id.strip():
            continue
        if alert_id       is not None and m.alertId     != alert_id.strip():
            continue
        if reasoning_id   is not None and m.reasoningId != reasoning_id.strip():
            continue
        if min_confidence is not None and m.confidence < min_confidence:
            continue
        if max_confidence is not None and m.confidence > max_confidence:
            continue
        if threat_actor_id is not None:
            actor_ids = {a.actorId for a in m.actors}
            if threat_actor_id.strip() not in actor_ids:
                continue
        if campaign_id is not None:
            camp_ids = {c.campaignId for c in m.campaigns}
            if campaign_id.strip() not in camp_ids:
                continue
        result.append(m)

    return result


# ===========================================================================
# Part 2 — Grouping
# ===========================================================================

def group_threat_actors(
    actors   : List[ThreatActor],
    group_by : str = "country",
) -> Dict[str, List[ThreatActor]]:
    """
    Group ThreatActor objects by a string attribute.

    Parameters
    ----------
    group_by : "country" (default) | "confidence" | "motivation"

    Each group's list is sorted by actorId ASC for determinism.
    Enum values are unwrapped to their .value string.
    Empty-string attribute values are grouped under key "unknown".

    Raises
    ------
    ValueError : for unknown group_by key.

    Returns
    -------
    Dict[str, List[ThreatActor]] — each list sorted by actorId ASC.
    Input is not mutated.
    """
    _valid = frozenset({"country", "confidence", "motivation"})
    if group_by not in _valid:
        raise ValueError(
            f"group_threat_actors: unknown key '{group_by}'. "
            f"Valid: {sorted(_valid)}"
        )

    groups: Dict[str, List[ThreatActor]] = {}
    for a in sorted(actors, key=lambda x: x.actorId):
        raw = getattr(a, group_by, None)
        if isinstance(raw, ThreatConfidenceEnum):
            key = raw.value
        elif raw:
            key = str(raw)
        else:
            key = "unknown"
        groups.setdefault(key, []).append(a)

    return groups


def group_campaigns(
    campaigns: List[ThreatCampaign],
    group_by : str = "confidence",
) -> Dict[str, List[ThreatCampaign]]:
    """
    Group ThreatCampaign objects by a string attribute.

    Parameters
    ----------
    group_by : "confidence" (default) | "startDate"

    Each group's list is sorted by campaignId ASC for determinism.
    Enum values are unwrapped to their .value string.
    Empty-string attribute values are grouped under key "unknown".

    Raises
    ------
    ValueError : for unknown group_by key.

    Returns
    -------
    Dict[str, List[ThreatCampaign]] — each list sorted by campaignId ASC.
    Input is not mutated.
    """
    _valid = frozenset({"confidence", "startDate"})
    if group_by not in _valid:
        raise ValueError(
            f"group_campaigns: unknown key '{group_by}'. "
            f"Valid: {sorted(_valid)}"
        )

    groups: Dict[str, List[ThreatCampaign]] = {}
    for c in sorted(campaigns, key=lambda x: x.campaignId):
        raw = getattr(c, group_by, None)
        if isinstance(raw, ThreatConfidenceEnum):
            key = raw.value
        elif raw:
            key = str(raw)
        else:
            key = "unknown"
        groups.setdefault(key, []).append(c)

    return groups


def group_threat_mappings(
    mappings : List[ThreatMapping],
    group_by : str = "findingId",
) -> Dict[str, List[ThreatMapping]]:
    """
    Group ThreatMapping objects by a string attribute.

    Parameters
    ----------
    group_by : "findingId" (default) | "alertId" | "reasoningId"

    Each group's list is sorted by mappingId ASC for determinism.
    Empty-string attribute values are grouped under key "none".

    Raises
    ------
    ValueError : for unknown group_by key.

    Returns
    -------
    Dict[str, List[ThreatMapping]] — each list sorted by mappingId ASC.
    Input is not mutated.
    """
    _valid = frozenset({"findingId", "alertId", "reasoningId"})
    if group_by not in _valid:
        raise ValueError(
            f"group_threat_mappings: unknown key '{group_by}'. "
            f"Valid: {sorted(_valid)}"
        )

    groups: Dict[str, List[ThreatMapping]] = {}
    for m in sorted(mappings, key=lambda x: x.mappingId):
        raw = getattr(m, group_by, "")
        key = str(raw) if raw else "none"
        groups.setdefault(key, []).append(m)

    return groups

