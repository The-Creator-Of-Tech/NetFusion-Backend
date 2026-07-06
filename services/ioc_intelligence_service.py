"""
IOC Intelligence Engine
========================
Phase A4.4.3 — Deterministic, immutable Indicator of Compromise (IOC) record
and mapping management for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model IOCRecord, IOCMapping, and IOCStatistics as immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_ioc_record, build_ioc_mapping, build_ioc_statistics.
- Expose validation functions:
    validate_ioc_record, validate_ioc_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  CVERecord, and MitreTechnique objects into IOC references.
  No AI execution.  No network.  Transform only.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No HTTP. No external API. No database. No AI execution.
- Pure deterministic business logic only.

Out of scope (Part B)
---------------------
- CRUD, Search, Filter, Sort, Group, Merge, Bulk Operations, Smoke Test.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import IOC_INTELLIGENCE_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("ioc_intelligence_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_IOC_NS = uuid.UUID("6ba7b870-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class IOCTypeEnum(str, Enum):
    """Indicator of Compromise type classification."""
    IP          = "IP"
    DOMAIN      = "DOMAIN"
    URL         = "URL"
    EMAIL       = "EMAIL"
    HASH_MD5    = "HASH_MD5"
    HASH_SHA1   = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    REGISTRY    = "REGISTRY"
    FILE        = "FILE"
    MUTEX       = "MUTEX"
    PROCESS     = "PROCESS"


class IOCSeverityEnum(str, Enum):
    """Severity classification for an IOC."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class IOCConfidenceEnum(str, Enum):
    """Confidence classification for an IOC."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    VERIFIED = "VERIFIED"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class IOCIntelligenceError(Exception):
    """Base class for all IOC Intelligence Engine errors."""


class InvalidIOCError(IOCIntelligenceError):
    """Raised when an IOCRecord fails validation."""


class InvalidIOCMappingError(IOCIntelligenceError):
    """Raised when an IOCMapping fails validation."""


class InvalidIOCTypeError(IOCIntelligenceError):
    """Raised when an IOCTypeEnum value fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class IOCRecord(BaseModel):
    """
    One immutable Indicator of Compromise record.

    Identity
    --------
    iocKey         : SHA256(iocType.value + value)[:32]
    iocId          : UUIDv5(_IOC_NS, iocKey)
    iocFingerprint : SHA256(iocKey + iocType.value + value +
                            severity.value + confidence.value)[:32]

    Fields
    ------
    iocId              : deterministic UUID derived from iocKey.
    iocKey             : 32-char SHA-256 identity key.
    iocFingerprint     : 32-char SHA-256 content fingerprint.
    iocType            : IOCTypeEnum — indicator type classification.
    value              : raw indicator value (e.g. IP address, domain, hash).
    severity           : IOCSeverityEnum — threat severity level.
    confidence         : IOCConfidenceEnum — confidence classification.
    description        : human-readable description of the IOC.
    source             : origin of this IOC (e.g. "finding", "alert", "manual").
    tags               : sorted tuple of lowercase classification tag strings.
    relatedCVEs        : sorted tuple of CVE ID strings linked to this IOC.
    relatedTechniques  : sorted tuple of MITRE ATT&CK technique ID strings.
    createdAt          : ISO-8601 timestamp (caller-supplied for determinism).
    """
    iocId             : str
    iocKey            : str
    iocFingerprint    : str
    iocType           : IOCTypeEnum
    value             : str
    severity          : IOCSeverityEnum
    confidence        : IOCConfidenceEnum
    description       : str
    source            : str
    tags              : Tuple[str, ...]
    relatedCVEs       : Tuple[str, ...]
    relatedTechniques : Tuple[str, ...]
    createdAt         : str

    class Config:
        frozen = True


class IOCMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to IOCRecord objects.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(iocRecordIds))[:32]
    mappingId          : UUIDv5(_IOC_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(iocRecordIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    mappingFingerprint : deterministic 32-char content fingerprint.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    iocRecords         : sorted tuple of IOCRecord objects linked
                         (sorted by iocType ASC then iocId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    mappingFingerprint : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    iocRecords         : Tuple[IOCRecord, ...]
    confidence         : float
    createdAt          : str

    class Config:
        frozen = True


class IOCStatistics(BaseModel):
    """
    Aggregate statistics over a collection of IOCRecord objects.

    Fields
    ------
    totalIOCs         : total count of distinct IOC records.
    verifiedIOCs      : count of records with confidence == VERIFIED.
    criticalIOCs      : count of records with severity == CRITICAL.
    highIOCs          : count of records with severity == HIGH.
    mediumIOCs        : count of records with severity == MEDIUM.
    lowIOCs           : count of records with severity == LOW.
    iocTypeCounts     : dict mapping IOCTypeEnum.value → count of distinct IOCs.
    averageConfidence : mean numeric confidence weight across all IOCs (0.0 if empty).
    """
    totalIOCs         : int
    verifiedIOCs      : int
    criticalIOCs      : int
    highIOCs          : int
    mediumIOCs        : int
    lowIOCs           : int
    iocTypeCounts     : Dict[str, int]
    averageConfidence : float

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
    """UUIDv5(_IOC_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_IOC_NS, key))


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
# Confidence enum → numeric weight (used for averageConfidence in statistics)
# ---------------------------------------------------------------------------
_CONFIDENCE_WEIGHT: Dict[IOCConfidenceEnum, float] = {
    IOCConfidenceEnum.LOW      : 25.0,
    IOCConfidenceEnum.MEDIUM   : 50.0,
    IOCConfidenceEnum.HIGH     : 75.0,
    IOCConfidenceEnum.VERIFIED : 100.0,
}


# ---------------------------------------------------------------------------
# Public key derivation functions (named per spec)
# ---------------------------------------------------------------------------

def iocKey(ioc_type: IOCTypeEnum, value: str) -> str:
    """
    iocKey = SHA256(iocType.value + value)[:32]

    Null-byte-separated to prevent cross-field collisions.
    Same (iocType, value) pair always produces the same key.
    """
    return _sha256_32(ioc_type.value, _norm(value))


def iocMappingKey(
    finding_id    : str,
    alert_id      : str,
    reasoning_id  : str,
    ioc_record_ids: Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(iocRecordIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    iocRecordIds sorted before joining for order-independence.
    """
    sorted_ids = "\x01".join(sorted(ioc_record_ids))
    return _sha256_32(
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_ids,
    )


def iocMappingFingerprint(
    m_key         : str,
    finding_id    : str,
    alert_id      : str,
    reasoning_id  : str,
    ioc_record_ids: Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(iocRecordIds))[:32]
    """
    sorted_ids = "\x01".join(sorted(ioc_record_ids))
    return _sha256_32(
        m_key,
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_ids,
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_ioc_record(
    ioc_type   : IOCTypeEnum,
    value      : str,
    severity   : IOCSeverityEnum,
    confidence : IOCConfidenceEnum,
    created_at : str,
) -> None:
    """
    Validate IOCRecord construction parameters.

    Checks
    ------
    - ioc_type is a valid IOCTypeEnum member.
    - value is non-empty.
    - severity is a valid IOCSeverityEnum member.
    - confidence is a valid IOCConfidenceEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidIOCTypeError : if ioc_type is not a valid IOCTypeEnum member.
    InvalidIOCError     : if any other field fails validation.
    """
    # Validate ioc_type first — raises its own typed exception
    if not isinstance(ioc_type, IOCTypeEnum):
        _log.warning(
            "validation_failure",
            extra={
                "validator": "validate_ioc_record",
                "field"    : "iocType",
                "value"    : repr(ioc_type),
            },
        )
        raise InvalidIOCTypeError(
            f"iocType must be an IOCTypeEnum member; got {ioc_type!r}."
        )

    errors: List[str] = []

    if not value or not value.strip():
        errors.append("value must not be empty.")

    if not isinstance(severity, IOCSeverityEnum):
        errors.append(
            f"severity must be an IOCSeverityEnum member; got {severity!r}."
        )

    if not isinstance(confidence, IOCConfidenceEnum):
        errors.append(
            f"confidence must be an IOCConfidenceEnum member; got {confidence!r}."
        )

    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_ioc_record", "errors": errors},
        )
        raise InvalidIOCError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_ioc_mapping(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    confidence  : float,
    created_at  : str,
) -> None:
    """
    Validate IOCMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidIOCMappingError : if any rule is violated.
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
            extra={"validator": "validate_ioc_mapping", "errors": errors},
        )
        raise InvalidIOCMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_ioc_record()
# ===========================================================================

def build_ioc_record(
    ioc_type           : IOCTypeEnum,
    value              : str,
    severity           : IOCSeverityEnum,
    confidence         : IOCConfidenceEnum,
    created_at         : str,
    description        : str                = "",
    source             : str                = "",
    tags               : Optional[List[str]] = None,
    related_cves       : Optional[List[str]] = None,
    related_techniques : Optional[List[str]] = None,
    validate           : bool               = True,
) -> IOCRecord:
    """
    Build an immutable IOCRecord.

    iocKey         = SHA256(iocType.value + value)[:32]
    iocId          = UUIDv5(_IOC_NS, iocKey)
    iocFingerprint = SHA256(iocKey + iocType.value + value +
                            severity.value + confidence.value)[:32]

    Parameters
    ----------
    ioc_type           : IOCTypeEnum — indicator type classification.
    value              : raw indicator value (non-empty; trimmed).
    severity           : IOCSeverityEnum — threat severity level.
    confidence         : IOCConfidenceEnum — confidence classification.
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    description        : human-readable description of the IOC.
    source             : origin identifier (e.g. "finding", "alert", "manual").
    tags               : classification tags (deduped + lowercase + sorted).
    related_cves       : CVE ID strings linked to this IOC
                         (deduped + uppercase + sorted).
    related_techniques : MITRE ATT&CK technique ID strings
                         (deduped + uppercase + sorted).
    validate           : if True, run validate_ioc_record() first.

    Returns
    -------
    IOCRecord (frozen / immutable)

    Raises
    ------
    InvalidIOCTypeError : if validate=True and ioc_type is invalid.
    InvalidIOCError     : if validate=True and other field validation fails.
    """
    if validate:
        validate_ioc_record(ioc_type, value, severity, confidence, created_at)

    norm_value = _norm(value)
    i_key = iocKey(ioc_type, norm_value)
    i_id  = _uuid5(i_key)

    # Content fingerprint: captures all content fields
    norm_cvs   = _norm_upper_strings(related_cves)
    norm_techs = _norm_upper_strings(related_techniques)
    i_fp = _sha256_32(
        i_key,
        ioc_type.value,
        norm_value,
        severity.value,
        confidence.value,
        "\x01".join(norm_cvs),
        "\x01".join(norm_techs),
    )

    return IOCRecord(
        iocId             = i_id,
        iocKey            = i_key,
        iocFingerprint    = i_fp,
        iocType           = ioc_type,
        value             = norm_value,
        severity          = severity,
        confidence        = confidence,
        description       = description,
        source            = _norm_lower(source),
        tags              = _norm_lower_strings(tags),
        relatedCVEs       = norm_cvs,
        relatedTechniques = norm_techs,
        createdAt         = created_at,
    )


# ===========================================================================
# Builder: build_ioc_mapping()
# ===========================================================================

def build_ioc_mapping(
    ioc_records  : List[IOCRecord],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> IOCMapping:
    """
    Build an immutable IOCMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(iocRecordIds))[:32]
    mappingId          = UUIDv5(_IOC_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(iocRecordIds))[:32]

    Parameters
    ----------
    ioc_records  : list of IOCRecord objects to link in this mapping.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_ioc_mapping() first.

    Returns
    -------
    IOCMapping (frozen / immutable)

    Raises
    ------
    InvalidIOCMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_ioc_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: iocType.value ASC, then iocId ASC
    sorted_records: Tuple[IOCRecord, ...] = tuple(
        sorted(
            ioc_records or [],
            key=lambda r: (r.iocType.value, r.iocId),
        )
    )

    # Collect record IDs for key computation
    record_ids: Tuple[str, ...] = tuple(r.iocId for r in sorted_records)

    m_key = iocMappingKey(finding_id, alert_id, reasoning_id, record_ids)
    m_id  = _uuid5(m_key)
    m_fp  = iocMappingFingerprint(
        m_key, finding_id, alert_id, reasoning_id, record_ids
    )

    return IOCMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        mappingFingerprint = m_fp,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        iocRecords         = sorted_records,
        confidence         = round(clamped_conf, 4),
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_ioc_statistics()
# ===========================================================================

def build_ioc_statistics(
    ioc_records: List[IOCRecord],
) -> IOCStatistics:
    """
    Compute IOCStatistics over a flat list of IOCRecord objects.

    Deterministic: canonical sort (by iocId ASC) before accumulation
    so all sums and counts are identical across every run.

    Deduplication is by iocId — first occurrence in sorted order wins.

    Parameters
    ----------
    ioc_records : any list of IOCRecord objects (may contain duplicates).

    Returns
    -------
    IOCStatistics (frozen / immutable)
    """
    if not ioc_records:
        return IOCStatistics(
            totalIOCs         = 0,
            verifiedIOCs      = 0,
            criticalIOCs      = 0,
            highIOCs          = 0,
            mediumIOCs        = 0,
            lowIOCs           = 0,
            iocTypeCounts     = {},
            averageConfidence = 0.0,
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(ioc_records, key=lambda r: r.iocId)

    # Deduplicate by iocId (first occurrence wins)
    seen_ids: Dict[str, IOCRecord] = {}
    for r in ordered:
        if r.iocId not in seen_ids:
            seen_ids[r.iocId] = r

    distinct = list(seen_ids.values())
    # Re-sort after dedup for deterministic counting
    distinct.sort(key=lambda r: r.iocId)

    total    = len(distinct)
    verified = sum(1 for r in distinct if r.confidence == IOCConfidenceEnum.VERIFIED)
    critical = sum(1 for r in distinct if r.severity   == IOCSeverityEnum.CRITICAL)
    high     = sum(1 for r in distinct if r.severity   == IOCSeverityEnum.HIGH)
    medium   = sum(1 for r in distinct if r.severity   == IOCSeverityEnum.MEDIUM)
    low      = sum(1 for r in distinct if r.severity   == IOCSeverityEnum.LOW)

    # Per-type counts — iterate IOCTypeEnum in deterministic declaration order
    type_counts: Dict[str, int] = {}
    for ioc_type in IOCTypeEnum:
        count = sum(1 for r in distinct if r.iocType == ioc_type)
        if count > 0:
            type_counts[ioc_type.value] = count

    # Average numeric confidence weight
    avg_conf = (
        round(
            sum(_CONFIDENCE_WEIGHT.get(r.confidence, 0.0) for r in distinct) / total,
            4,
        )
        if total > 0
        else 0.0
    )

    return IOCStatistics(
        totalIOCs         = total,
        verifiedIOCs      = verified,
        criticalIOCs      = critical,
        highIOCs          = high,
        mediumIOCs        = medium,
        lowIOCs           = low,
        iocTypeCounts     = type_counts,
        averageConfidence = avg_conf,
    )


# ===========================================================================
# Integration Helpers
# ===========================================================================
# These are pure transformation helpers.
# They accept objects from other engine services and return IOCMapping or
# IOCRecord objects.  No external lookups.  No AI execution.  No network.
# Duck-typed inputs — avoids import cycles with other service modules.
# ===========================================================================

def finding_to_ioc_mapping(
    finding     : Any,
    ioc_records : List[IOCRecord],
    created_at  : str,
    confidence  : float = 0.0,
    validate    : bool  = True,
) -> IOCMapping:
    """
    Convert a Finding (from finding_service) into an IOCMapping.

    Rules
    -----
    - findingId  = finding.findingId
    - alertId    = "" (no alert source)
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    finding     : Finding object from finding_service (duck-typed).
    ioc_records : list of IOCRecord objects to map.
    created_at  : ISO-8601 timestamp.
    confidence  : 0.0–100.0 caller-assessed confidence.
    validate    : if True, run validate_ioc_mapping().

    Returns
    -------
    IOCMapping (frozen / immutable)
    """
    _log.debug(
        "finding_to_ioc_mapping",
        extra={
            "findingId": finding.findingId,
            "iocCount" : len(ioc_records),
        },
    )
    return build_ioc_mapping(
        ioc_records  = ioc_records,
        created_at   = created_at,
        finding_id   = finding.findingId,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def alert_to_ioc_mapping(
    alert       : Any,
    ioc_records : List[IOCRecord],
    created_at  : str,
    confidence  : float = 0.0,
    validate    : bool  = True,
) -> IOCMapping:
    """
    Convert an Alert (from alert_service) into an IOCMapping.

    Rules
    -----
    - findingId  = alert.findingId  (Alert always has a source findingId)
    - alertId    = alert.alertId
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    alert       : Alert object from alert_service (duck-typed).
    ioc_records : list of IOCRecord objects to map.
    created_at  : ISO-8601 timestamp.
    confidence  : 0.0–100.0 caller-assessed confidence.
    validate    : if True, run validate_ioc_mapping().

    Returns
    -------
    IOCMapping (frozen / immutable)
    """
    _log.debug(
        "alert_to_ioc_mapping",
        extra={
            "alertId"  : alert.alertId,
            "findingId": alert.findingId,
            "iocCount" : len(ioc_records),
        },
    )
    return build_ioc_mapping(
        ioc_records  = ioc_records,
        created_at   = created_at,
        finding_id   = alert.findingId,
        alert_id     = alert.alertId,
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def reasoning_to_ioc_mapping(
    reasoning   : Any,
    ioc_records : List[IOCRecord],
    created_at  : str,
    finding_id  : str  = "",
    alert_id    : str  = "",
    validate    : bool = True,
) -> IOCMapping:
    """
    Convert a ReasoningResult (from reasoning_service) into an IOCMapping.

    Rules
    -----
    - reasoningId = reasoning.reasoningId
    - confidence  = reasoning.overallConfidence (already 0–100)
    - findingId and alertId are optional caller-supplied context linkages.

    Parameters
    ----------
    reasoning   : ReasoningResult object from reasoning_service (duck-typed).
    ioc_records : list of IOCRecord objects to map.
    created_at  : ISO-8601 timestamp.
    finding_id  : optional finding ID for context linkage (may be empty).
    alert_id    : optional alert ID for context linkage (may be empty).
    validate    : if True, run validate_ioc_mapping().

    Returns
    -------
    IOCMapping (frozen / immutable)
    """
    _log.debug(
        "reasoning_to_ioc_mapping",
        extra={
            "reasoningId": reasoning.reasoningId,
            "confidence" : reasoning.overallConfidence,
            "iocCount"   : len(ioc_records),
        },
    )
    return build_ioc_mapping(
        ioc_records  = ioc_records,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = reasoning.reasoningId,
        confidence   = reasoning.overallConfidence,
        validate     = validate,
    )


def cve_to_ioc_reference(
    cve_record : Any,
    ioc_record : IOCRecord,
) -> IOCRecord:
    """
    Create a deterministic reference between a CVERecord and an IOCRecord
    by returning a new IOCRecord that includes the CVE ID in its relatedCVEs
    tuple.

    Rules
    -----
    - If the cve_record.cveId is already present in ioc_record.relatedCVEs,
      the original record is returned unchanged (idempotent).
    - Otherwise, a new IOCRecord is returned with the CVE ID appended and
      re-sorted in relatedCVEs.
    - iocKey and iocId are stable — identity never changes.
    - iocFingerprint is recomputed because content has changed.
    - validate=False is used internally to avoid redundant field checks on
      already-validated stable fields.

    Parameters
    ----------
    cve_record : CVERecord object from cve_intelligence_service (duck-typed).
    ioc_record : Existing IOCRecord to extend.

    Returns
    -------
    IOCRecord (frozen / immutable) — original if CVE already linked,
    else a new record with the CVE ID added to relatedCVEs.
    """
    cve_id = _norm_upper_strings([getattr(cve_record, "cveId", "")])
    if not cve_id or cve_id[0] in ioc_record.relatedCVEs:
        return ioc_record

    new_cve_id = cve_id[0]

    _log.debug(
        "cve_to_ioc_reference",
        extra={
            "iocId" : ioc_record.iocId,
            "cveId" : new_cve_id,
        },
    )

    new_cves: Tuple[str, ...] = tuple(
        sorted(set(ioc_record.relatedCVEs) | {new_cve_id})
    )

    # Recompute fingerprint — relatedCVEs changed
    new_fp = _sha256_32(
        ioc_record.iocKey,
        ioc_record.iocType.value,
        ioc_record.value,
        ioc_record.severity.value,
        ioc_record.confidence.value,
        "\x01".join(new_cves),
        "\x01".join(ioc_record.relatedTechniques),
    )

    return IOCRecord(
        iocId             = ioc_record.iocId,
        iocKey            = ioc_record.iocKey,
        iocFingerprint    = new_fp,
        iocType           = ioc_record.iocType,
        value             = ioc_record.value,
        severity          = ioc_record.severity,
        confidence        = ioc_record.confidence,
        description       = ioc_record.description,
        source            = ioc_record.source,
        tags              = ioc_record.tags,
        relatedCVEs       = new_cves,
        relatedTechniques = ioc_record.relatedTechniques,
        createdAt         = ioc_record.createdAt,
    )


def mitre_to_ioc_reference(
    technique  : Any,
    ioc_record : IOCRecord,
) -> IOCRecord:
    """
    Create a deterministic reference between a MitreTechnique and an IOCRecord
    by returning a new IOCRecord that includes the technique's mitreId in its
    relatedTechniques tuple.

    Rules
    -----
    - If the technique's mitreId is already present in
      ioc_record.relatedTechniques, the original record is returned unchanged
      (idempotent).
    - Otherwise, a new IOCRecord is returned with the mitreId appended and
      re-sorted in relatedTechniques.
    - iocKey and iocId are stable — identity never changes.
    - iocFingerprint is recomputed because content has changed.
    - validate=False is used internally to avoid redundant field checks on
      already-validated stable fields.

    Parameters
    ----------
    technique  : MitreTechnique object from mitre_attack_service (duck-typed).
    ioc_record : Existing IOCRecord to extend.

    Returns
    -------
    IOCRecord (frozen / immutable) — original if technique already linked,
    else a new record with the mitreId added to relatedTechniques.
    """
    mitre_id_raw = getattr(technique, "mitreId", "")
    norm_mitre_id = mitre_id_raw.strip().upper() if mitre_id_raw else ""

    if not norm_mitre_id or norm_mitre_id in ioc_record.relatedTechniques:
        return ioc_record

    _log.debug(
        "mitre_to_ioc_reference",
        extra={
            "iocId"  : ioc_record.iocId,
            "mitreId": norm_mitre_id,
        },
    )

    new_techniques: Tuple[str, ...] = tuple(
        sorted(set(ioc_record.relatedTechniques) | {norm_mitre_id})
    )

    # Recompute fingerprint — relatedTechniques changed
    new_fp = _sha256_32(
        ioc_record.iocKey,
        ioc_record.iocType.value,
        ioc_record.value,
        ioc_record.severity.value,
        ioc_record.confidence.value,
        "\x01".join(ioc_record.relatedCVEs),
        "\x01".join(new_techniques),
    )

    return IOCRecord(
        iocId             = ioc_record.iocId,
        iocKey            = ioc_record.iocKey,
        iocFingerprint    = new_fp,
        iocType           = ioc_record.iocType,
        value             = ioc_record.value,
        severity          = ioc_record.severity,
        confidence        = ioc_record.confidence,
        description       = ioc_record.description,
        source            = ioc_record.source,
        tags              = ioc_record.tags,
        relatedCVEs       = ioc_record.relatedCVEs,
        relatedTechniques = new_techniques,
        createdAt         = ioc_record.createdAt,
    )


# ===========================================================================
# Part B — IOC Operations
# ===========================================================================

def add_ioc_record(
    collection  : List[IOCRecord],
    new_record  : IOCRecord,
) -> List[IOCRecord]:
    """
    Return a new list with new_record added, deduplicating by iocId.

    Rules
    -----
    - If a record with the same iocId already exists, the existing record
      is kept (first-write-wins — identity is stable).
    - Otherwise new_record is appended and the list is sorted by iocId ASC.
    - Input list is never mutated.

    Parameters
    ----------
    collection : existing list of IOCRecord objects.
    new_record : IOCRecord to add.

    Returns
    -------
    New sorted List[IOCRecord] — deduplicated by iocId.
    """
    existing_ids = {r.iocId for r in collection}
    if new_record.iocId in existing_ids:
        _log.debug(
            "ioc_record_duplicate_skipped",
            extra={"iocId": new_record.iocId},
        )
        return list(sorted(collection, key=lambda r: r.iocId))

    result = list(collection) + [new_record]
    result.sort(key=lambda r: r.iocId)
    _log.info(
        "ioc_record_created",
        extra={"iocId": new_record.iocId, "iocType": new_record.iocType.value},
    )
    return result


def update_ioc_record(
    collection  : List[IOCRecord],
    updated     : IOCRecord,
) -> List[IOCRecord]:
    """
    Return a new list where the record matching updated.iocId is replaced.

    Rules
    -----
    - Match is by iocId — iocKey and iocId are stable (never recomputed).
    - If no matching record is found, the list is returned unchanged.
    - iocFingerprint on the updated record should already reflect new content.
    - Input list is never mutated.

    Parameters
    ----------
    collection : existing list of IOCRecord objects.
    updated    : replacement IOCRecord (same iocId).

    Returns
    -------
    New sorted List[IOCRecord].
    """
    replaced = False
    result: List[IOCRecord] = []
    for r in collection:
        if r.iocId == updated.iocId:
            result.append(updated)
            replaced = True
        else:
            result.append(r)

    if replaced:
        result.sort(key=lambda r: r.iocId)
        _log.info(
            "ioc_record_updated",
            extra={"iocId": updated.iocId, "iocType": updated.iocType.value},
        )
    return result


def remove_ioc_record(
    collection : List[IOCRecord],
    ioc_id     : str,
) -> List[IOCRecord]:
    """
    Return a new list with the record matching ioc_id removed.

    Rules
    -----
    - Match is by iocId (exact, case-sensitive).
    - If no match, the original list is returned unchanged.
    - Input list is never mutated.

    Parameters
    ----------
    collection : existing list of IOCRecord objects.
    ioc_id     : iocId of the record to remove.

    Returns
    -------
    New List[IOCRecord] with the matching record excluded.
    """
    result = [r for r in collection if r.iocId != ioc_id]
    if len(result) < len(collection):
        _log.info(
            "ioc_record_removed",
            extra={"iocId": ioc_id},
        )
    return result


def merge_ioc_records(
    base    : List[IOCRecord],
    incoming: List[IOCRecord],
) -> List[IOCRecord]:
    """
    Merge two IOCRecord collections deterministically.

    Rules
    -----
    - Deduplication is by iocId.
    - For a collision (same iocId), the record from *base* is kept
      (base takes precedence — stable identity).
    - Result is sorted by iocId ASC.
    - Input lists are never mutated.
    - Zero randomness: canonical sort before any iteration.

    Parameters
    ----------
    base     : authoritative collection (takes precedence on collision).
    incoming : records to merge in (only non-duplicate entries are added).

    Returns
    -------
    New merged and sorted List[IOCRecord].
    """
    # Canonical sort before merge for determinism
    ordered_base     = sorted(base,     key=lambda r: r.iocId)
    ordered_incoming = sorted(incoming, key=lambda r: r.iocId)

    merged: Dict[str, IOCRecord] = {}
    for r in ordered_base:
        merged[r.iocId] = r
    for r in ordered_incoming:
        if r.iocId not in merged:
            merged[r.iocId] = r

    result = sorted(merged.values(), key=lambda r: r.iocId)
    _log.info(
        "ioc_records_merge_completed",
        extra={
            "baseCount"    : len(base),
            "incomingCount": len(incoming),
            "resultCount"  : len(result),
        },
    )
    return result


# ===========================================================================
# Part B — Mapping Operations
# ===========================================================================

def add_ioc_mapping(
    collection  : List[IOCMapping],
    new_mapping : IOCMapping,
) -> List[IOCMapping]:
    """
    Return a new list with new_mapping added, deduplicating by mappingId.

    Rules
    -----
    - If a mapping with the same mappingId already exists, the existing
      mapping is kept (idempotent / first-write-wins).
    - Otherwise new_mapping is appended and the list sorted by mappingId ASC.
    - Input list is never mutated.

    Parameters
    ----------
    collection  : existing list of IOCMapping objects.
    new_mapping : IOCMapping to add.

    Returns
    -------
    New sorted List[IOCMapping].
    """
    existing_ids = {m.mappingId for m in collection}
    if new_mapping.mappingId in existing_ids:
        _log.debug(
            "ioc_mapping_duplicate_skipped",
            extra={"mappingId": new_mapping.mappingId},
        )
        return list(sorted(collection, key=lambda m: m.mappingId))

    result = list(collection) + [new_mapping]
    result.sort(key=lambda m: m.mappingId)
    _log.info(
        "ioc_mapping_created",
        extra={"mappingId": new_mapping.mappingId},
    )
    return result


def remove_ioc_mapping(
    collection  : List[IOCMapping],
    mapping_id  : str,
) -> List[IOCMapping]:
    """
    Return a new list with the mapping matching mapping_id removed.

    Rules
    -----
    - Match is by mappingId (exact, case-sensitive).
    - If no match, original list is returned unchanged.
    - Input list is never mutated.

    Parameters
    ----------
    collection : existing list of IOCMapping objects.
    mapping_id : mappingId of the mapping to remove.

    Returns
    -------
    New List[IOCMapping] with the matching mapping excluded.
    """
    result = [m for m in collection if m.mappingId != mapping_id]
    if len(result) < len(collection):
        _log.info(
            "ioc_mapping_removed",
            extra={"mappingId": mapping_id},
        )
    return result


def merge_ioc_mappings(
    base    : List[IOCMapping],
    incoming: List[IOCMapping],
) -> List[IOCMapping]:
    """
    Merge two IOCMapping collections deterministically.

    Rules
    -----
    - Deduplication is by mappingId.
    - For a collision (same mappingId), the mapping from *base* is kept.
    - Result is sorted by mappingId ASC.
    - Input lists are never mutated.
    - Zero randomness: canonical sort before any iteration.

    Parameters
    ----------
    base     : authoritative collection (takes precedence on collision).
    incoming : mappings to merge in (only non-duplicate entries added).

    Returns
    -------
    New merged and sorted List[IOCMapping].
    """
    ordered_base     = sorted(base,     key=lambda m: m.mappingId)
    ordered_incoming = sorted(incoming, key=lambda m: m.mappingId)

    merged: Dict[str, IOCMapping] = {}
    for m in ordered_base:
        merged[m.mappingId] = m
    for m in ordered_incoming:
        if m.mappingId not in merged:
            merged[m.mappingId] = m

    result = sorted(merged.values(), key=lambda m: m.mappingId)
    _log.info(
        "ioc_mappings_merge_completed",
        extra={
            "baseCount"    : len(base),
            "incomingCount": len(incoming),
            "resultCount"  : len(result),
        },
    )
    return result


# ===========================================================================
# Part B — Search Utilities
# ===========================================================================

def find_ioc_record(
    collection : List[IOCRecord],
    ioc_id     : Optional[str] = None,
    value      : Optional[str] = None,
) -> Optional[IOCRecord]:
    """
    Find a single IOCRecord by iocId or value.

    Rules
    -----
    - ioc_id takes priority over value when both are supplied.
    - Lookup by ioc_id is an exact case-sensitive match.
    - Lookup by value is exact case-sensitive match against IOCRecord.value.
    - Returns the first matching record in deterministic iocId ASC order.
    - Returns None if no match is found.
    - Input list is never mutated.

    Parameters
    ----------
    collection : list of IOCRecord objects to search.
    ioc_id     : iocId to match (exact).
    value      : raw indicator value to match (exact).

    Returns
    -------
    First matching IOCRecord, or None.
    """
    ordered = sorted(collection, key=lambda r: r.iocId)

    if ioc_id is not None:
        for r in ordered:
            if r.iocId == ioc_id.strip():
                return r
        return None

    if value is not None:
        norm_v = _norm(value)
        for r in ordered:
            if r.value == norm_v:
                return r
        return None

    return None


def find_ioc_mapping(
    collection : List[IOCMapping],
    mapping_id : Optional[str] = None,
) -> Optional[IOCMapping]:
    """
    Find a single IOCMapping by mappingId.

    Rules
    -----
    - Lookup is an exact case-sensitive match against mappingId.
    - Returns the first match in deterministic mappingId ASC order.
    - Returns None if no match is found.
    - Input list is never mutated.

    Parameters
    ----------
    collection : list of IOCMapping objects to search.
    mapping_id : mappingId to match (exact).

    Returns
    -------
    First matching IOCMapping, or None.
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
# Part B — Sorting
# ===========================================================================

# Severity order for deterministic sorting (higher = more severe)
_SEVERITY_ORDER: Dict[IOCSeverityEnum, int] = {
    IOCSeverityEnum.CRITICAL : 4,
    IOCSeverityEnum.HIGH     : 3,
    IOCSeverityEnum.MEDIUM   : 2,
    IOCSeverityEnum.LOW      : 1,
}

# Confidence order for deterministic sorting (higher = more confident)
_CONFIDENCE_ORDER: Dict[IOCConfidenceEnum, int] = {
    IOCConfidenceEnum.VERIFIED : 4,
    IOCConfidenceEnum.HIGH     : 3,
    IOCConfidenceEnum.MEDIUM   : 2,
    IOCConfidenceEnum.LOW      : 1,
}

_VALID_RECORD_SORT_KEYS = frozenset({
    "iocType", "severity", "confidence", "value", "createdAt",
})

_VALID_MAPPING_SORT_KEYS = frozenset({
    "confidence", "createdAt", "mappingId",
})


def sort_ioc_records(
    records   : List[IOCRecord],
    by        : str  = "severity",
    ascending : bool = False,
) -> List[IOCRecord]:
    """
    Return a new sorted list of IOCRecord objects.

    Parameters
    ----------
    by        : "severity" (default) | "iocType" | "confidence" | "value"
                | "createdAt"
    ascending : False = descending — highest severity/confidence first (default).

    Tie-breaking is always by iocId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted List[IOCRecord] — input is not mutated.
    """
    if by not in _VALID_RECORD_SORT_KEYS:
        raise ValueError(
            f"sort_ioc_records: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_RECORD_SORT_KEYS)}"
        )

    def _key(r: IOCRecord) -> tuple:
        if by == "severity":
            primary = _SEVERITY_ORDER.get(r.severity, 0)
        elif by == "confidence":
            primary = _CONFIDENCE_ORDER.get(r.confidence, 0)
        elif by == "iocType":
            primary = r.iocType.value
        elif by == "value":
            primary = r.value
        else:  # createdAt
            primary = r.createdAt
        return (primary, r.iocId)

    return sorted(records, key=_key, reverse=not ascending)


def sort_ioc_mappings(
    mappings  : List[IOCMapping],
    by        : str  = "confidence",
    ascending : bool = False,
) -> List[IOCMapping]:
    """
    Return a new sorted list of IOCMapping objects.

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
    New sorted List[IOCMapping] — input is not mutated.
    """
    if by not in _VALID_MAPPING_SORT_KEYS:
        raise ValueError(
            f"sort_ioc_mappings: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: IOCMapping) -> tuple:
        if by == "confidence":
            primary = m.confidence
        elif by == "createdAt":
            primary = m.createdAt
        else:  # mappingId
            primary = m.mappingId
        return (primary, m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Part B — Filtering
# ===========================================================================

def filter_ioc_records(
    records            : List[IOCRecord],
    ioc_type           : Optional[IOCTypeEnum]       = None,
    severity           : Optional[IOCSeverityEnum]   = None,
    confidence         : Optional[IOCConfidenceEnum] = None,
    source             : Optional[str]               = None,
    related_cve        : Optional[str]               = None,
    related_technique  : Optional[str]               = None,
    tag                : Optional[str]               = None,
) -> List[IOCRecord]:
    """
    Filter IOCRecord objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    ioc_type          : keep only records of this IOCTypeEnum.
    severity          : keep only records with this IOCSeverityEnum.
    confidence        : keep only records with this IOCConfidenceEnum.
    source            : keep only records whose source matches (case-insensitive).
    related_cve       : keep only records that have this CVE ID in relatedCVEs
                        (case-insensitive match; stored as uppercase).
    related_technique : keep only records that have this technique ID in
                        relatedTechniques (case-insensitive; stored uppercase).
    tag               : keep only records that have this tag in tags
                        (case-insensitive; stored lowercase).

    Returns
    -------
    New filtered List[IOCRecord] — input is not mutated.
    Deterministic: filtered result is sorted by iocId ASC.
    """
    result: List[IOCRecord] = []

    norm_source = _norm_lower(source) if source is not None else None
    norm_cve    = source and _norm(related_cve or "").upper()
    # Fix: compute normalised cve and technique independently
    norm_cve       = _norm(related_cve or "").upper()       if related_cve       is not None else None
    norm_technique = _norm(related_technique or "").upper() if related_technique is not None else None
    norm_tag       = _norm_lower(tag)                       if tag               is not None else None

    for r in sorted(records, key=lambda x: x.iocId):
        if ioc_type  is not None and r.iocType    != ioc_type:
            continue
        if severity  is not None and r.severity   != severity:
            continue
        if confidence is not None and r.confidence != confidence:
            continue
        if norm_source is not None and r.source != norm_source:
            continue
        if norm_cve is not None and norm_cve not in r.relatedCVEs:
            continue
        if norm_technique is not None and norm_technique not in r.relatedTechniques:
            continue
        if norm_tag is not None and norm_tag not in r.tags:
            continue
        result.append(r)

    return result


def filter_ioc_mappings(
    mappings     : List[IOCMapping],
    finding_id   : Optional[str] = None,
    alert_id     : Optional[str] = None,
    reasoning_id : Optional[str] = None,
    min_confidence: Optional[float] = None,
    max_confidence: Optional[float] = None,
) -> List[IOCMapping]:
    """
    Filter IOCMapping objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    finding_id    : keep only mappings with this findingId (exact).
    alert_id      : keep only mappings with this alertId (exact).
    reasoning_id  : keep only mappings with this reasoningId (exact).
    min_confidence: keep only mappings with confidence >= min_confidence.
    max_confidence: keep only mappings with confidence <= max_confidence.

    Returns
    -------
    New filtered List[IOCMapping] — input is not mutated.
    Deterministic: result is sorted by mappingId ASC.
    """
    result: List[IOCMapping] = []

    for m in sorted(mappings, key=lambda x: x.mappingId):
        if finding_id    is not None and m.findingId   != finding_id.strip():
            continue
        if alert_id      is not None and m.alertId     != alert_id.strip():
            continue
        if reasoning_id  is not None and m.reasoningId != reasoning_id.strip():
            continue
        if min_confidence is not None and m.confidence < min_confidence:
            continue
        if max_confidence is not None and m.confidence > max_confidence:
            continue
        result.append(m)

    return result


# ===========================================================================
# Part B — Grouping
# ===========================================================================

def group_ioc_records(
    records  : List[IOCRecord],
    group_by : str = "iocType",
) -> Dict[str, List[IOCRecord]]:
    """
    Group IOCRecord objects by a string attribute.

    Parameters
    ----------
    group_by : "iocType" (default) | "severity" | "confidence" | "source"

    Each group's list is sorted by iocId ASC for determinism.
    Enum values are unwrapped to their .value string.
    Unknown attribute values fall back to key "unknown".

    Raises
    ------
    ValueError : for unknown group_by key.

    Returns
    -------
    Dict[str, List[IOCRecord]] — each list sorted by iocId ASC.
    Input is not mutated.
    """
    _valid = frozenset({"iocType", "severity", "confidence", "source"})
    if group_by not in _valid:
        raise ValueError(
            f"group_ioc_records: unknown key '{group_by}'. "
            f"Valid: {sorted(_valid)}"
        )

    groups: Dict[str, List[IOCRecord]] = {}
    for r in sorted(records, key=lambda x: x.iocId):
        raw = getattr(r, group_by, None)
        key = raw.value if isinstance(raw, (IOCTypeEnum, IOCSeverityEnum, IOCConfidenceEnum)) \
              else (str(raw) if raw is not None else "unknown")
        groups.setdefault(key, []).append(r)

    # Each group is already in iocId ASC order (pre-sorted above)
    return groups


def group_ioc_mappings(
    mappings : List[IOCMapping],
    group_by : str = "findingId",
) -> Dict[str, List[IOCMapping]]:
    """
    Group IOCMapping objects by a string attribute.

    Parameters
    ----------
    group_by : "findingId" (default) | "alertId" | "reasoningId"

    Each group's list is sorted by mappingId ASC for determinism.
    Empty-string attribute values are grouped under the key "none".

    Raises
    ------
    ValueError : for unknown group_by key.

    Returns
    -------
    Dict[str, List[IOCMapping]] — each list sorted by mappingId ASC.
    Input is not mutated.
    """
    _valid = frozenset({"findingId", "alertId", "reasoningId"})
    if group_by not in _valid:
        raise ValueError(
            f"group_ioc_mappings: unknown key '{group_by}'. "
            f"Valid: {sorted(_valid)}"
        )

    groups: Dict[str, List[IOCMapping]] = {}
    for m in sorted(mappings, key=lambda x: x.mappingId):
        raw = getattr(m, group_by, "")
        key = str(raw) if raw else "none"
        groups.setdefault(key, []).append(m)

    return groups
