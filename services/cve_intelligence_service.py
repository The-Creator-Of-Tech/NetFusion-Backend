"""
CVE Intelligence Engine
========================
Phase A4.3.8 — Deterministic, immutable CVE record and mapping management.

Responsibilities
----------------
- Model CVERecord and CVEMapping as immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_cve_record, build_cve_mapping, build_cve_statistics.
- Expose validation functions:
    validate_cve_record, validate_cve_mapping.
- Expose integration helpers:
    finding_to_cve_mapping, alert_to_cve_mapping,
    reasoning_to_cve_mapping, mitre_to_cve_reference.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No HTTP. No NVD API. No CVE downloads. No internet access.
- No database. No frontend. No AI execution.
- Provider-agnostic.

Out of scope
------------
- NVD/CVE database fetching, live lookups, CVSS calculation.
- Streaming, retry/failover, HTTP, websocket.
- Actual AI execution.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import CVE_INTELLIGENCE_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("cve_intelligence_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_CVE_NS = uuid.UUID("6ba7b860-9dad-11d1-80b4-00c04fd430c8")

# ---------------------------------------------------------------------------
# CVE ID validation pattern: CVE-YYYY-NNNN (NNNN is 4+ digits)
# ---------------------------------------------------------------------------
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ===========================================================================
# Enumerations
# ===========================================================================

class SeverityEnum(str, Enum):
    """CVSS-aligned severity classification."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class CVEIntelligenceError(Exception):
    """Base class for all CVE Intelligence Engine errors."""


class InvalidCVEError(CVEIntelligenceError):
    """Raised when a CVERecord fails validation."""


class InvalidCVEMappingError(CVEIntelligenceError):
    """Raised when a CVEMapping fails validation."""


class InvalidCVSSScoreError(CVEIntelligenceError):
    """Raised when a CVSS score is out of the valid [0.0, 10.0] range."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class CVERecord(BaseModel):
    """
    One immutable CVE record.

    Identity
    --------
    recordKey : SHA256(cveId.upper())[:32]
    recordId  : UUIDv5(_CVE_NS, recordKey)

    Fields
    ------
    recordId          : deterministic UUID derived from recordKey.
    recordKey         : 32-char SHA-256 key.
    cveId             : Canonical CVE ID (e.g. "CVE-2021-44228").
    description       : human-readable vulnerability description.
    severity          : SeverityEnum classification.
    cvssScore         : CVSS base score [0.0, 10.0].
    publishedDate     : ISO-8601 publication date string (may be empty).
    modifiedDate      : ISO-8601 last-modified date string (may be empty).
    references        : sorted tuple of reference URL strings.
    affectedPlatforms : sorted tuple of affected platform strings.
    mappedTechniques  : sorted tuple of MitreTechnique objects associated
                        with this CVE (sorted by mitreId ASC).
    createdAt         : ISO-8601 timestamp (caller-supplied for determinism).
    """
    recordId          : str
    recordKey         : str
    cveId             : str
    description       : str
    severity          : SeverityEnum
    cvssScore         : float
    publishedDate     : str
    modifiedDate      : str
    references        : Tuple[str, ...]
    affectedPlatforms : Tuple[str, ...]
    mappedTechniques  : Tuple[Any, ...]   # Tuple[MitreTechnique, ...]
    createdAt         : str

    class Config:
        frozen = True


class CVEMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to CVE records.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(cveRecordIds))[:32]
    mappingId          : UUIDv5(_CVE_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(cveRecordIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 key.
    mappingFingerprint : deterministic 32-char content fingerprint.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    cveRecords         : sorted tuple of CVERecord objects matched
                         (sorted by cveId ASC then recordId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    mappingFingerprint : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    cveRecords         : Tuple[CVERecord, ...]
    confidence         : float
    createdAt          : str

    class Config:
        frozen = True


class CVEStatistics(BaseModel):
    """
    Aggregate statistics over a collection of CVEMapping objects.

    Fields
    ------
    totalCVEs         : count of distinct cveIds across all mappings.
    criticalCVEs      : count of distinct CVEs with severity CRITICAL.
    highCVEs          : count of distinct CVEs with severity HIGH.
    mediumCVEs        : count of distinct CVEs with severity MEDIUM.
    lowCVEs           : count of distinct CVEs with severity LOW.
    averageCVSS       : mean cvssScore across all distinct CVEs (0.0 if none).
    mappedTechniques  : count of distinct MitreTechnique mitreIds across all CVEs.
    averageConfidence : mean mapping.confidence across all mappings (0.0 if empty).
    """
    totalCVEs         : int
    criticalCVEs      : int
    highCVEs          : int
    mediumCVEs        : int
    lowCVEs           : int
    averageCVSS       : float
    mappedTechniques  : int
    averageConfidence : float

    class Config:
        frozen = True


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _sha256_32(*parts: str) -> str:
    """SHA256(null-byte-joined parts)[:32] — 32 lowercase hex chars."""
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _uuid5(key: str) -> str:
    """UUIDv5(_CVE_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_CVE_NS, key))


def _norm(s: str) -> str:
    """Strip and return a string."""
    return s.strip() if s else ""


def _norm_upper(s: str) -> str:
    """Strip and uppercase a string."""
    return s.strip().upper() if s else ""


def _norm_lower(s: str) -> str:
    """Lowercase + strip a string."""
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


def _clamp_cvss(v: float) -> float:
    """Clamp a CVSS score to [0.0, 10.0]."""
    return float(max(0.0, min(10.0, v)))


def _clamp_confidence(v: float) -> float:
    """Clamp a confidence score to [0.0, 100.0]."""
    return float(max(0.0, min(100.0, v)))


# ---------------------------------------------------------------------------
# Public key derivation functions
# ---------------------------------------------------------------------------

def recordKey(cve_id: str) -> str:
    """
    recordKey = SHA256(cveId.upper())[:32]

    Identical cveId always produces the same key.
    """
    return _sha256_32(cve_id.strip().upper())


def cveMappingKey(
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    cve_record_ids: Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(cveRecordIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    cveRecordIds sorted before joining for order-independence.
    """
    sorted_ids = "\x01".join(sorted(cve_record_ids))
    return _sha256_32(
        finding_id.strip(),
        alert_id.strip(),
        reasoning_id.strip(),
        sorted_ids,
    )


def cveMappingFingerprint(
    m_key        : str,
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    cve_record_ids: Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(cveRecordIds))[:32]
    """
    sorted_ids = "\x01".join(sorted(cve_record_ids))
    return _sha256_32(
        m_key,
        finding_id.strip(),
        alert_id.strip(),
        reasoning_id.strip(),
        sorted_ids,
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_cve_record(
    cve_id     : str,
    severity   : SeverityEnum,
    cvss_score : float,
    created_at : str,
) -> None:
    """
    Validate CVERecord construction parameters.

    Checks
    ------
    - cve_id is non-empty and matches CVE-YYYY-NNNN pattern.
    - severity is a valid SeverityEnum member.
    - cvss_score is in [0.0, 10.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidCVEError      : if cve_id or other non-score fields fail.
    InvalidCVSSScoreError: if cvss_score is outside [0.0, 10.0].
    """
    errors: List[str] = []

    if not cve_id or not cve_id.strip():
        errors.append("cveId must not be empty.")
    elif not _CVE_ID_RE.match(cve_id.strip()):
        errors.append(
            f"cveId='{cve_id}' must match CVE-YYYY-NNNN format "
            "(e.g. CVE-2021-44228)."
        )

    if not isinstance(severity, SeverityEnum):
        errors.append(
            f"severity must be a SeverityEnum member; got {severity!r}."
        )

    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    # CVSS score validated separately — raises its own typed exception
    if not isinstance(cvss_score, (int, float)) or not (0.0 <= float(cvss_score) <= 10.0):
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_cve_record",
                   "field": "cvssScore", "value": repr(cvss_score)},
        )
        raise InvalidCVSSScoreError(
            f"cvssScore={cvss_score!r} must be a float in [0.0, 10.0]."
        )

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_cve_record", "errors": errors},
        )
        raise InvalidCVEError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_cve_mapping(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    confidence  : float,
    created_at  : str,
) -> None:
    """
    Validate CVEMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidCVEMappingError : if any rule is violated.
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
            extra={"validator": "validate_cve_mapping", "errors": errors},
        )
        raise InvalidCVEMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_cve_record()
# ===========================================================================

def build_cve_record(
    cve_id             : str,
    severity           : SeverityEnum,
    cvss_score         : float,
    created_at         : str,
    description        : str                = "",
    published_date     : str                = "",
    modified_date      : str                = "",
    references         : Optional[List[str]] = None,
    affected_platforms : Optional[List[str]] = None,
    mapped_techniques  : Optional[List[Any]] = None,
    validate           : bool               = True,
) -> CVERecord:
    """
    Build an immutable CVERecord.

    recordKey = SHA256(cveId.upper())[:32]
    recordId  = UUIDv5(_CVE_NS, recordKey)

    Parameters
    ----------
    cve_id             : Canonical CVE identifier (e.g. "CVE-2021-44228").
                         Case-insensitive; stored uppercase.
    severity           : SeverityEnum classification.
    cvss_score         : CVSS base score [0.0, 10.0] (clamped after validation).
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    description        : human-readable vulnerability description (may be empty).
    published_date     : ISO-8601 publication date (may be empty).
    modified_date      : ISO-8601 last-modified date (may be empty).
    references         : reference URL strings (deduped + sorted, case-preserved).
    affected_platforms : affected platform strings (deduped + lowercase + sorted).
    mapped_techniques  : MitreTechnique objects associated with this CVE
                         (sorted by mitreId ASC then techniqueId ASC).
    validate           : if True, run validate_cve_record() first.

    Returns
    -------
    CVERecord (frozen / immutable)

    Raises
    ------
    InvalidCVEError       : if validate=True and field validation fails.
    InvalidCVSSScoreError : if validate=True and cvss_score is out of range.
    """
    if validate:
        validate_cve_record(cve_id, severity, cvss_score, created_at)

    r_key = recordKey(cve_id)
    r_id  = _uuid5(r_key)

    # Sort techniques deterministically: mitreId ASC, then techniqueId ASC
    sorted_techniques: Tuple[Any, ...] = tuple(
        sorted(
            mapped_techniques or [],
            key=lambda t: (
                getattr(t, "mitreId", ""),
                getattr(t, "techniqueId", ""),
            ),
        )
    )

    return CVERecord(
        recordId          = r_id,
        recordKey         = r_key,
        cveId             = cve_id.strip().upper(),
        description       = description,
        severity          = severity,
        cvssScore         = round(_clamp_cvss(float(cvss_score)), 4),
        publishedDate     = published_date,
        modifiedDate      = modified_date,
        references        = _norm_strings(references),
        affectedPlatforms = _norm_lower_strings(affected_platforms),
        mappedTechniques  = sorted_techniques,
        createdAt         = created_at,
    )


# ===========================================================================
# Builder: build_cve_mapping()
# ===========================================================================

def build_cve_mapping(
    cve_records  : List[CVERecord],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> CVEMapping:
    """
    Build an immutable CVEMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(cveRecordIds))[:32]
    mappingId          = UUIDv5(_CVE_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(cveRecordIds))[:32]

    Parameters
    ----------
    cve_records  : list of CVERecord objects to map.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_cve_mapping() first.

    Returns
    -------
    CVEMapping (frozen / immutable)

    Raises
    ------
    InvalidCVEMappingError : if validate=True and validation fails.
    """
    clamped_confidence = _clamp_confidence(float(confidence))

    if validate:
        validate_cve_mapping(finding_id, alert_id, reasoning_id,
                              clamped_confidence, created_at)

    # Sort CVE records: cveId ASC, then recordId ASC for full determinism
    sorted_records: Tuple[CVERecord, ...] = tuple(
        sorted(
            cve_records or [],
            key=lambda r: (r.cveId, r.recordId),
        )
    )

    # Collect record IDs for key computation
    record_ids: Tuple[str, ...] = tuple(r.recordId for r in sorted_records)

    m_key = cveMappingKey(finding_id, alert_id, reasoning_id, record_ids)
    m_id  = _uuid5(m_key)
    m_fp  = cveMappingFingerprint(m_key, finding_id, alert_id, reasoning_id, record_ids)

    return CVEMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        mappingFingerprint = m_fp,
        findingId          = finding_id.strip(),
        alertId            = alert_id.strip(),
        reasoningId        = reasoning_id.strip(),
        cveRecords         = sorted_records,
        confidence         = round(clamped_confidence, 4),
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_cve_statistics()
# ===========================================================================

def build_cve_statistics(
    mappings: List[CVEMapping],
) -> CVEStatistics:
    """
    Compute CVEStatistics over a list of CVEMapping objects.

    Deterministic: canonical sort (by mappingId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    mappings : any list of CVEMapping objects.

    Returns
    -------
    CVEStatistics (frozen / immutable)
    """
    if not mappings:
        return CVEStatistics(
            totalCVEs         = 0,
            criticalCVEs      = 0,
            highCVEs          = 0,
            mediumCVEs        = 0,
            lowCVEs           = 0,
            averageCVSS       = 0.0,
            mappedTechniques  = 0,
            averageConfidence = 0.0,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(mappings, key=lambda m: m.mappingId)

    # Collect all distinct CVE records (dedup by cveId)
    seen_cve_ids: dict = {}   # cveId → CVERecord (first seen wins)
    for m in ordered:
        for r in m.cveRecords:
            if r.cveId not in seen_cve_ids:
                seen_cve_ids[r.cveId] = r

    distinct_records = list(seen_cve_ids.values())
    # Sort for deterministic accumulation
    distinct_records.sort(key=lambda r: r.cveId)

    total     = len(distinct_records)
    critical  = sum(1 for r in distinct_records if r.severity == SeverityEnum.CRITICAL)
    high      = sum(1 for r in distinct_records if r.severity == SeverityEnum.HIGH)
    medium    = sum(1 for r in distinct_records if r.severity == SeverityEnum.MEDIUM)
    low       = sum(1 for r in distinct_records if r.severity == SeverityEnum.LOW)

    avg_cvss = (
        round(sum(r.cvssScore for r in distinct_records) / total, 4)
        if total > 0 else 0.0
    )

    # Count distinct MitreTechnique mitreIds across all CVERecords
    distinct_mitre_ids = {
        getattr(t, "mitreId", "")
        for r in distinct_records
        for t in r.mappedTechniques
        if getattr(t, "mitreId", "")
    }

    n = len(ordered)
    avg_conf = round(sum(m.confidence for m in ordered) / n, 4)

    return CVEStatistics(
        totalCVEs         = total,
        criticalCVEs      = critical,
        highCVEs          = high,
        mediumCVEs        = medium,
        lowCVEs           = low,
        averageCVSS       = avg_cvss,
        mappedTechniques  = len(distinct_mitre_ids),
        averageConfidence = avg_conf,
    )


# ===========================================================================
# Integration helpers — transform Finding, Alert, ReasoningResult, and
# MitreTechnique objects into CVEMapping / CVERecord references.
# No AI execution.  No network.  Transform only.
# ===========================================================================

def finding_to_cve_mapping(
    finding     : Any,
    cve_records : List[CVERecord],
    created_at  : str,
    confidence  : float = 0.0,
    validate    : bool  = True,
) -> CVEMapping:
    """
    Convert a Finding (from finding_service) into a CVEMapping.

    Rules
    -----
    - findingId  = finding.findingId
    - alertId    = "" (no alert source)
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    finding     : Finding object from finding_service (duck-typed).
    cve_records : list of CVERecord objects to map.
    created_at  : ISO-8601 timestamp.
    confidence  : 0.0–100.0 caller-assessed confidence.
    validate    : if True, run validate_cve_mapping().

    Returns
    -------
    CVEMapping (frozen / immutable)
    """
    _log.debug(
        "finding_to_cve_mapping",
        extra={
            "findingId" : finding.findingId,
            "cveCount"  : len(cve_records),
        },
    )
    return build_cve_mapping(
        cve_records  = cve_records,
        created_at   = created_at,
        finding_id   = finding.findingId,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def alert_to_cve_mapping(
    alert       : Any,
    cve_records : List[CVERecord],
    created_at  : str,
    confidence  : float = 0.0,
    validate    : bool  = True,
) -> CVEMapping:
    """
    Convert an Alert (from alert_service) into a CVEMapping.

    Rules
    -----
    - findingId  = alert.findingId  (Alert always has a source findingId)
    - alertId    = alert.alertId
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    alert       : Alert object from alert_service (duck-typed).
    cve_records : list of CVERecord objects to map.
    created_at  : ISO-8601 timestamp.
    confidence  : 0.0–100.0 caller-assessed confidence.
    validate    : if True, run validate_cve_mapping().

    Returns
    -------
    CVEMapping (frozen / immutable)
    """
    _log.debug(
        "alert_to_cve_mapping",
        extra={
            "alertId"   : alert.alertId,
            "findingId" : alert.findingId,
            "cveCount"  : len(cve_records),
        },
    )
    return build_cve_mapping(
        cve_records  = cve_records,
        created_at   = created_at,
        finding_id   = alert.findingId,
        alert_id     = alert.alertId,
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def reasoning_to_cve_mapping(
    reasoning   : Any,
    cve_records : List[CVERecord],
    created_at  : str,
    finding_id  : str  = "",
    alert_id    : str  = "",
    validate    : bool = True,
) -> CVEMapping:
    """
    Convert a ReasoningResult (from reasoning_service) into a CVEMapping.

    Rules
    -----
    - reasoningId = reasoning.reasoningId
    - confidence  = reasoning.overallConfidence (already 0–100)
    - findingId and alertId are optional caller-supplied context linkages.

    Parameters
    ----------
    reasoning   : ReasoningResult object from reasoning_service (duck-typed).
    cve_records : list of CVERecord objects to map.
    created_at  : ISO-8601 timestamp.
    finding_id  : optional finding ID for context linkage (may be empty).
    alert_id    : optional alert ID for context linkage (may be empty).
    validate    : if True, run validate_cve_mapping().

    Returns
    -------
    CVEMapping (frozen / immutable)
    """
    _log.debug(
        "reasoning_to_cve_mapping",
        extra={
            "reasoningId" : reasoning.reasoningId,
            "confidence"  : reasoning.overallConfidence,
            "cveCount"    : len(cve_records),
        },
    )
    return build_cve_mapping(
        cve_records  = cve_records,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = reasoning.reasoningId,
        confidence   = reasoning.overallConfidence,
        validate     = validate,
    )


def mitre_to_cve_reference(
    technique   : Any,
    cve_record  : CVERecord,
    created_at  : str,
) -> CVERecord:
    """
    Create a deterministic reference between a MitreTechnique and a CVERecord
    by returning a new CVERecord that includes the technique in its
    mappedTechniques tuple.

    Rules
    -----
    - If the technique is already in cve_record.mappedTechniques (matched by
      techniqueId), the original record is returned unchanged (idempotent).
    - Otherwise, a new CVERecord is built from the existing record's fields
      plus the new technique inserted in sorted order.
    - The new record has the same recordKey and recordId as the original
      (identity is stable — only mappedTechniques changes).
    - No validation is re-run on stable fields; validate=False is used
      internally to avoid redundant checks.

    Parameters
    ----------
    technique  : MitreTechnique object from mitre_attack_service (duck-typed).
    cve_record : Existing CVERecord to extend.
    created_at : ISO-8601 timestamp for the new record's createdAt.

    Returns
    -------
    CVERecord (frozen / immutable) — either the original (if already linked)
    or a new record with the technique added.
    """
    existing_ids = {
        getattr(t, "techniqueId", None)
        for t in cve_record.mappedTechniques
    }
    t_id = getattr(technique, "techniqueId", None)

    if t_id and t_id in existing_ids:
        # Already linked — return unchanged (idempotent)
        return cve_record

    _log.debug(
        "mitre_to_cve_reference",
        extra={
            "cveId"      : cve_record.cveId,
            "techniqueId": t_id,
            "mitreId"    : getattr(technique, "mitreId", ""),
        },
    )

    new_techniques = list(cve_record.mappedTechniques) + [technique]
    # Sort deterministically
    new_techniques_sorted: Tuple[Any, ...] = tuple(
        sorted(
            new_techniques,
            key=lambda x: (
                getattr(x, "mitreId", ""),
                getattr(x, "techniqueId", ""),
            ),
        )
    )

    return CVERecord(
        recordId          = cve_record.recordId,
        recordKey         = cve_record.recordKey,
        cveId             = cve_record.cveId,
        description       = cve_record.description,
        severity          = cve_record.severity,
        cvssScore         = cve_record.cvssScore,
        publishedDate     = cve_record.publishedDate,
        modifiedDate      = cve_record.modifiedDate,
        references        = cve_record.references,
        affectedPlatforms = cve_record.affectedPlatforms,
        mappedTechniques  = new_techniques_sorted,
        createdAt         = created_at,
    )


# ===========================================================================
# CVE Operations
# ===========================================================================

def add_cve_record(
    store: List[CVERecord],
    record: CVERecord,
) -> List[CVERecord]:
    """
    Add a CVERecord to a list, deduplicating by cveId (case-insensitive).

    Rules
    -----
    - If a record with the same cveId already exists, the existing record is
      kept and the new one is ignored (idempotent / no duplicate creation).
    - Returns a NEW sorted list (cveId ASC, recordId ASC).
    - Original list is not mutated.

    Raises
    ------
    Does not raise; duplicate is silently ignored.
    """
    existing_ids = {r.cveId.upper() for r in store}
    if record.cveId.upper() in existing_ids:
        return sorted(store, key=lambda r: (r.cveId, r.recordId))

    _log.info(
        "record_created",
        extra={"recordId": record.recordId, "cveId": record.cveId},
    )
    result = list(store) + [record]
    return sorted(result, key=lambda r: (r.cveId, r.recordId))


def update_cve_record(
    store: List[CVERecord],
    record_id: str,
    severity: Optional[SeverityEnum] = None,
    cvss_score: Optional[float] = None,
    description: Optional[str] = None,
    published_date: Optional[str] = None,
    modified_date: Optional[str] = None,
    references: Optional[List[str]] = None,
    affected_platforms: Optional[List[str]] = None,
    mapped_techniques: Optional[List[Any]] = None,
    created_at: Optional[str] = None,
) -> List[CVERecord]:
    """
    Replace the CVERecord matching record_id with an updated copy.

    Rules
    -----
    - Only supplied (non-None) fields are replaced.
    - recordId, recordKey, and cveId are never changed.
    - Returns a NEW sorted list.
    - If record_id is not found, the original list is returned unchanged.
    """
    updated: List[CVERecord] = []
    found = False
    for r in store:
        if r.recordId == record_id:
            found = True
            new_severity   = severity          if severity          is not None else r.severity
            new_cvss       = cvss_score        if cvss_score        is not None else r.cvssScore
            new_desc       = description       if description       is not None else r.description
            new_pub        = published_date    if published_date    is not None else r.publishedDate
            new_mod        = modified_date     if modified_date     is not None else r.modifiedDate
            new_refs       = _norm_strings(references) if references is not None else r.references
            new_plats      = _norm_lower_strings(affected_platforms) if affected_platforms is not None else r.affectedPlatforms
            new_techniques: Tuple[Any, ...]
            if mapped_techniques is not None:
                new_techniques = tuple(
                    sorted(
                        mapped_techniques,
                        key=lambda t: (getattr(t, "mitreId", ""), getattr(t, "techniqueId", "")),
                    )
                )
            else:
                new_techniques = r.mappedTechniques
            new_created    = created_at        if created_at        is not None else r.createdAt
            new_record = CVERecord(
                recordId          = r.recordId,
                recordKey         = r.recordKey,
                cveId             = r.cveId,
                description       = new_desc,
                severity          = new_severity,
                cvssScore         = round(_clamp_cvss(float(new_cvss)), 4),
                publishedDate     = new_pub,
                modifiedDate      = new_mod,
                references        = new_refs,
                affectedPlatforms = new_plats,
                mappedTechniques  = new_techniques,
                createdAt         = new_created,
            )
            _log.info(
                "record_updated",
                extra={"recordId": record_id, "cveId": r.cveId},
            )
            updated.append(new_record)
        else:
            updated.append(r)
    if not found:
        return sorted(store, key=lambda r: (r.cveId, r.recordId))
    return sorted(updated, key=lambda r: (r.cveId, r.recordId))


def remove_cve_record(
    store: List[CVERecord],
    record_id: str,
) -> List[CVERecord]:
    """
    Remove the CVERecord matching record_id from the store.

    Returns a NEW sorted list.  If not found, returns original list unchanged.
    """
    result = [r for r in store if r.recordId != record_id]
    removed = len(result) < len(store)
    if removed:
        _log.info(
            "record_removed",
            extra={"recordId": record_id},
        )
    return sorted(result, key=lambda r: (r.cveId, r.recordId))


def merge_cve_records(
    base: CVERecord,
    incoming: CVERecord,
    created_at: str,
) -> CVERecord:
    """
    Merge two CVERecords with the same cveId into one.

    Merge rules (all deterministic)
    --------------------------------
    - recordId / recordKey / cveId : always taken from base (identity stable).
    - description        : incoming wins if non-empty, else base.
    - severity           : highest severity wins (CRITICAL > HIGH > MEDIUM > LOW).
    - cvssScore          : max of the two.
    - publishedDate      : non-empty wins; base preferred on tie.
    - modifiedDate       : non-empty wins; incoming preferred (newer update).
    - references         : union, deduped + sorted.
    - affectedPlatforms  : union, deduped + lower + sorted.
    - mappedTechniques   : union by techniqueId, sorted.
    - createdAt          : caller-supplied.

    Raises
    ------
    CVEIntelligenceError : if cveIds differ (cannot merge unrelated records).
    """
    if base.cveId.upper() != incoming.cveId.upper():
        raise CVEIntelligenceError(
            f"Cannot merge records with different cveIds: "
            f"'{base.cveId}' vs '{incoming.cveId}'."
        )

    _severity_order = {
        SeverityEnum.LOW:      0,
        SeverityEnum.MEDIUM:   1,
        SeverityEnum.HIGH:     2,
        SeverityEnum.CRITICAL: 3,
    }
    merged_severity = (
        base.severity
        if _severity_order.get(base.severity, 0) >= _severity_order.get(incoming.severity, 0)
        else incoming.severity
    )

    merged_desc = incoming.description if incoming.description else base.description

    merged_pub = base.publishedDate if base.publishedDate else incoming.publishedDate
    merged_mod = incoming.modifiedDate if incoming.modifiedDate else base.modifiedDate

    merged_refs = _norm_strings(list(base.references) + list(incoming.references))
    merged_plats = _norm_lower_strings(list(base.affectedPlatforms) + list(incoming.affectedPlatforms))

    # Union of techniques by techniqueId
    seen_technique_ids: set = set()
    merged_techniques_list: List[Any] = []
    for t in list(base.mappedTechniques) + list(incoming.mappedTechniques):
        t_id = getattr(t, "techniqueId", id(t))
        if t_id not in seen_technique_ids:
            seen_technique_ids.add(t_id)
            merged_techniques_list.append(t)
    merged_techniques: Tuple[Any, ...] = tuple(
        sorted(
            merged_techniques_list,
            key=lambda x: (getattr(x, "mitreId", ""), getattr(x, "techniqueId", "")),
        )
    )

    _log.info(
        "record_updated",
        extra={"recordId": base.recordId, "cveId": base.cveId, "action": "merge"},
    )

    return CVERecord(
        recordId          = base.recordId,
        recordKey         = base.recordKey,
        cveId             = base.cveId,
        description       = merged_desc,
        severity          = merged_severity,
        cvssScore         = round(_clamp_cvss(max(base.cvssScore, incoming.cvssScore)), 4),
        publishedDate     = merged_pub,
        modifiedDate      = merged_mod,
        references        = merged_refs,
        affectedPlatforms = merged_plats,
        mappedTechniques  = merged_techniques,
        createdAt         = created_at,
    )


# ===========================================================================
# Mapping Operations
# ===========================================================================

def add_mapping_record(
    store: List[CVEMapping],
    mapping: CVEMapping,
) -> List[CVEMapping]:
    """
    Add a CVEMapping to a list, deduplicating by mappingKey.

    Rules
    -----
    - If a mapping with the same mappingKey already exists, the existing one
      is kept (idempotent — no duplicate creation).
    - Returns a NEW sorted list (mappingId ASC).
    - Original list is not mutated.
    """
    existing_keys = {m.mappingKey for m in store}
    if mapping.mappingKey in existing_keys:
        return sorted(store, key=lambda m: m.mappingId)

    _log.info(
        "mapping_created",
        extra={"mappingId": mapping.mappingId, "mappingKey": mapping.mappingKey},
    )
    result = list(store) + [mapping]
    return sorted(result, key=lambda m: m.mappingId)


def remove_mapping_record(
    store: List[CVEMapping],
    mapping_id: str,
) -> List[CVEMapping]:
    """
    Remove the CVEMapping matching mapping_id from the store.

    Returns a NEW sorted list.  If not found, returns original list unchanged.
    """
    result = [m for m in store if m.mappingId != mapping_id]
    removed = len(result) < len(store)
    if removed:
        _log.info(
            "mapping_removed",
            extra={"mappingId": mapping_id},
        )
    return sorted(result, key=lambda m: m.mappingId)


def merge_mappings(
    base: CVEMapping,
    incoming: CVEMapping,
    created_at: str,
) -> CVEMapping:
    """
    Merge two CVEMappings that share findingId + alertId + reasoningId.

    Merge rules (deterministic)
    ----------------------------
    - mappingId / mappingKey / findingId / alertId / reasoningId :
        taken from base (identity stable).
    - cveRecords       : union by cveId, sorted (cveId ASC, recordId ASC).
    - confidence       : max of the two.
    - createdAt        : caller-supplied.
    - mappingFingerprint: recomputed from merged record IDs.

    Raises
    ------
    CVEIntelligenceError : if findingId, alertId, or reasoningId differ.
    """
    if (
        base.findingId   != incoming.findingId
        or base.alertId  != incoming.alertId
        or base.reasoningId != incoming.reasoningId
    ):
        raise CVEIntelligenceError(
            "Cannot merge mappings with different source IDs "
            f"(findingId/alertId/reasoningId mismatch)."
        )

    # Union CVE records by cveId
    seen_cve_ids_map: dict = {}
    for r in list(base.cveRecords) + list(incoming.cveRecords):
        if r.cveId not in seen_cve_ids_map:
            seen_cve_ids_map[r.cveId] = r
    merged_records: Tuple[CVERecord, ...] = tuple(
        sorted(seen_cve_ids_map.values(), key=lambda r: (r.cveId, r.recordId))
    )

    merged_confidence = round(_clamp_confidence(max(base.confidence, incoming.confidence)), 4)

    record_ids: Tuple[str, ...] = tuple(r.recordId for r in merged_records)
    m_fp = cveMappingFingerprint(
        base.mappingKey,
        base.findingId,
        base.alertId,
        base.reasoningId,
        record_ids,
    )

    _log.info(
        "mapping_created",
        extra={"mappingId": base.mappingId, "action": "merge"},
    )

    return CVEMapping(
        mappingId          = base.mappingId,
        mappingKey         = base.mappingKey,
        mappingFingerprint = m_fp,
        findingId          = base.findingId,
        alertId            = base.alertId,
        reasoningId        = base.reasoningId,
        cveRecords         = merged_records,
        confidence         = merged_confidence,
        createdAt          = created_at,
    )


# ===========================================================================
# Search Utilities
# ===========================================================================

def find_cve_record(
    store: List[CVERecord],
    record_id: Optional[str] = None,
    cve_id: Optional[str] = None,
) -> Optional[CVERecord]:
    """
    Find a CVERecord by recordId or cveId.

    Lookup priority: recordId > cveId.
    cveId lookup is case-insensitive.

    Returns
    -------
    First matching CVERecord, or None if not found.
    """
    if record_id is not None:
        for r in store:
            if r.recordId == record_id:
                return r
    if cve_id is not None:
        needle = cve_id.strip().upper()
        for r in store:
            if r.cveId.upper() == needle:
                return r
    return None


def find_mapping(
    store: List[CVEMapping],
    mapping_id: Optional[str] = None,
    mapping_key: Optional[str] = None,
) -> Optional[CVEMapping]:
    """
    Find a CVEMapping by mappingId or mappingKey.

    Lookup priority: mappingId > mappingKey.

    Returns
    -------
    First matching CVEMapping, or None if not found.
    """
    if mapping_id is not None:
        for m in store:
            if m.mappingId == mapping_id:
                return m
    if mapping_key is not None:
        for m in store:
            if m.mappingKey == mapping_key:
                return m
    return None


# ===========================================================================
# Sorting
# ===========================================================================

_CVE_RECORD_SORT_KEYS = frozenset({
    "cveId", "severity", "cvssScore", "confidence", "createdAt",
})

_CVE_MAPPING_SORT_KEYS = frozenset({
    "mappingId", "confidence", "createdAt",
})

_SEVERITY_SORT_ORDER = {
    SeverityEnum.LOW:      0,
    SeverityEnum.MEDIUM:   1,
    SeverityEnum.HIGH:     2,
    SeverityEnum.CRITICAL: 3,
}


def sort_cve_records(
    records: List[CVERecord],
    by: str = "cveId",
    ascending: bool = True,
) -> List[CVERecord]:
    """
    Sort a list of CVERecords.

    Supported keys: cveId, severity, cvssScore, confidence, createdAt.
    'severity' sorts by LOW < MEDIUM < HIGH < CRITICAL.
    'confidence' is not a CVERecord field — treated as cvssScore alias for
    compatibility; use 'cvssScore' instead.

    Raises
    ------
    ValueError : if 'by' is not a supported sort key.
    """
    valid = {"cveId", "severity", "cvssScore", "createdAt"}
    if by not in valid:
        raise ValueError(
            f"sort_cve_records: unsupported sort key {by!r}. "
            f"Valid keys: {sorted(valid)}"
        )

    def _key(r: CVERecord):
        if by == "severity":
            return (_SEVERITY_SORT_ORDER.get(r.severity, 0), r.cveId)
        if by == "cvssScore":
            return (r.cvssScore, r.cveId)
        if by == "createdAt":
            return (r.createdAt, r.cveId)
        # cveId
        return (r.cveId,)

    return sorted(records, key=_key, reverse=not ascending)


def sort_cve_mappings(
    mappings: List[CVEMapping],
    by: str = "mappingId",
    ascending: bool = True,
) -> List[CVEMapping]:
    """
    Sort a list of CVEMappings.

    Supported keys: mappingId, confidence, createdAt.

    Raises
    ------
    ValueError : if 'by' is not a supported sort key.
    """
    valid = {"mappingId", "confidence", "createdAt"}
    if by not in valid:
        raise ValueError(
            f"sort_cve_mappings: unsupported sort key {by!r}. "
            f"Valid keys: {sorted(valid)}"
        )

    def _key(m: CVEMapping):
        if by == "confidence":
            return (m.confidence, m.mappingId)
        if by == "createdAt":
            return (m.createdAt, m.mappingId)
        return (m.mappingId,)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Filtering
# ===========================================================================

def filter_cve_records(
    records: List[CVERecord],
    severity: Optional[SeverityEnum] = None,
    min_cvss: Optional[float] = None,
    max_cvss: Optional[float] = None,
    affected_platform: Optional[str] = None,
    mapped_technique_id: Optional[str] = None,
) -> List[CVERecord]:
    """
    Filter CVERecords by one or more criteria.

    Parameters
    ----------
    severity            : exact severity match (SeverityEnum).
    min_cvss            : inclusive lower bound for cvssScore.
    max_cvss            : inclusive upper bound for cvssScore.
    affected_platform   : case-insensitive substring match in affectedPlatforms.
    mapped_technique_id : match techniqueId in any mappedTechnique.

    Returns
    -------
    List of matching CVERecord objects (original order preserved).
    """
    result: List[CVERecord] = []
    for r in records:
        if severity is not None and r.severity != severity:
            continue
        if min_cvss is not None and r.cvssScore < min_cvss:
            continue
        if max_cvss is not None and r.cvssScore > max_cvss:
            continue
        if affected_platform is not None:
            needle = affected_platform.strip().lower()
            if not any(needle in p for p in r.affectedPlatforms):
                continue
        if mapped_technique_id is not None:
            ids = {getattr(t, "techniqueId", "") for t in r.mappedTechniques}
            if mapped_technique_id not in ids:
                continue
        result.append(r)
    return result


def filter_cve_mappings(
    mappings: List[CVEMapping],
    severity: Optional[SeverityEnum] = None,
    min_cvss: Optional[float] = None,
    max_cvss: Optional[float] = None,
    affected_platform: Optional[str] = None,
    mapped_technique_id: Optional[str] = None,
    min_confidence: Optional[float] = None,
) -> List[CVEMapping]:
    """
    Filter CVEMappings by CVE-level criteria or confidence.

    Parameters
    ----------
    severity            : at least one CVE in the mapping has this severity.
    min_cvss            : at least one CVE in the mapping meets this floor.
    max_cvss            : all CVEs in the mapping are at or below this ceiling.
    affected_platform   : at least one CVE matches (case-insensitive).
    mapped_technique_id : at least one CVE contains a technique with this ID.
    min_confidence      : inclusive lower bound on mapping.confidence.

    Returns
    -------
    List of matching CVEMapping objects.
    """
    result: List[CVEMapping] = []
    for m in mappings:
        if min_confidence is not None and m.confidence < min_confidence:
            continue
        if severity is not None:
            if not any(r.severity == severity for r in m.cveRecords):
                continue
        if min_cvss is not None:
            if not any(r.cvssScore >= min_cvss for r in m.cveRecords):
                continue
        if max_cvss is not None:
            if not all(r.cvssScore <= max_cvss for r in m.cveRecords):
                continue
        if affected_platform is not None:
            needle = affected_platform.strip().lower()
            if not any(
                any(needle in p for p in r.affectedPlatforms)
                for r in m.cveRecords
            ):
                continue
        if mapped_technique_id is not None:
            found = False
            for r in m.cveRecords:
                ids = {getattr(t, "techniqueId", "") for t in r.mappedTechniques}
                if mapped_technique_id in ids:
                    found = True
                    break
            if not found:
                continue
        result.append(m)
    return result


# ===========================================================================
# Grouping
# ===========================================================================

def group_cve_records(
    records: List[CVERecord],
    by: str = "severity",
) -> Dict[str, List[CVERecord]]:
    """
    Group CVERecords by a given dimension.

    Supported 'by' values
    ---------------------
    severity        : group by SeverityEnum value string ("CRITICAL", etc.)
    year            : group by 4-digit year extracted from cveId (e.g. "2021")
    platform        : one entry per affectedPlatform (records appear in all
                      matching groups)
    mapped_technique: one entry per mappedTechnique mitreId

    Returns
    -------
    Dict[str, List[CVERecord]] with sorted keys and each list sorted by cveId.

    Raises
    ------
    ValueError : if 'by' is not a supported group key.
    """
    valid = {"severity", "year", "platform", "mapped_technique"}
    if by not in valid:
        raise ValueError(
            f"group_cve_records: unsupported group key {by!r}. "
            f"Valid keys: {sorted(valid)}"
        )

    groups: Dict[str, List[CVERecord]] = {}

    for r in records:
        if by == "severity":
            key = r.severity.value
            groups.setdefault(key, []).append(r)

        elif by == "year":
            # CVE-YYYY-NNNN — extract YYYY
            parts = r.cveId.split("-")
            key = parts[1] if len(parts) >= 2 else "unknown"
            groups.setdefault(key, []).append(r)

        elif by == "platform":
            for p in r.affectedPlatforms:
                groups.setdefault(p, []).append(r)
            if not r.affectedPlatforms:
                groups.setdefault("unknown", []).append(r)

        elif by == "mapped_technique":
            if r.mappedTechniques:
                for t in r.mappedTechniques:
                    mid = getattr(t, "mitreId", "unknown") or "unknown"
                    groups.setdefault(mid, []).append(r)
            else:
                groups.setdefault("unmapped", []).append(r)

    # Sort each group's list by cveId for determinism
    return {k: sorted(v, key=lambda r: r.cveId) for k, v in sorted(groups.items())}


def group_cve_mappings(
    mappings: List[CVEMapping],
    by: str = "severity",
) -> Dict[str, List[CVEMapping]]:
    """
    Group CVEMappings by a given dimension derived from their CVE records.

    Supported 'by' values
    ---------------------
    severity        : group by highest severity present in each mapping's CVEs
    year            : group by year of first (lowest cveId) CVE record
    platform        : one entry per distinct affectedPlatform across all CVEs
    mapped_technique: one entry per mitreId across all technique mappings

    Returns
    -------
    Dict[str, List[CVEMapping]] with sorted keys and each list sorted by mappingId.

    Raises
    ------
    ValueError : if 'by' is not a supported group key.
    """
    valid = {"severity", "year", "platform", "mapped_technique"}
    if by not in valid:
        raise ValueError(
            f"group_cve_mappings: unsupported group key {by!r}. "
            f"Valid keys: {sorted(valid)}"
        )

    groups: Dict[str, List[CVEMapping]] = {}

    for m in mappings:
        if by == "severity":
            # Highest severity across all CVE records
            if m.cveRecords:
                best = max(
                    m.cveRecords,
                    key=lambda r: _SEVERITY_SORT_ORDER.get(r.severity, 0),
                )
                key = best.severity.value
            else:
                key = "unknown"
            groups.setdefault(key, []).append(m)

        elif by == "year":
            if m.cveRecords:
                first_cve = sorted(m.cveRecords, key=lambda r: r.cveId)[0]
                parts = first_cve.cveId.split("-")
                key = parts[1] if len(parts) >= 2 else "unknown"
            else:
                key = "unknown"
            groups.setdefault(key, []).append(m)

        elif by == "platform":
            all_plats: set = set()
            for r in m.cveRecords:
                all_plats.update(r.affectedPlatforms)
            if all_plats:
                for p in sorted(all_plats):
                    groups.setdefault(p, []).append(m)
            else:
                groups.setdefault("unknown", []).append(m)

        elif by == "mapped_technique":
            all_mids: set = set()
            for r in m.cveRecords:
                for t in r.mappedTechniques:
                    mid = getattr(t, "mitreId", "") or ""
                    if mid:
                        all_mids.add(mid)
            if all_mids:
                for mid in sorted(all_mids):
                    groups.setdefault(mid, []).append(m)
            else:
                groups.setdefault("unmapped", []).append(m)

    return {k: sorted(v, key=lambda m: m.mappingId) for k, v in sorted(groups.items())}
