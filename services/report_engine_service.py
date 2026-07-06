"""
Report Engine
=============
Phase A4.6.1 — Deterministic, immutable report record and mapping management
for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model ReportSection, Report, ReportMapping, and ReportStatistics as
  immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_report_section, build_report, build_report_mapping,
    build_report_statistics.
- Expose validation functions:
    validate_report_section, validate_report, validate_report_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  TimelineEvent, Playbook, and IOCRecord objects into report references.
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
- No PDF. No DOCX. No HTML. No Markdown rendering. No export.
- Pure deterministic business logic only.

Out of scope (Part B)
---------------------
- CRUD, Merge, Search, Sort, Filter, Group, Export, PDF, HTML, DOCX,
  Markdown rendering, Smoke Test.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import REPORT_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("report_engine_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_REPORT_ENGINE_NS = uuid.UUID("6ba7b890-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class ReportEngineError(Exception):
    """Base class for all Report Engine errors."""


class InvalidReportError(ReportEngineError):
    """Raised when a Report fails validation."""


class InvalidReportSectionError(ReportEngineError):
    """Raised when a ReportSection fails validation."""


class InvalidReportMappingError(ReportEngineError):
    """Raised when a ReportMapping fails validation."""


# ===========================================================================
# Enumerations
# ===========================================================================

class ReportTypeEnum(str, Enum):
    """Report type classification."""
    EXECUTIVE  = "EXECUTIVE"
    TECHNICAL  = "TECHNICAL"
    SOC        = "SOC"
    INCIDENT   = "INCIDENT"
    IOC        = "IOC"
    FORENSICS  = "FORENSICS"
    SUMMARY    = "SUMMARY"


class ReportStatusEnum(str, Enum):
    """Report lifecycle status."""
    DRAFT     = "DRAFT"
    READY     = "READY"
    PUBLISHED = "PUBLISHED"
    ARCHIVED  = "ARCHIVED"


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class ReportSection(BaseModel):
    """
    One immutable report section record.

    Identity
    --------
    sectionKey : SHA256(reportId + str(order) + title)[:32]
    sectionId  : UUIDv5(_REPORT_ENGINE_NS, sectionKey)

    Fields
    ------
    sectionId  : deterministic UUID derived from sectionKey.
    sectionKey : 32-char SHA-256 identity key.
    title      : human-readable section title (non-empty).
    order      : 1-based monotonic position in the report.
    content    : section body text or structured content string.
    createdAt  : ISO-8601 timestamp (caller-supplied for determinism).
    """
    sectionId  : str
    sectionKey : str
    title      : str
    order      : int
    content    : str
    createdAt  : str

    class Config:
        frozen = True


class Report(BaseModel):
    """
    One immutable Report record.

    Identity
    --------
    reportKey : SHA256(title + reportType.value + sorted(findingIds))[:32]
    reportId  : UUIDv5(_REPORT_ENGINE_NS, reportKey)

    Fields
    ------
    reportId      : deterministic UUID derived from reportKey.
    reportKey     : 32-char SHA-256 identity key.
    title         : human-readable report title (non-empty).
    description   : overview of the report scope and context.
    reportType    : ReportTypeEnum — audience / format classification.
    status        : ReportStatusEnum — lifecycle status.
    sections      : sorted tuple of ReportSection objects (by order ASC).
    findingIds    : sorted tuple of linked Finding IDs.
    alertIds      : sorted tuple of linked Alert IDs.
    evidenceIds   : sorted tuple of linked Evidence IDs.
    timelineIds   : sorted tuple of linked timeline event IDs.
    iocIds        : sorted tuple of linked IOC record IDs.
    playbookIds   : sorted tuple of linked Playbook IDs.
    confidence    : 0.0–100.0 confidence score (clamped).
    createdAt     : ISO-8601 timestamp (caller-supplied for determinism).
    """
    reportId    : str
    reportKey   : str
    title       : str
    description : str
    reportType  : ReportTypeEnum
    status      : ReportStatusEnum
    sections    : Tuple[ReportSection, ...]
    findingIds  : Tuple[str, ...]
    alertIds    : Tuple[str, ...]
    evidenceIds : Tuple[str, ...]
    timelineIds : Tuple[str, ...]
    iocIds      : Tuple[str, ...]
    playbookIds : Tuple[str, ...]
    confidence  : float
    createdAt   : str

    class Config:
        frozen = True


class ReportMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to Report objects.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(reportIds))[:32]
    mappingId          : UUIDv5(_REPORT_ENGINE_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(reportIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    reports            : sorted tuple of Report objects linked
                         (sorted by reportType ASC then reportId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    mappingFingerprint : deterministic 32-char content fingerprint.
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    reports            : Tuple[Report, ...]
    confidence         : float
    mappingFingerprint : str
    createdAt          : str

    class Config:
        frozen = True


class ReportStatistics(BaseModel):
    """
    Aggregate statistics over a collection of Report objects.

    Fields
    ------
    totalReports      : total count of distinct reports.
    draftReports      : count with status == DRAFT.
    readyReports      : count with status == READY.
    publishedReports  : count with status == PUBLISHED.
    archivedReports   : count with status == ARCHIVED.
    averageConfidence : mean report.confidence across all reports (0.0 if empty).
    averageSections   : mean section count per report (0.0 if empty).
    """
    totalReports      : int
    draftReports      : int
    readyReports      : int
    publishedReports  : int
    archivedReports   : int
    averageConfidence : float
    averageSections   : float

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
    """UUIDv5(_REPORT_ENGINE_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_REPORT_ENGINE_NS, key))


def _norm(s: str) -> str:
    """Strip a string; return empty string if None."""
    return s.strip() if s else ""


def _norm_ids(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort an ID list."""
    if not items:
        return ()
    return tuple(sorted({i.strip() for i in items if i and i.strip()}))


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


# ---------------------------------------------------------------------------
# Public key derivation functions (named per spec)
# ---------------------------------------------------------------------------

def sectionKey(report_id: str, order: int, title: str) -> str:
    """
    sectionKey = SHA256(reportId + str(order) + title)[:32]

    Null-byte-separated to prevent cross-field collisions.
    Same (reportId, order, title) triple always produces the same key.
    """
    return _sha256_32(_norm(report_id), str(order), _norm(title))


def reportKey(
    title       : str,
    report_type : ReportTypeEnum,
    finding_ids : Tuple[str, ...],
) -> str:
    """
    reportKey = SHA256(title + reportType.value + sorted(findingIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    findingIds sorted before joining for order-independence.
    """
    sorted_fids = "\x01".join(sorted(finding_ids))
    return _sha256_32(_norm(title), report_type.value, sorted_fids)


def mappingKey(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    report_ids  : Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(reportIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    reportIds sorted before joining for order-independence.
    """
    sorted_ids = "\x01".join(sorted(report_ids))
    return _sha256_32(
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_ids,
    )


def mappingFingerprint(
    m_key       : str,
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    report_ids  : Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(reportIds))[:32]
    """
    sorted_ids = "\x01".join(sorted(report_ids))
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

def validate_report_section(
    order     : int,
    title     : str,
    created_at: str,
) -> None:
    """
    Validate ReportSection construction parameters.

    Checks
    ------
    - order is a positive integer (>= 1).
    - title is non-empty.
    - created_at is non-empty.

    Raises
    ------
    InvalidReportSectionError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(order, int) or order < 1:
        errors.append(
            f"order={order!r} must be a positive integer (>= 1)."
        )
    if not title or not title.strip():
        errors.append("title must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_report_section", "errors": errors},
        )
        raise InvalidReportSectionError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_report(
    title      : str,
    report_type: ReportTypeEnum,
    status     : ReportStatusEnum,
    created_at : str,
) -> None:
    """
    Validate Report construction parameters.

    Checks
    ------
    - title is non-empty.
    - report_type is a valid ReportTypeEnum member.
    - status is a valid ReportStatusEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidReportError : if any rule is violated.
    """
    errors: List[str] = []

    if not title or not title.strip():
        errors.append("title must not be empty.")
    if not isinstance(report_type, ReportTypeEnum):
        errors.append(
            f"reportType must be a ReportTypeEnum member; got {report_type!r}."
        )
    if not isinstance(status, ReportStatusEnum):
        errors.append(
            f"status must be a ReportStatusEnum member; got {status!r}."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_report", "errors": errors},
        )
        raise InvalidReportError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_report_mapping(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    confidence  : float,
    created_at  : str,
) -> None:
    """
    Validate ReportMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidReportMappingError : if any rule is violated.
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
            extra={"validator": "validate_report_mapping", "errors": errors},
        )
        raise InvalidReportMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_report_section()
# ===========================================================================

def build_report_section(
    report_id  : str,
    order      : int,
    title      : str,
    created_at : str,
    content    : str  = "",
    validate   : bool = True,
) -> ReportSection:
    """
    Build an immutable ReportSection.

    sectionKey = SHA256(reportId + str(order) + title)[:32]
    sectionId  = UUIDv5(_REPORT_ENGINE_NS, sectionKey)

    Parameters
    ----------
    report_id  : ID of the parent Report (scopes section identity).
    order      : 1-based position in the report (must be >= 1).
    title      : human-readable section title (must be non-empty).
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    content    : section body text or structured content string (may be empty).
    validate   : if True, run validate_report_section() first.

    Returns
    -------
    ReportSection (frozen / immutable)

    Raises
    ------
    InvalidReportSectionError : if validate=True and validation fails.
    """
    if validate:
        validate_report_section(order, title, created_at)

    s_key = sectionKey(report_id, order, title)
    s_id  = _uuid5(s_key)

    return ReportSection(
        sectionId  = s_id,
        sectionKey = s_key,
        title      = _norm(title),
        order      = order,
        content    = content,
        createdAt  = created_at,
    )


# ===========================================================================
# Builder: build_report()
# ===========================================================================

def build_report(
    title        : str,
    report_type  : ReportTypeEnum,
    created_at   : str,
    description  : str                           = "",
    status       : ReportStatusEnum              = ReportStatusEnum.DRAFT,
    sections     : Optional[List[ReportSection]] = None,
    finding_ids  : Optional[List[str]]           = None,
    alert_ids    : Optional[List[str]]           = None,
    evidence_ids : Optional[List[str]]           = None,
    timeline_ids : Optional[List[str]]           = None,
    ioc_ids      : Optional[List[str]]           = None,
    playbook_ids : Optional[List[str]]           = None,
    confidence   : float                         = 0.0,
    validate     : bool                          = True,
) -> Report:
    """
    Build an immutable Report.

    reportKey = SHA256(title + reportType.value + sorted(findingIds))[:32]
    reportId  = UUIDv5(_REPORT_ENGINE_NS, reportKey)

    Parameters
    ----------
    title        : human-readable report title (must be non-empty).
    report_type  : ReportTypeEnum — audience / format classification.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    description  : overview of the report scope and context (may be empty).
    status       : ReportStatusEnum — lifecycle status (default DRAFT).
    sections     : list of ReportSection objects (sorted by order ASC).
    finding_ids  : linked Finding IDs (deduped + sorted).
    alert_ids    : linked Alert IDs (deduped + sorted).
    evidence_ids : linked Evidence IDs (deduped + sorted).
    timeline_ids : linked timeline event IDs (deduped + sorted).
    ioc_ids      : linked IOC record IDs (deduped + sorted).
    playbook_ids : linked Playbook IDs (deduped + sorted).
    confidence   : 0.0–100.0 confidence score (clamped).
    validate     : if True, run validate_report() first.

    Returns
    -------
    Report (frozen / immutable)

    Raises
    ------
    InvalidReportError : if validate=True and validation fails.
    """
    if validate:
        validate_report(title, report_type, status, created_at)

    clamped_conf = _clamp(float(confidence))

    norm_finding_ids  = _norm_ids(finding_ids)
    norm_alert_ids    = _norm_ids(alert_ids)
    norm_evidence_ids = _norm_ids(evidence_ids)
    norm_timeline_ids = _norm_ids(timeline_ids)
    norm_ioc_ids      = _norm_ids(ioc_ids)
    norm_playbook_ids = _norm_ids(playbook_ids)

    # Sort sections deterministically: order ASC, then sectionId ASC for ties
    sorted_sections: Tuple[ReportSection, ...] = tuple(
        sorted(
            sections or [],
            key=lambda s: (s.order, s.sectionId),
        )
    )

    r_key = reportKey(title, report_type, norm_finding_ids)
    r_id  = _uuid5(r_key)

    return Report(
        reportId    = r_id,
        reportKey   = r_key,
        title       = _norm(title),
        description = description,
        reportType  = report_type,
        status      = status,
        sections    = sorted_sections,
        findingIds  = norm_finding_ids,
        alertIds    = norm_alert_ids,
        evidenceIds = norm_evidence_ids,
        timelineIds = norm_timeline_ids,
        iocIds      = norm_ioc_ids,
        playbookIds = norm_playbook_ids,
        confidence  = round(clamped_conf, 4),
        createdAt   = created_at,
    )


# ===========================================================================
# Builder: build_report_mapping()
# ===========================================================================

def build_report_mapping(
    reports      : List[Report],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> ReportMapping:
    """
    Build an immutable ReportMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(reportIds))[:32]
    mappingId          = UUIDv5(_REPORT_ENGINE_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(reportIds))[:32]

    Parameters
    ----------
    reports      : list of Report objects to link in this mapping.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_report_mapping() first.

    Returns
    -------
    ReportMapping (frozen / immutable)

    Raises
    ------
    InvalidReportMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_report_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: reportType ASC, then reportId ASC
    sorted_reports: Tuple[Report, ...] = tuple(
        sorted(
            reports or [],
            key=lambda r: (r.reportType.value, r.reportId),
        )
    )

    # Collect report IDs for key computation
    r_ids: Tuple[str, ...] = tuple(r.reportId for r in sorted_reports)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, r_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(m_key, finding_id, alert_id, reasoning_id, r_ids)

    return ReportMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        reports            = sorted_reports,
        confidence         = round(clamped_conf, 4),
        mappingFingerprint = m_fp,
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_report_statistics()
# ===========================================================================

def build_report_statistics(
    reports: List[Report],
) -> ReportStatistics:
    """
    Compute ReportStatistics over a flat list of Report objects.

    Deterministic: canonical sort (by reportId ASC) before accumulation so
    floating-point sums and counts are identical across every run regardless
    of input ordering.

    Deduplication is by reportId — first occurrence in sorted order wins.

    Parameters
    ----------
    reports : any list of Report objects (may contain duplicates by reportId).

    Returns
    -------
    ReportStatistics (frozen / immutable)
    """
    if not reports:
        return ReportStatistics(
            totalReports      = 0,
            draftReports      = 0,
            readyReports      = 0,
            publishedReports  = 0,
            archivedReports   = 0,
            averageConfidence = 0.0,
            averageSections   = 0.0,
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(reports, key=lambda r: r.reportId)

    # Deduplicate by reportId — first occurrence in sorted order wins
    seen_ids: Dict[str, Report] = {}
    for r in ordered:
        if r.reportId not in seen_ids:
            seen_ids[r.reportId] = r

    distinct = list(seen_ids.values())
    # Re-sort after dedup for deterministic counting
    distinct.sort(key=lambda r: r.reportId)

    total     = len(distinct)
    draft     = sum(1 for r in distinct if r.status == ReportStatusEnum.DRAFT)
    ready     = sum(1 for r in distinct if r.status == ReportStatusEnum.READY)
    published = sum(1 for r in distinct if r.status == ReportStatusEnum.PUBLISHED)
    archived  = sum(1 for r in distinct if r.status == ReportStatusEnum.ARCHIVED)

    avg_confidence = (
        round(sum(r.confidence for r in distinct) / total, 4)
        if total > 0 else 0.0
    )
    avg_sections = (
        round(sum(len(r.sections) for r in distinct) / total, 4)
        if total > 0 else 0.0
    )

    return ReportStatistics(
        totalReports      = total,
        draftReports      = draft,
        readyReports      = ready,
        publishedReports  = published,
        archivedReports   = archived,
        averageConfidence = avg_confidence,
        averageSections   = avg_sections,
    )


# ===========================================================================
# Integration Helpers
# ===========================================================================
# Pure transformation helpers. Accept objects from other engine services and
# return ReportMapping objects or report reference strings.
# No external lookups. No AI execution. No network. Duck-typed input objects
# are accepted so there is no circular import at module load time.
# No rendering. No export. No PDF. No DOCX. No HTML.
# Only deterministic transformations.
# ===========================================================================

def finding_to_report_mapping(
    finding    : Any,
    reports    : List[Report],
    created_at : str,
    confidence : float = 0.0,
) -> ReportMapping:
    """
    Transform a Finding object into a ReportMapping.

    Extracts findingId from finding.findingId (duck-typed).
    alertId and reasoningId are left empty.

    Parameters
    ----------
    finding    : any object with a .findingId string attribute.
    reports    : list of Report objects to link to this finding.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    confidence : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    ReportMapping (frozen / immutable)
    """
    finding_id = _norm(getattr(finding, "findingId", ""))
    _log.debug(
        "finding_to_report_mapping",
        extra={"findingId": finding_id, "reportCount": len(reports)},
    )
    return build_report_mapping(
        reports      = reports,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
    )


def alert_to_report_mapping(
    alert      : Any,
    reports    : List[Report],
    created_at : str,
    confidence : float = 0.0,
) -> ReportMapping:
    """
    Transform an Alert object into a ReportMapping.

    Extracts findingId and alertId from the alert (duck-typed).
    reasoningId is left empty.

    Parameters
    ----------
    alert      : any object with .alertId and .findingId string attributes.
    reports    : list of Report objects to link to this alert.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    confidence : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    ReportMapping (frozen / immutable)
    """
    finding_id = _norm(getattr(alert, "findingId", ""))
    alert_id   = _norm(getattr(alert, "alertId", ""))
    _log.debug(
        "alert_to_report_mapping",
        extra={
            "alertId"    : alert_id,
            "findingId"  : finding_id,
            "reportCount": len(reports),
        },
    )
    return build_report_mapping(
        reports      = reports,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = "",
        confidence   = confidence,
    )


def reasoning_to_report_mapping(
    reasoning  : Any,
    reports    : List[Report],
    created_at : str,
    finding_id : str = "",
    alert_id   : str = "",
) -> ReportMapping:
    """
    Transform a ReasoningResult object into a ReportMapping.

    Extracts reasoningId and overallConfidence from the reasoning object
    (duck-typed).  findingId and alertId are optional caller-supplied
    context linkages.

    Parameters
    ----------
    reasoning  : any object with .reasoningId and .overallConfidence attributes.
    reports    : list of Report objects to link to this reasoning result.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id : optional finding ID for context linkage (may be empty).
    alert_id   : optional alert ID for context linkage (may be empty).

    Returns
    -------
    ReportMapping (frozen / immutable)
    """
    reasoning_id = _norm(getattr(reasoning, "reasoningId", ""))
    conf         = float(getattr(reasoning, "overallConfidence", 0.0))
    _log.debug(
        "reasoning_to_report_mapping",
        extra={
            "reasoningId": reasoning_id,
            "confidence" : conf,
            "reportCount": len(reports),
        },
    )
    return build_report_mapping(
        reports      = reports,
        created_at   = created_at,
        finding_id   = _norm(finding_id),
        alert_id     = _norm(alert_id),
        reasoning_id = reasoning_id,
        confidence   = conf,
    )


def timeline_to_report_reference(
    timeline_event : Any,
) -> str:
    """
    Extract a deterministic reference string from a timeline event object.

    Returns the timelineEventId attribute (duck-typed) as a stripped string,
    or an empty string if the attribute is absent or blank.

    This helper enables Report builders to collect timeline event IDs for
    the report.timelineIds tuple without importing the timeline service.

    No rendering.  No transformation beyond ID extraction.

    Parameters
    ----------
    timeline_event : any object with a .timelineEventId string attribute.

    Returns
    -------
    str — the timeline event ID, or "" if not present.
    """
    return _norm(getattr(timeline_event, "timelineEventId", ""))


def playbook_to_report_reference(
    playbook : Any,
) -> str:
    """
    Extract a deterministic reference string from a Playbook object.

    Returns the playbookId attribute (duck-typed) as a stripped string,
    or an empty string if the attribute is absent or blank.

    This helper enables Report builders to collect playbook IDs for the
    report.playbookIds tuple without importing the playbook service.

    No rendering.  No transformation beyond ID extraction.

    Parameters
    ----------
    playbook : any object with a .playbookId string attribute.

    Returns
    -------
    str — the playbook ID, or "" if not present.
    """
    return _norm(getattr(playbook, "playbookId", ""))


def ioc_to_report_reference(
    ioc_record : Any,
) -> str:
    """
    Extract a deterministic reference string from an IOCRecord object.

    Returns the iocId attribute (duck-typed) as a stripped string,
    or an empty string if the attribute is absent or blank.

    This helper enables Report builders to collect IOC record IDs for the
    report.iocIds tuple without importing the IOC intelligence service.

    No rendering.  No transformation beyond ID extraction.

    Parameters
    ----------
    ioc_record : any object with a .iocId string attribute.

    Returns
    -------
    str — the IOC record ID, or "" if not present.
    """
    return _norm(getattr(ioc_record, "iocId", ""))


# ===========================================================================
# Part B — Report Operations, Section Operations, Mapping Operations,
#           Search, Sort, Filter, Group, extended Statistics, Logging
# ===========================================================================


# ---------------------------------------------------------------------------
# Internal helpers shared by operations
# ---------------------------------------------------------------------------

def _rebuild_report_from(
    base       : Report,
    sections   : Optional[Tuple[ReportSection, ...]] = None,
    title      : Optional[str]              = None,
    description: Optional[str]              = None,
    report_type: Optional[ReportTypeEnum]   = None,
    status     : Optional[ReportStatusEnum] = None,
    finding_ids: Optional[Tuple[str, ...]]  = None,
    alert_ids  : Optional[Tuple[str, ...]]  = None,
    evidence_ids: Optional[Tuple[str, ...]] = None,
    timeline_ids: Optional[Tuple[str, ...]] = None,
    ioc_ids    : Optional[Tuple[str, ...]]  = None,
    playbook_ids: Optional[Tuple[str, ...]] = None,
    confidence : Optional[float]            = None,
) -> Report:
    """Return a new Report built from *base* with only the supplied fields changed.

    reportKey / reportId are recomputed only when title, report_type, or
    finding_ids change — all other field changes preserve the existing identity.
    """
    new_title      = _norm(title)      if title       is not None else base.title
    new_type       = report_type       if report_type  is not None else base.reportType
    new_finding_ids= finding_ids       if finding_ids  is not None else base.findingIds
    new_status     = status            if status        is not None else base.status
    new_desc       = description       if description   is not None else base.description
    new_alert_ids  = alert_ids         if alert_ids     is not None else base.alertIds
    new_ev_ids     = evidence_ids      if evidence_ids  is not None else base.evidenceIds
    new_tl_ids     = timeline_ids      if timeline_ids  is not None else base.timelineIds
    new_ioc_ids    = ioc_ids           if ioc_ids       is not None else base.iocIds
    new_pb_ids     = playbook_ids      if playbook_ids  is not None else base.playbookIds
    new_conf       = round(_clamp(float(confidence)), 4) if confidence is not None else base.confidence
    new_sections   = sections          if sections      is not None else base.sections

    # Recompute key/id only when identity-determining fields changed
    if new_title != base.title or new_type != base.reportType or new_finding_ids != base.findingIds:
        r_key = reportKey(new_title, new_type, new_finding_ids)
        r_id  = _uuid5(r_key)
    else:
        r_key = base.reportKey
        r_id  = base.reportId

    return Report(
        reportId    = r_id,
        reportKey   = r_key,
        title       = new_title,
        description = new_desc,
        reportType  = new_type,
        status      = new_status,
        sections    = new_sections,
        findingIds  = new_finding_ids,
        alertIds    = new_alert_ids,
        evidenceIds = new_ev_ids,
        timelineIds = new_tl_ids,
        iocIds      = new_ioc_ids,
        playbookIds = new_pb_ids,
        confidence  = new_conf,
        createdAt   = base.createdAt,
    )


# ===========================================================================
# Report Operations
# ===========================================================================

def add_report(
    reports : List[Report],
    report  : Report,
) -> List[Report]:
    """
    Add *report* to *reports* if its reportId is not already present.

    Idempotent: duplicate reportId → returns unchanged copy (input not mutated).

    Returns a new list sorted by reportId ASC.
    """
    if any(r.reportId == report.reportId for r in reports):
        return list(reports)
    result = list(reports) + [report]
    result.sort(key=lambda r: r.reportId)
    _log.info("report_created", extra={"reportId": report.reportId, "title": report.title})
    return result


def update_report(
    reports     : List[Report],
    report_id   : str,
    title       : Optional[str]              = None,
    description : Optional[str]              = None,
    report_type : Optional[ReportTypeEnum]   = None,
    status      : Optional[ReportStatusEnum] = None,
    finding_ids : Optional[List[str]]        = None,
    alert_ids   : Optional[List[str]]        = None,
    evidence_ids: Optional[List[str]]        = None,
    timeline_ids: Optional[List[str]]        = None,
    ioc_ids     : Optional[List[str]]        = None,
    playbook_ids: Optional[List[str]]        = None,
    confidence  : Optional[float]            = None,
) -> List[Report]:
    """
    Return a new list with the matching report replaced by an updated copy.

    - Non-None arguments replace the corresponding field on the found report.
    - None arguments leave the field unchanged.
    - If reportId not found, the original list is returned unchanged.
    - Input list is never mutated.
    - reportKey / reportId are recomputed only when identity fields change.
    """
    result: List[Report] = []
    changed = False
    for r in reports:
        if r.reportId != report_id:
            result.append(r)
            continue
        changed = True
        updated = _rebuild_report_from(
            r,
            title        = title,
            description  = description,
            report_type  = report_type,
            status       = status,
            finding_ids  = _norm_ids(finding_ids) if finding_ids is not None else None,
            alert_ids    = _norm_ids(alert_ids)    if alert_ids   is not None else None,
            evidence_ids = _norm_ids(evidence_ids) if evidence_ids is not None else None,
            timeline_ids = _norm_ids(timeline_ids) if timeline_ids is not None else None,
            ioc_ids      = _norm_ids(ioc_ids)      if ioc_ids     is not None else None,
            playbook_ids = _norm_ids(playbook_ids) if playbook_ids is not None else None,
            confidence   = confidence,
        )
        result.append(updated)
        _log.info("report_updated", extra={"reportId": report_id})
    if not changed:
        return list(reports)
    result.sort(key=lambda r: r.reportId)
    return result


def remove_report(
    reports   : List[Report],
    report_id : str,
) -> List[Report]:
    """
    Return a new list with the report matching *report_id* removed.

    Idempotent: if not found, returns an unchanged copy.
    Input list is never mutated.
    """
    result = [r for r in reports if r.reportId != report_id]
    if len(result) < len(reports):
        _log.info("report_removed", extra={"reportId": report_id})
    return result


def merge_reports(
    base     : List[Report],
    incoming : List[Report],
) -> List[Report]:
    """
    Merge *incoming* reports into *base*.

    Rules
    -----
    - Deduplication by reportId — base wins on conflict (base entry is kept).
    - Result is sorted by reportId ASC.
    - Neither input list is mutated.
    - IDs and fingerprints from base entries are fully preserved.
    """
    seen: Dict[str, Report] = {}
    for r in sorted(base, key=lambda x: x.reportId):
        seen[r.reportId] = r
    for r in sorted(incoming, key=lambda x: x.reportId):
        if r.reportId not in seen:
            seen[r.reportId] = r
    result = sorted(seen.values(), key=lambda r: r.reportId)
    _log.info("merge_completed", extra={"mergedCount": len(result), "kind": "reports"})
    return result


# ===========================================================================
# Section Operations
# ===========================================================================

def add_report_section(
    report  : Report,
    section : ReportSection,
) -> Report:
    """
    Return a new Report with *section* added to its sections tuple.

    Idempotent by sectionId — if the section is already present, the report
    is returned unchanged.  Sections remain sorted by (order ASC, sectionId ASC).
    """
    if any(s.sectionId == section.sectionId for s in report.sections):
        return report
    new_sections = tuple(
        sorted(
            list(report.sections) + [section],
            key=lambda s: (s.order, s.sectionId),
        )
    )
    _log.info("section_created", extra={"sectionId": section.sectionId, "reportId": report.reportId})
    return _rebuild_report_from(report, sections=new_sections)


def update_report_section(
    report     : Report,
    section_id : str,
    title      : Optional[str] = None,
    content    : Optional[str] = None,
    order      : Optional[int] = None,
) -> Report:
    """
    Return a new Report with the matching section replaced by an updated copy.

    - sectionKey and sectionId are preserved (identity is stable).
    - None arguments leave the existing field unchanged.
    - If section not found, the report is returned unchanged.
    """
    new_sections_list: List[ReportSection] = []
    changed = False
    for s in report.sections:
        if s.sectionId != section_id:
            new_sections_list.append(s)
            continue
        changed = True
        new_title   = _norm(title)   if title   is not None else s.title
        new_content = content        if content is not None else s.content
        new_order   = order          if order   is not None else s.order
        updated_sec = ReportSection(
            sectionId  = s.sectionId,
            sectionKey = s.sectionKey,
            title      = new_title,
            order      = new_order,
            content    = new_content,
            createdAt  = s.createdAt,
        )
        new_sections_list.append(updated_sec)
        _log.info("section_updated", extra={"sectionId": section_id, "reportId": report.reportId})
    if not changed:
        return report
    sorted_secs = tuple(sorted(new_sections_list, key=lambda s: (s.order, s.sectionId)))
    return _rebuild_report_from(report, sections=sorted_secs)


def remove_report_section(
    report     : Report,
    section_id : str,
) -> Report:
    """
    Return a new Report with the section matching *section_id* removed.

    Idempotent: if not found, the report is returned unchanged.
    """
    remaining = [s for s in report.sections if s.sectionId != section_id]
    if len(remaining) == len(report.sections):
        return report
    _log.info("section_removed", extra={"sectionId": section_id, "reportId": report.reportId})
    return _rebuild_report_from(report, sections=tuple(remaining))


def merge_report_sections(
    report   : Report,
    sections : List[ReportSection],
) -> Report:
    """
    Merge *sections* into *report*.sections.

    Rules
    -----
    - Deduplication by sectionId — base (existing) section wins on conflict.
    - Result is sorted by (order ASC, sectionId ASC).
    - Input list is not mutated; report is not mutated.
    """
    seen: Dict[str, ReportSection] = {s.sectionId: s for s in report.sections}
    for s in sections:
        if s.sectionId not in seen:
            seen[s.sectionId] = s
    merged_secs = tuple(
        sorted(seen.values(), key=lambda s: (s.order, s.sectionId))
    )
    _log.info("merge_completed", extra={
        "kind"      : "sections",
        "reportId"  : report.reportId,
        "totalCount": len(merged_secs),
    })
    return _rebuild_report_from(report, sections=merged_secs)


# ===========================================================================
# Mapping Operations
# ===========================================================================

def add_report_mapping(
    mappings : List[ReportMapping],
    mapping  : ReportMapping,
) -> List[ReportMapping]:
    """
    Add *mapping* to *mappings* if its mappingId is not already present.

    Idempotent: duplicate mappingId → returns unchanged copy.
    Returns a new list sorted by mappingId ASC.
    """
    if any(m.mappingId == mapping.mappingId for m in mappings):
        return list(mappings)
    result = list(mappings) + [mapping]
    result.sort(key=lambda m: m.mappingId)
    _log.info("mapping_created", extra={"mappingId": mapping.mappingId})
    return result


def remove_report_mapping(
    mappings   : List[ReportMapping],
    mapping_id : str,
) -> List[ReportMapping]:
    """
    Return a new list with the mapping matching *mapping_id* removed.

    Idempotent: if not found, returns an unchanged copy.
    """
    return [m for m in mappings if m.mappingId != mapping_id]


def merge_report_mappings(
    base     : List[ReportMapping],
    incoming : List[ReportMapping],
) -> List[ReportMapping]:
    """
    Merge *incoming* mappings into *base*.

    Rules
    -----
    - Deduplication by mappingId — base wins on conflict.
    - Result is sorted by mappingId ASC.
    - Neither input is mutated.
    """
    seen: Dict[str, ReportMapping] = {}
    for m in sorted(base, key=lambda x: x.mappingId):
        seen[m.mappingId] = m
    for m in sorted(incoming, key=lambda x: x.mappingId):
        if m.mappingId not in seen:
            seen[m.mappingId] = m
    result = sorted(seen.values(), key=lambda m: m.mappingId)
    _log.info("merge_completed", extra={"mergedCount": len(result), "kind": "mappings"})
    return result


# ===========================================================================
# Search Utilities
# ===========================================================================

def find_report(
    reports   : List[Report],
    report_id : Optional[str] = None,
    report_key: Optional[str] = None,
) -> Optional[Report]:
    """
    Find a single Report by reportId or reportKey.

    - reportId takes precedence over reportKey if both are provided.
    - Returns None if no match is found.

    Parameters
    ----------
    reports    : list of Report objects to search.
    report_id  : exact reportId string to look for.
    report_key : exact reportKey string to look for.

    Returns
    -------
    Report or None
    """
    if report_id:
        for r in reports:
            if r.reportId == report_id:
                return r
    if report_key:
        for r in reports:
            if r.reportKey == report_key:
                return r
    return None


def find_report_section(
    report     : Report,
    section_id : Optional[str] = None,
    section_key: Optional[str] = None,
) -> Optional[ReportSection]:
    """
    Find a single ReportSection within *report* by sectionId or sectionKey.

    - sectionId takes precedence over sectionKey if both are provided.
    - Returns None if no match is found.
    """
    if section_id:
        for s in report.sections:
            if s.sectionId == section_id:
                return s
    if section_key:
        for s in report.sections:
            if s.sectionKey == section_key:
                return s
    return None


def find_report_mapping(
    mappings   : List[ReportMapping],
    mapping_id : Optional[str] = None,
) -> Optional[ReportMapping]:
    """
    Find a single ReportMapping by mappingId.

    Returns None if no match is found.
    """
    if mapping_id:
        for m in mappings:
            if m.mappingId == mapping_id:
                return m
    return None


# ===========================================================================
# Sorting
# ===========================================================================

_VALID_REPORT_SORT_KEYS = frozenset({"title", "reportType", "status", "confidence", "createdAt"})
_VALID_SECTION_SORT_KEYS = frozenset({"title", "order", "createdAt"})
_VALID_MAPPING_SORT_KEYS = frozenset({"confidence", "createdAt", "findingId", "alertId"})


def sort_reports(
    reports   : List[Report],
    by        : str  = "createdAt",
    ascending : bool = True,
) -> List[Report]:
    """
    Return a new sorted list of Report objects.

    Parameters
    ----------
    by        : "title" | "reportType" | "status" | "confidence" | "createdAt"
    ascending : True = A→Z / low→high (default); False = reverse.

    Tie-breaking is always by reportId ASC for full determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_REPORT_SORT_KEYS:
        raise ValueError(
            f"sort_reports: unknown key '{by}'. Valid: {sorted(_VALID_REPORT_SORT_KEYS)}"
        )

    def _key(r: Report) -> tuple:
        if by == "reportType":
            primary = r.reportType.value
        elif by == "status":
            primary = r.status.value
        elif by == "confidence":
            primary = r.confidence
        else:
            primary = getattr(r, by, "")
        return (primary, r.reportId)

    return sorted(reports, key=_key, reverse=not ascending)


def sort_report_sections(
    sections  : List[ReportSection],
    by        : str  = "order",
    ascending : bool = True,
) -> List[ReportSection]:
    """
    Return a new sorted list of ReportSection objects.

    Parameters
    ----------
    by        : "title" | "order" | "createdAt"
    ascending : True = ascending (default).

    Tie-breaking is always by sectionId ASC.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_SECTION_SORT_KEYS:
        raise ValueError(
            f"sort_report_sections: unknown key '{by}'. Valid: {sorted(_VALID_SECTION_SORT_KEYS)}"
        )

    def _key(s: ReportSection) -> tuple:
        return (getattr(s, by, ""), s.sectionId)

    return sorted(sections, key=_key, reverse=not ascending)


def sort_report_mappings(
    mappings  : List[ReportMapping],
    by        : str  = "createdAt",
    ascending : bool = True,
) -> List[ReportMapping]:
    """
    Return a new sorted list of ReportMapping objects.

    Parameters
    ----------
    by        : "confidence" | "createdAt" | "findingId" | "alertId"
    ascending : True = ascending (default).

    Tie-breaking is always by mappingId ASC.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_MAPPING_SORT_KEYS:
        raise ValueError(
            f"sort_report_mappings: unknown key '{by}'. Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: ReportMapping) -> tuple:
        return (getattr(m, by, ""), m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Filtering
# ===========================================================================

def filter_reports(
    reports          : List[Report],
    report_type      : Optional[ReportTypeEnum]   = None,
    status           : Optional[ReportStatusEnum] = None,
    min_confidence   : Optional[float]            = None,
    max_confidence   : Optional[float]            = None,
    finding_id       : Optional[str]              = None,
    alert_id         : Optional[str]              = None,
) -> List[Report]:
    """
    Filter reports by one or more criteria (all ANDed together).

    Parameters
    ----------
    report_type    : keep only reports with this ReportTypeEnum.
    status         : keep only reports with this ReportStatusEnum.
    min_confidence : keep reports with confidence >= min_confidence.
    max_confidence : keep reports with confidence <= max_confidence.
    finding_id     : keep only reports whose findingIds contains this ID.
    alert_id       : keep only reports whose alertIds contains this ID.

    Returns a new list (input is not mutated).
    """
    result: List[Report] = []
    for r in reports:
        if report_type    is not None and r.reportType != report_type:
            continue
        if status         is not None and r.status != status:
            continue
        if min_confidence is not None and r.confidence < min_confidence:
            continue
        if max_confidence is not None and r.confidence > max_confidence:
            continue
        if finding_id     is not None and finding_id not in r.findingIds:
            continue
        if alert_id       is not None and alert_id not in r.alertIds:
            continue
        result.append(r)
    return result


def filter_report_sections(
    sections         : List[ReportSection],
    title_contains   : Optional[str]   = None,
    min_order        : Optional[int]   = None,
    max_order        : Optional[int]   = None,
) -> List[ReportSection]:
    """
    Filter sections by one or more criteria (all ANDed together).

    Parameters
    ----------
    title_contains : keep sections whose title contains this substring (case-insensitive).
    min_order      : keep sections with order >= min_order.
    max_order      : keep sections with order <= max_order.

    Returns a new list (input is not mutated).
    """
    result: List[ReportSection] = []
    for s in sections:
        if title_contains is not None and title_contains.lower() not in s.title.lower():
            continue
        if min_order is not None and s.order < min_order:
            continue
        if max_order is not None and s.order > max_order:
            continue
        result.append(s)
    return result


def filter_report_mappings(
    mappings       : List[ReportMapping],
    finding_id     : Optional[str]   = None,
    alert_id       : Optional[str]   = None,
    reasoning_id   : Optional[str]   = None,
    min_confidence : Optional[float] = None,
    max_confidence : Optional[float] = None,
) -> List[ReportMapping]:
    """
    Filter mappings by one or more criteria (all ANDed together).

    Parameters
    ----------
    finding_id     : keep only mappings with this findingId.
    alert_id       : keep only mappings with this alertId.
    reasoning_id   : keep only mappings with this reasoningId.
    min_confidence : keep mappings with confidence >= min_confidence.
    max_confidence : keep mappings with confidence <= max_confidence.

    Returns a new list (input is not mutated).
    """
    result: List[ReportMapping] = []
    for m in mappings:
        if finding_id     is not None and m.findingId   != finding_id:
            continue
        if alert_id       is not None and m.alertId     != alert_id:
            continue
        if reasoning_id   is not None and m.reasoningId != reasoning_id:
            continue
        if min_confidence is not None and m.confidence  < min_confidence:
            continue
        if max_confidence is not None and m.confidence  > max_confidence:
            continue
        result.append(m)
    return result


# ===========================================================================
# Grouping
# ===========================================================================

def group_reports(
    reports  : List[Report],
    group_by : str = "reportType",
) -> Dict[str, List[Report]]:
    """
    Group reports by a string attribute.

    Parameters
    ----------
    group_by : "reportType" | "status" | or any Report attribute whose value
               serialises to str.  Enum values are unwrapped to .value.
               Unknown attribute values fall back to key "unknown".

    Each group is sorted by reportId ASC.

    Returns
    -------
    Dict[str, List[Report]]
    """
    groups: Dict[str, List[Report]] = {}
    for r in reports:
        raw = getattr(r, group_by, None)
        if isinstance(raw, (ReportTypeEnum, ReportStatusEnum)):
            key = raw.value
        elif raw is not None:
            key = str(raw)
        else:
            key = "unknown"
        groups.setdefault(key, []).append(r)
    return {k: sorted(v, key=lambda r: r.reportId) for k, v in groups.items()}


def group_report_sections(
    sections : List[ReportSection],
    group_by : str = "title",
) -> Dict[str, List[ReportSection]]:
    """
    Group sections by a string attribute.

    Parameters
    ----------
    group_by : "title" | "order" | or any ReportSection attribute.
               Values are coerced to str.  Missing → "unknown".

    Each group is sorted by (order ASC, sectionId ASC).

    Returns
    -------
    Dict[str, List[ReportSection]]
    """
    groups: Dict[str, List[ReportSection]] = {}
    for s in sections:
        raw = getattr(s, group_by, None)
        key = str(raw) if raw is not None else "unknown"
        groups.setdefault(key, []).append(s)
    return {
        k: sorted(v, key=lambda s: (s.order, s.sectionId))
        for k, v in groups.items()
    }


def group_report_mappings(
    mappings : List[ReportMapping],
    group_by : str = "findingId",
) -> Dict[str, List[ReportMapping]]:
    """
    Group mappings by a string attribute.

    Parameters
    ----------
    group_by : "findingId" | "alertId" | "reasoningId" | or any
               ReportMapping attribute.  Values are coerced to str.
               Empty string → group key "".

    Each group is sorted by mappingId ASC.

    Returns
    -------
    Dict[str, List[ReportMapping]]
    """
    groups: Dict[str, List[ReportMapping]] = {}
    for m in mappings:
        raw = getattr(m, group_by, None)
        key = str(raw) if raw is not None else ""
        groups.setdefault(key, []).append(m)
    return {k: sorted(v, key=lambda m: m.mappingId) for k, v in groups.items()}


# ===========================================================================
# Extended build_report_statistics()
# ===========================================================================
# Replaces the Part A version with the extended schema that also includes
# reportTypeCounts and statusCounts.
# The function name is unchanged so callers built against Part A continue
# to work; the ReportStatistics model is extended in place.

# Extend ReportStatistics to carry the two new fields.
# Because frozen Pydantic models cannot be mutated, we redefine the class
# here — the new definition supersedes the Part A definition in the same
# module namespace at runtime.  All Part A behaviour (totalReports,
# draftReports, etc.) is fully preserved.

class ReportStatistics(BaseModel):  # type: ignore[no-redef]
    """
    Aggregate statistics over a collection of Report objects (extended).

    Fields
    ------
    totalReports      : total count of distinct reports.
    draftReports      : count with status == DRAFT.
    readyReports      : count with status == READY.
    publishedReports  : count with status == PUBLISHED.
    archivedReports   : count with status == ARCHIVED.
    averageConfidence : mean report.confidence across all reports (0.0 if empty).
    averageSections   : mean section count per report (0.0 if empty).
    reportTypeCounts  : dict mapping ReportTypeEnum.value → count (non-zero keys only).
    statusCounts      : dict mapping ReportStatusEnum.value → count (non-zero keys only).
    """
    totalReports      : int
    draftReports      : int
    readyReports      : int
    publishedReports  : int
    archivedReports   : int
    averageConfidence : float
    averageSections   : float
    reportTypeCounts  : Dict[str, int]
    statusCounts      : Dict[str, int]

    class Config:
        frozen = True


def build_report_statistics(  # type: ignore[no-redef]
    reports: List[Report],
) -> ReportStatistics:
    """
    Compute ReportStatistics over a flat list of Report objects (extended).

    Deterministic: canonical sort by reportId ASC before accumulation.
    Deduplication by reportId — first occurrence in sorted order wins.
    Order-independent: same statistics regardless of input ordering.

    Parameters
    ----------
    reports : any list of Report objects (may contain duplicates by reportId).

    Returns
    -------
    ReportStatistics (frozen / immutable) — includes reportTypeCounts and statusCounts.
    """
    if not reports:
        return ReportStatistics(
            totalReports      = 0,
            draftReports      = 0,
            readyReports      = 0,
            publishedReports  = 0,
            archivedReports   = 0,
            averageConfidence = 0.0,
            averageSections   = 0.0,
            reportTypeCounts  = {},
            statusCounts      = {},
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(reports, key=lambda r: r.reportId)

    # Deduplicate by reportId (first occurrence wins)
    seen: Dict[str, Report] = {}
    for r in ordered:
        if r.reportId not in seen:
            seen[r.reportId] = r

    distinct = sorted(seen.values(), key=lambda r: r.reportId)
    total = len(distinct)

    draft     = sum(1 for r in distinct if r.status == ReportStatusEnum.DRAFT)
    ready     = sum(1 for r in distinct if r.status == ReportStatusEnum.READY)
    published = sum(1 for r in distinct if r.status == ReportStatusEnum.PUBLISHED)
    archived  = sum(1 for r in distinct if r.status == ReportStatusEnum.ARCHIVED)

    avg_confidence = (
        round(sum(r.confidence for r in distinct) / total, 4)
        if total > 0 else 0.0
    )
    avg_sections = (
        round(sum(len(r.sections) for r in distinct) / total, 4)
        if total > 0 else 0.0
    )

    # reportTypeCounts — iterate enum in declaration order for determinism
    type_counts: Dict[str, int] = {}
    for rt in ReportTypeEnum:
        cnt = sum(1 for r in distinct if r.reportType == rt)
        if cnt > 0:
            type_counts[rt.value] = cnt

    # statusCounts — iterate enum in declaration order for determinism
    status_counts: Dict[str, int] = {}
    for st in ReportStatusEnum:
        cnt = sum(1 for r in distinct if r.status == st)
        if cnt > 0:
            status_counts[st.value] = cnt

    return ReportStatistics(
        totalReports      = total,
        draftReports      = draft,
        readyReports      = ready,
        publishedReports  = published,
        archivedReports   = archived,
        averageConfidence = avg_confidence,
        averageSections   = avg_sections,
        reportTypeCounts  = type_counts,
        statusCounts      = status_counts,
    )
