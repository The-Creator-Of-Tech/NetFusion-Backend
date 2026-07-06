"""
Case Flow Engine
================
Phase A4.5.3 — Deterministic, immutable case record and mapping management
for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model CaseStep, Case, CaseMapping, and CaseStatistics as immutable,
  typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_case_step, build_case, build_case_mapping,
    build_case_statistics.
- Expose validation functions:
    validate_case_step, validate_case, validate_case_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  Playbook, Automation, and Rule objects into CaseMapping or case reference
  strings.  No AI execution.  No network.  Transform only.

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
- CRUD, Search, Filter, Sort, Group, Merge, Case transitions,
  Assignments, Workflow execution, Smoke Test.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import CASE_FLOW_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("case_flow_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_CASE_FLOW_NS = uuid.UUID("6ba7b887-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class CaseFlowEngineError(Exception):
    """Base class for all Case Flow Engine errors."""


class InvalidCaseError(CaseFlowEngineError):
    """Raised when a Case fails validation."""


class InvalidCaseStepError(CaseFlowEngineError):
    """Raised when a CaseStep fails validation."""


class InvalidCaseMappingError(CaseFlowEngineError):
    """Raised when a CaseMapping fails validation."""


# ===========================================================================
# Enumerations
# ===========================================================================

class CaseStatusEnum(str, Enum):
    """Case lifecycle status."""
    OPEN        = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ON_HOLD     = "ON_HOLD"
    RESOLVED    = "RESOLVED"
    CLOSED      = "CLOSED"


class CasePriorityEnum(str, Enum):
    """Case priority classification."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class CaseStepTypeEnum(str, Enum):
    """Case step lifecycle phase classification."""
    CREATED     = "CREATED"
    ASSIGNED    = "ASSIGNED"
    INVESTIGATED = "INVESTIGATED"
    CONTAINED   = "CONTAINED"
    ERADICATED  = "ERADICATED"
    RECOVERED   = "RECOVERED"
    CLOSED      = "CLOSED"


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class CaseStep(BaseModel):
    """
    One immutable case step record representing a lifecycle phase.

    Identity
    --------
    stepKey : SHA256(caseId + str(stepNumber))[:32]
    stepId  : UUIDv5(_CASE_FLOW_NS, stepKey)

    Fields
    ------
    stepId      : deterministic UUID derived from stepKey.
    stepKey     : 32-char SHA-256 identity key.
    stepNumber  : 1-based monotonic position in the case.
    stepType    : CaseStepTypeEnum — lifecycle phase classification.
    title       : human-readable step title (non-empty).
    description : detailed step notes.
    assignedTo  : analyst or system identifier this step is assigned to.
    createdAt   : ISO-8601 timestamp (caller-supplied for determinism).
    """
    stepId      : str
    stepKey     : str
    stepNumber  : int
    stepType    : CaseStepTypeEnum
    title       : str
    description : str
    assignedTo  : str
    createdAt   : str

    class Config:
        frozen = True


class Case(BaseModel):
    """
    One immutable Case record representing an investigation case.

    Identity
    --------
    caseKey : SHA256(title + priority.value + sorted(findingIds))[:32]
    caseId  : UUIDv5(_CASE_FLOW_NS, caseKey)

    Fields
    ------
    caseId       : deterministic UUID derived from caseKey.
    caseKey      : 32-char SHA-256 identity key.
    caseNumber   : human-readable sequential case reference (e.g. "CASE-001").
    title        : human-readable case title (non-empty).
    description  : overview of the case scope and context.
    status       : CaseStatusEnum — lifecycle status.
    priority     : CasePriorityEnum — urgency classification.
    steps        : sorted tuple of CaseStep objects (by stepNumber ASC).
    findingIds   : sorted tuple of linked Finding IDs.
    alertIds     : sorted tuple of linked Alert IDs.
    evidenceIds  : sorted tuple of linked Evidence IDs.
    playbookIds  : sorted tuple of linked Playbook IDs.
    assignedTo   : analyst or system identifier this case is assigned to.
    confidence   : 0.0–100.0 confidence (clamped).
    createdAt    : ISO-8601 timestamp (caller-supplied for determinism).
    """
    caseId      : str
    caseKey     : str
    caseNumber  : str
    title       : str
    description : str
    status      : CaseStatusEnum
    priority    : CasePriorityEnum
    steps       : Tuple[CaseStep, ...]
    findingIds  : Tuple[str, ...]
    alertIds    : Tuple[str, ...]
    evidenceIds : Tuple[str, ...]
    playbookIds : Tuple[str, ...]
    assignedTo  : str
    confidence  : float
    createdAt   : str

    class Config:
        frozen = True


class CaseMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to Case objects.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(caseIds))[:32]
    mappingId          : UUIDv5(_CASE_FLOW_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(caseIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    cases              : sorted tuple of Case objects linked
                         (sorted by priority DESC then caseId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    mappingFingerprint : deterministic 32-char content fingerprint.
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    cases              : Tuple[Case, ...]
    confidence         : float
    mappingFingerprint : str
    createdAt          : str

    class Config:
        frozen = True


class CaseStatistics(BaseModel):
    """
    Aggregate statistics over a collection of Case objects.

    Fields
    ------
    totalCases          : total count of distinct cases.
    openCases           : count with status == OPEN.
    inProgressCases     : count with status == IN_PROGRESS.
    onHoldCases         : count with status == ON_HOLD.
    resolvedCases       : count with status == RESOLVED.
    closedCases         : count with status == CLOSED.
    averageConfidence   : mean case.confidence across all cases (0.0 if empty).
    averageSteps        : mean step count per case (0.0 if empty).
    priorityCounts      : dict mapping CasePriorityEnum.value → count
                          (only keys with count > 0 are present).
    statusCounts        : dict mapping CaseStatusEnum.value → count
                          (only keys with count > 0 are present).
    """
    totalCases        : int
    openCases         : int
    inProgressCases   : int
    onHoldCases       : int
    resolvedCases     : int
    closedCases       : int
    averageConfidence : float
    averageSteps      : float
    priorityCounts    : Dict[str, int]
    statusCounts      : Dict[str, int]

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
    """UUIDv5(_CASE_FLOW_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_CASE_FLOW_NS, key))


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
# Priority sort order (CRITICAL first for deterministic mapping ordering)
# ---------------------------------------------------------------------------
_PRIORITY_ORDER: Dict[CasePriorityEnum, int] = {
    CasePriorityEnum.CRITICAL : 4,
    CasePriorityEnum.HIGH     : 3,
    CasePriorityEnum.MEDIUM   : 2,
    CasePriorityEnum.LOW      : 1,
}


# ---------------------------------------------------------------------------
# Public key derivation functions (named per spec)
# ---------------------------------------------------------------------------

def stepKey(case_id: str, step_number: int) -> str:
    """
    stepKey = SHA256(caseId + str(stepNumber))[:32]

    Null-byte-separated to prevent cross-field collisions.
    Same (caseId, stepNumber) pair always produces the same key.
    """
    return _sha256_32(case_id.strip(), str(step_number))


def caseKey(
    title      : str,
    priority   : CasePriorityEnum,
    finding_ids: Tuple[str, ...],
) -> str:
    """
    caseKey = SHA256(title + priority.value + sorted(findingIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    findingIds sorted before joining for order-independence.
    """
    sorted_fids = "\x01".join(sorted(finding_ids))
    return _sha256_32(title.strip(), priority.value, sorted_fids)


def mappingKey(
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    case_ids     : Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(caseIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    caseIds sorted before joining for order-independence.
    """
    sorted_ids = "\x01".join(sorted(case_ids))
    return _sha256_32(
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_ids,
    )


def mappingFingerprint(
    m_key        : str,
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    case_ids     : Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(caseIds))[:32]
    """
    sorted_ids = "\x01".join(sorted(case_ids))
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

def validate_case_step(
    step_number : int,
    step_type   : CaseStepTypeEnum,
    title       : str,
    created_at  : str,
) -> None:
    """
    Validate CaseStep construction parameters.

    Checks
    ------
    - step_number is a positive integer (>= 1).
    - step_type is a valid CaseStepTypeEnum member.
    - title is non-empty.
    - created_at is non-empty.

    Raises
    ------
    InvalidCaseStepError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(step_number, int) or step_number < 1:
        errors.append(
            f"stepNumber={step_number!r} must be a positive integer (>= 1)."
        )
    if not isinstance(step_type, CaseStepTypeEnum):
        errors.append(
            f"stepType must be a CaseStepTypeEnum member; got {step_type!r}."
        )
    if not title or not title.strip():
        errors.append("title must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_case_step", "errors": errors},
        )
        raise InvalidCaseStepError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_case(
    title      : str,
    status     : CaseStatusEnum,
    priority   : CasePriorityEnum,
    created_at : str,
) -> None:
    """
    Validate Case construction parameters.

    Checks
    ------
    - title is non-empty.
    - status is a valid CaseStatusEnum member.
    - priority is a valid CasePriorityEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidCaseError : if any rule is violated.
    """
    errors: List[str] = []

    if not title or not title.strip():
        errors.append("title must not be empty.")
    if not isinstance(status, CaseStatusEnum):
        errors.append(
            f"status must be a CaseStatusEnum member; got {status!r}."
        )
    if not isinstance(priority, CasePriorityEnum):
        errors.append(
            f"priority must be a CasePriorityEnum member; got {priority!r}."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_case", "errors": errors},
        )
        raise InvalidCaseError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_case_mapping(
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    confidence   : float,
    created_at   : str,
) -> None:
    """
    Validate CaseMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidCaseMappingError : if any rule is violated.
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
            extra={"validator": "validate_case_mapping", "errors": errors},
        )
        raise InvalidCaseMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_case_step()
# ===========================================================================

def build_case_step(
    case_id     : str,
    step_number : int,
    step_type   : CaseStepTypeEnum,
    title       : str,
    created_at  : str,
    description : str  = "",
    assigned_to : str  = "",
    validate    : bool = True,
) -> CaseStep:
    """
    Build an immutable CaseStep.

    stepKey = SHA256(caseId + str(stepNumber))[:32]
    stepId  = UUIDv5(_CASE_FLOW_NS, stepKey)

    Parameters
    ----------
    case_id     : ID of the parent Case (scopes step identity).
    step_number : 1-based position in the case (must be >= 1).
    step_type   : CaseStepTypeEnum — lifecycle phase classification.
    title       : human-readable step title (must be non-empty).
    created_at  : ISO-8601 timestamp (caller-supplied for determinism).
    description : detailed step notes (may be empty).
    assigned_to : analyst or system identifier (may be empty).
    validate    : if True, run validate_case_step() first.

    Returns
    -------
    CaseStep (frozen / immutable)

    Raises
    ------
    InvalidCaseStepError : if validate=True and step validation fails.
    """
    if validate:
        validate_case_step(step_number, step_type, title, created_at)

    s_key = stepKey(case_id, step_number)
    s_id  = _uuid5(s_key)

    return CaseStep(
        stepId      = s_id,
        stepKey     = s_key,
        stepNumber  = step_number,
        stepType    = step_type,
        title       = title.strip(),
        description = description,
        assignedTo  = _norm(assigned_to),
        createdAt   = created_at,
    )


# ===========================================================================
# Builder: build_case()
# ===========================================================================

def build_case(
    title        : str,
    priority     : CasePriorityEnum,
    created_at   : str,
    case_number  : str                       = "",
    description  : str                       = "",
    status       : CaseStatusEnum            = CaseStatusEnum.OPEN,
    steps        : Optional[List[CaseStep]]  = None,
    finding_ids  : Optional[List[str]]       = None,
    alert_ids    : Optional[List[str]]       = None,
    evidence_ids : Optional[List[str]]       = None,
    playbook_ids : Optional[List[str]]       = None,
    assigned_to  : str                       = "",
    confidence   : float                     = 0.0,
    validate     : bool                      = True,
) -> Case:
    """
    Build an immutable Case.

    caseKey = SHA256(title + priority.value + sorted(findingIds))[:32]
    caseId  = UUIDv5(_CASE_FLOW_NS, caseKey)

    Parameters
    ----------
    title        : human-readable case title (must be non-empty).
    priority     : CasePriorityEnum — urgency classification.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    case_number  : human-readable reference string (e.g. "CASE-001").
                   Defaults to a deterministic prefix of caseId if empty.
    description  : overview of the case scope and context (may be empty).
    status       : CaseStatusEnum — lifecycle status (default OPEN).
    steps        : list of CaseStep objects (sorted by stepNumber ASC).
    finding_ids  : linked Finding IDs (deduped + sorted).
    alert_ids    : linked Alert IDs (deduped + sorted).
    evidence_ids : linked Evidence IDs (deduped + sorted).
    playbook_ids : linked Playbook IDs (deduped + sorted).
    assigned_to  : analyst or system identifier (may be empty).
    confidence   : 0.0–100.0 confidence score (clamped).
    validate     : if True, run validate_case() first.

    Returns
    -------
    Case (frozen / immutable)

    Raises
    ------
    InvalidCaseError : if validate=True and case validation fails.
    """
    if validate:
        validate_case(title, status, priority, created_at)

    clamped_conf = _clamp(float(confidence))

    norm_finding_ids  = _norm_ids(finding_ids)
    norm_alert_ids    = _norm_ids(alert_ids)
    norm_evidence_ids = _norm_ids(evidence_ids)
    norm_playbook_ids = _norm_ids(playbook_ids)

    # Sort steps deterministically: stepNumber ASC, then stepId ASC for ties
    sorted_steps: Tuple[CaseStep, ...] = tuple(
        sorted(
            steps or [],
            key=lambda s: (s.stepNumber, s.stepId),
        )
    )

    c_key = caseKey(title, priority, norm_finding_ids)
    c_id  = _uuid5(c_key)

    # Generate a deterministic case number from the caseId prefix if not supplied
    resolved_case_number = (
        case_number.strip()
        if case_number and case_number.strip()
        else f"CASE-{c_id[:8].upper()}"
    )

    return Case(
        caseId      = c_id,
        caseKey     = c_key,
        caseNumber  = resolved_case_number,
        title       = title.strip(),
        description = description,
        status      = status,
        priority    = priority,
        steps       = sorted_steps,
        findingIds  = norm_finding_ids,
        alertIds    = norm_alert_ids,
        evidenceIds = norm_evidence_ids,
        playbookIds = norm_playbook_ids,
        assignedTo  = _norm(assigned_to),
        confidence  = round(clamped_conf, 4),
        createdAt   = created_at,
    )


# ===========================================================================
# Builder: build_case_mapping()
# ===========================================================================

def build_case_mapping(
    cases        : List[Case],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> CaseMapping:
    """
    Build an immutable CaseMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(caseIds))[:32]
    mappingId          = UUIDv5(_CASE_FLOW_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(caseIds))[:32]

    Parameters
    ----------
    cases        : list of Case objects to link in this mapping.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_case_mapping() first.

    Returns
    -------
    CaseMapping (frozen / immutable)

    Raises
    ------
    InvalidCaseMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_case_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: priority DESC (CRITICAL first), then caseId ASC
    sorted_cases: Tuple[Case, ...] = tuple(
        sorted(
            cases or [],
            key=lambda c: (-_PRIORITY_ORDER.get(c.priority, 0), c.caseId),
        )
    )

    # Collect case IDs for key computation
    c_ids: Tuple[str, ...] = tuple(c.caseId for c in sorted_cases)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, c_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(m_key, finding_id, alert_id, reasoning_id, c_ids)

    return CaseMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        cases              = sorted_cases,
        confidence         = round(clamped_conf, 4),
        mappingFingerprint = m_fp,
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_case_statistics()
# ===========================================================================

def build_case_statistics(
    cases: List[Case],
) -> CaseStatistics:
    """
    Compute CaseStatistics over a flat list of Case objects.

    Deterministic: canonical sort by caseId ASC before accumulation so
    floating-point sums and counts are identical across every run regardless
    of input ordering.

    Deduplication is by caseId — first occurrence in sorted order wins.

    Parameters
    ----------
    cases : any list of Case objects (may contain duplicates by caseId).

    Returns
    -------
    CaseStatistics (frozen / immutable)
    """
    if not cases:
        return CaseStatistics(
            totalCases        = 0,
            openCases         = 0,
            inProgressCases   = 0,
            onHoldCases       = 0,
            resolvedCases     = 0,
            closedCases       = 0,
            averageConfidence = 0.0,
            averageSteps      = 0.0,
            priorityCounts    = {},
            statusCounts      = {},
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(cases, key=lambda c: c.caseId)

    # Deduplicate by caseId — first occurrence in sorted order wins
    seen_ids: Dict[str, Case] = {}
    for c in ordered:
        if c.caseId not in seen_ids:
            seen_ids[c.caseId] = c

    distinct = list(seen_ids.values())
    # Re-sort after dedup for deterministic counting
    distinct.sort(key=lambda c: c.caseId)

    total       = len(distinct)
    open_count  = sum(1 for c in distinct if c.status == CaseStatusEnum.OPEN)
    in_progress = sum(1 for c in distinct if c.status == CaseStatusEnum.IN_PROGRESS)
    on_hold     = sum(1 for c in distinct if c.status == CaseStatusEnum.ON_HOLD)
    resolved    = sum(1 for c in distinct if c.status == CaseStatusEnum.RESOLVED)
    closed      = sum(1 for c in distinct if c.status == CaseStatusEnum.CLOSED)

    avg_confidence = (
        round(sum(c.confidence for c in distinct) / total, 4)
        if total > 0 else 0.0
    )
    avg_steps = (
        round(sum(len(c.steps) for c in distinct) / total, 4)
        if total > 0 else 0.0
    )

    return CaseStatistics(
        totalCases        = total,
        openCases         = open_count,
        inProgressCases   = in_progress,
        onHoldCases       = on_hold,
        resolvedCases     = resolved,
        closedCases       = closed,
        averageConfidence = avg_confidence,
        averageSteps      = avg_steps,
        priorityCounts    = {
            p.value: cnt
            for p in CasePriorityEnum
            for cnt in [sum(1 for c in distinct if c.priority == p)]
            if cnt > 0
        },
        statusCounts      = {
            s.value: cnt
            for s in CaseStatusEnum
            for cnt in [sum(1 for c in distinct if c.status == s)]
            if cnt > 0
        },
    )


# ===========================================================================
# Integration Helpers
# ===========================================================================
# Pure transformation helpers. Accept objects from other engine services and
# return CaseMapping objects or case reference strings.
# No external lookups. No AI execution. No network. Duck-typed input objects
# are accepted so there is no circular import at module load time.
# No workflow evaluation. No scheduling. Only deterministic transformations.


def finding_to_case_mapping(
    finding    : Any,
    cases      : List[Case],
    created_at : str,
    confidence : float = 0.0,
) -> CaseMapping:
    """
    Transform a Finding object into a CaseMapping.

    Extracts findingId from finding.findingId (duck-typed).
    alertId and reasoningId are left empty.

    Parameters
    ----------
    finding    : any object with a .findingId string attribute.
    cases      : list of Case objects to link to this finding.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    confidence : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    CaseMapping (frozen / immutable)
    """
    finding_id = _norm(getattr(finding, "findingId", ""))
    return build_case_mapping(
        cases        = cases,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
    )


def alert_to_case_mapping(
    alert      : Any,
    cases      : List[Case],
    created_at : str,
    confidence : float = 0.0,
) -> CaseMapping:
    """
    Transform an Alert object into a CaseMapping.

    Extracts alertId from alert.alertId (duck-typed).
    findingId is sourced from alert.findingId when present.
    reasoningId is left empty.

    Parameters
    ----------
    alert      : any object with .alertId and optionally .findingId.
    cases      : list of Case objects to link to this alert.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    confidence : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    CaseMapping (frozen / immutable)
    """
    alert_id   = _norm(getattr(alert, "alertId", ""))
    finding_id = _norm(getattr(alert, "findingId", ""))
    return build_case_mapping(
        cases        = cases,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = "",
        confidence   = confidence,
    )


def reasoning_to_case_mapping(
    reasoning  : Any,
    cases      : List[Case],
    created_at : str,
    confidence : float = 0.0,
) -> CaseMapping:
    """
    Transform a ReasoningResult object into a CaseMapping.

    Extracts reasoningId from reasoning.reasoningId (duck-typed).
    findingId and alertId are left empty.

    Parameters
    ----------
    reasoning  : any object with a .reasoningId string attribute.
    cases      : list of Case objects to link to this reasoning result.
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    confidence : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    CaseMapping (frozen / immutable)
    """
    reasoning_id = _norm(getattr(reasoning, "reasoningId", ""))
    return build_case_mapping(
        cases        = cases,
        created_at   = created_at,
        finding_id   = "",
        alert_id     = "",
        reasoning_id = reasoning_id,
        confidence   = confidence,
    )


def playbook_to_case_reference(playbook: Any) -> str:
    """
    Extract a stable case reference string from a Playbook object.

    Returns a string of the form "playbook:<playbookId>" that can be stored
    in case metadata or step parameters to link a Case to a Playbook without
    creating a circular dependency.

    Parameters
    ----------
    playbook : any object with a .playbookId string attribute (duck-typed).

    Returns
    -------
    str — "playbook:<playbookId>" or "playbook:" if playbookId is absent/empty.
    """
    playbook_id = _norm(getattr(playbook, "playbookId", ""))
    return f"playbook:{playbook_id}"


def automation_to_case_reference(automation: Any) -> str:
    """
    Extract a stable case reference string from an Automation object.

    Returns a string of the form "automation:<automationId>" that can be
    stored in case metadata or step parameters to link a Case to an
    Automation without creating a circular dependency.

    Parameters
    ----------
    automation : any object with a .automationId string attribute (duck-typed).

    Returns
    -------
    str — "automation:<automationId>" or "automation:" if absent/empty.
    """
    automation_id = _norm(getattr(automation, "automationId", ""))
    return f"automation:{automation_id}"


def rule_to_case_reference(rule: Any) -> str:
    """
    Extract a stable case reference string from a Rule object.

    Returns a string of the form "rule:<ruleId>" that can be stored in case
    metadata or step parameters to link a Case to a Rule without creating a
    circular dependency.

    Parameters
    ----------
    rule : any object with a .ruleId string attribute (duck-typed).

    Returns
    -------
    str — "rule:<ruleId>" or "rule:" if ruleId is absent/empty.
    """
    rule_id = _norm(getattr(rule, "ruleId", ""))
    return f"rule:{rule_id}"


# ===========================================================================
# Part B — Operations, Search, Sort, Filter, Group
# ===========================================================================

# ---------------------------------------------------------------------------
# Internal sort-order helpers
# ---------------------------------------------------------------------------

_STATUS_ORDER: Dict[CaseStatusEnum, int] = {
    CaseStatusEnum.OPEN        : 5,
    CaseStatusEnum.IN_PROGRESS : 4,
    CaseStatusEnum.ON_HOLD     : 3,
    CaseStatusEnum.RESOLVED    : 2,
    CaseStatusEnum.CLOSED      : 1,
}

_VALID_CASE_SORT_KEYS = frozenset({
    "caseNumber", "title", "status", "priority", "confidence", "createdAt",
})

_VALID_STEP_SORT_KEYS = frozenset({
    "stepNumber", "title", "stepType", "createdAt",
})

_VALID_MAPPING_SORT_KEYS = frozenset({
    "confidence", "createdAt", "findingId", "alertId", "reasoningId",
})


# ===========================================================================
# Case Operations
# ===========================================================================

def add_case(
    cases : List[Case],
    case  : Case,
) -> List[Case]:
    """
    Return a new list with *case* appended.

    Duplicate detection: if a Case with the same caseId already exists in
    *cases*, the original list is returned unchanged (idempotent).

    Parameters
    ----------
    cases : existing list of Case objects.
    case  : Case to add.

    Returns
    -------
    New list — input is not mutated.
    """
    for existing in cases:
        if existing.caseId == case.caseId:
            _log.info(
                "case_add_skipped_duplicate",
                extra={"caseId": case.caseId},
            )
            return list(cases)
    result = list(cases) + [case]
    _log.info(
        "case_created",
        extra={"caseId": case.caseId, "caseNumber": case.caseNumber},
    )
    return result


def update_case(
    cases      : List[Case],
    case_id    : str,
    created_at : str,
    title        : Optional[str]              = None,
    description  : Optional[str]              = None,
    status       : Optional[CaseStatusEnum]   = None,
    priority     : Optional[CasePriorityEnum] = None,
    case_number  : Optional[str]              = None,
    steps        : Optional[List[CaseStep]]   = None,
    finding_ids  : Optional[List[str]]        = None,
    alert_ids    : Optional[List[str]]        = None,
    evidence_ids : Optional[List[str]]        = None,
    playbook_ids : Optional[List[str]]        = None,
    assigned_to  : Optional[str]              = None,
    confidence   : Optional[float]            = None,
) -> List[Case]:
    """
    Return a new list where the Case with *case_id* has the supplied fields
    replaced.  Fields set to None are left unchanged.

    caseKey and caseId are recomputed when title, priority, or finding_ids
    change (content-addressable identity).  caseNumber is preserved unless
    explicitly overridden.

    If no Case with *case_id* is found, the list is returned unchanged.

    Returns
    -------
    New list — input is not mutated.
    """
    result: List[Case] = []
    updated = False
    for c in cases:
        if c.caseId != case_id:
            result.append(c)
            continue
        new_title        = title.strip()    if title        is not None else c.title
        new_desc         = description      if description  is not None else c.description
        new_status       = status           if status       is not None else c.status
        new_priority     = priority         if priority     is not None else c.priority
        new_case_number  = case_number      if case_number  is not None else c.caseNumber
        new_steps        = steps            if steps        is not None else list(c.steps)
        new_finding_ids  = finding_ids      if finding_ids  is not None else list(c.findingIds)
        new_alert_ids    = alert_ids        if alert_ids    is not None else list(c.alertIds)
        new_evidence_ids = evidence_ids     if evidence_ids is not None else list(c.evidenceIds)
        new_playbook_ids = playbook_ids     if playbook_ids is not None else list(c.playbookIds)
        new_assigned_to  = assigned_to      if assigned_to  is not None else c.assignedTo
        new_confidence   = confidence       if confidence   is not None else c.confidence

        rebuilt = build_case(
            title        = new_title,
            priority     = new_priority,
            created_at   = created_at,
            case_number  = new_case_number,
            description  = new_desc,
            status       = new_status,
            steps        = new_steps,
            finding_ids  = new_finding_ids,
            alert_ids    = new_alert_ids,
            evidence_ids = new_evidence_ids,
            playbook_ids = new_playbook_ids,
            assigned_to  = new_assigned_to,
            confidence   = new_confidence,
        )
        result.append(rebuilt)
        updated = True
        _log.info(
            "case_updated",
            extra={"caseId": case_id, "caseNumber": rebuilt.caseNumber},
        )
    if not updated:
        _log.warning(
            "case_update_not_found",
            extra={"caseId": case_id},
        )
    return result


def remove_case(
    cases   : List[Case],
    case_id : str,
) -> List[Case]:
    """
    Return a new list with the Case matching *case_id* removed.

    If no match is found, returns the list unchanged (idempotent).

    Returns
    -------
    New list — input is not mutated.
    """
    result = [c for c in cases if c.caseId != case_id]
    if len(result) < len(cases):
        _log.info(
            "case_removed",
            extra={"caseId": case_id},
        )
    return result


def merge_cases(
    base     : List[Case],
    incoming : List[Case],
) -> List[Case]:
    """
    Deterministically merge *incoming* into *base*.

    Rules
    -----
    - Existing cases (same caseId) are preserved unchanged (base wins).
    - New cases (unseen caseId) are appended.
    - Result is sorted by caseId ASC for full determinism.
    - Zero randomness; no timestamp-derived ordering.

    Returns
    -------
    New deduplicated, sorted list — inputs are not mutated.
    """
    seen: Dict[str, Case] = {c.caseId: c for c in base}
    added = 0
    for c in incoming:
        if c.caseId not in seen:
            seen[c.caseId] = c
            added += 1
    result = sorted(seen.values(), key=lambda c: c.caseId)
    _log.info(
        "case_merge_completed",
        extra={"baseCount": len(base), "incomingCount": len(incoming), "added": added},
    )
    return result


# ===========================================================================
# Case Step Operations
# ===========================================================================

def add_case_step(
    case       : Case,
    step       : CaseStep,
    created_at : str,
) -> Case:
    """
    Return a new Case with *step* added to its steps.

    Duplicate detection: if a step with the same stepId already exists,
    the original case is returned unchanged (idempotent).
    caseKey and caseId are NOT recomputed (steps don't affect the case key).

    Returns
    -------
    New Case (frozen / immutable) — input is not mutated.
    """
    for existing in case.steps:
        if existing.stepId == step.stepId:
            _log.info(
                "case_step_add_skipped_duplicate",
                extra={"stepId": step.stepId, "caseId": case.caseId},
            )
            return case

    new_steps = sorted(
        list(case.steps) + [step],
        key=lambda s: (s.stepNumber, s.stepId),
    )
    rebuilt = build_case(
        title        = case.title,
        priority     = case.priority,
        created_at   = created_at,
        case_number  = case.caseNumber,
        description  = case.description,
        status       = case.status,
        steps        = new_steps,
        finding_ids  = list(case.findingIds),
        alert_ids    = list(case.alertIds),
        evidence_ids = list(case.evidenceIds),
        playbook_ids = list(case.playbookIds),
        assigned_to  = case.assignedTo,
        confidence   = case.confidence,
    )
    _log.info(
        "case_step_created",
        extra={"stepId": step.stepId, "caseId": rebuilt.caseId},
    )
    return rebuilt


def update_case_step(
    case        : Case,
    step_id     : str,
    created_at  : str,
    title       : Optional[str]           = None,
    description : Optional[str]           = None,
    step_type   : Optional[CaseStepTypeEnum] = None,
    assigned_to : Optional[str]           = None,
) -> Case:
    """
    Return a new Case with the step matching *step_id* updated.

    stepId and stepKey are preserved (identity is stable).
    If no step with *step_id* is found, the case is returned unchanged.

    Returns
    -------
    New Case (frozen / immutable) — input is not mutated.
    """
    new_steps: List[CaseStep] = []
    updated = False
    for s in case.steps:
        if s.stepId != step_id:
            new_steps.append(s)
            continue
        rebuilt_step = CaseStep(
            stepId      = s.stepId,
            stepKey     = s.stepKey,
            stepNumber  = s.stepNumber,
            stepType    = (step_type   if step_type   is not None else s.stepType),
            title       = (title.strip() if title     is not None else s.title),
            description = (description  if description is not None else s.description),
            assignedTo  = (_norm(assigned_to) if assigned_to is not None else s.assignedTo),
            createdAt   = s.createdAt,
        )
        new_steps.append(rebuilt_step)
        updated = True
        _log.info(
            "case_step_updated",
            extra={"stepId": step_id, "caseId": case.caseId},
        )

    if not updated:
        _log.warning(
            "case_step_update_not_found",
            extra={"stepId": step_id, "caseId": case.caseId},
        )
        return case

    return build_case(
        title        = case.title,
        priority     = case.priority,
        created_at   = created_at,
        case_number  = case.caseNumber,
        description  = case.description,
        status       = case.status,
        steps        = new_steps,
        finding_ids  = list(case.findingIds),
        alert_ids    = list(case.alertIds),
        evidence_ids = list(case.evidenceIds),
        playbook_ids = list(case.playbookIds),
        assigned_to  = case.assignedTo,
        confidence   = case.confidence,
    )


def remove_case_step(
    case       : Case,
    step_id    : str,
    created_at : str,
) -> Case:
    """
    Return a new Case with the step matching *step_id* removed.

    If no step with *step_id* is found, the case is returned unchanged (idempotent).

    Returns
    -------
    New Case (frozen / immutable) — input is not mutated.
    """
    new_steps = [s for s in case.steps if s.stepId != step_id]
    if len(new_steps) == len(case.steps):
        _log.warning(
            "case_step_remove_not_found",
            extra={"stepId": step_id, "caseId": case.caseId},
        )
        return case

    _log.info(
        "case_step_removed",
        extra={"stepId": step_id, "caseId": case.caseId},
    )
    return build_case(
        title        = case.title,
        priority     = case.priority,
        created_at   = created_at,
        case_number  = case.caseNumber,
        description  = case.description,
        status       = case.status,
        steps        = new_steps,
        finding_ids  = list(case.findingIds),
        alert_ids    = list(case.alertIds),
        evidence_ids = list(case.evidenceIds),
        playbook_ids = list(case.playbookIds),
        assigned_to  = case.assignedTo,
        confidence   = case.confidence,
    )


def merge_case_steps(
    case       : Case,
    incoming   : List[CaseStep],
    created_at : str,
) -> Case:
    """
    Deterministically merge *incoming* steps into *case*.

    Rules
    -----
    - Existing steps (same stepId) are preserved unchanged (base wins).
    - New steps (unseen stepId) are appended.

    Returns
    -------
    New Case (frozen / immutable) — input is not mutated.
    """
    seen: Dict[str, CaseStep] = {s.stepId: s for s in case.steps}
    added = 0
    for s in incoming:
        if s.stepId not in seen:
            seen[s.stepId] = s
            added += 1
    merged_steps = sorted(seen.values(), key=lambda s: (s.stepNumber, s.stepId))
    _log.info(
        "case_merge_completed",
        extra={
            "caseId": case.caseId,
            "baseSteps": len(case.steps),
            "incomingSteps": len(incoming),
            "added": added,
        },
    )
    return build_case(
        title        = case.title,
        priority     = case.priority,
        created_at   = created_at,
        case_number  = case.caseNumber,
        description  = case.description,
        status       = case.status,
        steps        = merged_steps,
        finding_ids  = list(case.findingIds),
        alert_ids    = list(case.alertIds),
        evidence_ids = list(case.evidenceIds),
        playbook_ids = list(case.playbookIds),
        assigned_to  = case.assignedTo,
        confidence   = case.confidence,
    )


# ===========================================================================
# Mapping Operations
# ===========================================================================

def add_case_mapping(
    mappings : List[CaseMapping],
    mapping  : CaseMapping,
) -> List[CaseMapping]:
    """
    Return a new list with *mapping* appended.

    Duplicate detection: if a mapping with the same mappingId already exists,
    the original list is returned unchanged (idempotent).

    Returns
    -------
    New list — input is not mutated.
    """
    for existing in mappings:
        if existing.mappingId == mapping.mappingId:
            _log.info(
                "case_mapping_add_skipped_duplicate",
                extra={"mappingId": mapping.mappingId},
            )
            return list(mappings)
    result = list(mappings) + [mapping]
    _log.info(
        "case_mapping_created",
        extra={"mappingId": mapping.mappingId},
    )
    return result


def remove_case_mapping(
    mappings   : List[CaseMapping],
    mapping_id : str,
) -> List[CaseMapping]:
    """
    Return a new list with the CaseMapping matching *mapping_id* removed.

    If no match is found, returns the list unchanged (idempotent).

    Returns
    -------
    New list — input is not mutated.
    """
    result = [m for m in mappings if m.mappingId != mapping_id]
    if len(result) < len(mappings):
        _log.info(
            "case_mapping_removed",
            extra={"mappingId": mapping_id},
        )
    return result


def merge_case_mappings(
    base     : List[CaseMapping],
    incoming : List[CaseMapping],
) -> List[CaseMapping]:
    """
    Deterministically merge *incoming* mappings into *base*.

    Rules
    -----
    - Existing mappings (same mappingId) are preserved unchanged (base wins).
    - New mappings (unseen mappingId) are appended.
    - Result is sorted by mappingId ASC for full determinism.

    Returns
    -------
    New deduplicated, sorted list — inputs are not mutated.
    """
    seen: Dict[str, CaseMapping] = {m.mappingId: m for m in base}
    added = 0
    for m in incoming:
        if m.mappingId not in seen:
            seen[m.mappingId] = m
            added += 1
    result = sorted(seen.values(), key=lambda m: m.mappingId)
    _log.info(
        "case_merge_completed",
        extra={"baseCount": len(base), "incomingCount": len(incoming), "added": added},
    )
    return result


# ===========================================================================
# Search Utilities
# ===========================================================================

def find_case(
    cases    : List[Case],
    case_id  : Optional[str] = None,
    case_key : Optional[str] = None,
) -> Optional[Case]:
    """
    Look up a single Case by caseId or caseKey.

    caseId takes precedence over caseKey when both are supplied.
    Returns the first match or None.

    Parameters
    ----------
    cases    : list to search.
    case_id  : exact caseId to match.
    case_key : exact caseKey to match (used if case_id is None).

    Returns
    -------
    Case or None.
    """
    if case_id is not None:
        for c in cases:
            if c.caseId == case_id:
                return c
        return None
    if case_key is not None:
        for c in cases:
            if c.caseKey == case_key:
                return c
    return None


def find_case_step(
    cases    : List[Case],
    step_id  : Optional[str] = None,
    step_key : Optional[str] = None,
) -> Optional[CaseStep]:
    """
    Look up a single CaseStep by stepId or stepKey across all cases.

    stepId takes precedence over stepKey when both are supplied.
    Returns the first match or None.

    Parameters
    ----------
    cases    : list to search.
    step_id  : exact stepId to match.
    step_key : exact stepKey to match (used if step_id is None).

    Returns
    -------
    CaseStep or None.
    """
    if step_id is not None:
        for c in cases:
            for s in c.steps:
                if s.stepId == step_id:
                    return s
        return None
    if step_key is not None:
        for c in cases:
            for s in c.steps:
                if s.stepKey == step_key:
                    return s
    return None


def find_case_mapping(
    mappings   : List[CaseMapping],
    mapping_id : Optional[str] = None,
) -> Optional[CaseMapping]:
    """
    Look up a single CaseMapping by mappingId.

    Returns the first match or None.

    Parameters
    ----------
    mappings   : list to search.
    mapping_id : exact mappingId to match.

    Returns
    -------
    CaseMapping or None.
    """
    if mapping_id is not None:
        for m in mappings:
            if m.mappingId == mapping_id:
                return m
    return None


# ===========================================================================
# Sorting
# ===========================================================================

def sort_cases(
    cases     : List[Case],
    by        : str  = "priority",
    ascending : bool = False,
) -> List[Case]:
    """
    Return a new sorted list of cases.

    Parameters
    ----------
    by        : "caseNumber" | "title" | "status" | "priority" (default) |
                "confidence" | "createdAt"
    ascending : False = CRITICAL first / highest confidence first (default).

    Tie-breaking is always by caseId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted list — input is not mutated.
    """
    if by not in _VALID_CASE_SORT_KEYS:
        raise ValueError(
            f"sort_cases: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_CASE_SORT_KEYS)}"
        )

    def _key(c: Case) -> tuple:
        if by == "priority":
            primary = _PRIORITY_ORDER.get(c.priority, 0)
        elif by == "status":
            primary = _STATUS_ORDER.get(c.status, 0)
        elif by == "confidence":
            primary = c.confidence
        elif by == "title":
            primary = c.title.lower()
        elif by == "caseNumber":
            primary = c.caseNumber
        else:  # createdAt
            primary = c.createdAt
        return (primary, c.caseId)

    return sorted(cases, key=_key, reverse=not ascending)


def sort_case_steps(
    steps     : List[CaseStep],
    by        : str  = "stepNumber",
    ascending : bool = True,
) -> List[CaseStep]:
    """
    Return a new sorted list of case steps.

    Parameters
    ----------
    by        : "stepNumber" (default) | "title" | "stepType" | "createdAt"
    ascending : True = step 1 first (default); False = last step first.

    Tie-breaking is always by stepId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted list — input is not mutated.
    """
    if by not in _VALID_STEP_SORT_KEYS:
        raise ValueError(
            f"sort_case_steps: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_STEP_SORT_KEYS)}"
        )

    def _key(s: CaseStep) -> tuple:
        if by == "stepNumber":
            primary = s.stepNumber
        elif by == "title":
            primary = s.title.lower()
        elif by == "stepType":
            primary = s.stepType.value
        else:  # createdAt
            primary = s.createdAt
        return (primary, s.stepId)

    return sorted(steps, key=_key, reverse=not ascending)


def sort_case_mappings(
    mappings  : List[CaseMapping],
    by        : str  = "createdAt",
    ascending : bool = True,
) -> List[CaseMapping]:
    """
    Return a new sorted list of case mappings.

    Parameters
    ----------
    by        : "confidence" | "createdAt" (default) | "findingId" |
                "alertId" | "reasoningId"
    ascending : True = oldest / lowest confidence first (default).

    Tie-breaking is always by mappingId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted list — input is not mutated.
    """
    if by not in _VALID_MAPPING_SORT_KEYS:
        raise ValueError(
            f"sort_case_mappings: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: CaseMapping) -> tuple:
        if by == "confidence":
            primary = m.confidence
        elif by == "findingId":
            primary = m.findingId
        elif by == "alertId":
            primary = m.alertId
        elif by == "reasoningId":
            primary = m.reasoningId
        else:  # createdAt
            primary = m.createdAt
        return (primary, m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Filtering
# ===========================================================================

def filter_cases(
    cases       : List[Case],
    status      : Optional[CaseStatusEnum]   = None,
    priority    : Optional[CasePriorityEnum] = None,
    assigned_to : Optional[str]              = None,
) -> List[Case]:
    """
    Filter cases by one or more criteria (all ANDed together).

    Parameters
    ----------
    status      : keep only cases with this status.
    priority    : keep only cases with this priority.
    assigned_to : keep only cases assigned to this analyst/system.

    Returns
    -------
    New filtered list — input is not mutated.
    """
    result: List[Case] = []
    for c in cases:
        if status      is not None and c.status     != status:
            continue
        if priority    is not None and c.priority   != priority:
            continue
        if assigned_to is not None and c.assignedTo != assigned_to:
            continue
        result.append(c)
    return result


def filter_case_steps(
    cases     : List[Case],
    step_type : Optional[CaseStepTypeEnum] = None,
    assigned_to: Optional[str]             = None,
) -> List[CaseStep]:
    """
    Collect all CaseStep objects across *cases*, optionally filtered.

    Parameters
    ----------
    cases      : list of Case objects to collect steps from.
    step_type  : keep only steps with this stepType.
    assigned_to: keep only steps assigned to this analyst/system.

    Returns
    -------
    New flat list of CaseStep objects — input is not mutated.
    """
    result: List[CaseStep] = []
    for c in cases:
        for s in c.steps:
            if step_type  is not None and s.stepType  != step_type:
                continue
            if assigned_to is not None and s.assignedTo != assigned_to:
                continue
            result.append(s)
    return result


def filter_case_mappings(
    mappings      : List[CaseMapping],
    finding_id    : Optional[str]   = None,
    alert_id      : Optional[str]   = None,
    reasoning_id  : Optional[str]   = None,
    min_confidence: Optional[float] = None,
    max_confidence: Optional[float] = None,
) -> List[CaseMapping]:
    """
    Filter case mappings by one or more criteria (all ANDed together).

    Parameters
    ----------
    finding_id    : keep only mappings with this findingId.
    alert_id      : keep only mappings with this alertId.
    reasoning_id  : keep only mappings with this reasoningId.
    min_confidence: keep mappings with confidence >= min_confidence.
    max_confidence: keep mappings with confidence <= max_confidence.

    Returns
    -------
    New filtered list — input is not mutated.
    """
    result: List[CaseMapping] = []
    for m in mappings:
        if finding_id    is not None and m.findingId   != finding_id:
            continue
        if alert_id      is not None and m.alertId     != alert_id:
            continue
        if reasoning_id  is not None and m.reasoningId != reasoning_id:
            continue
        if min_confidence is not None and m.confidence < min_confidence:
            continue
        if max_confidence is not None and m.confidence > max_confidence:
            continue
        result.append(m)
    return result


# ===========================================================================
# Grouping
# ===========================================================================

def group_cases(
    cases    : List[Case],
    group_by : str = "status",
) -> Dict[str, List[Case]]:
    """
    Group cases by a string attribute.

    Parameters
    ----------
    cases    : list of Case objects.
    group_by : "status" (default) | "priority" | "assignedTo"
               Enum values are unwrapped to their .value string.

    Each group is sorted by caseId ASC for full determinism.

    Returns
    -------
    Dict[str, List[Case]] — each group sorted by caseId ASC.
    """
    groups: Dict[str, List[Case]] = {}
    for c in cases:
        raw = getattr(c, group_by, None)
        key = raw.value if isinstance(raw, (CaseStatusEnum, CasePriorityEnum)) else (
            str(raw) if raw is not None else "unknown"
        )
        groups.setdefault(key, []).append(c)
    return {k: sorted(v, key=lambda c: c.caseId) for k, v in groups.items()}


def group_case_steps(
    cases    : List[Case],
    group_by : str = "stepType",
) -> Dict[str, List[CaseStep]]:
    """
    Group all CaseStep objects from *cases* by a string attribute.

    Parameters
    ----------
    cases    : list of Case objects to collect steps from.
    group_by : "stepType" (default) | "assignedTo"
               Enum values are unwrapped to their .value string.

    Each group is sorted by stepNumber ASC then stepId ASC.

    Returns
    -------
    Dict[str, List[CaseStep]] — each group sorted by stepNumber then stepId.
    """
    groups: Dict[str, List[CaseStep]] = {}
    for c in cases:
        for s in c.steps:
            raw = getattr(s, group_by, None)
            key = raw.value if isinstance(raw, CaseStepTypeEnum) else (
                str(raw) if raw is not None else "unknown"
            )
            groups.setdefault(key, []).append(s)
    return {
        k: sorted(v, key=lambda s: (s.stepNumber, s.stepId))
        for k, v in groups.items()
    }


def group_case_mappings(
    mappings : List[CaseMapping],
    group_by : str = "findingId",
) -> Dict[str, List[CaseMapping]]:
    """
    Group case mappings by a string attribute.

    Parameters
    ----------
    mappings : list of CaseMapping objects.
    group_by : "findingId" (default) | "alertId" | "reasoningId"
               Unknown attribute values fall back to key "unknown".

    Each group is sorted by mappingId ASC.

    Returns
    -------
    Dict[str, List[CaseMapping]] — each group sorted by mappingId ASC.
    """
    groups: Dict[str, List[CaseMapping]] = {}
    for m in mappings:
        raw = getattr(m, group_by, None)
        key = str(raw) if raw is not None else "unknown"
        groups.setdefault(key, []).append(m)
    return {k: sorted(v, key=lambda m: m.mappingId) for k, v in groups.items()}
