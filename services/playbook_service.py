"""
Playbook Engine
===============
Phase A4.4.5 — Deterministic, immutable Playbook record and mapping management
for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model Playbook, PlaybookStep, PlaybookMapping, and PlaybookStatistics as
  immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_playbook_step, build_playbook, build_playbook_mapping,
    build_playbook_statistics.
- Expose validation functions:
    validate_playbook_step, validate_playbook, validate_playbook_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  CVERecord, IOCRecord, MitreTechnique, and ThreatActor objects into Playbook
  references. No AI execution.  No network.  Transform only.

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

from core.constants import PLAYBOOK_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("playbook_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_PLAYBOOK_NS = uuid.UUID("6ba7b880-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class PlaybookSeverityEnum(str, Enum):
    """Playbook severity classification."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class PlaybookStatusEnum(str, Enum):
    """Playbook lifecycle status."""
    DRAFT      = "DRAFT"
    ACTIVE     = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ARCHIVED   = "ARCHIVED"


class PlaybookStepTypeEnum(str, Enum):
    """Playbook step action type classification."""
    MANUAL        = "MANUAL"
    AUTOMATED     = "AUTOMATED"
    VERIFICATION  = "VERIFICATION"
    CONTAINMENT   = "CONTAINMENT"
    ERADICATION   = "ERADICATION"
    RECOVERY      = "RECOVERY"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class PlaybookEngineError(Exception):
    """Base class for all Playbook Engine errors."""


class InvalidPlaybookError(PlaybookEngineError):
    """Raised when a Playbook fails validation."""


class InvalidPlaybookStepError(PlaybookEngineError):
    """Raised when a PlaybookStep fails validation."""


class InvalidPlaybookMappingError(PlaybookEngineError):
    """Raised when a PlaybookMapping fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class PlaybookStep(BaseModel):
    """
    One immutable playbook step record.

    Identity
    --------
    stepKey : SHA256(playbookId + stepNumber)[:32]
    stepId  : UUIDv5(_PLAYBOOK_NS, stepKey)

    Fields
    ------
    stepId             : deterministic UUID derived from stepKey.
    stepKey            : 32-char SHA-256 identity key.
    stepNumber         : 1-based monotonic position in the playbook.
    title              : human-readable step title.
    description        : detailed step instructions.
    stepType           : PlaybookStepTypeEnum — action type classification.
    expectedOutcome    : what successful completion of this step achieves.
    relatedTechniques  : sorted tuple of MITRE ATT&CK technique ID strings.
    relatedCVEs        : sorted tuple of CVE ID strings linked to this step.
    relatedIOCs        : sorted tuple of IOC value strings linked to this step.
    createdAt          : ISO-8601 timestamp (caller-supplied for determinism).
    """
    stepId            : str
    stepKey           : str
    stepNumber        : int
    title             : str
    description       : str
    stepType          : PlaybookStepTypeEnum
    executor          : Optional[str] = None
    expectedOutcome   : str
    relatedTechniques : Tuple[str, ...]
    relatedCVEs       : Tuple[str, ...]
    relatedIOCs       : Tuple[str, ...]
    createdAt         : str
    config            : Optional[Dict[str, Any]] = None

    class Config:
        frozen = True


class Playbook(BaseModel):
    """
    One immutable Playbook record representing a response procedure.

    Identity
    --------
    playbookKey : SHA256(name + severity.value + sorted(stepIds))[:32]
    playbookId  : UUIDv5(_PLAYBOOK_NS, playbookKey)

    Fields
    ------
    playbookId          : deterministic UUID derived from playbookKey.
    playbookKey         : 32-char SHA-256 identity key.
    name                : human-readable playbook name.
    description         : overview of the playbook's purpose and scope.
    severity            : PlaybookSeverityEnum — threat severity this addresses.
    status              : PlaybookStatusEnum — lifecycle status.
    steps               : sorted tuple of PlaybookStep objects (by stepNumber ASC).
    relatedThreatActors : sorted tuple of threat actor name strings.
    relatedCampaigns    : sorted tuple of campaign name strings.
    confidence          : 0.0–100.0 confidence this playbook is appropriate.
    createdAt           : ISO-8601 timestamp (caller-supplied for determinism).
    """
    playbookId          : str
    playbookKey         : str
    name                : str
    description         : str
    severity            : PlaybookSeverityEnum
    status              : PlaybookStatusEnum
    steps               : Tuple[PlaybookStep, ...]
    relatedThreatActors : Tuple[str, ...]
    relatedCampaigns    : Tuple[str, ...]
    confidence          : float
    createdAt           : str

    class Config:
        frozen = True


class PlaybookMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to Playbook objects.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(playbookIds))[:32]
    mappingId          : UUIDv5(_PLAYBOOK_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(playbookIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    mappingFingerprint : deterministic 32-char content fingerprint.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    playbooks          : sorted tuple of Playbook objects linked
                         (sorted by severity DESC then playbookId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    mappingFingerprint : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    playbooks          : Tuple[Playbook, ...]
    confidence         : float
    createdAt          : str

    class Config:
        frozen = True


class PlaybookStatistics(BaseModel):
    """
    Aggregate statistics over a collection of Playbook objects.

    Fields
    ------
    totalPlaybooks      : total count of distinct playbooks.
    activePlaybooks     : count of playbooks with status == ACTIVE.
    draftPlaybooks      : count of playbooks with status == DRAFT.
    deprecatedPlaybooks : count of playbooks with status == DEPRECATED.
    archivedPlaybooks   : count of playbooks with status == ARCHIVED.
    averageConfidence   : mean playbook.confidence across all playbooks (0.0 if empty).
    averageSteps        : mean step count per playbook (0.0 if empty).
    severityCounts      : dict mapping PlaybookSeverityEnum.value → count.
    statusCounts        : dict mapping PlaybookStatusEnum.value → count.
    """
    totalPlaybooks      : int
    activePlaybooks     : int
    draftPlaybooks      : int
    deprecatedPlaybooks : int
    archivedPlaybooks   : int
    averageConfidence   : float
    averageSteps        : float
    severityCounts      : Dict[str, int]
    statusCounts        : Dict[str, int]

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
    """UUIDv5(_PLAYBOOK_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_PLAYBOOK_NS, key))


def _norm(s: str) -> str:
    """Strip a string; return empty string if None."""
    return s.strip() if s else ""


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings (case-preserved)."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _norm_upper_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, uppercase, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip().upper() for s in items if s and s.strip()}))


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


# ---------------------------------------------------------------------------
# Severity-based sort order (for deterministic playbook ordering)
# ---------------------------------------------------------------------------
_SEVERITY_ORDER: Dict[PlaybookSeverityEnum, int] = {
    PlaybookSeverityEnum.CRITICAL : 4,
    PlaybookSeverityEnum.HIGH     : 3,
    PlaybookSeverityEnum.MEDIUM   : 2,
    PlaybookSeverityEnum.LOW      : 1,
}


# ---------------------------------------------------------------------------
# Public key derivation functions (named per spec)
# ---------------------------------------------------------------------------

def stepKey(playbook_id: str, step_number: int) -> str:
    """
    stepKey = SHA256(playbookId + stepNumber)[:32]

    Same (playbookId, stepNumber) pair always produces the same key.
    """
    return _sha256_32(playbook_id.strip(), str(step_number))


def playbookKey(name: str, severity: PlaybookSeverityEnum, step_ids: Tuple[str, ...]) -> str:
    """
    playbookKey = SHA256(name + severity.value + sorted(stepIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    stepIds sorted before joining for order-independence.
    """
    sorted_steps = "\x01".join(sorted(step_ids))
    return _sha256_32(name.strip(), severity.value, sorted_steps)


def mappingKey(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    playbook_ids: Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(playbookIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    playbookIds sorted before joining for order-independence.
    """
    sorted_ids = "\x01".join(sorted(playbook_ids))
    return _sha256_32(
        finding_id.strip(),
        alert_id.strip(),
        reasoning_id.strip(),
        sorted_ids,
    )


def mappingFingerprint(
    m_key       : str,
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    playbook_ids: Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(playbookIds))[:32]
    """
    sorted_ids = "\x01".join(sorted(playbook_ids))
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

def validate_playbook_step(
    step_number : int,
    title       : str,
    step_type   : PlaybookStepTypeEnum,
    created_at  : str,
) -> None:
    """
    Validate PlaybookStep construction parameters.

    Checks
    ------
    - step_number is a positive integer (>= 1).
    - title is non-empty.
    - step_type is a valid PlaybookStepTypeEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidPlaybookStepError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(step_number, int) or step_number < 1:
        errors.append(
            f"stepNumber={step_number!r} must be a positive integer (>= 1)."
        )
    if not title or not title.strip():
        errors.append("title must not be empty.")
    if not isinstance(step_type, PlaybookStepTypeEnum):
        errors.append(
            f"stepType must be a PlaybookStepTypeEnum member; got {step_type!r}."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_playbook_step", "errors": errors},
        )
        raise InvalidPlaybookStepError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_playbook(
    name       : str,
    severity   : PlaybookSeverityEnum,
    status     : PlaybookStatusEnum,
    created_at : str,
) -> None:
    """
    Validate Playbook construction parameters.

    Checks
    ------
    - name is non-empty.
    - severity is a valid PlaybookSeverityEnum member.
    - status is a valid PlaybookStatusEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidPlaybookError : if any rule is violated.
    """
    errors: List[str] = []

    if not name or not name.strip():
        errors.append("name must not be empty.")
    if not isinstance(severity, PlaybookSeverityEnum):
        errors.append(
            f"severity must be a PlaybookSeverityEnum member; got {severity!r}."
        )
    if not isinstance(status, PlaybookStatusEnum):
        errors.append(
            f"status must be a PlaybookStatusEnum member; got {status!r}."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_playbook", "errors": errors},
        )
        raise InvalidPlaybookError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_playbook_mapping(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    confidence  : float,
    created_at  : str,
) -> None:
    """
    Validate PlaybookMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidPlaybookMappingError : if any rule is violated.
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
            extra={"validator": "validate_playbook_mapping", "errors": errors},
        )
        raise InvalidPlaybookMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_playbook_step()
# ===========================================================================

def build_playbook_step(
    playbook_id        : str,
    step_number        : int,
    title              : str,
    step_type          : PlaybookStepTypeEnum,
    created_at         : str,
    description        : str                = "",
    executor           : Optional[str]      = None,
    expected_outcome   : str                = "",
    related_techniques : Optional[List[str]] = None,
    related_cves       : Optional[List[str]] = None,
    related_iocs       : Optional[List[str]] = None,
    validate           : bool               = True,
    config             : Optional[Dict[str, Any]] = None,
) -> PlaybookStep:
    """
    Build an immutable PlaybookStep.

    stepKey = SHA256(playbookId + stepNumber)[:32]
    stepId  = UUIDv5(_PLAYBOOK_NS, stepKey)

    Parameters
    ----------
    playbook_id        : ID of the parent Playbook (used to scope step identity).
    step_number        : 1-based position in the playbook (must be >= 1).
    title              : human-readable step title (must be non-empty).
    step_type          : PlaybookStepTypeEnum — action type classification.
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    description        : detailed step instructions (may be empty).
    expected_outcome   : what successful completion achieves (may be empty).
    related_techniques : MITRE ATT&CK technique ID strings
                         (deduped + uppercase + sorted).
    related_cves       : CVE ID strings linked to this step
                         (deduped + uppercase + sorted).
    related_iocs       : IOC value strings linked to this step
                         (deduped + stripped + sorted, case-preserved).
    validate           : if True, run validate_playbook_step() first.

    Returns
    -------
    PlaybookStep (frozen / immutable)

    Raises
    ------
    InvalidPlaybookStepError : if validate=True and step validation fails.
    """
    if validate:
        validate_playbook_step(step_number, title, step_type, created_at)

    s_key = stepKey(playbook_id, step_number)
    s_id  = _uuid5(s_key)

    return PlaybookStep(
        stepId            = s_id,
        stepKey           = s_key,
        stepNumber        = step_number,
        title             = title.strip(),
        description       = description,
        stepType          = step_type,
        executor          = executor,
        expectedOutcome   = expected_outcome,
        relatedTechniques = _norm_upper_strings(related_techniques),
        relatedCVEs       = _norm_upper_strings(related_cves),
        relatedIOCs       = _norm_strings(related_iocs),
        createdAt         = created_at,
        config            = config,
    )


# ===========================================================================
# Builder: build_playbook()
# ===========================================================================

def build_playbook(
    name                 : str,
    severity             : PlaybookSeverityEnum,
    created_at           : str,
    description          : str                      = "",
    status               : PlaybookStatusEnum       = PlaybookStatusEnum.DRAFT,
    steps                : Optional[List[PlaybookStep]] = None,
    related_threat_actors: Optional[List[str]]      = None,
    related_campaigns    : Optional[List[str]]      = None,
    confidence           : float                    = 0.0,
    validate             : bool                     = True,
) -> Playbook:
    """
    Build an immutable Playbook.

    playbookKey = SHA256(name + severity.value + sorted(stepIds))[:32]
    playbookId  = UUIDv5(_PLAYBOOK_NS, playbookKey)

    Parameters
    ----------
    name                  : human-readable playbook name (must be non-empty).
    severity              : PlaybookSeverityEnum — threat severity this addresses.
    created_at            : ISO-8601 timestamp (caller-supplied for determinism).
    description           : overview of the playbook's purpose (may be empty).
    status                : PlaybookStatusEnum — lifecycle status (default DRAFT).
    steps                 : list of PlaybookStep objects (sorted by stepNumber ASC).
    related_threat_actors : threat actor name strings (deduped + stripped + sorted).
    related_campaigns     : campaign name strings (deduped + stripped + sorted).
    confidence            : 0.0–100.0 confidence this playbook is appropriate (clamped).
    validate              : if True, run validate_playbook() first.

    Returns
    -------
    Playbook (frozen / immutable)

    Raises
    ------
    InvalidPlaybookError : if validate=True and playbook validation fails.
    """
    if validate:
        validate_playbook(name, severity, status, created_at)

    clamped_confidence = _clamp(float(confidence))

    # Sort steps deterministically: stepNumber ASC, then stepId ASC for ties
    sorted_steps: Tuple[PlaybookStep, ...] = tuple(
        sorted(
            steps or [],
            key=lambda s: (s.stepNumber, s.stepId),
        )
    )

    # Collect step IDs for playbookKey derivation
    step_ids: Tuple[str, ...] = tuple(s.stepId for s in sorted_steps)

    p_key = playbookKey(name, severity, step_ids)
    p_id  = _uuid5(p_key)

    return Playbook(
        playbookId          = p_id,
        playbookKey         = p_key,
        name                = name.strip(),
        description         = description,
        severity            = severity,
        status              = status,
        steps               = sorted_steps,
        relatedThreatActors = _norm_strings(related_threat_actors),
        relatedCampaigns    = _norm_strings(related_campaigns),
        confidence          = round(clamped_confidence, 4),
        createdAt           = created_at,
    )


# ===========================================================================
# Builder: build_playbook_mapping()
# ===========================================================================

def build_playbook_mapping(
    playbooks    : List[Playbook],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> PlaybookMapping:
    """
    Build an immutable PlaybookMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(playbookIds))[:32]
    mappingId          = UUIDv5(_PLAYBOOK_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(playbookIds))[:32]

    Parameters
    ----------
    playbooks    : list of Playbook objects to link in this mapping.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_playbook_mapping() first.

    Returns
    -------
    PlaybookMapping (frozen / immutable)

    Raises
    ------
    InvalidPlaybookMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_playbook_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: severity DESC (CRITICAL first), then playbookId ASC
    sorted_playbooks: Tuple[Playbook, ...] = tuple(
        sorted(
            playbooks or [],
            key=lambda p: (-_SEVERITY_ORDER.get(p.severity, 0), p.playbookId),
        )
    )

    # Collect playbook IDs for key computation
    p_ids: Tuple[str, ...] = tuple(p.playbookId for p in sorted_playbooks)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, p_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(m_key, finding_id, alert_id, reasoning_id, p_ids)

    return PlaybookMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        mappingFingerprint = m_fp,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        playbooks          = sorted_playbooks,
        confidence         = round(clamped_conf, 4),
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_playbook_statistics()
# ===========================================================================

def build_playbook_statistics(
    playbooks: List[Playbook],
) -> PlaybookStatistics:
    """
    Compute PlaybookStatistics over a flat list of Playbook objects.

    Deterministic: canonical sort (by playbookId ASC) before accumulation
    so floating-point sums and counts are identical across every run.

    Deduplication is by playbookId — first occurrence in sorted order wins.

    Parameters
    ----------
    playbooks : any list of Playbook objects (may contain duplicates).

    Returns
    -------
    PlaybookStatistics (frozen / immutable)
    """
    if not playbooks:
        return PlaybookStatistics(
            totalPlaybooks      = 0,
            activePlaybooks     = 0,
            draftPlaybooks      = 0,
            deprecatedPlaybooks = 0,
            archivedPlaybooks   = 0,
            averageConfidence   = 0.0,
            averageSteps        = 0.0,
            severityCounts      = {},
            statusCounts        = {},
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(playbooks, key=lambda p: p.playbookId)

    # Deduplicate by playbookId (first occurrence wins)
    seen_ids: Dict[str, Playbook] = {}
    for p in ordered:
        if p.playbookId not in seen_ids:
            seen_ids[p.playbookId] = p

    distinct = list(seen_ids.values())
    # Re-sort after dedup for deterministic counting
    distinct.sort(key=lambda p: p.playbookId)

    total      = len(distinct)
    active     = sum(1 for p in distinct if p.status == PlaybookStatusEnum.ACTIVE)
    draft      = sum(1 for p in distinct if p.status == PlaybookStatusEnum.DRAFT)
    deprecated = sum(1 for p in distinct if p.status == PlaybookStatusEnum.DEPRECATED)
    archived   = sum(1 for p in distinct if p.status == PlaybookStatusEnum.ARCHIVED)

    avg_conf = (
        round(sum(p.confidence for p in distinct) / total, 4)
        if total > 0 else 0.0
    )
    avg_steps = (
        round(sum(len(p.steps) for p in distinct) / total, 4)
        if total > 0 else 0.0
    )

    # Severity counts — iterate enum in declaration order for determinism
    severity_counts: Dict[str, int] = {}
    for sev in PlaybookSeverityEnum:
        count = sum(1 for p in distinct if p.severity == sev)
        if count > 0:
            severity_counts[sev.value] = count

    # Status counts — iterate enum in declaration order for determinism
    status_counts: Dict[str, int] = {}
    for st in PlaybookStatusEnum:
        count = sum(1 for p in distinct if p.status == st)
        if count > 0:
            status_counts[st.value] = count

    return PlaybookStatistics(
        totalPlaybooks      = total,
        activePlaybooks     = active,
        draftPlaybooks      = draft,
        deprecatedPlaybooks = deprecated,
        archivedPlaybooks   = archived,
        averageConfidence   = avg_conf,
        averageSteps        = avg_steps,
        severityCounts      = severity_counts,
        statusCounts        = status_counts,
    )


# ===========================================================================
# Integration Helpers
# ===========================================================================
# Pure transformation helpers. Accept objects from other engine services and
# return Playbook-relevant reference strings or PlaybookMapping objects.
# No external lookups. No AI execution. No network. Duck-typed inputs to
# avoid import cycles with other service modules.
# ===========================================================================

def mitre_to_playbook_reference(technique: Any) -> str:
    """
    Extract a MITRE ATT&CK technique reference string from a MitreTechnique
    object for use in PlaybookStep.relatedTechniques.

    Rules
    -----
    - Returns technique.mitreId (uppercase, stripped).
    - Falls back to technique.techniqueId if mitreId is unavailable.
    - Returns empty string if neither attribute is present.

    Parameters
    ----------
    technique : MitreTechnique object from mitre_attack_service (duck-typed).

    Returns
    -------
    str — technique reference string (uppercase mitreId), or "" if unavailable.
    """
    mitre_id = getattr(technique, "mitreId", None)
    if mitre_id and str(mitre_id).strip():
        return str(mitre_id).strip().upper()
    tech_id = getattr(technique, "techniqueId", None)
    if tech_id and str(tech_id).strip():
        return str(tech_id).strip()
    return ""


def cve_to_playbook_reference(cve_record: Any) -> str:
    """
    Extract a CVE reference string from a CVERecord object for use in
    PlaybookStep.relatedCVEs.

    Rules
    -----
    - Returns cve_record.cveId (uppercase, stripped).
    - Falls back to cve_record.recordId if cveId is unavailable.
    - Returns empty string if neither attribute is present.

    Parameters
    ----------
    cve_record : CVERecord object from cve_intelligence_service (duck-typed).

    Returns
    -------
    str — CVE reference string (uppercase cveId), or "" if unavailable.
    """
    cve_id = getattr(cve_record, "cveId", None)
    if cve_id and str(cve_id).strip():
        return str(cve_id).strip().upper()
    record_id = getattr(cve_record, "recordId", None)
    if record_id and str(record_id).strip():
        return str(record_id).strip()
    return ""


def ioc_to_playbook_reference(ioc_record: Any) -> str:
    """
    Extract an IOC reference string from an IOCRecord object for use in
    PlaybookStep.relatedIOCs.

    Rules
    -----
    - Returns ioc_record.value (stripped, case-preserved).
    - Falls back to ioc_record.iocId if value is unavailable.
    - Returns empty string if neither attribute is present.

    Parameters
    ----------
    ioc_record : IOCRecord object from ioc_intelligence_service (duck-typed).

    Returns
    -------
    str — IOC value string (stripped), or "" if unavailable.
    """
    value = getattr(ioc_record, "value", None)
    if value and str(value).strip():
        return str(value).strip()
    ioc_id = getattr(ioc_record, "iocId", None)
    if ioc_id and str(ioc_id).strip():
        return str(ioc_id).strip()
    return ""


def threat_to_playbook_reference(threat_actor: Any) -> str:
    """
    Extract a threat actor reference string from a ThreatActor object for
    use in Playbook.relatedThreatActors.

    Rules
    -----
    - Returns threat_actor.name (stripped, case-preserved).
    - Falls back to threat_actor.actorId if name is unavailable.
    - Returns empty string if neither attribute is present.

    Parameters
    ----------
    threat_actor : ThreatActor object from threat_intelligence_service (duck-typed).

    Returns
    -------
    str — threat actor name string (stripped), or "" if unavailable.
    """
    name = getattr(threat_actor, "name", None)
    if name and str(name).strip():
        return str(name).strip()
    actor_id = getattr(threat_actor, "actorId", None)
    if actor_id and str(actor_id).strip():
        return str(actor_id).strip()
    return ""


def finding_to_playbook_mapping(
    finding    : Any,
    playbooks  : List[Playbook],
    created_at : str,
    confidence : float = 0.0,
    validate   : bool  = True,
) -> PlaybookMapping:
    """
    Convert a Finding (from finding_service) into a PlaybookMapping.

    Rules
    -----
    - findingId   = finding.findingId
    - alertId     = "" (no alert source)
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    finding    : Finding object from finding_service (duck-typed).
    playbooks  : list of Playbook objects to map.
    created_at : ISO-8601 timestamp.
    confidence : 0.0–100.0 caller-assessed confidence.
    validate   : if True, run validate_playbook_mapping().

    Returns
    -------
    PlaybookMapping (frozen / immutable)
    """
    _log.debug(
        "finding_to_playbook_mapping",
        extra={
            "findingId"    : finding.findingId,
            "playbookCount": len(playbooks),
        },
    )
    return build_playbook_mapping(
        playbooks    = playbooks,
        created_at   = created_at,
        finding_id   = finding.findingId,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def alert_to_playbook_mapping(
    alert      : Any,
    playbooks  : List[Playbook],
    created_at : str,
    confidence : float = 0.0,
    validate   : bool  = True,
) -> PlaybookMapping:
    """
    Convert an Alert (from alert_service) into a PlaybookMapping.

    Rules
    -----
    - findingId   = alert.findingId  (Alert always has a source findingId)
    - alertId     = alert.alertId
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    alert      : Alert object from alert_service (duck-typed).
    playbooks  : list of Playbook objects to map.
    created_at : ISO-8601 timestamp.
    confidence : 0.0–100.0 caller-assessed confidence.
    validate   : if True, run validate_playbook_mapping().

    Returns
    -------
    PlaybookMapping (frozen / immutable)
    """
    _log.debug(
        "alert_to_playbook_mapping",
        extra={
            "alertId"      : alert.alertId,
            "findingId"    : alert.findingId,
            "playbookCount": len(playbooks),
        },
    )
    return build_playbook_mapping(
        playbooks    = playbooks,
        created_at   = created_at,
        finding_id   = alert.findingId,
        alert_id     = alert.alertId,
        reasoning_id = "",
        confidence   = confidence,
        validate     = validate,
    )


def reasoning_to_playbook_mapping(
    reasoning  : Any,
    playbooks  : List[Playbook],
    created_at : str,
    finding_id : str  = "",
    alert_id   : str  = "",
    validate   : bool = True,
) -> PlaybookMapping:
    """
    Convert a ReasoningResult (from reasoning_service) into a PlaybookMapping.

    Rules
    -----
    - reasoningId = reasoning.reasoningId
    - confidence  = reasoning.overallConfidence (already 0–100)
    - findingId and alertId are optional caller-supplied context linkages.

    Parameters
    ----------
    reasoning  : ReasoningResult object from reasoning_service (duck-typed).
    playbooks  : list of Playbook objects to map.
    created_at : ISO-8601 timestamp.
    finding_id : optional finding ID for context linkage (may be empty).
    alert_id   : optional alert ID for context linkage (may be empty).
    validate   : if True, run validate_playbook_mapping().

    Returns
    -------
    PlaybookMapping (frozen / immutable)
    """
    _log.debug(
        "reasoning_to_playbook_mapping",
        extra={
            "reasoningId"  : reasoning.reasoningId,
            "confidence"   : reasoning.overallConfidence,
            "playbookCount": len(playbooks),
        },
    )
    return build_playbook_mapping(
        playbooks    = playbooks,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = reasoning.reasoningId,
        confidence   = reasoning.overallConfidence,
        validate     = validate,
    )


# ===========================================================================
# Part B — Operations, Search, Sort, Filter, Group, Extended Statistics
# ===========================================================================


# ---------------------------------------------------------------------------
# Internal rebuild helper — reconstruct a Playbook with a new step list.
# ID is recomputed because step composition changed.
# ---------------------------------------------------------------------------

def _rebuild_playbook_with_steps(
    playbook   : Playbook,
    new_steps  : List[PlaybookStep],
    updated_at : str = "",
) -> Playbook:
    """Return a new Playbook whose steps tuple is replaced by *new_steps*.

    playbookKey / playbookId are recomputed because step composition changed.
    All other fields are preserved verbatim.
    updated_at is not stored on the model but used for logging context only.
    """
    sorted_steps: Tuple[PlaybookStep, ...] = tuple(
        sorted(new_steps, key=lambda s: (s.stepNumber, s.stepId))
    )
    step_ids: Tuple[str, ...] = tuple(s.stepId for s in sorted_steps)
    p_key = playbookKey(playbook.name, playbook.severity, step_ids)
    p_id  = _uuid5(p_key)
    return Playbook(
        playbookId          = p_id,
        playbookKey         = p_key,
        name                = playbook.name,
        description         = playbook.description,
        severity            = playbook.severity,
        status              = playbook.status,
        steps               = sorted_steps,
        relatedThreatActors = playbook.relatedThreatActors,
        relatedCampaigns    = playbook.relatedCampaigns,
        confidence          = playbook.confidence,
        createdAt           = playbook.createdAt,
    )


# ===========================================================================
# Playbook Operations
# ===========================================================================

def add_playbook(
    playbooks  : List[Playbook],
    playbook   : Playbook,
) -> List[Playbook]:
    """
    Add *playbook* to *playbooks*, skipping it if a playbook with the same
    playbookId already exists (idempotent, duplicate-safe).

    Returns a new sorted list (playbookId ASC).  Input list is not mutated.
    """
    existing_ids = {p.playbookId for p in playbooks}
    if playbook.playbookId in existing_ids:
        _log.debug(
            "playbook_add_skipped_duplicate",
            extra={"playbookId": playbook.playbookId},
        )
        return sorted(playbooks, key=lambda p: p.playbookId)
    result = playbooks + [playbook]
    _log.info(
        "playbook_created",
        extra={"playbookId": playbook.playbookId, "playbookName": playbook.name},
    )
    return sorted(result, key=lambda p: p.playbookId)


def update_playbook(
    playbooks            : List[Playbook],
    playbook_id          : str,
    updated_at           : str,
    name                 : Optional[str]                  = None,
    description          : Optional[str]                  = None,
    severity             : Optional[PlaybookSeverityEnum] = None,
    status               : Optional[PlaybookStatusEnum]   = None,
    confidence           : Optional[float]                = None,
    related_threat_actors: Optional[List[str]]            = None,
    related_campaigns    : Optional[List[str]]            = None,
) -> List[Playbook]:
    """
    Return a new list where the playbook matching *playbook_id* is replaced
    by a new instance with supplied fields changed.

    Rules
    -----
    - None arguments keep the existing value.
    - playbookKey / playbookId are recomputed only when name or severity changes.
    - steps are preserved unchanged.
    - If no playbook matches *playbook_id* the list is returned unchanged.
    - Input list is not mutated.

    Returns sorted list (playbookId ASC).
    """
    result: List[Playbook] = []
    found = False
    for p in playbooks:
        if p.playbookId != playbook_id:
            result.append(p)
            continue
        found = True
        new_name     = name.strip()     if name     is not None else p.name
        new_desc     = description      if description is not None else p.description
        new_sev      = severity         if severity  is not None else p.severity
        new_status   = status           if status    is not None else p.status
        new_conf     = _clamp(float(confidence)) if confidence is not None else p.confidence
        new_actors   = _norm_strings(related_threat_actors) if related_threat_actors is not None else p.relatedThreatActors
        new_campaigns= _norm_strings(related_campaigns)     if related_campaigns    is not None else p.relatedCampaigns

        # Recompute key only when identity-affecting fields change
        if new_name != p.name or new_sev != p.severity:
            step_ids: Tuple[str, ...] = tuple(s.stepId for s in p.steps)
            p_key = playbookKey(new_name, new_sev, step_ids)
            p_id  = _uuid5(p_key)
        else:
            p_key = p.playbookKey
            p_id  = p.playbookId

        updated = Playbook(
            playbookId          = p_id,
            playbookKey         = p_key,
            name                = new_name,
            description         = new_desc,
            severity            = new_sev,
            status              = new_status,
            steps               = p.steps,
            relatedThreatActors = new_actors,
            relatedCampaigns    = new_campaigns,
            confidence          = round(new_conf, 4),
            createdAt           = p.createdAt,
        )
        result.append(updated)
        _log.info(
            "playbook_updated",
            extra={"playbookId": p_id, "originalId": playbook_id},
        )

    if not found:
        _log.debug(
            "playbook_update_not_found",
            extra={"playbookId": playbook_id},
        )
    return sorted(result, key=lambda p: p.playbookId)


def remove_playbook(
    playbooks  : List[Playbook],
    playbook_id: str,
) -> List[Playbook]:
    """
    Return a new list with the playbook matching *playbook_id* removed.

    If no playbook matches, the list is returned unchanged (idempotent).
    Input list is not mutated.  Returns sorted list (playbookId ASC).
    """
    result = [p for p in playbooks if p.playbookId != playbook_id]
    if len(result) < len(playbooks):
        _log.info(
            "playbook_removed",
            extra={"playbookId": playbook_id},
        )
    return sorted(result, key=lambda p: p.playbookId)


def merge_playbooks(
    base     : List[Playbook],
    incoming : List[Playbook],
) -> List[Playbook]:
    """
    Merge *incoming* playbooks into *base*.

    Rules
    -----
    - Duplicate detection by playbookId — if an incoming playbook already
      exists in base, the base version wins (base takes priority).
    - New playbookIds from incoming are appended.
    - IDs are preserved; no new IDs are generated.
    - Result is sorted by playbookId ASC for determinism.
    - Zero randomness.

    Parameters
    ----------
    base     : authoritative list of Playbook objects.
    incoming : playbooks to merge in.

    Returns
    -------
    New merged, sorted list (input lists not mutated).
    """
    seen: Dict[str, Playbook] = {p.playbookId: p for p in base}
    for p in incoming:
        if p.playbookId not in seen:
            seen[p.playbookId] = p
    result = sorted(seen.values(), key=lambda p: p.playbookId)
    _log.info(
        "merge_completed",
        extra={
            "operation"     : "merge_playbooks",
            "baseCount"     : len(base),
            "incomingCount" : len(incoming),
            "resultCount"   : len(result),
        },
    )
    return result


# ===========================================================================
# Step Operations
# ===========================================================================

def add_playbook_step(
    playbook   : Playbook,
    step       : PlaybookStep,
) -> Playbook:
    """
    Return a new Playbook with *step* added to its steps.

    Rules
    -----
    - If a step with the same stepId already exists, the original playbook
      is returned unchanged (idempotent).
    - playbookKey / playbookId are recomputed because step composition changed.
    - steps are re-sorted by stepNumber ASC, then stepId ASC.

    Returns new Playbook (immutable).  Input is not mutated.
    """
    existing_ids = {s.stepId for s in playbook.steps}
    if step.stepId in existing_ids:
        _log.debug(
            "step_add_skipped_duplicate",
            extra={"stepId": step.stepId, "playbookId": playbook.playbookId},
        )
        return playbook
    new_steps = list(playbook.steps) + [step]
    result = _rebuild_playbook_with_steps(playbook, new_steps)
    _log.info(
        "step_created",
        extra={
            "stepId"     : step.stepId,
            "stepNumber" : step.stepNumber,
            "playbookId" : result.playbookId,
        },
    )
    return result


def update_playbook_step(
    playbook        : Playbook,
    step_id         : str,
    title           : Optional[str]               = None,
    description     : Optional[str]               = None,
    step_type       : Optional[PlaybookStepTypeEnum] = None,
    executor        : Optional[str]               = None,
    expected_outcome: Optional[str]               = None,
    related_techniques: Optional[List[str]]       = None,
    related_cves    : Optional[List[str]]         = None,
    related_iocs    : Optional[List[str]]         = None,
    config          : Optional[Dict[str, Any]]    = None,
) -> Playbook:
    """
    Return a new Playbook where the step matching *step_id* has updated fields.

    Rules
    -----
    - None arguments keep the existing value.
    - stepKey / stepId are never recomputed — identity is stable.
    - If no step matches *step_id*, the playbook is returned unchanged.
    - playbookKey / playbookId are NOT recomputed when only step content
      changes (keys derive from step identity, not content).

    Returns new Playbook (immutable).  Input is not mutated.
    """
    new_steps: List[PlaybookStep] = []
    found = False
    for s in playbook.steps:
        if s.stepId != step_id:
            new_steps.append(s)
            continue
        found = True
        updated_step = PlaybookStep(
            stepId            = s.stepId,
            stepKey           = s.stepKey,
            stepNumber        = s.stepNumber,
            title             = title.strip() if title is not None else s.title,
            description       = description   if description is not None else s.description,
            stepType          = step_type     if step_type  is not None else s.stepType,
            executor          = executor      if executor   is not None else s.executor,
            expectedOutcome   = expected_outcome if expected_outcome is not None else s.expectedOutcome,
            relatedTechniques = _norm_upper_strings(related_techniques) if related_techniques is not None else s.relatedTechniques,
            relatedCVEs       = _norm_upper_strings(related_cves)       if related_cves       is not None else s.relatedCVEs,
            relatedIOCs       = _norm_strings(related_iocs)             if related_iocs       is not None else s.relatedIOCs,
            createdAt         = s.createdAt,
            config            = config                                  if config             is not None else s.config,
        )
        new_steps.append(updated_step)
        _log.info(
            "step_updated",
            extra={"stepId": step_id, "playbookId": playbook.playbookId},
        )

    if not found:
        _log.debug(
            "step_update_not_found",
            extra={"stepId": step_id, "playbookId": playbook.playbookId},
        )
        return playbook

    # step content changed but identity (stepId) unchanged →
    # playbookKey stays the same since it depends only on step IDs
    sorted_steps = tuple(sorted(new_steps, key=lambda s: (s.stepNumber, s.stepId)))
    return Playbook(
        playbookId          = playbook.playbookId,
        playbookKey         = playbook.playbookKey,
        name                = playbook.name,
        description         = playbook.description,
        severity            = playbook.severity,
        status              = playbook.status,
        steps               = sorted_steps,
        relatedThreatActors = playbook.relatedThreatActors,
        relatedCampaigns    = playbook.relatedCampaigns,
        confidence          = playbook.confidence,
        createdAt           = playbook.createdAt,
    )


def remove_playbook_step(
    playbook : Playbook,
    step_id  : str,
) -> Playbook:
    """
    Return a new Playbook with the step matching *step_id* removed.

    Rules
    -----
    - playbookKey / playbookId are recomputed because step composition changed.
    - If no step matches, the original playbook is returned unchanged (idempotent).

    Returns new Playbook (immutable).  Input is not mutated.
    """
    new_steps = [s for s in playbook.steps if s.stepId != step_id]
    if len(new_steps) == len(playbook.steps):
        _log.debug(
            "step_remove_not_found",
            extra={"stepId": step_id, "playbookId": playbook.playbookId},
        )
        return playbook
    result = _rebuild_playbook_with_steps(playbook, new_steps)
    _log.info(
        "step_removed",
        extra={"stepId": step_id, "playbookId": result.playbookId},
    )
    return result


def merge_playbook_steps(
    playbook : Playbook,
    steps    : List[PlaybookStep],
) -> Playbook:
    """
    Merge *steps* into *playbook.steps*.

    Rules
    -----
    - Duplicate detection by stepId — existing steps win (base takes priority).
    - New stepIds from *steps* are appended.
    - playbookKey / playbookId are recomputed if any new step was added.
    - If no new steps, the original playbook is returned unchanged (idempotent).
    - Result steps sorted by stepNumber ASC, then stepId ASC.

    Returns new Playbook (immutable).  Input is not mutated.
    """
    existing: Dict[str, PlaybookStep] = {s.stepId: s for s in playbook.steps}
    added = False
    for s in steps:
        if s.stepId not in existing:
            existing[s.stepId] = s
            added = True
    if not added:
        return playbook
    result = _rebuild_playbook_with_steps(playbook, list(existing.values()))
    _log.info(
        "merge_completed",
        extra={
            "operation"  : "merge_playbook_steps",
            "playbookId" : result.playbookId,
            "stepCount"  : len(result.steps),
        },
    )
    return result


# ===========================================================================
# Mapping Operations
# ===========================================================================

def add_playbook_mapping(
    mappings : List[PlaybookMapping],
    mapping  : PlaybookMapping,
) -> List[PlaybookMapping]:
    """
    Add *mapping* to *mappings*, skipping it if a mapping with the same
    mappingId already exists (idempotent, duplicate-safe).

    Returns a new sorted list (mappingId ASC).  Input list is not mutated.
    """
    existing_ids = {m.mappingId for m in mappings}
    if mapping.mappingId in existing_ids:
        _log.debug(
            "mapping_add_skipped_duplicate",
            extra={"mappingId": mapping.mappingId},
        )
        return sorted(mappings, key=lambda m: m.mappingId)
    result = mappings + [mapping]
    _log.info(
        "mapping_created",
        extra={"mappingId": mapping.mappingId},
    )
    return sorted(result, key=lambda m: m.mappingId)


def remove_playbook_mapping(
    mappings  : List[PlaybookMapping],
    mapping_id: str,
) -> List[PlaybookMapping]:
    """
    Return a new list with the mapping matching *mapping_id* removed.

    If no mapping matches, the list is returned unchanged (idempotent).
    Input list is not mutated.  Returns sorted list (mappingId ASC).
    """
    result = [m for m in mappings if m.mappingId != mapping_id]
    return sorted(result, key=lambda m: m.mappingId)


def merge_playbook_mappings(
    base     : List[PlaybookMapping],
    incoming : List[PlaybookMapping],
) -> List[PlaybookMapping]:
    """
    Merge *incoming* mappings into *base*.

    Rules
    -----
    - Duplicate detection by mappingId — base version wins.
    - New mappingIds from incoming are appended.
    - IDs and fingerprints are preserved; no new IDs generated.
    - Result sorted by mappingId ASC.

    Returns new merged, sorted list (input lists not mutated).
    """
    seen: Dict[str, PlaybookMapping] = {m.mappingId: m for m in base}
    for m in incoming:
        if m.mappingId not in seen:
            seen[m.mappingId] = m
    result = sorted(seen.values(), key=lambda m: m.mappingId)
    _log.info(
        "merge_completed",
        extra={
            "operation"     : "merge_playbook_mappings",
            "baseCount"     : len(base),
            "incomingCount" : len(incoming),
            "resultCount"   : len(result),
        },
    )
    return result


# ===========================================================================
# Search Utilities
# ===========================================================================

def find_playbook(
    playbooks : List[Playbook],
    playbook_id: Optional[str] = None,
    playbook_key: Optional[str] = None,
) -> Optional[Playbook]:
    """
    Find a Playbook by playbookId or playbookKey.

    Parameters
    ----------
    playbooks    : list of Playbook objects to search.
    playbook_id  : exact playbookId to match (checked first).
    playbook_key : exact playbookKey to match (checked if playbookId not given).

    Returns first match or None.  Search is O(n).
    """
    if playbook_id:
        for p in playbooks:
            if p.playbookId == playbook_id:
                return p
    if playbook_key:
        for p in playbooks:
            if p.playbookKey == playbook_key:
                return p
    return None


def find_playbook_step(
    playbooks : List[Playbook],
    step_id   : Optional[str] = None,
    step_key  : Optional[str] = None,
) -> Optional[PlaybookStep]:
    """
    Find a PlaybookStep across all playbooks by stepId or stepKey.

    Parameters
    ----------
    playbooks : list of Playbook objects to search.
    step_id   : exact stepId to match (checked first).
    step_key  : exact stepKey to match (checked if step_id not given).

    Returns first match or None.  Search is O(p * s).
    """
    for p in playbooks:
        for s in p.steps:
            if step_id and s.stepId == step_id:
                return s
            if step_key and s.stepKey == step_key:
                return s
    return None


def find_playbook_mapping(
    mappings   : List[PlaybookMapping],
    mapping_id : Optional[str] = None,
) -> Optional[PlaybookMapping]:
    """
    Find a PlaybookMapping by mappingId.

    Parameters
    ----------
    mappings   : list of PlaybookMapping objects to search.
    mapping_id : exact mappingId to match.

    Returns first match or None.
    """
    if mapping_id:
        for m in mappings:
            if m.mappingId == mapping_id:
                return m
    return None


# ===========================================================================
# Sorting
# ===========================================================================

# Canonical severity → integer for sorting (higher = more critical)
_SEV_SORT: Dict[PlaybookSeverityEnum, int] = {
    PlaybookSeverityEnum.CRITICAL : 4,
    PlaybookSeverityEnum.HIGH     : 3,
    PlaybookSeverityEnum.MEDIUM   : 2,
    PlaybookSeverityEnum.LOW      : 1,
}

_STATUS_SORT: Dict[PlaybookStatusEnum, int] = {
    PlaybookStatusEnum.ACTIVE     : 4,
    PlaybookStatusEnum.DRAFT      : 3,
    PlaybookStatusEnum.DEPRECATED : 2,
    PlaybookStatusEnum.ARCHIVED   : 1,
}

_VALID_PLAYBOOK_SORT_KEYS = frozenset({"name", "severity", "status", "confidence", "createdAt"})
_VALID_STEP_SORT_KEYS     = frozenset({"stepNumber", "title", "stepType", "createdAt"})
_VALID_MAPPING_SORT_KEYS  = frozenset({"confidence", "createdAt", "findingId", "alertId"})


def sort_playbooks(
    playbooks : List[Playbook],
    by        : str  = "severity",
    ascending : bool = False,
) -> List[Playbook]:
    """
    Return a new sorted list of Playbook objects.

    Parameters
    ----------
    by        : "severity" | "status" | "name" | "confidence" | "createdAt"
    ascending : False = descending (highest severity first, default)

    Tie-breaking: playbookId ASC for full determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_PLAYBOOK_SORT_KEYS:
        raise ValueError(
            f"sort_playbooks: unknown key '{by}'. Valid: {sorted(_VALID_PLAYBOOK_SORT_KEYS)}"
        )

    def _key(p: Playbook):
        if by == "severity":
            primary = _SEV_SORT.get(p.severity, 0)
        elif by == "status":
            primary = _STATUS_SORT.get(p.status, 0)
        elif by == "confidence":
            primary = p.confidence
        else:
            primary = getattr(p, by, "")
        return (primary, p.playbookId)

    return sorted(playbooks, key=_key, reverse=not ascending)


def sort_playbook_steps(
    steps     : List[PlaybookStep],
    by        : str  = "stepNumber",
    ascending : bool = True,
) -> List[PlaybookStep]:
    """
    Return a new sorted list of PlaybookStep objects.

    Parameters
    ----------
    by        : "stepNumber" | "title" | "stepType" | "createdAt"
    ascending : True = ascending (step 1 first, default)

    Tie-breaking: stepId ASC for full determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_STEP_SORT_KEYS:
        raise ValueError(
            f"sort_playbook_steps: unknown key '{by}'. Valid: {sorted(_VALID_STEP_SORT_KEYS)}"
        )

    def _key(s: PlaybookStep):
        if by == "stepType":
            primary = s.stepType.value
        else:
            primary = getattr(s, by, "")
        return (primary, s.stepId)

    return sorted(steps, key=_key, reverse=not ascending)


def sort_playbook_mappings(
    mappings  : List[PlaybookMapping],
    by        : str  = "confidence",
    ascending : bool = False,
) -> List[PlaybookMapping]:
    """
    Return a new sorted list of PlaybookMapping objects.

    Parameters
    ----------
    by        : "confidence" | "createdAt" | "findingId" | "alertId"
    ascending : False = descending (highest confidence first, default)

    Tie-breaking: mappingId ASC for full determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_MAPPING_SORT_KEYS:
        raise ValueError(
            f"sort_playbook_mappings: unknown key '{by}'. Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: PlaybookMapping):
        return (getattr(m, by, ""), m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Filtering
# ===========================================================================

def filter_playbooks(
    playbooks          : List[Playbook],
    severity           : Optional[PlaybookSeverityEnum] = None,
    status             : Optional[PlaybookStatusEnum]   = None,
    min_confidence     : Optional[float]                = None,
    max_confidence     : Optional[float]                = None,
    technique          : Optional[str]                  = None,
    cve                : Optional[str]                  = None,
    ioc                : Optional[str]                  = None,
    threat_actor       : Optional[str]                  = None,
    campaign           : Optional[str]                  = None,
) -> List[Playbook]:
    """
    Filter Playbook objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    severity       : keep only playbooks with this severity.
    status         : keep only playbooks with this status.
    min_confidence : keep playbooks with confidence >= min_confidence.
    max_confidence : keep playbooks with confidence <= max_confidence.
    technique      : keep playbooks where any step contains this technique ID
                     (case-insensitive prefix/exact match, uppercase normalised).
    cve            : keep playbooks where any step contains this CVE ID
                     (case-insensitive, uppercase normalised).
    ioc            : keep playbooks where any step contains this IOC value
                     (case-sensitive substring match).
    threat_actor   : keep playbooks whose relatedThreatActors contains this
                     string (case-insensitive substring match).
    campaign       : keep playbooks whose relatedCampaigns contains this
                     string (case-insensitive substring match).

    Returns
    -------
    New filtered list (input not mutated).
    """
    result: List[Playbook] = []
    norm_tech    = technique.strip().upper()    if technique    else None
    norm_cve     = cve.strip().upper()          if cve          else None
    norm_ioc     = ioc.strip()                  if ioc          else None
    norm_actor   = threat_actor.strip().lower() if threat_actor else None
    norm_campaign= campaign.strip().lower()     if campaign     else None

    for p in playbooks:
        if severity        is not None and p.severity != severity:
            continue
        if status          is not None and p.status   != status:
            continue
        if min_confidence  is not None and p.confidence < min_confidence:
            continue
        if max_confidence  is not None and p.confidence > max_confidence:
            continue
        if norm_tech is not None:
            if not any(norm_tech in t for s in p.steps for t in s.relatedTechniques):
                continue
        if norm_cve is not None:
            if not any(norm_cve in c for s in p.steps for c in s.relatedCVEs):
                continue
        if norm_ioc is not None:
            if not any(norm_ioc in i for s in p.steps for i in s.relatedIOCs):
                continue
        if norm_actor is not None:
            if not any(norm_actor in a.lower() for a in p.relatedThreatActors):
                continue
        if norm_campaign is not None:
            if not any(norm_campaign in c.lower() for c in p.relatedCampaigns):
                continue
        result.append(p)
    return result


def filter_playbook_steps(
    steps          : List[PlaybookStep],
    step_type      : Optional[PlaybookStepTypeEnum] = None,
    technique      : Optional[str]                  = None,
    cve            : Optional[str]                  = None,
    ioc            : Optional[str]                  = None,
    min_step_number: Optional[int]                  = None,
    max_step_number: Optional[int]                  = None,
) -> List[PlaybookStep]:
    """
    Filter PlaybookStep objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    step_type       : keep only steps with this type.
    technique       : keep steps containing this technique ID (uppercase match).
    cve             : keep steps containing this CVE ID (uppercase match).
    ioc             : keep steps containing this IOC value (substring match).
    min_step_number : keep steps with stepNumber >= min_step_number.
    max_step_number : keep steps with stepNumber <= max_step_number.

    Returns new filtered list (input not mutated).
    """
    norm_tech = technique.strip().upper() if technique else None
    norm_cve  = cve.strip().upper()       if cve       else None
    norm_ioc  = ioc.strip()               if ioc       else None

    result: List[PlaybookStep] = []
    for s in steps:
        if step_type       is not None and s.stepType  != step_type:
            continue
        if min_step_number is not None and s.stepNumber < min_step_number:
            continue
        if max_step_number is not None and s.stepNumber > max_step_number:
            continue
        if norm_tech is not None:
            if not any(norm_tech in t for t in s.relatedTechniques):
                continue
        if norm_cve is not None:
            if not any(norm_cve in c for c in s.relatedCVEs):
                continue
        if norm_ioc is not None:
            if not any(norm_ioc in i for i in s.relatedIOCs):
                continue
        result.append(s)
    return result


def filter_playbook_mappings(
    mappings       : List[PlaybookMapping],
    finding_id     : Optional[str]                  = None,
    alert_id       : Optional[str]                  = None,
    reasoning_id   : Optional[str]                  = None,
    min_confidence : Optional[float]                = None,
    max_confidence : Optional[float]                = None,
    severity       : Optional[PlaybookSeverityEnum] = None,
) -> List[PlaybookMapping]:
    """
    Filter PlaybookMapping objects by one or more criteria (all ANDed together).

    Parameters
    ----------
    finding_id     : keep mappings with this findingId (exact match).
    alert_id       : keep mappings with this alertId (exact match).
    reasoning_id   : keep mappings with this reasoningId (exact match).
    min_confidence : keep mappings with confidence >= min_confidence.
    max_confidence : keep mappings with confidence <= max_confidence.
    severity       : keep mappings that contain at least one playbook with
                     this severity.

    Returns new filtered list (input not mutated).
    """
    result: List[PlaybookMapping] = []
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
        if severity is not None:
            if not any(p.severity == severity for p in m.playbooks):
                continue
        result.append(m)
    return result


# ===========================================================================
# Grouping
# ===========================================================================

def group_playbooks(
    playbooks : List[Playbook],
    group_by  : str = "severity",
) -> Dict[str, List[Playbook]]:
    """
    Group Playbook objects by a string attribute.

    Parameters
    ----------
    playbooks : list of Playbook objects.
    group_by  : "severity" | "status" | "threat_actor" | "campaign"
                Enum values are unwrapped to their .value string.
                For "threat_actor" and "campaign", a playbook may appear
                in multiple groups (one per actor/campaign).
                Unknown attribute values fall back to key "unknown".

    Each group is sorted by playbookId ASC for determinism.

    Returns
    -------
    Dict[str, List[Playbook]] — each group sorted by playbookId ASC.
    """
    groups: Dict[str, List[Playbook]] = {}

    for p in playbooks:
        if group_by == "threat_actor":
            keys = list(p.relatedThreatActors) if p.relatedThreatActors else ["unknown"]
        elif group_by == "campaign":
            keys = list(p.relatedCampaigns) if p.relatedCampaigns else ["unknown"]
        elif group_by == "severity":
            keys = [p.severity.value]
        elif group_by == "status":
            keys = [p.status.value]
        else:
            raw = getattr(p, group_by, None)
            keys = [raw.value if hasattr(raw, "value") else (str(raw) if raw is not None else "unknown")]

        for k in keys:
            groups.setdefault(k, []).append(p)

    return {k: sorted(v, key=lambda p: p.playbookId) for k, v in groups.items()}


def group_playbook_steps(
    steps    : List[PlaybookStep],
    group_by : str = "stepType",
) -> Dict[str, List[PlaybookStep]]:
    """
    Group PlaybookStep objects by a string attribute.

    Parameters
    ----------
    steps    : list of PlaybookStep objects.
    group_by : "stepType" | any PlaybookStep field name.
               Enum values are unwrapped to their .value string.
               Unknown attribute values fall back to key "unknown".

    Each group is sorted by stepNumber ASC, then stepId ASC.

    Returns
    -------
    Dict[str, List[PlaybookStep]]
    """
    groups: Dict[str, List[PlaybookStep]] = {}
    for s in steps:
        raw = getattr(s, group_by, None)
        key = raw.value if hasattr(raw, "value") else (str(raw) if raw is not None else "unknown")
        groups.setdefault(key, []).append(s)
    return {k: sorted(v, key=lambda s: (s.stepNumber, s.stepId)) for k, v in groups.items()}


def group_playbook_mappings(
    mappings : List[PlaybookMapping],
    group_by : str = "severity",
) -> Dict[str, List[PlaybookMapping]]:
    """
    Group PlaybookMapping objects by a derived attribute.

    Parameters
    ----------
    mappings : list of PlaybookMapping objects.
    group_by : "severity" | "status" | "threat_actor" | "campaign"
               For "severity" / "status": groups by the severity/status
               values present in each mapping's playbooks tuple; a mapping
               may appear in multiple groups.
               For "threat_actor" / "campaign": groups by values across all
               playbooks in each mapping.

    Each group is sorted by mappingId ASC.

    Returns
    -------
    Dict[str, List[PlaybookMapping]]
    """
    groups: Dict[str, List[PlaybookMapping]] = {}
    for m in mappings:
        if group_by == "severity":
            keys = sorted({p.severity.value for p in m.playbooks}) if m.playbooks else ["unknown"]
        elif group_by == "status":
            keys = sorted({p.status.value for p in m.playbooks}) if m.playbooks else ["unknown"]
        elif group_by == "threat_actor":
            actors = sorted({a for p in m.playbooks for a in p.relatedThreatActors})
            keys = actors if actors else ["unknown"]
        elif group_by == "campaign":
            camps = sorted({c for p in m.playbooks for c in p.relatedCampaigns})
            keys = camps if camps else ["unknown"]
        else:
            keys = ["unknown"]

        for k in keys:
            groups.setdefault(k, []).append(m)

    return {k: sorted(v, key=lambda m: m.mappingId) for k, v in groups.items()}

