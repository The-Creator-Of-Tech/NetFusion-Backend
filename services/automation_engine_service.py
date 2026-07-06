"""
Automation Engine
=================
Phase A4.5.2 — Deterministic, immutable automation record and mapping
management for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model AutomationStep, Automation, AutomationMapping, and
  AutomationStatistics as immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_automation_step, build_automation, build_automation_mapping,
    build_automation_statistics.
- Expose validation functions:
    validate_automation_step, validate_automation, validate_automation_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  Rule, and Playbook objects into AutomationMapping or automation reference
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
- CRUD, Search, Filter, Sort, Group, Merge, Execution, Scheduler,
  Retries, Workflow runtime, Smoke Test.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import AUTOMATION_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("automation_engine_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_AUTOMATION_NS = uuid.UUID("6ba7b886-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class AutomationEngineError(Exception):
    """Base class for all Automation Engine errors."""


class InvalidAutomationError(AutomationEngineError):
    """Raised when an Automation fails validation."""


class InvalidAutomationStepError(AutomationEngineError):
    """Raised when an AutomationStep fails validation."""


class InvalidAutomationMappingError(AutomationEngineError):
    """Raised when an AutomationMapping fails validation."""


# ===========================================================================
# Enumerations
# ===========================================================================

class AutomationStatusEnum(str, Enum):
    """Automation lifecycle status."""
    DRAFT    = "DRAFT"
    ACTIVE   = "ACTIVE"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class AutomationTriggerEnum(str, Enum):
    """Events that can trigger an automation."""
    FINDING_CREATED   = "FINDING_CREATED"
    ALERT_CREATED     = "ALERT_CREATED"
    RULE_MATCHED      = "RULE_MATCHED"
    PLAYBOOK_SELECTED = "PLAYBOOK_SELECTED"
    TIMELINE_EVENT    = "TIMELINE_EVENT"
    MANUAL            = "MANUAL"


class AutomationActionEnum(str, Enum):
    """Actions an automation step can perform."""
    CREATE_ALERT         = "CREATE_ALERT"
    CREATE_TIMELINE_EVENT = "CREATE_TIMELINE_EVENT"
    START_PLAYBOOK       = "START_PLAYBOOK"
    UPDATE_FINDING       = "UPDATE_FINDING"
    UPDATE_ALERT         = "UPDATE_ALERT"
    TAG_INVESTIGATION    = "TAG_INVESTIGATION"


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class AutomationStep(BaseModel):
    """
    One immutable automation step record.

    Identity
    --------
    stepKey : SHA256(automationId + str(stepNumber))[:32]
    stepId  : UUIDv5(_AUTOMATION_NS, stepKey)

    Fields
    ------
    stepId      : deterministic UUID derived from stepKey.
    stepKey     : 32-char SHA-256 identity key.
    stepNumber  : 1-based monotonic position in the automation.
    name        : human-readable step name (non-empty).
    description : detailed step instructions.
    action      : AutomationActionEnum — what this step does.
    parameters  : arbitrary JSON-serialisable dict of action parameters.
    createdAt   : ISO-8601 timestamp (caller-supplied for determinism).
    """
    stepId      : str
    stepKey     : str
    stepNumber  : int
    name        : str
    description : str
    action      : AutomationActionEnum
    parameters  : Dict[str, Any]
    createdAt   : str

    class Config:
        frozen = True


class Automation(BaseModel):
    """
    One immutable Automation record representing a response automation.

    Identity
    --------
    automationKey : SHA256(name + trigger.value + sorted(stepIds))[:32]
    automationId  : UUIDv5(_AUTOMATION_NS, automationKey)

    Fields
    ------
    automationId  : deterministic UUID derived from automationKey.
    automationKey : 32-char SHA-256 identity key.
    name          : human-readable automation name (non-empty).
    description   : overview of the automation's purpose and scope.
    status        : AutomationStatusEnum — lifecycle status.
    trigger       : AutomationTriggerEnum — event that fires this automation.
    steps         : sorted tuple of AutomationStep objects (by stepNumber ASC).
    priority      : integer priority; lower number = higher priority (>= 1).
    createdAt     : ISO-8601 timestamp (caller-supplied for determinism).
    """
    automationId  : str
    automationKey : str
    name          : str
    description   : str
    status        : AutomationStatusEnum
    trigger       : AutomationTriggerEnum
    steps         : Tuple[AutomationStep, ...]
    priority      : int
    createdAt     : str

    class Config:
        frozen = True


class AutomationMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to Automation objects.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(automationIds))[:32]
    mappingId          : UUIDv5(_AUTOMATION_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(automationIds))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    automations        : sorted tuple of Automation objects linked
                         (sorted by priority ASC then automationId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    mappingFingerprint : deterministic 32-char content fingerprint.
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    automations        : Tuple[Automation, ...]
    confidence         : float
    mappingFingerprint : str
    createdAt          : str

    class Config:
        frozen = True


class AutomationStatistics(BaseModel):
    """
    Aggregate statistics over a collection of Automation objects.

    Fields
    ------
    totalAutomations    : total count of distinct automations.
    activeAutomations   : count with status == ACTIVE.
    draftAutomations    : count with status == DRAFT.
    disabledAutomations : count with status == DISABLED.
    archivedAutomations : count with status == ARCHIVED.
    averagePriority     : mean automation.priority across all automations
                          (0.0 if empty).
    triggerCounts       : dict mapping AutomationTriggerEnum.value → count
                          (only keys with count > 0 are present).
    actionCounts        : dict mapping AutomationActionEnum.value → count of
                          automations that include at least one step with that
                          action (only keys with count > 0 are present).
    """
    totalAutomations    : int
    activeAutomations   : int
    draftAutomations    : int
    disabledAutomations : int
    archivedAutomations : int
    averagePriority     : float
    triggerCounts       : Dict[str, int]
    actionCounts        : Dict[str, int]

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
    """UUIDv5(_AUTOMATION_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_AUTOMATION_NS, key))


def _norm(s: str) -> str:
    """Strip a string; return empty string if None."""
    return s.strip() if s else ""


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


# ---------------------------------------------------------------------------
# Public key derivation functions
# ---------------------------------------------------------------------------

def stepKey(automation_id: str, step_number: int) -> str:
    """
    stepKey = SHA256(automationId + str(stepNumber))[:32]

    Null-byte-separated to prevent cross-field collisions.
    Same (automationId, stepNumber) pair always produces the same key.
    """
    return _sha256_32(automation_id.strip(), str(step_number))


def automationKey(
    name     : str,
    trigger  : AutomationTriggerEnum,
    step_ids : Tuple[str, ...],
) -> str:
    """
    automationKey = SHA256(name + trigger.value + sorted(stepIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    stepIds sorted before joining for order-independence.
    """
    sorted_steps = "\x01".join(sorted(step_ids))
    return _sha256_32(name.strip(), trigger.value, sorted_steps)


def mappingKey(
    finding_id    : str,
    alert_id      : str,
    reasoning_id  : str,
    automation_ids: Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(automationIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    automationIds sorted before joining for order-independence.
    """
    sorted_ids = "\x01".join(sorted(automation_ids))
    return _sha256_32(
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_ids,
    )


def mappingFingerprint(
    m_key         : str,
    finding_id    : str,
    alert_id      : str,
    reasoning_id  : str,
    automation_ids: Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(automationIds))[:32]
    """
    sorted_ids = "\x01".join(sorted(automation_ids))
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

def validate_automation_step(
    step_number : int,
    name        : str,
    action      : AutomationActionEnum,
    created_at  : str,
) -> None:
    """
    Validate AutomationStep construction parameters.

    Checks
    ------
    - step_number is a positive integer (>= 1).
    - name is non-empty.
    - action is a valid AutomationActionEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidAutomationStepError : if any rule is violated.
    """
    errors: List[str] = []

    if not isinstance(step_number, int) or step_number < 1:
        errors.append(
            f"stepNumber={step_number!r} must be a positive integer (>= 1)."
        )
    if not name or not name.strip():
        errors.append("name must not be empty.")
    if not isinstance(action, AutomationActionEnum):
        errors.append(
            f"action must be an AutomationActionEnum member; got {action!r}."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_automation_step", "errors": errors},
        )
        raise InvalidAutomationStepError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_automation(
    name       : str,
    status     : AutomationStatusEnum,
    trigger    : AutomationTriggerEnum,
    priority   : int,
    created_at : str,
) -> None:
    """
    Validate Automation construction parameters.

    Checks
    ------
    - name is non-empty.
    - status is a valid AutomationStatusEnum member.
    - trigger is a valid AutomationTriggerEnum member.
    - priority is a positive integer (>= 1).
    - created_at is non-empty.

    Raises
    ------
    InvalidAutomationError : if any rule is violated.
    """
    errors: List[str] = []

    if not name or not name.strip():
        errors.append("name must not be empty.")
    if not isinstance(status, AutomationStatusEnum):
        errors.append(
            f"status must be an AutomationStatusEnum member; got {status!r}."
        )
    if not isinstance(trigger, AutomationTriggerEnum):
        errors.append(
            f"trigger must be an AutomationTriggerEnum member; got {trigger!r}."
        )
    if not isinstance(priority, int) or priority < 1:
        errors.append(
            f"priority={priority!r} must be a positive integer (>= 1)."
        )
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_automation", "errors": errors},
        )
        raise InvalidAutomationError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_automation_mapping(
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    confidence   : float,
    created_at   : str,
) -> None:
    """
    Validate AutomationMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidAutomationMappingError : if any rule is violated.
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
            extra={"validator": "validate_automation_mapping", "errors": errors},
        )
        raise InvalidAutomationMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_automation_step()
# ===========================================================================

def build_automation_step(
    automation_id : str,
    step_number   : int,
    name          : str,
    action        : AutomationActionEnum,
    created_at    : str,
    description   : str                        = "",
    parameters    : Optional[Dict[str, Any]]   = None,
    validate      : bool                       = True,
) -> AutomationStep:
    """
    Build an immutable AutomationStep.

    stepKey = SHA256(automationId + str(stepNumber))[:32]
    stepId  = UUIDv5(_AUTOMATION_NS, stepKey)

    Parameters
    ----------
    automation_id : ID of the parent Automation (scopes step identity).
    step_number   : 1-based position in the automation (must be >= 1).
    name          : human-readable step name (must be non-empty).
    action        : AutomationActionEnum — what this step does.
    created_at    : ISO-8601 timestamp (caller-supplied for determinism).
    description   : detailed step instructions (may be empty).
    parameters    : arbitrary JSON-serialisable dict of action parameters.
    validate      : if True, run validate_automation_step() first.

    Returns
    -------
    AutomationStep (frozen / immutable)

    Raises
    ------
    InvalidAutomationStepError : if validate=True and step validation fails.
    """
    if validate:
        validate_automation_step(step_number, name, action, created_at)

    s_key = stepKey(automation_id, step_number)
    s_id  = _uuid5(s_key)

    return AutomationStep(
        stepId      = s_id,
        stepKey     = s_key,
        stepNumber  = step_number,
        name        = name.strip(),
        description = description,
        action      = action,
        parameters  = dict(parameters) if parameters else {},
        createdAt   = created_at,
    )


# ===========================================================================
# Builder: build_automation()
# ===========================================================================

def build_automation(
    name        : str,
    trigger     : AutomationTriggerEnum,
    created_at  : str,
    description : str                              = "",
    status      : AutomationStatusEnum             = AutomationStatusEnum.DRAFT,
    steps       : Optional[List[AutomationStep]]   = None,
    priority    : int                              = 100,
    validate    : bool                             = True,
) -> Automation:
    """
    Build an immutable Automation.

    automationKey = SHA256(name + trigger.value + sorted(stepIds))[:32]
    automationId  = UUIDv5(_AUTOMATION_NS, automationKey)

    Parameters
    ----------
    name        : human-readable automation name (must be non-empty).
    trigger     : AutomationTriggerEnum — event that fires this automation.
    created_at  : ISO-8601 timestamp (caller-supplied for determinism).
    description : overview of the automation's purpose (may be empty).
    status      : AutomationStatusEnum — lifecycle status (default DRAFT).
    steps       : list of AutomationStep objects
                  (sorted by stepNumber ASC, then stepId ASC for ties).
    priority    : integer priority; lower = higher priority (default 100, >= 1).
    validate    : if True, run validate_automation() first.

    Returns
    -------
    Automation (frozen / immutable)

    Raises
    ------
    InvalidAutomationError : if validate=True and automation validation fails.
    """
    if validate:
        validate_automation(name, status, trigger, priority, created_at)

    # Sort steps deterministically: stepNumber ASC, then stepId ASC for ties
    sorted_steps: Tuple[AutomationStep, ...] = tuple(
        sorted(
            steps or [],
            key=lambda s: (s.stepNumber, s.stepId),
        )
    )

    # Collect step IDs for automationKey derivation
    step_ids: Tuple[str, ...] = tuple(s.stepId for s in sorted_steps)

    a_key = automationKey(name, trigger, step_ids)
    a_id  = _uuid5(a_key)

    return Automation(
        automationId  = a_id,
        automationKey = a_key,
        name          = name.strip(),
        description   = description,
        status        = status,
        trigger       = trigger,
        steps         = sorted_steps,
        priority      = priority,
        createdAt     = created_at,
    )


# ===========================================================================
# Builder: build_automation_mapping()
# ===========================================================================

def build_automation_mapping(
    automations  : List[Automation],
    created_at   : str,
    finding_id   : str   = "",
    alert_id     : str   = "",
    reasoning_id : str   = "",
    confidence   : float = 0.0,
    validate     : bool  = True,
) -> AutomationMapping:
    """
    Build an immutable AutomationMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(automationIds))[:32]
    mappingId          = UUIDv5(_AUTOMATION_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(automationIds))[:32]

    Parameters
    ----------
    automations  : list of Automation objects to link in this mapping.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id   : ID of the linked Finding (may be empty).
    alert_id     : ID of the linked Alert (may be empty).
    reasoning_id : ID of the linked ReasoningResult (may be empty).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).
    validate     : if True, run validate_automation_mapping() first.

    Returns
    -------
    AutomationMapping (frozen / immutable)

    Raises
    ------
    InvalidAutomationMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_automation_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: priority ASC (lower = higher priority),
    # then automationId ASC as tiebreaker
    sorted_automations: Tuple[Automation, ...] = tuple(
        sorted(
            automations or [],
            key=lambda a: (a.priority, a.automationId),
        )
    )

    # Collect automation IDs for key computation
    a_ids: Tuple[str, ...] = tuple(a.automationId for a in sorted_automations)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, a_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(m_key, finding_id, alert_id, reasoning_id, a_ids)

    return AutomationMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        automations        = sorted_automations,
        confidence         = round(clamped_conf, 4),
        mappingFingerprint = m_fp,
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_automation_statistics()
# ===========================================================================

def build_automation_statistics(
    automations: List[Automation],
) -> AutomationStatistics:
    """
    Compute AutomationStatistics over a flat list of Automation objects.

    Deterministic: canonical sort by automationId ASC before accumulation
    so floating-point sums and counts are identical across every run
    regardless of input ordering.

    Deduplication is by automationId — first occurrence in sorted order wins.

    Parameters
    ----------
    automations : any list of Automation objects (may contain duplicates).

    Returns
    -------
    AutomationStatistics (frozen / immutable)
    """
    if not automations:
        return AutomationStatistics(
            totalAutomations    = 0,
            activeAutomations   = 0,
            draftAutomations    = 0,
            disabledAutomations = 0,
            archivedAutomations = 0,
            averagePriority     = 0.0,
            triggerCounts       = {},
            actionCounts        = {},
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(automations, key=lambda a: a.automationId)

    # Deduplicate by automationId — first occurrence in sorted order wins
    seen_ids: Dict[str, Automation] = {}
    for a in ordered:
        if a.automationId not in seen_ids:
            seen_ids[a.automationId] = a

    distinct = list(seen_ids.values())
    # Re-sort after dedup for deterministic counting
    distinct.sort(key=lambda a: a.automationId)

    total    = len(distinct)
    active   = sum(1 for a in distinct if a.status == AutomationStatusEnum.ACTIVE)
    draft    = sum(1 for a in distinct if a.status == AutomationStatusEnum.DRAFT)
    disabled = sum(1 for a in distinct if a.status == AutomationStatusEnum.DISABLED)
    archived = sum(1 for a in distinct if a.status == AutomationStatusEnum.ARCHIVED)

    avg_priority = (
        round(sum(a.priority for a in distinct) / total, 4)
        if total > 0 else 0.0
    )

    # Trigger counts — iterate enum in declaration order for determinism
    trigger_counts: Dict[str, int] = {}
    for trig in AutomationTriggerEnum:
        count = sum(1 for a in distinct if a.trigger == trig)
        if count > 0:
            trigger_counts[trig.value] = count

    # Action counts — count automations that have at least one step with
    # the given action; iterate enum in declaration order for determinism
    action_counts: Dict[str, int] = {}
    for act in AutomationActionEnum:
        count = sum(
            1 for a in distinct
            if any(s.action == act for s in a.steps)
        )
        if count > 0:
            action_counts[act.value] = count

    return AutomationStatistics(
        totalAutomations    = total,
        activeAutomations   = active,
        draftAutomations    = draft,
        disabledAutomations = disabled,
        archivedAutomations = archived,
        averagePriority     = avg_priority,
        triggerCounts       = trigger_counts,
        actionCounts        = action_counts,
    )


# ===========================================================================
# Integration Helpers
# ===========================================================================
# Pure transformation helpers. Accept objects from other engine services and
# return AutomationMapping objects or automation reference strings.
# No external lookups. No AI execution. No network. Duck-typed input objects
# are accepted so there is no circular import at module load time.
# No workflow evaluation. No scheduling. Only deterministic transformations.


def rule_to_automation_reference(rule: Any) -> str:
    """
    Extract a stable automation reference string from a Rule object.

    Returns a string of the form "rule:<ruleId>" that can be stored in
    automation metadata or step parameters to link an Automation to a Rule
    without creating a circular dependency.

    Parameters
    ----------
    rule : any object with a .ruleId string attribute (duck-typed).

    Returns
    -------
    str — "rule:<ruleId>" or "rule:" if ruleId is absent/empty.
    """
    rule_id = _norm(getattr(rule, "ruleId", ""))
    return f"rule:{rule_id}"


def playbook_to_automation_reference(playbook: Any) -> str:
    """
    Extract a stable automation reference string from a Playbook object.

    Returns a string of the form "playbook:<playbookId>" that can be stored
    in automation metadata or step parameters to link an Automation to a
    Playbook without creating a circular dependency.

    Parameters
    ----------
    playbook : any object with a .playbookId string attribute (duck-typed).

    Returns
    -------
    str — "playbook:<playbookId>" or "playbook:" if playbookId is absent/empty.
    """
    playbook_id = _norm(getattr(playbook, "playbookId", ""))
    return f"playbook:{playbook_id}"


def finding_to_automation_mapping(
    finding      : Any,
    automations  : List[Automation],
    created_at   : str,
    confidence   : float = 0.0,
) -> AutomationMapping:
    """
    Transform a Finding object into an AutomationMapping.

    Extracts findingId from finding.findingId (duck-typed).
    alertId and reasoningId are left empty.

    Parameters
    ----------
    finding      : any object with a .findingId string attribute.
    automations  : list of Automation objects to link to this finding.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    AutomationMapping (frozen / immutable)
    """
    finding_id = _norm(getattr(finding, "findingId", ""))
    return build_automation_mapping(
        automations  = automations,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = "",
        reasoning_id = "",
        confidence   = confidence,
    )


def alert_to_automation_mapping(
    alert        : Any,
    automations  : List[Automation],
    created_at   : str,
    confidence   : float = 0.0,
) -> AutomationMapping:
    """
    Transform an Alert object into an AutomationMapping.

    Extracts alertId from alert.alertId (duck-typed).
    findingId is sourced from alert.findingId when present.
    reasoningId is left empty.

    Parameters
    ----------
    alert        : any object with .alertId and optionally .findingId.
    automations  : list of Automation objects to link to this alert.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    AutomationMapping (frozen / immutable)
    """
    alert_id   = _norm(getattr(alert, "alertId", ""))
    finding_id = _norm(getattr(alert, "findingId", ""))
    return build_automation_mapping(
        automations  = automations,
        created_at   = created_at,
        finding_id   = finding_id,
        alert_id     = alert_id,
        reasoning_id = "",
        confidence   = confidence,
    )


def reasoning_to_automation_mapping(
    reasoning    : Any,
    automations  : List[Automation],
    created_at   : str,
    confidence   : float = 0.0,
) -> AutomationMapping:
    """
    Transform a ReasoningResult object into an AutomationMapping.

    Extracts reasoningId from reasoning.reasoningId (duck-typed).
    findingId and alertId are left empty.

    Parameters
    ----------
    reasoning    : any object with a .reasoningId string attribute.
    automations  : list of Automation objects to link to this reasoning result.
    created_at   : ISO-8601 timestamp (caller-supplied for determinism).
    confidence   : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    AutomationMapping (frozen / immutable)
    """
    reasoning_id = _norm(getattr(reasoning, "reasoningId", ""))
    return build_automation_mapping(
        automations  = automations,
        created_at   = created_at,
        finding_id   = "",
        alert_id     = "",
        reasoning_id = reasoning_id,
        confidence   = confidence,
    )


# ===========================================================================
# Part B — Operations, Search, Sort, Filter, Group, Statistics (extended)
# ===========================================================================

# ---------------------------------------------------------------------------
# Internal sort-order helpers
# ---------------------------------------------------------------------------

_STATUS_ORDER: Dict[AutomationStatusEnum, int] = {
    AutomationStatusEnum.ACTIVE   : 4,
    AutomationStatusEnum.DRAFT    : 3,
    AutomationStatusEnum.DISABLED : 2,
    AutomationStatusEnum.ARCHIVED : 1,
}

_TRIGGER_ORDER: Dict[AutomationTriggerEnum, int] = {
    AutomationTriggerEnum.FINDING_CREATED   : 6,
    AutomationTriggerEnum.ALERT_CREATED     : 5,
    AutomationTriggerEnum.RULE_MATCHED      : 4,
    AutomationTriggerEnum.PLAYBOOK_SELECTED : 3,
    AutomationTriggerEnum.TIMELINE_EVENT    : 2,
    AutomationTriggerEnum.MANUAL            : 1,
}

_VALID_AUTOMATION_SORT_KEYS = frozenset({
    "name", "status", "trigger", "priority", "createdAt",
})

_VALID_STEP_SORT_KEYS = frozenset({
    "name", "stepNumber", "action", "createdAt",
})

_VALID_MAPPING_SORT_KEYS = frozenset({
    "confidence", "createdAt", "findingId", "alertId", "reasoningId",
})


# ===========================================================================
# Automation Operations
# ===========================================================================

def add_automation(
    automations : List[Automation],
    automation  : Automation,
) -> List[Automation]:
    """
    Return a new list with *automation* appended.

    Duplicate detection: if an Automation with the same automationId already
    exists in *automations*, the original list is returned unchanged (idempotent).

    Parameters
    ----------
    automations : existing list of Automation objects.
    automation  : Automation to add.

    Returns
    -------
    New list — input is not mutated.
    """
    for existing in automations:
        if existing.automationId == automation.automationId:
            _log.info(
                "automation_add_skipped_duplicate",
                extra={"automationId": automation.automationId},
            )
            return list(automations)
    result = list(automations) + [automation]
    _log.info(
        "automation_created",
        extra={"automationId": automation.automationId, "automationName": automation.name},
    )
    return result


def update_automation(
    automations   : List[Automation],
    automation_id : str,
    created_at    : str,
    name          : Optional[str]                    = None,
    description   : Optional[str]                    = None,
    status        : Optional[AutomationStatusEnum]   = None,
    trigger       : Optional[AutomationTriggerEnum]  = None,
    steps         : Optional[List[AutomationStep]]   = None,
    priority      : Optional[int]                    = None,
) -> List[Automation]:
    """
    Return a new list where the Automation with *automation_id* has the
    supplied fields replaced.  The automationId is always preserved.
    Fields set to None are left unchanged.

    If no Automation with *automation_id* is found, the list is returned
    unchanged.

    The automationKey and automationId are recomputed when name, trigger,
    or steps change (content-addressable identity).

    Parameters
    ----------
    automations   : existing list of Automation objects.
    automation_id : automationId of the record to update.
    created_at    : ISO-8601 timestamp for the new record.
    name / description / status / trigger / steps / priority : optional overrides.

    Returns
    -------
    New list — input is not mutated.
    """
    result: List[Automation] = []
    updated = False
    for a in automations:
        if a.automationId != automation_id:
            result.append(a)
            continue
        new_name        = name        if name        is not None else a.name
        new_desc        = description if description is not None else a.description
        new_status      = status      if status      is not None else a.status
        new_trigger     = trigger     if trigger     is not None else a.trigger
        new_steps_list  = steps       if steps       is not None else list(a.steps)
        new_priority    = priority    if priority    is not None else a.priority

        rebuilt = build_automation(
            name        = new_name,
            trigger     = new_trigger,
            created_at  = created_at,
            description = new_desc,
            status      = new_status,
            steps       = new_steps_list,
            priority    = new_priority,
        )
        result.append(rebuilt)
        updated = True
        _log.info(
            "automation_updated",
            extra={"automationId": automation_id, "automationName": new_name},
        )
    if not updated:
        _log.warning(
            "automation_update_not_found",
            extra={"automationId": automation_id},
        )
    return result


def remove_automation(
    automations   : List[Automation],
    automation_id : str,
) -> List[Automation]:
    """
    Return a new list with the Automation matching *automation_id* removed.

    If no match is found, returns the list unchanged (idempotent).

    Parameters
    ----------
    automations   : existing list of Automation objects.
    automation_id : automationId of the record to remove.

    Returns
    -------
    New list — input is not mutated.
    """
    result = [a for a in automations if a.automationId != automation_id]
    if len(result) < len(automations):
        _log.info(
            "automation_removed",
            extra={"automationId": automation_id},
        )
    return result


def merge_automations(
    base   : List[Automation],
    incoming: List[Automation],
) -> List[Automation]:
    """
    Deterministically merge *incoming* into *base*.

    Rules
    -----
    - Existing automations (same automationId) are preserved unchanged
      (base wins — no silent overwrites).
    - New automations in *incoming* (unseen automationId) are appended.
    - Result is sorted by automationId ASC for full determinism.
    - No randomness; no timestamp-derived ordering.

    Parameters
    ----------
    base     : authoritative list.
    incoming : list of Automation objects to merge in.

    Returns
    -------
    New deduplicated, sorted list — inputs are not mutated.
    """
    seen: Dict[str, Automation] = {a.automationId: a for a in base}
    added = 0
    for a in incoming:
        if a.automationId not in seen:
            seen[a.automationId] = a
            added += 1
    result = sorted(seen.values(), key=lambda a: a.automationId)
    _log.info(
        "automation_merge_completed",
        extra={"baseCount": len(base), "incomingCount": len(incoming), "added": added},
    )
    return result


# ===========================================================================
# Step Operations
# ===========================================================================

def add_automation_step(
    automation : Automation,
    step       : AutomationStep,
    created_at : str,
) -> Automation:
    """
    Return a new Automation with *step* added to its steps.

    Duplicate detection: if a step with the same stepId already exists,
    the original automation is returned unchanged (idempotent).
    The automationKey and automationId are recomputed to reflect the new
    step set (content-addressable identity).

    Parameters
    ----------
    automation : existing Automation.
    step       : AutomationStep to add.
    created_at : ISO-8601 timestamp for the rebuilt Automation.

    Returns
    -------
    New Automation (frozen / immutable) — input is not mutated.
    """
    for existing in automation.steps:
        if existing.stepId == step.stepId:
            _log.info(
                "automation_step_add_skipped_duplicate",
                extra={"stepId": step.stepId, "automationId": automation.automationId},
            )
            return automation

    new_steps = list(automation.steps) + [step]
    rebuilt = build_automation(
        name        = automation.name,
        trigger     = automation.trigger,
        created_at  = created_at,
        description = automation.description,
        status      = automation.status,
        steps       = new_steps,
        priority    = automation.priority,
    )
    _log.info(
        "automation_step_created",
        extra={"stepId": step.stepId, "automationId": rebuilt.automationId},
    )
    return rebuilt


def update_automation_step(
    automation  : Automation,
    step_id     : str,
    created_at  : str,
    name        : Optional[str]                  = None,
    description : Optional[str]                  = None,
    action      : Optional[AutomationActionEnum] = None,
    parameters  : Optional[Dict[str, Any]]       = None,
) -> Automation:
    """
    Return a new Automation with the step matching *step_id* updated.

    stepId and stepKey are preserved (identity is stable).
    automationKey and automationId are recomputed only when step content
    changes cause a new step set composition (stepIds unchanged here, so
    automationKey is stable).

    If no step with *step_id* is found, the automation is returned unchanged.

    Parameters
    ----------
    automation  : existing Automation.
    step_id     : stepId of the step to update.
    created_at  : ISO-8601 timestamp for the rebuilt Automation.
    name / description / action / parameters : optional overrides.

    Returns
    -------
    New Automation (frozen / immutable) — input is not mutated.
    """
    new_steps: List[AutomationStep] = []
    updated = False
    for s in automation.steps:
        if s.stepId != step_id:
            new_steps.append(s)
            continue
        # Rebuild with overrides, preserving stepId/stepKey/stepNumber
        rebuilt_step = AutomationStep(
            stepId      = s.stepId,
            stepKey     = s.stepKey,
            stepNumber  = s.stepNumber,
            name        = (name.strip() if name is not None else s.name),
            description = (description if description is not None else s.description),
            action      = (action if action is not None else s.action),
            parameters  = (dict(parameters) if parameters is not None else dict(s.parameters)),
            createdAt   = s.createdAt,
        )
        new_steps.append(rebuilt_step)
        updated = True
        _log.info(
            "automation_step_updated",
            extra={"stepId": step_id, "automationId": automation.automationId},
        )

    if not updated:
        _log.warning(
            "automation_step_update_not_found",
            extra={"stepId": step_id, "automationId": automation.automationId},
        )
        return automation

    return build_automation(
        name        = automation.name,
        trigger     = automation.trigger,
        created_at  = created_at,
        description = automation.description,
        status      = automation.status,
        steps       = new_steps,
        priority    = automation.priority,
    )


def remove_automation_step(
    automation : Automation,
    step_id    : str,
    created_at : str,
) -> Automation:
    """
    Return a new Automation with the step matching *step_id* removed.

    If no step with *step_id* is found, the automation is returned unchanged
    (idempotent).  automationKey and automationId are recomputed because the
    step set changed.

    Parameters
    ----------
    automation : existing Automation.
    step_id    : stepId of the step to remove.
    created_at : ISO-8601 timestamp for the rebuilt Automation.

    Returns
    -------
    New Automation (frozen / immutable) — input is not mutated.
    """
    new_steps = [s for s in automation.steps if s.stepId != step_id]
    if len(new_steps) == len(automation.steps):
        _log.warning(
            "automation_step_remove_not_found",
            extra={"stepId": step_id, "automationId": automation.automationId},
        )
        return automation

    _log.info(
        "automation_step_removed",
        extra={"stepId": step_id, "automationId": automation.automationId},
    )
    return build_automation(
        name        = automation.name,
        trigger     = automation.trigger,
        created_at  = created_at,
        description = automation.description,
        status      = automation.status,
        steps       = new_steps,
        priority    = automation.priority,
    )


def merge_automation_steps(
    automation   : Automation,
    incoming     : List[AutomationStep],
    created_at   : str,
) -> Automation:
    """
    Deterministically merge *incoming* steps into *automation*.

    Rules
    -----
    - Existing steps (same stepId) are preserved unchanged (base wins).
    - New steps (unseen stepId) are appended.
    - automationKey and automationId are recomputed to reflect the merged set.

    Parameters
    ----------
    automation : existing Automation.
    incoming   : steps to merge in.
    created_at : ISO-8601 timestamp for the rebuilt Automation.

    Returns
    -------
    New Automation (frozen / immutable) — input is not mutated.
    """
    seen: Dict[str, AutomationStep] = {s.stepId: s for s in automation.steps}
    added = 0
    for s in incoming:
        if s.stepId not in seen:
            seen[s.stepId] = s
            added += 1
    merged_steps = sorted(seen.values(), key=lambda s: (s.stepNumber, s.stepId))
    _log.info(
        "automation_merge_completed",
        extra={
            "automationId": automation.automationId,
            "baseSteps": len(automation.steps),
            "incomingSteps": len(incoming),
            "added": added,
        },
    )
    return build_automation(
        name        = automation.name,
        trigger     = automation.trigger,
        created_at  = created_at,
        description = automation.description,
        status      = automation.status,
        steps       = merged_steps,
        priority    = automation.priority,
    )


# ===========================================================================
# Mapping Operations
# ===========================================================================

def add_automation_mapping(
    mappings : List[AutomationMapping],
    mapping  : AutomationMapping,
) -> List[AutomationMapping]:
    """
    Return a new list with *mapping* appended.

    Duplicate detection: if a mapping with the same mappingId already exists,
    the original list is returned unchanged (idempotent).

    Parameters
    ----------
    mappings : existing list of AutomationMapping objects.
    mapping  : AutomationMapping to add.

    Returns
    -------
    New list — input is not mutated.
    """
    for existing in mappings:
        if existing.mappingId == mapping.mappingId:
            _log.info(
                "automation_mapping_add_skipped_duplicate",
                extra={"mappingId": mapping.mappingId},
            )
            return list(mappings)
    result = list(mappings) + [mapping]
    _log.info(
        "automation_mapping_created",
        extra={"mappingId": mapping.mappingId},
    )
    return result


def remove_automation_mapping(
    mappings   : List[AutomationMapping],
    mapping_id : str,
) -> List[AutomationMapping]:
    """
    Return a new list with the AutomationMapping matching *mapping_id* removed.

    If no match is found, returns the list unchanged (idempotent).

    Parameters
    ----------
    mappings   : existing list of AutomationMapping objects.
    mapping_id : mappingId of the record to remove.

    Returns
    -------
    New list — input is not mutated.
    """
    result = [m for m in mappings if m.mappingId != mapping_id]
    if len(result) < len(mappings):
        _log.info(
            "automation_mapping_removed",
            extra={"mappingId": mapping_id},
        )
    return result


def merge_automation_mappings(
    base     : List[AutomationMapping],
    incoming : List[AutomationMapping],
) -> List[AutomationMapping]:
    """
    Deterministically merge *incoming* mappings into *base*.

    Rules
    -----
    - Existing mappings (same mappingId) are preserved unchanged (base wins).
    - New mappings (unseen mappingId) are appended.
    - Result is sorted by mappingId ASC for full determinism.

    Parameters
    ----------
    base     : authoritative list.
    incoming : list of AutomationMapping objects to merge in.

    Returns
    -------
    New deduplicated, sorted list — inputs are not mutated.
    """
    seen: Dict[str, AutomationMapping] = {m.mappingId: m for m in base}
    added = 0
    for m in incoming:
        if m.mappingId not in seen:
            seen[m.mappingId] = m
            added += 1
    result = sorted(seen.values(), key=lambda m: m.mappingId)
    _log.info(
        "automation_merge_completed",
        extra={"baseCount": len(base), "incomingCount": len(incoming), "added": added},
    )
    return result


# ===========================================================================
# Search Utilities
# ===========================================================================

def find_automation(
    automations   : List[Automation],
    automation_id : Optional[str] = None,
    automation_key: Optional[str] = None,
) -> Optional[Automation]:
    """
    Look up a single Automation by automationId or automationKey.

    automationId takes precedence over automationKey when both are supplied.
    Returns the first match or None.

    Parameters
    ----------
    automations    : list to search.
    automation_id  : exact automationId to match.
    automation_key : exact automationKey to match (used if automation_id is None).

    Returns
    -------
    Automation or None.
    """
    if automation_id is not None:
        for a in automations:
            if a.automationId == automation_id:
                return a
        return None
    if automation_key is not None:
        for a in automations:
            if a.automationKey == automation_key:
                return a
    return None


def find_automation_step(
    automations : List[Automation],
    step_id     : Optional[str] = None,
    step_key    : Optional[str] = None,
) -> Optional[AutomationStep]:
    """
    Look up a single AutomationStep by stepId or stepKey across all automations.

    stepId takes precedence over stepKey when both are supplied.
    Returns the first match or None.

    Parameters
    ----------
    automations : list to search.
    step_id     : exact stepId to match.
    step_key    : exact stepKey to match (used if step_id is None).

    Returns
    -------
    AutomationStep or None.
    """
    if step_id is not None:
        for a in automations:
            for s in a.steps:
                if s.stepId == step_id:
                    return s
        return None
    if step_key is not None:
        for a in automations:
            for s in a.steps:
                if s.stepKey == step_key:
                    return s
    return None


def find_automation_mapping(
    mappings   : List[AutomationMapping],
    mapping_id : Optional[str] = None,
) -> Optional[AutomationMapping]:
    """
    Look up a single AutomationMapping by mappingId.

    Returns the first match or None.

    Parameters
    ----------
    mappings   : list to search.
    mapping_id : exact mappingId to match.

    Returns
    -------
    AutomationMapping or None.
    """
    if mapping_id is not None:
        for m in mappings:
            if m.mappingId == mapping_id:
                return m
    return None


# ===========================================================================
# Sorting
# ===========================================================================

def sort_automations(
    automations : List[Automation],
    by          : str  = "priority",
    ascending   : bool = True,
) -> List[Automation]:
    """
    Return a new sorted list of automations.

    Parameters
    ----------
    by        : "name" | "status" | "trigger" | "priority" (default) | "createdAt"
    ascending : True = lowest priority first (default); False = highest first.

    Tie-breaking is always by automationId ASC for full determinism.

    Raises
    ------
    ValueError : for unknown sort key.

    Returns
    -------
    New sorted list — input is not mutated.
    """
    if by not in _VALID_AUTOMATION_SORT_KEYS:
        raise ValueError(
            f"sort_automations: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_AUTOMATION_SORT_KEYS)}"
        )

    def _key(a: Automation) -> tuple:
        if by == "priority":
            primary = a.priority
        elif by == "status":
            primary = _STATUS_ORDER.get(a.status, 0)
        elif by == "trigger":
            primary = _TRIGGER_ORDER.get(a.trigger, 0)
        elif by == "name":
            primary = a.name.lower()
        else:  # createdAt
            primary = a.createdAt
        return (primary, a.automationId)

    return sorted(automations, key=_key, reverse=not ascending)


def sort_automation_steps(
    steps     : List[AutomationStep],
    by        : str  = "stepNumber",
    ascending : bool = True,
) -> List[AutomationStep]:
    """
    Return a new sorted list of automation steps.

    Parameters
    ----------
    by        : "name" | "stepNumber" (default) | "action" | "createdAt"
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
            f"sort_automation_steps: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_STEP_SORT_KEYS)}"
        )

    def _key(s: AutomationStep) -> tuple:
        if by == "stepNumber":
            primary = s.stepNumber
        elif by == "name":
            primary = s.name.lower()
        elif by == "action":
            primary = s.action.value
        else:  # createdAt
            primary = s.createdAt
        return (primary, s.stepId)

    return sorted(steps, key=_key, reverse=not ascending)


def sort_automation_mappings(
    mappings  : List[AutomationMapping],
    by        : str  = "createdAt",
    ascending : bool = True,
) -> List[AutomationMapping]:
    """
    Return a new sorted list of automation mappings.

    Parameters
    ----------
    by        : "confidence" | "createdAt" (default) | "findingId" |
                "alertId" | "reasoningId"
    ascending : True = oldest first (default); False = newest first.

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
            f"sort_automation_mappings: unknown key '{by}'. "
            f"Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: AutomationMapping) -> tuple:
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

def filter_automations(
    automations : List[Automation],
    status      : Optional[AutomationStatusEnum]  = None,
    trigger     : Optional[AutomationTriggerEnum] = None,
    min_priority: Optional[int]                   = None,
    max_priority: Optional[int]                   = None,
) -> List[Automation]:
    """
    Filter automations by one or more criteria (all ANDed together).

    Parameters
    ----------
    status       : keep only automations with this status.
    trigger      : keep only automations with this trigger.
    min_priority : keep automations with priority >= min_priority.
    max_priority : keep automations with priority <= max_priority.

    Returns
    -------
    New filtered list — input is not mutated.
    """
    result: List[Automation] = []
    for a in automations:
        if status       is not None and a.status   != status:
            continue
        if trigger      is not None and a.trigger  != trigger:
            continue
        if min_priority is not None and a.priority < min_priority:
            continue
        if max_priority is not None and a.priority > max_priority:
            continue
        result.append(a)
    return result


def filter_automation_steps(
    automations : List[Automation],
    action      : Optional[AutomationActionEnum] = None,
) -> List[AutomationStep]:
    """
    Collect all AutomationStep objects across *automations*, optionally
    filtered by action type.

    Parameters
    ----------
    automations : list of Automation objects to collect steps from.
    action      : keep only steps with this action.

    Returns
    -------
    New flat list of AutomationStep objects — input is not mutated.
    """
    result: List[AutomationStep] = []
    for a in automations:
        for s in a.steps:
            if action is not None and s.action != action:
                continue
            result.append(s)
    return result


def filter_automation_mappings(
    mappings     : List[AutomationMapping],
    finding_id   : Optional[str] = None,
    alert_id     : Optional[str] = None,
    reasoning_id : Optional[str] = None,
    min_confidence: Optional[float] = None,
    max_confidence: Optional[float] = None,
) -> List[AutomationMapping]:
    """
    Filter automation mappings by one or more criteria (all ANDed together).

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
    result: List[AutomationMapping] = []
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

def group_automations(
    automations : List[Automation],
    group_by    : str = "status",
) -> Dict[str, List[Automation]]:
    """
    Group automations by a string attribute.

    Parameters
    ----------
    automations : list of Automation objects.
    group_by    : "status" (default) | "trigger" | "priority"
                  Enum values are unwrapped to their .value string.
                  "priority" is converted to str for use as a dict key.

    Each group is sorted by automationId ASC for determinism.

    Returns
    -------
    Dict[str, List[Automation]] — each group sorted by automationId ASC.
    """
    groups: Dict[str, List[Automation]] = {}
    for a in automations:
        if group_by == "status":
            key = a.status.value
        elif group_by == "trigger":
            key = a.trigger.value
        elif group_by == "priority":
            key = str(a.priority)
        else:
            raw = getattr(a, group_by, None)
            key = raw.value if hasattr(raw, "value") else (
                str(raw) if raw is not None else "unknown"
            )
        groups.setdefault(key, []).append(a)
    return {k: sorted(v, key=lambda a: a.automationId) for k, v in groups.items()}


def group_automation_steps(
    automations : List[Automation],
    group_by    : str = "action",
) -> Dict[str, List[AutomationStep]]:
    """
    Group all AutomationStep objects across *automations* by a step attribute.

    Parameters
    ----------
    automations : list of Automation objects to collect steps from.
    group_by    : "action" (default) | any AutomationStep field name.
                  Enum values are unwrapped to their .value string.

    Each group is sorted by (stepNumber ASC, stepId ASC) for determinism.

    Returns
    -------
    Dict[str, List[AutomationStep]] — each group sorted by stepNumber ASC.
    """
    groups: Dict[str, List[AutomationStep]] = {}
    for a in automations:
        for s in a.steps:
            if group_by == "action":
                key = s.action.value
            else:
                raw = getattr(s, group_by, None)
                key = raw.value if hasattr(raw, "value") else (
                    str(raw) if raw is not None else "unknown"
                )
            groups.setdefault(key, []).append(s)
    return {
        k: sorted(v, key=lambda s: (s.stepNumber, s.stepId))
        for k, v in groups.items()
    }


def group_automation_mappings(
    mappings : List[AutomationMapping],
    group_by : str = "findingId",
) -> Dict[str, List[AutomationMapping]]:
    """
    Group automation mappings by a string attribute.

    Parameters
    ----------
    mappings : list of AutomationMapping objects.
    group_by : "findingId" (default) | "alertId" | "reasoningId"
               Any other AutomationMapping string field is also accepted.

    Each group is sorted by mappingId ASC for determinism.

    Returns
    -------
    Dict[str, List[AutomationMapping]] — each group sorted by mappingId ASC.
    """
    groups: Dict[str, List[AutomationMapping]] = {}
    for m in mappings:
        raw = getattr(m, group_by, None)
        key = raw.value if hasattr(raw, "value") else (
            str(raw) if raw is not None else "unknown"
        )
        groups.setdefault(key, []).append(m)
    return {k: sorted(v, key=lambda m: m.mappingId) for k, v in groups.items()}
