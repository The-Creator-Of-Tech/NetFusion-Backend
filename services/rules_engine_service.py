"""
Rules Engine
============
Phase A4.5.1 — Deterministic, immutable rule condition, rule, and mapping
management for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model RuleCondition, Rule, RuleMapping, and RuleStatistics as immutable,
  typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_rule_condition, build_rule, build_rule_mapping,
    build_rule_statistics.
- Expose validation functions:
    validate_rule_condition, validate_rule, validate_rule_mapping.
- Expose integration helpers that transform Finding, Alert, ReasoningResult,
  Playbook, and ThreatActor/ThreatCampaign objects into RuleMapping or rule
  reference strings. No AI execution. No network. Transform only.

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
- Rule evaluation, execution, CRUD, Merge, Search, Sort, Filter, Grouping,
  Bulk Operations, Smoke Test.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from core.constants import RULES_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("rules_engine_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_RULES_NS = uuid.UUID("6ba7b884-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class RuleSeverityEnum(str, Enum):
    """Rule severity classification."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class RuleStatusEnum(str, Enum):
    """Rule lifecycle status."""
    DRAFT    = "DRAFT"
    ACTIVE   = "ACTIVE"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class RuleActionEnum(str, Enum):
    """Actions a rule can trigger when it matches."""
    CREATE_FINDING     = "CREATE_FINDING"
    CREATE_ALERT       = "CREATE_ALERT"
    UPDATE_SEVERITY    = "UPDATE_SEVERITY"
    TAG_INVESTIGATION  = "TAG_INVESTIGATION"
    START_PLAYBOOK     = "START_PLAYBOOK"
    ADD_TIMELINE_EVENT = "ADD_TIMELINE_EVENT"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class RulesEngineError(Exception):
    """Base class for all Rules Engine errors."""


class InvalidRuleError(RulesEngineError):
    """Raised when a Rule fails validation."""


class InvalidRuleConditionError(RulesEngineError):
    """Raised when a RuleCondition fails validation."""


class InvalidRuleMappingError(RulesEngineError):
    """Raised when a RuleMapping fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class RuleCondition(BaseModel):
    """
    One immutable rule condition record.

    Identity
    --------
    conditionKey : SHA256(field + operator + value)[:32]
    conditionId  : UUIDv5(_RULES_NS, conditionKey)

    Fields
    ------
    conditionId  : deterministic UUID derived from conditionKey.
    conditionKey : 32-char SHA-256 identity key.
    field        : the data field this condition evaluates (non-empty).
    operator     : the comparison operator (e.g. "eq", "gt", "contains").
    value        : the value to compare against (string-encoded).
    createdAt    : ISO-8601 timestamp (caller-supplied for determinism).
    """
    conditionId  : str
    conditionKey : str
    field        : str
    operator     : str
    value        : str
    createdAt    : str

    class Config:
        frozen = True


class Rule(BaseModel):
    """
    One immutable Rule record representing a detection or response rule.

    Identity
    --------
    ruleKey : SHA256(ruleKey + severity.value +
                     sorted(conditionIds) + sorted(actions))[:32]
    ruleId  : UUIDv5(_RULES_NS, ruleKey)

    Fields
    ------
    ruleId       : deterministic UUID derived from ruleKey.
    ruleKey      : 32-char SHA-256 identity key.
    name         : human-readable rule name (non-empty).
    description  : detailed rule description.
    severity     : RuleSeverityEnum — threat severity classification.
    status       : RuleStatusEnum — lifecycle status.
    conditions   : sorted tuple of RuleCondition objects (by conditionId ASC).
    actions      : sorted tuple of RuleActionEnum values for this rule.
    priority     : integer priority; lower number = higher priority (>= 1).
    createdAt    : ISO-8601 timestamp (caller-supplied for determinism).
    """
    ruleId      : str
    ruleKey     : str
    name        : str
    description : str
    severity    : RuleSeverityEnum
    status      : RuleStatusEnum
    conditions  : Tuple[RuleCondition, ...]
    actions     : Tuple[RuleActionEnum, ...]
    priority    : int
    createdAt   : str

    class Config:
        frozen = True


class RuleMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to matched Rules.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(matchedRules))[:32]
    mappingId          : UUIDv5(_RULES_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(matchedRules))[:32]

    Fields
    ------
    mappingId          : deterministic UUID.
    mappingKey         : 32-char SHA-256 identity key.
    findingId          : ID of the linked Finding (may be empty).
    alertId            : ID of the linked Alert (may be empty).
    reasoningId        : ID of the linked ReasoningResult (may be empty).
    matchedRules       : sorted tuple of Rule objects that matched
                         (sorted by priority ASC then ruleId ASC).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    mappingFingerprint : deterministic 32-char content fingerprint.
    createdAt          : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    matchedRules       : Tuple[Rule, ...]
    confidence         : float
    mappingFingerprint : str
    createdAt          : str

    class Config:
        frozen = True


class RuleStatistics(BaseModel):
    """
    Aggregate statistics over a collection of Rule objects.

    Fields
    ------
    totalRules      : total count of distinct rules.
    activeRules     : count of rules with status == ACTIVE.
    draftRules      : count of rules with status == DRAFT.
    disabledRules   : count of rules with status == DISABLED.
    archivedRules   : count of rules with status == ARCHIVED.
    averagePriority : mean rule.priority across all rules (0.0 if empty).
    severityCounts  : dict mapping RuleSeverityEnum.value → count
                      (only keys with count > 0 are present).
    actionCounts    : dict mapping RuleActionEnum.value → count of rules
                      that include that action (only keys with count > 0).
    """
    totalRules      : int
    activeRules     : int
    draftRules      : int
    disabledRules   : int
    archivedRules   : int
    averagePriority : float
    severityCounts  : Dict[str, int]
    actionCounts    : Dict[str, int]

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
    """UUIDv5(_RULES_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_RULES_NS, key))


def _norm(s: str) -> str:
    """Strip a string; return empty string if None."""
    return s.strip() if s else ""


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


# ---------------------------------------------------------------------------
# Public key derivation functions (named per spec)
# ---------------------------------------------------------------------------

def conditionKey(field: str, operator: str, value: str) -> str:
    """
    conditionKey = SHA256(field + operator + value)[:32]

    Null-byte-separated to prevent cross-field collisions.
    Same (field, operator, value) triple always produces the same key.
    """
    return _sha256_32(field.strip(), operator.strip(), value.strip())


def ruleKey(
    name       : str,
    severity   : RuleSeverityEnum,
    condition_ids: Tuple[str, ...],
    actions    : Tuple[RuleActionEnum, ...],
) -> str:
    """
    ruleKey = SHA256(name + severity.value +
                     sorted(conditionIds) + sorted(actions))[:32]

    Null-byte-separated to prevent cross-field collisions.
    conditionIds and actions sorted before joining for order-independence.
    """
    sorted_cids    = "\x01".join(sorted(condition_ids))
    sorted_actions = "\x01".join(sorted(a.value for a in actions))
    return _sha256_32(name.strip(), severity.value, sorted_cids, sorted_actions)


def mappingKey(
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    rule_ids     : Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(ruleIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    ruleIds sorted before joining for order-independence.
    """
    sorted_rids = "\x01".join(sorted(rule_ids))
    return _sha256_32(
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_rids,
    )


def mappingFingerprint(
    m_key        : str,
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    rule_ids     : Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(ruleIds))[:32]
    """
    sorted_rids = "\x01".join(sorted(rule_ids))
    return _sha256_32(
        m_key,
        _norm(finding_id),
        _norm(alert_id),
        _norm(reasoning_id),
        sorted_rids,
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_rule_condition(
    field      : str,
    operator   : str,
    value      : str,
    created_at : str,
) -> None:
    """
    Validate RuleCondition construction parameters.

    Checks
    ------
    - field is non-empty.
    - operator is non-empty.
    - value is non-empty.
    - created_at is non-empty.

    Raises
    ------
    InvalidRuleConditionError : if any rule is violated.
    """
    errors: List[str] = []

    if not field or not field.strip():
        errors.append("field must not be empty.")
    if not operator or not operator.strip():
        errors.append("operator must not be empty.")
    if not value or not value.strip():
        errors.append("value must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_rule_condition", "errors": errors},
        )
        raise InvalidRuleConditionError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_rule(
    name       : str,
    severity   : RuleSeverityEnum,
    status     : RuleStatusEnum,
    priority   : int,
    created_at : str,
) -> None:
    """
    Validate Rule construction parameters.

    Checks
    ------
    - name is non-empty.
    - severity is a valid RuleSeverityEnum member.
    - status is a valid RuleStatusEnum member.
    - priority is a positive integer (>= 1).
    - created_at is non-empty.

    Raises
    ------
    InvalidRuleError : if any rule is violated.
    """
    errors: List[str] = []

    if not name or not name.strip():
        errors.append("name must not be empty.")
    if not isinstance(severity, RuleSeverityEnum):
        errors.append(
            f"severity must be a RuleSeverityEnum member; got {severity!r}."
        )
    if not isinstance(status, RuleStatusEnum):
        errors.append(
            f"status must be a RuleStatusEnum member; got {status!r}."
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
            extra={"validator": "validate_rule", "errors": errors},
        )
        raise InvalidRuleError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_rule_mapping(
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    confidence   : float,
    created_at   : str,
) -> None:
    """
    Validate RuleMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence is in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidRuleMappingError : if any rule is violated.
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
            extra={"validator": "validate_rule_mapping", "errors": errors},
        )
        raise InvalidRuleMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_rule_condition()
# ===========================================================================

def build_rule_condition(
    field      : str,
    operator   : str,
    value      : str,
    created_at : str,
    validate   : bool = True,
) -> RuleCondition:
    """
    Build an immutable RuleCondition.

    conditionKey = SHA256(field + operator + value)[:32]
    conditionId  = UUIDv5(_RULES_NS, conditionKey)

    Parameters
    ----------
    field      : data field this condition evaluates (non-empty).
    operator   : comparison operator string (non-empty, e.g. "eq", "gt").
    value      : value to compare against (non-empty, string-encoded).
    created_at : ISO-8601 timestamp (caller-supplied for determinism).
    validate   : if True, run validate_rule_condition() first.

    Returns
    -------
    RuleCondition (frozen / immutable)

    Raises
    ------
    InvalidRuleConditionError : if validate=True and condition validation fails.
    """
    if validate:
        validate_rule_condition(field, operator, value, created_at)

    c_key = conditionKey(field, operator, value)
    c_id  = _uuid5(c_key)

    return RuleCondition(
        conditionId  = c_id,
        conditionKey = c_key,
        field        = field.strip(),
        operator     = operator.strip(),
        value        = value.strip(),
        createdAt    = created_at,
    )


# ===========================================================================
# Builder: build_rule()
# ===========================================================================

def build_rule(
    name        : str,
    severity    : RuleSeverityEnum,
    created_at  : str,
    description : str                          = "",
    status      : RuleStatusEnum               = RuleStatusEnum.DRAFT,
    conditions  : Optional[List[RuleCondition]] = None,
    actions     : Optional[List[RuleActionEnum]] = None,
    priority    : int                          = 100,
    validate    : bool                         = True,
) -> Rule:
    """
    Build an immutable Rule.

    ruleKey = SHA256(name + severity.value +
                     sorted(conditionIds) + sorted(actions))[:32]
    ruleId  = UUIDv5(_RULES_NS, ruleKey)

    Parameters
    ----------
    name        : human-readable rule name (non-empty).
    severity    : RuleSeverityEnum — threat severity classification.
    created_at  : ISO-8601 timestamp (caller-supplied for determinism).
    description : detailed rule description (may be empty).
    status      : RuleStatusEnum — lifecycle status (default DRAFT).
    conditions  : list of RuleCondition objects
                  (sorted by conditionId ASC for determinism).
    actions     : list of RuleActionEnum values for this rule
                  (deduplicated and sorted by .value ASC).
    priority    : integer priority; lower = higher priority (default 100, >= 1).
    validate    : if True, run validate_rule() first.

    Returns
    -------
    Rule (frozen / immutable)

    Raises
    ------
    InvalidRuleError : if validate=True and rule validation fails.
    """
    if validate:
        validate_rule(name, severity, status, priority, created_at)

    # Sort conditions deterministically: conditionId ASC
    sorted_conditions: Tuple[RuleCondition, ...] = tuple(
        sorted(conditions or [], key=lambda c: c.conditionId)
    )

    # Deduplicate and sort actions by .value ASC for determinism
    seen_actions: Dict[str, RuleActionEnum] = {}
    for a in (actions or []):
        if isinstance(a, RuleActionEnum):
            seen_actions[a.value] = a
    sorted_actions: Tuple[RuleActionEnum, ...] = tuple(
        seen_actions[k] for k in sorted(seen_actions)
    )

    # Collect IDs for ruleKey derivation
    condition_ids: Tuple[str, ...] = tuple(c.conditionId for c in sorted_conditions)

    r_key = ruleKey(name, severity, condition_ids, sorted_actions)
    r_id  = _uuid5(r_key)

    return Rule(
        ruleId      = r_id,
        ruleKey     = r_key,
        name        = name.strip(),
        description = description,
        severity    = severity,
        status      = status,
        conditions  = sorted_conditions,
        actions     = sorted_actions,
        priority    = priority,
        createdAt   = created_at,
    )


# ===========================================================================
# Builder: build_rule_mapping()
# ===========================================================================

def build_rule_mapping(
    matched_rules : List[Rule],
    created_at    : str,
    finding_id    : str   = "",
    alert_id      : str   = "",
    reasoning_id  : str   = "",
    confidence    : float = 0.0,
    validate      : bool  = True,
) -> RuleMapping:
    """
    Build an immutable RuleMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(ruleIds))[:32]
    mappingId          = UUIDv5(_RULES_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(ruleIds))[:32]

    Parameters
    ----------
    matched_rules : list of Rule objects that matched in this mapping.
    created_at    : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id    : ID of the linked Finding (may be empty).
    alert_id      : ID of the linked Alert (may be empty).
    reasoning_id  : ID of the linked ReasoningResult (may be empty).
    confidence    : 0.0–100.0 caller-assessed confidence (clamped).
    validate      : if True, run validate_rule_mapping() first.

    Returns
    -------
    RuleMapping (frozen / immutable)

    Raises
    ------
    InvalidRuleMappingError : if validate=True and validation fails.
    """
    clamped_conf = _clamp(float(confidence))

    if validate:
        validate_rule_mapping(
            finding_id, alert_id, reasoning_id, clamped_conf, created_at
        )

    # Deterministic ordering: priority ASC (lower = higher priority),
    # then ruleId ASC as tiebreaker
    sorted_rules: Tuple[Rule, ...] = tuple(
        sorted(matched_rules or [], key=lambda r: (r.priority, r.ruleId))
    )

    # Collect rule IDs for key computation
    r_ids: Tuple[str, ...] = tuple(r.ruleId for r in sorted_rules)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, r_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(m_key, finding_id, alert_id, reasoning_id, r_ids)

    return RuleMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        findingId          = _norm(finding_id),
        alertId            = _norm(alert_id),
        reasoningId        = _norm(reasoning_id),
        matchedRules       = sorted_rules,
        confidence         = round(clamped_conf, 4),
        mappingFingerprint = m_fp,
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_rule_statistics()
# ===========================================================================

def build_rule_statistics(
    rules: List[Rule],
) -> RuleStatistics:
    """
    Compute RuleStatistics over a flat list of Rule objects.

    Deterministic: canonical sort by ruleId ASC before accumulation so
    floating-point sums and counts are identical across every run regardless
    of input ordering.

    Deduplication is by ruleId — first occurrence in sorted order wins.

    Parameters
    ----------
    rules : any list of Rule objects (may contain duplicates by ruleId).

    Returns
    -------
    RuleStatistics (frozen / immutable)
    """
    if not rules:
        return RuleStatistics(
            totalRules      = 0,
            activeRules     = 0,
            draftRules      = 0,
            disabledRules   = 0,
            archivedRules   = 0,
            averagePriority = 0.0,
            severityCounts  = {},
            actionCounts    = {},
        )

    # Canonical sort for deterministic accumulation
    ordered = sorted(rules, key=lambda r: r.ruleId)

    # Deduplicate by ruleId — first occurrence in sorted order wins
    seen_ids: Dict[str, Rule] = {}
    for r in ordered:
        if r.ruleId not in seen_ids:
            seen_ids[r.ruleId] = r

    distinct = list(seen_ids.values())
    # Re-sort after dedup for deterministic counting
    distinct.sort(key=lambda r: r.ruleId)

    total    = len(distinct)
    active   = sum(1 for r in distinct if r.status == RuleStatusEnum.ACTIVE)
    draft    = sum(1 for r in distinct if r.status == RuleStatusEnum.DRAFT)
    disabled = sum(1 for r in distinct if r.status == RuleStatusEnum.DISABLED)
    archived = sum(1 for r in distinct if r.status == RuleStatusEnum.ARCHIVED)

    avg_priority = (
        round(sum(r.priority for r in distinct) / total, 4)
        if total > 0 else 0.0
    )

    return RuleStatistics(
        totalRules      = total,
        activeRules     = active,
        draftRules      = draft,
        disabledRules   = disabled,
        archivedRules   = archived,
        averagePriority = avg_priority,
        severityCounts  = {
            sev.value: cnt
            for sev in RuleSeverityEnum
            for cnt in [sum(1 for r in distinct if r.severity == sev)]
            if cnt > 0
        },
        actionCounts    = {
            act.value: cnt
            for act in RuleActionEnum
            for cnt in [sum(1 for r in distinct if act in r.actions)]
            if cnt > 0
        },
    )


# ===========================================================================
# Integration Helpers
# ===========================================================================
# Pure transformation helpers.  Accept objects from other engine services and
# return RuleMapping objects or rule reference strings.
# No external lookups. No AI execution. No network. Duck-typed input objects
# are accepted so there is no circular import at module load time.


def finding_to_rule_mapping(
    finding      : Any,
    matched_rules: List[Rule],
    created_at   : str,
    confidence   : float = 0.0,
) -> RuleMapping:
    """
    Transform a Finding object into a RuleMapping.

    Extracts findingId from finding.findingId (duck-typed).
    alertId and reasoningId are left empty — caller may override by
    re-building with build_rule_mapping() if needed.

    Parameters
    ----------
    finding       : any object with a .findingId string attribute.
    matched_rules : list of Rule objects that matched this finding.
    created_at    : ISO-8601 timestamp (caller-supplied for determinism).
    confidence    : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    RuleMapping (frozen / immutable)
    """
    finding_id = _norm(getattr(finding, "findingId", ""))
    return build_rule_mapping(
        matched_rules = matched_rules,
        created_at    = created_at,
        finding_id    = finding_id,
        alert_id      = "",
        reasoning_id  = "",
        confidence    = confidence,
    )


def alert_to_rule_mapping(
    alert        : Any,
    matched_rules: List[Rule],
    created_at   : str,
    confidence   : float = 0.0,
) -> RuleMapping:
    """
    Transform an Alert object into a RuleMapping.

    Extracts alertId from alert.alertId (duck-typed).
    findingId is sourced from alert.findingId when present.
    reasoningId is left empty.

    Parameters
    ----------
    alert         : any object with .alertId and optionally .findingId.
    matched_rules : list of Rule objects that matched this alert.
    created_at    : ISO-8601 timestamp (caller-supplied for determinism).
    confidence    : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    RuleMapping (frozen / immutable)
    """
    alert_id   = _norm(getattr(alert, "alertId", ""))
    finding_id = _norm(getattr(alert, "findingId", ""))
    return build_rule_mapping(
        matched_rules = matched_rules,
        created_at    = created_at,
        finding_id    = finding_id,
        alert_id      = alert_id,
        reasoning_id  = "",
        confidence    = confidence,
    )


def reasoning_to_rule_mapping(
    reasoning    : Any,
    matched_rules: List[Rule],
    created_at   : str,
    confidence   : float = 0.0,
) -> RuleMapping:
    """
    Transform a ReasoningResult object into a RuleMapping.

    Extracts reasoningId from reasoning.reasoningId (duck-typed).
    findingId and alertId are left empty.

    Parameters
    ----------
    reasoning     : any object with a .reasoningId string attribute.
    matched_rules : list of Rule objects that matched this reasoning result.
    created_at    : ISO-8601 timestamp (caller-supplied for determinism).
    confidence    : 0.0–100.0 caller-assessed confidence (clamped).

    Returns
    -------
    RuleMapping (frozen / immutable)
    """
    reasoning_id = _norm(getattr(reasoning, "reasoningId", ""))
    return build_rule_mapping(
        matched_rules = matched_rules,
        created_at    = created_at,
        finding_id    = "",
        alert_id      = "",
        reasoning_id  = reasoning_id,
        confidence    = confidence,
    )


def playbook_to_rule_reference(playbook: Any) -> str:
    """
    Extract a stable rule reference string from a Playbook object.

    Returns a string of the form "playbook:<playbookId>" that can be stored
    in rule metadata or condition values to link a Rule to a Playbook without
    creating a circular dependency.

    Parameters
    ----------
    playbook : any object with a .playbookId string attribute (duck-typed).

    Returns
    -------
    str — "playbook:<playbookId>" or "playbook:" if playbookId is absent.
    """
    playbook_id = _norm(getattr(playbook, "playbookId", ""))
    return f"playbook:{playbook_id}"


def threat_to_rule_reference(threat: Any) -> str:
    """
    Extract a stable rule reference string from a ThreatActor or
    ThreatCampaign object.

    Returns a string of the form "threat:<actorId>" or "threat:<campaignId>"
    depending on which attribute is present, so a Rule can reference a threat
    object without a circular import.

    Duck-typed: prefers .actorId, falls back to .campaignId, then empty.

    Parameters
    ----------
    threat : any object with .actorId or .campaignId string attribute.

    Returns
    -------
    str — "threat:<id>" or "threat:" if no recognised ID attribute is found.
    """
    threat_id = _norm(getattr(threat, "actorId", "") or getattr(threat, "campaignId", ""))
    return f"threat:{threat_id}"


# ===========================================================================
# Rule Operations
# ===========================================================================

def add_rule(rules: List[Rule], rule: Rule) -> List[Rule]:
    """
    Add a Rule to a list if its ruleId is not already present.

    Idempotent: duplicate ruleId → returns unchanged list (new list object).
    Result is sorted by ruleId ASC for deterministic ordering.

    Parameters
    ----------
    rules : existing list of Rule objects.
    rule  : Rule to add.

    Returns
    -------
    New sorted List[Rule] (input is not mutated).
    """
    if any(r.ruleId == rule.ruleId for r in rules):
        _log.warning("rule_add_duplicate", extra={"ruleId": rule.ruleId})
        return sorted(list(rules), key=lambda r: r.ruleId)
    result = sorted([*rules, rule], key=lambda r: r.ruleId)
    _log.info("rule_created", extra={"ruleId": rule.ruleId, "ruleName": rule.name})
    return result


def update_rule(
    rules      : List[Rule],
    rule_id    : str,
    updated_at : str,
    name        : Optional[str]                   = None,
    description : Optional[str]                   = None,
    severity    : Optional[RuleSeverityEnum]      = None,
    status      : Optional[RuleStatusEnum]        = None,
    conditions  : Optional[List[RuleCondition]]   = None,
    actions     : Optional[List[RuleActionEnum]]  = None,
    priority    : Optional[int]                   = None,
) -> List[Rule]:
    """
    Return a new list with the matching Rule replaced by an updated copy.

    Identity-stable: ruleKey and ruleId are recomputed only when name,
    severity, conditions, or actions change — content-defining fields.
    If none of those change, the original ruleId / ruleKey are preserved.
    Status, description, priority changes do NOT alter the rule's identity.

    Not-found: returns a new list identical to the input (no mutation).

    Parameters
    ----------
    rules       : existing list of Rule objects.
    rule_id     : ruleId of the Rule to update.
    updated_at  : ISO-8601 timestamp (unused in frozen model, kept for
                  logging/audit symmetry with other engines).
    name / description / severity / status / conditions / actions / priority :
                  fields to update; None → keep existing value.

    Returns
    -------
    New List[Rule] sorted by ruleId ASC (input is not mutated).
    """
    result: List[Rule] = []
    updated = False

    for r in rules:
        if r.ruleId != rule_id:
            result.append(r)
            continue

        new_name        = name        if name        is not None else r.name
        new_description = description if description is not None else r.description
        new_severity    = severity    if severity    is not None else r.severity
        new_status      = status      if status      is not None else r.status
        new_priority    = priority    if priority    is not None else r.priority
        new_conditions  = conditions  if conditions  is not None else list(r.conditions)
        new_actions     = actions     if actions     is not None else list(r.actions)

        # Determine whether identity-defining fields changed
        identity_changed = (
            name       is not None and name.strip() != r.name
            or severity   is not None and severity != r.severity
            or conditions is not None
            or actions    is not None
        )

        if identity_changed:
            # Rebuild with full key recomputation
            new_rule = build_rule(
                name        = new_name,
                severity    = new_severity,
                created_at  = r.createdAt,
                description = new_description,
                status      = new_status,
                conditions  = new_conditions,
                actions     = new_actions,
                priority    = new_priority,
                validate    = False,
            )
        else:
            # Only metadata changed — preserve ruleId / ruleKey
            new_rule = Rule(
                ruleId      = r.ruleId,
                ruleKey     = r.ruleKey,
                name        = new_name.strip(),
                description = new_description,
                severity    = new_severity,
                status      = new_status,
                conditions  = r.conditions,
                actions     = r.actions,
                priority    = new_priority,
                createdAt   = r.createdAt,
            )

        result.append(new_rule)
        updated = True
        _log.info("rule_updated", extra={"ruleId": rule_id, "identity_changed": identity_changed})

    if not updated:
        _log.warning("rule_update_not_found", extra={"ruleId": rule_id})

    return sorted(result, key=lambda r: r.ruleId)


def remove_rule(rules: List[Rule], rule_id: str) -> List[Rule]:
    """
    Return a new list with the Rule identified by rule_id removed.

    Idempotent: not-found → returns a new copy of the original list.
    Result is sorted by ruleId ASC.

    Parameters
    ----------
    rules   : existing list of Rule objects.
    rule_id : ruleId to remove.

    Returns
    -------
    New List[Rule] sorted by ruleId ASC (input is not mutated).
    """
    result = [r for r in rules if r.ruleId != rule_id]
    if len(result) < len(rules):
        _log.info("rule_removed", extra={"ruleId": rule_id})
    else:
        _log.warning("rule_remove_not_found", extra={"ruleId": rule_id})
    return sorted(result, key=lambda r: r.ruleId)


def merge_rules(base: List[Rule], incoming: List[Rule]) -> List[Rule]:
    """
    Merge two Rule lists; base takes priority on ruleId collision.

    Deterministic: canonical sort by ruleId ASC on output.
    Deduplication: first occurrence (base wins) kept for duplicate ruleIds.

    Parameters
    ----------
    base     : authoritative list; wins on duplicate ruleId.
    incoming : list to merge in; adds only rules absent from base.

    Returns
    -------
    New sorted List[Rule] (neither input is mutated).
    """
    seen: Dict[str, Rule] = {}
    for r in sorted(base, key=lambda r: r.ruleId):
        if r.ruleId not in seen:
            seen[r.ruleId] = r
    for r in sorted(incoming, key=lambda r: r.ruleId):
        if r.ruleId not in seen:
            seen[r.ruleId] = r
    result = sorted(seen.values(), key=lambda r: r.ruleId)
    _log.info("merge_completed", extra={"type": "rules", "total": len(result)})
    return result

# ===========================================================================
# Condition Operations
# ===========================================================================

def add_rule_condition(rule: Rule, condition: RuleCondition) -> Rule:
    """
    Return a new Rule with condition added (if not already present by conditionId).

    The ruleKey / ruleId are recomputed because conditions are identity-defining.
    Idempotent: duplicate conditionId → returns rebuilt Rule with same identity.

    Parameters
    ----------
    rule      : source Rule (not mutated).
    condition : RuleCondition to add.

    Returns
    -------
    New Rule (frozen).
    """
    existing_ids = {c.conditionId for c in rule.conditions}
    if condition.conditionId in existing_ids:
        _log.warning("condition_add_duplicate", extra={"conditionId": condition.conditionId})
        return rule
    new_conditions = sorted([*rule.conditions, condition], key=lambda c: c.conditionId)
    new_rule = build_rule(
        name        = rule.name,
        severity    = rule.severity,
        created_at  = rule.createdAt,
        description = rule.description,
        status      = rule.status,
        conditions  = list(new_conditions),
        actions     = list(rule.actions),
        priority    = rule.priority,
        validate    = False,
    )
    _log.info("condition_created", extra={"conditionId": condition.conditionId, "ruleId": new_rule.ruleId})
    return new_rule


def update_rule_condition(
    rule         : Rule,
    condition_id : str,
    field        : Optional[str] = None,
    operator     : Optional[str] = None,
    value        : Optional[str] = None,
    created_at   : Optional[str] = None,
) -> Rule:
    """
    Return a new Rule with the matching RuleCondition replaced.

    The conditionKey / conditionId of the updated condition are recomputed
    when field, operator, or value change (identity-defining fields).
    The Rule's ruleKey / ruleId are also recomputed.
    Not-found conditionId → returns the original Rule unchanged.

    Parameters
    ----------
    rule         : source Rule (not mutated).
    condition_id : conditionId of the condition to update.
    field / operator / value / created_at : fields to change; None → keep existing.

    Returns
    -------
    New Rule (frozen).
    """
    new_conditions: List[RuleCondition] = []
    found = False

    for c in rule.conditions:
        if c.conditionId != condition_id:
            new_conditions.append(c)
            continue
        found = True
        new_field    = field    if field    is not None else c.field
        new_operator = operator if operator is not None else c.operator
        new_value    = value    if value    is not None else c.value
        new_ts       = created_at if created_at is not None else c.createdAt
        updated_c = build_rule_condition(
            new_field, new_operator, new_value, new_ts, validate=False
        )
        new_conditions.append(updated_c)
        _log.info("condition_updated", extra={
            "old_conditionId": condition_id,
            "new_conditionId": updated_c.conditionId,
        })

    if not found:
        _log.warning("condition_update_not_found", extra={"conditionId": condition_id})
        return rule

    return build_rule(
        name        = rule.name,
        severity    = rule.severity,
        created_at  = rule.createdAt,
        description = rule.description,
        status      = rule.status,
        conditions  = new_conditions,
        actions     = list(rule.actions),
        priority    = rule.priority,
        validate    = False,
    )


def remove_rule_condition(rule: Rule, condition_id: str) -> Rule:
    """
    Return a new Rule with the matching RuleCondition removed.

    ruleKey / ruleId are recomputed (conditions are identity-defining).
    Idempotent: not-found conditionId → returns original Rule unchanged.

    Parameters
    ----------
    rule         : source Rule (not mutated).
    condition_id : conditionId to remove.

    Returns
    -------
    New Rule (frozen).
    """
    remaining = [c for c in rule.conditions if c.conditionId != condition_id]
    if len(remaining) == len(rule.conditions):
        _log.warning("condition_remove_not_found", extra={"conditionId": condition_id})
        return rule
    new_rule = build_rule(
        name        = rule.name,
        severity    = rule.severity,
        created_at  = rule.createdAt,
        description = rule.description,
        status      = rule.status,
        conditions  = remaining,
        actions     = list(rule.actions),
        priority    = rule.priority,
        validate    = False,
    )
    _log.info("condition_removed", extra={"conditionId": condition_id, "ruleId": new_rule.ruleId})
    return new_rule


def merge_rule_conditions(rule: Rule, incoming: List[RuleCondition]) -> Rule:
    """
    Merge incoming RuleConditions into a Rule; existing conditions win on collision.

    Deterministic: canonical sort by conditionId ASC.
    Deduplication: first occurrence (existing) kept for duplicate conditionIds.
    If no new conditions are added the original Rule object is returned unchanged.

    Parameters
    ----------
    rule     : source Rule (not mutated).
    incoming : list of RuleCondition objects to merge in.

    Returns
    -------
    New Rule (or original if no change).
    """
    existing_ids = {c.conditionId for c in rule.conditions}
    new_ones = [c for c in incoming if c.conditionId not in existing_ids]
    if not new_ones:
        return rule
    merged = sorted([*rule.conditions, *new_ones], key=lambda c: c.conditionId)
    new_rule = build_rule(
        name        = rule.name,
        severity    = rule.severity,
        created_at  = rule.createdAt,
        description = rule.description,
        status      = rule.status,
        conditions  = list(merged),
        actions     = list(rule.actions),
        priority    = rule.priority,
        validate    = False,
    )
    _log.info("merge_completed", extra={"type": "conditions", "added": len(new_ones), "ruleId": new_rule.ruleId})
    return new_rule

# ===========================================================================
# Mapping Operations
# ===========================================================================

def add_rule_mapping(mappings: List[RuleMapping], mapping: RuleMapping) -> List[RuleMapping]:
    """
    Add a RuleMapping to a list if its mappingId is not already present.

    Idempotent: duplicate mappingId → returns a new copy of the list unchanged.
    Result is sorted by mappingId ASC.

    Parameters
    ----------
    mappings : existing list of RuleMapping objects.
    mapping  : RuleMapping to add.

    Returns
    -------
    New sorted List[RuleMapping] (input is not mutated).
    """
    if any(m.mappingId == mapping.mappingId for m in mappings):
        _log.warning("mapping_add_duplicate", extra={"mappingId": mapping.mappingId})
        return sorted(list(mappings), key=lambda m: m.mappingId)
    result = sorted([*mappings, mapping], key=lambda m: m.mappingId)
    _log.info("mapping_created", extra={"mappingId": mapping.mappingId})
    return result


def remove_rule_mapping(mappings: List[RuleMapping], mapping_id: str) -> List[RuleMapping]:
    """
    Return a new list with the RuleMapping identified by mapping_id removed.

    Idempotent: not-found → returns a new copy of the original list.
    Result is sorted by mappingId ASC.

    Parameters
    ----------
    mappings   : existing list of RuleMapping objects.
    mapping_id : mappingId to remove.

    Returns
    -------
    New sorted List[RuleMapping] (input is not mutated).
    """
    result = [m for m in mappings if m.mappingId != mapping_id]
    if len(result) < len(mappings):
        _log.info("mapping_removed", extra={"mappingId": mapping_id})
    else:
        _log.warning("mapping_remove_not_found", extra={"mappingId": mapping_id})
    return sorted(result, key=lambda m: m.mappingId)


def merge_rule_mappings(
    base     : List[RuleMapping],
    incoming : List[RuleMapping],
) -> List[RuleMapping]:
    """
    Merge two RuleMapping lists; base takes priority on mappingId collision.

    Deterministic: canonical sort by mappingId ASC on output.

    Parameters
    ----------
    base     : authoritative list; wins on duplicate mappingId.
    incoming : list to merge in; adds only mappings absent from base.

    Returns
    -------
    New sorted List[RuleMapping] (neither input is mutated).
    """
    seen: Dict[str, RuleMapping] = {}
    for m in sorted(base, key=lambda m: m.mappingId):
        if m.mappingId not in seen:
            seen[m.mappingId] = m
    for m in sorted(incoming, key=lambda m: m.mappingId):
        if m.mappingId not in seen:
            seen[m.mappingId] = m
    result = sorted(seen.values(), key=lambda m: m.mappingId)
    _log.info("merge_completed", extra={"type": "mappings", "total": len(result)})
    return result

# ===========================================================================
# Search Utilities
# ===========================================================================

def find_rule(
    rules      : List[Rule],
    rule_id    : Optional[str] = None,
    rule_key   : Optional[str] = None,
) -> Optional[Rule]:
    """
    Return the first Rule matching the given criterion, or None.

    Parameters
    ----------
    rules    : list to search.
    rule_id  : search by ruleId (exact match).
    rule_key : search by ruleKey (exact match).

    Returns None if no criterion is supplied or no match is found.
    """
    if rule_id is not None:
        for r in rules:
            if r.ruleId == rule_id:
                return r
    if rule_key is not None:
        for r in rules:
            if r.ruleKey == rule_key:
                return r
    return None


def find_rule_condition(
    rules        : List[Rule],
    condition_id  : Optional[str] = None,
    condition_key : Optional[str] = None,
) -> Optional[RuleCondition]:
    """
    Search all conditions across a list of Rules and return the first match.

    Parameters
    ----------
    rules         : list of Rule objects to search within.
    condition_id  : search by conditionId (exact match).
    condition_key : search by conditionKey (exact match).

    Returns None if no criterion is supplied or no match is found.
    """
    for r in rules:
        for c in r.conditions:
            if condition_id  is not None and c.conditionId  == condition_id:
                return c
            if condition_key is not None and c.conditionKey == condition_key:
                return c
    return None


def find_rule_mapping(
    mappings   : List[RuleMapping],
    mapping_id : Optional[str] = None,
) -> Optional[RuleMapping]:
    """
    Return the first RuleMapping matching the given criterion, or None.

    Parameters
    ----------
    mappings   : list to search.
    mapping_id : search by mappingId (exact match).

    Returns None if no criterion is supplied or no match is found.
    """
    if mapping_id is not None:
        for m in mappings:
            if m.mappingId == mapping_id:
                return m
    return None

# ===========================================================================
# Sorting
# ===========================================================================

# Severity sort order (higher = more severe)
_SEVERITY_ORDER: Dict[RuleSeverityEnum, int] = {
    RuleSeverityEnum.CRITICAL : 4,
    RuleSeverityEnum.HIGH     : 3,
    RuleSeverityEnum.MEDIUM   : 2,
    RuleSeverityEnum.LOW      : 1,
}

# Status sort order (higher = more actionable)
_STATUS_ORDER: Dict[RuleStatusEnum, int] = {
    RuleStatusEnum.ACTIVE   : 4,
    RuleStatusEnum.DRAFT    : 3,
    RuleStatusEnum.DISABLED : 2,
    RuleStatusEnum.ARCHIVED : 1,
}

_VALID_RULE_SORT_KEYS = frozenset({"name", "severity", "status", "priority", "createdAt"})
_VALID_CONDITION_SORT_KEYS = frozenset({"field", "operator", "value", "createdAt"})
_VALID_MAPPING_SORT_KEYS = frozenset({"confidence", "createdAt", "findingId", "alertId"})


def sort_rules(
    rules     : List[Rule],
    by        : str  = "priority",
    ascending : bool = True,
) -> List[Rule]:
    """
    Return a new sorted list of Rules.

    Parameters
    ----------
    by        : "priority" (default) | "name" | "severity" | "status" | "createdAt"
    ascending : True = ascending (default for priority: lowest number first).

    Tie-breaking is always by ruleId ASC for full determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_RULE_SORT_KEYS:
        raise ValueError(
            f"sort_rules: unknown key '{by}'. Valid: {sorted(_VALID_RULE_SORT_KEYS)}"
        )

    def _key(r: Rule) -> tuple:
        if by == "severity":
            primary = _SEVERITY_ORDER.get(r.severity, 0)
        elif by == "status":
            primary = _STATUS_ORDER.get(r.status, 0)
        elif by == "priority":
            primary = r.priority
        else:
            primary = getattr(r, by, "")
        return (primary, r.ruleId)

    return sorted(rules, key=_key, reverse=not ascending)


def sort_rule_conditions(
    conditions : List[RuleCondition],
    by         : str  = "field",
    ascending  : bool = True,
) -> List[RuleCondition]:
    """
    Return a new sorted list of RuleConditions.

    Parameters
    ----------
    by        : "field" (default) | "operator" | "value" | "createdAt"
    ascending : True = ascending (default).

    Tie-breaking is always by conditionId ASC.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_CONDITION_SORT_KEYS:
        raise ValueError(
            f"sort_rule_conditions: unknown key '{by}'. Valid: {sorted(_VALID_CONDITION_SORT_KEYS)}"
        )

    def _key(c: RuleCondition) -> tuple:
        return (getattr(c, by, ""), c.conditionId)

    return sorted(conditions, key=_key, reverse=not ascending)


def sort_rule_mappings(
    mappings  : List[RuleMapping],
    by        : str  = "confidence",
    ascending : bool = False,
) -> List[RuleMapping]:
    """
    Return a new sorted list of RuleMappings.

    Parameters
    ----------
    by        : "confidence" (default) | "createdAt" | "findingId" | "alertId"
    ascending : False = descending confidence (highest first, default).

    Tie-breaking is always by mappingId ASC.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_MAPPING_SORT_KEYS:
        raise ValueError(
            f"sort_rule_mappings: unknown key '{by}'. Valid: {sorted(_VALID_MAPPING_SORT_KEYS)}"
        )

    def _key(m: RuleMapping) -> tuple:
        return (getattr(m, by, ""), m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)

# ===========================================================================
# Filtering
# ===========================================================================

def filter_rules(
    rules           : List[Rule],
    severity        : Optional[RuleSeverityEnum] = None,
    status          : Optional[RuleStatusEnum]   = None,
    min_priority    : Optional[int]              = None,
    max_priority    : Optional[int]              = None,
    action          : Optional[RuleActionEnum]   = None,
) -> List[Rule]:
    """
    Filter rules by one or more criteria (all ANDed together).

    Parameters
    ----------
    severity     : keep only rules with this severity.
    status       : keep only rules with this status.
    min_priority : keep rules with priority >= min_priority.
    max_priority : keep rules with priority <= max_priority.
    action       : keep rules that include this RuleActionEnum.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[Rule] = []
    for r in rules:
        if severity     is not None and r.severity != severity:
            continue
        if status       is not None and r.status   != status:
            continue
        if min_priority is not None and r.priority < min_priority:
            continue
        if max_priority is not None and r.priority > max_priority:
            continue
        if action       is not None and action not in r.actions:
            continue
        result.append(r)
    return result


def filter_rule_conditions(
    conditions  : List[RuleCondition],
    field       : Optional[str] = None,
    operator    : Optional[str] = None,
    value       : Optional[str] = None,
) -> List[RuleCondition]:
    """
    Filter rule conditions by one or more criteria (all ANDed together).

    All string comparisons are case-insensitive substring matches.

    Parameters
    ----------
    field    : keep conditions whose field contains this string (case-insensitive).
    operator : keep conditions whose operator equals this string (case-insensitive).
    value    : keep conditions whose value contains this string (case-insensitive).

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[RuleCondition] = []
    for c in conditions:
        if field    is not None and field.lower()    not in c.field.lower():
            continue
        if operator is not None and operator.lower() != c.operator.lower():
            continue
        if value    is not None and value.lower()    not in c.value.lower():
            continue
        result.append(c)
    return result


def filter_rule_mappings(
    mappings        : List[RuleMapping],
    finding_id      : Optional[str]   = None,
    alert_id        : Optional[str]   = None,
    reasoning_id    : Optional[str]   = None,
    min_confidence  : Optional[float] = None,
    max_confidence  : Optional[float] = None,
    severity        : Optional[RuleSeverityEnum] = None,
) -> List[RuleMapping]:
    """
    Filter rule mappings by one or more criteria (all ANDed together).

    Parameters
    ----------
    finding_id     : keep mappings whose findingId equals this string.
    alert_id       : keep mappings whose alertId equals this string.
    reasoning_id   : keep mappings whose reasoningId equals this string.
    min_confidence : keep mappings with confidence >= min_confidence.
    max_confidence : keep mappings with confidence <= max_confidence.
    severity       : keep mappings that contain at least one Rule with this severity.

    Returns
    -------
    New filtered list (input is not mutated).
    """
    result: List[RuleMapping] = []
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
            if not any(r.severity == severity for r in m.matchedRules):
                continue
        result.append(m)
    return result

# ===========================================================================
# Grouping
# ===========================================================================

def group_rules(
    rules    : List[Rule],
    group_by : str = "severity",
) -> Dict[str, List[Rule]]:
    """
    Group rules by a string attribute.

    Supported group_by values
    -------------------------
    "severity" : groups by RuleSeverityEnum.value
    "status"   : groups by RuleStatusEnum.value
    "priority" : groups by str(rule.priority)
    "action"   : multi-group — a Rule appears in every group for each of its actions

    Each group list is sorted by ruleId ASC for determinism.
    Rules with no applicable value (empty action list for "action") go to "unknown".

    Parameters
    ----------
    rules    : list of Rule objects.
    group_by : grouping dimension (see above).

    Returns
    -------
    Dict[str, List[Rule]] — each group sorted by ruleId ASC.
    """
    groups: Dict[str, List[Rule]] = {}

    for r in rules:
        if group_by == "severity":
            keys = [r.severity.value]
        elif group_by == "status":
            keys = [r.status.value]
        elif group_by == "priority":
            keys = [str(r.priority)]
        elif group_by == "action":
            keys = [a.value for a in r.actions] if r.actions else ["unknown"]
        else:
            raw = getattr(r, group_by, None)
            keys = [raw.value if hasattr(raw, "value") else str(raw) if raw is not None else "unknown"]

        for k in keys:
            groups.setdefault(k, []).append(r)

    return {k: sorted(v, key=lambda r: r.ruleId) for k, v in groups.items()}


def group_rule_conditions(
    conditions : List[RuleCondition],
    group_by   : str = "field",
) -> Dict[str, List[RuleCondition]]:
    """
    Group rule conditions by a string attribute.

    Supported group_by values
    -------------------------
    "field"    : groups by condition.field
    "operator" : groups by condition.operator
    "value"    : groups by condition.value (exact)

    Each group list is sorted by conditionId ASC.
    Unknown group_by attributes fall back to key "unknown".

    Parameters
    ----------
    conditions : list of RuleCondition objects.
    group_by   : grouping dimension.

    Returns
    -------
    Dict[str, List[RuleCondition]] — each group sorted by conditionId ASC.
    """
    groups: Dict[str, List[RuleCondition]] = {}

    for c in conditions:
        raw = getattr(c, group_by, None)
        key = str(raw) if raw is not None else "unknown"
        groups.setdefault(key, []).append(c)

    return {k: sorted(v, key=lambda c: c.conditionId) for k, v in groups.items()}


def group_rule_mappings(
    mappings : List[RuleMapping],
    group_by : str = "severity",
) -> Dict[str, List[RuleMapping]]:
    """
    Group rule mappings by a dimension of the contained matched Rules.

    Supported group_by values
    -------------------------
    "severity" : multi-group — mapping appears in every severity group
                 of its matchedRules; "unknown" when matchedRules is empty.
    "status"   : multi-group — same logic for rule status.
    "priority" : multi-group — keyed by str(rule.priority).
    "action"   : multi-group — keyed by RuleActionEnum.value of each rule action.

    Each group list is sorted by mappingId ASC.

    Parameters
    ----------
    mappings : list of RuleMapping objects.
    group_by : grouping dimension.

    Returns
    -------
    Dict[str, List[RuleMapping]] — each group sorted by mappingId ASC.
    """
    groups: Dict[str, List[RuleMapping]] = {}

    for m in mappings:
        if not m.matchedRules:
            groups.setdefault("unknown", []).append(m)
            continue

        keys_seen: set = set()
        for r in m.matchedRules:
            if group_by == "severity":
                keys = [r.severity.value]
            elif group_by == "status":
                keys = [r.status.value]
            elif group_by == "priority":
                keys = [str(r.priority)]
            elif group_by == "action":
                keys = [a.value for a in r.actions] if r.actions else ["unknown"]
            else:
                raw = getattr(r, group_by, None)
                keys = [raw.value if hasattr(raw, "value") else str(raw) if raw is not None else "unknown"]

            for k in keys:
                if k not in keys_seen:
                    keys_seen.add(k)
                    groups.setdefault(k, []).append(m)

    return {k: sorted(v, key=lambda m: m.mappingId) for k, v in groups.items()}
