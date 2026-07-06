"""
MITRE ATT&CK Engine (Attack Service)
======================================
Phase A4.3.7 — Deterministic, immutable MITRE ATT&CK technique and mapping
objects for the NetFusion investigation pipeline.

Responsibilities
----------------
- Model MitreTechnique and MitreMapping as immutable, typed objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute mappingFingerprint for cache/replay stability.
- Expose builder functions:
    build_mitre_technique, build_mitre_mapping, build_mitre_statistics.
- Expose validation functions:
    validate_technique, validate_mapping.
- Expose integration helpers that transform Finding, Alert, and
  ReasoningResult objects into MitreMapping objects without executing AI.

Design principles
-----------------
- All models are immutable (frozen=True Pydantic models).
- All builder/utility functions return NEW objects; nothing is mutated.
- Fully deterministic: same inputs → same outputs across every run.
- No uuid4(). No random module. No unordered set iteration.
- Deterministic IDs via SHA-256 + UUIDv5 only.
- Engine version from core/constants.py — never hardcoded.
- No HTTP. No TAXII. No STIX download. No MITRE website calls.
- No database. No frontend. No AI execution.
- Provider-agnostic.

Out of scope
------------
- STIX/TAXII fetching, ATT&CK Navigator integration, live lookups.
- Streaming, retry/failover, HTTP, websocket.
- Actual AI execution.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from core.constants import MITRE_ATTACK_ENGINE_VERSION
from core.logging import get_logger

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
_log = get_logger("mitre_attack_service")

# ---------------------------------------------------------------------------
# UUIDv5 namespace — fixed; never change (invalidates stored IDs)
# ---------------------------------------------------------------------------
_MITRE_ATTACK_NS = uuid.UUID("6ba7b850-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class TacticEnum(str, Enum):
    """All fourteen Enterprise ATT&CK tactics."""
    RECONNAISSANCE        = "RECONNAISSANCE"
    RESOURCE_DEVELOPMENT  = "RESOURCE_DEVELOPMENT"
    INITIAL_ACCESS        = "INITIAL_ACCESS"
    EXECUTION             = "EXECUTION"
    PERSISTENCE           = "PERSISTENCE"
    PRIVILEGE_ESCALATION  = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION       = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS     = "CREDENTIAL_ACCESS"
    DISCOVERY             = "DISCOVERY"
    LATERAL_MOVEMENT      = "LATERAL_MOVEMENT"
    COLLECTION            = "COLLECTION"
    COMMAND_AND_CONTROL   = "COMMAND_AND_CONTROL"
    EXFILTRATION          = "EXFILTRATION"
    IMPACT                = "IMPACT"


# ===========================================================================
# Typed Exceptions
# ===========================================================================

class MitreAttackError(Exception):
    """Base class for all MITRE ATT&CK Engine errors."""


class InvalidTechniqueError(MitreAttackError):
    """Raised when a MitreTechnique fails validation."""


class InvalidTacticError(MitreAttackError):
    """Raised when a tactic value fails validation."""


class InvalidMitreMappingError(MitreAttackError):
    """Raised when a MitreMapping fails validation."""


# ===========================================================================
# Immutable Pydantic models (frozen=True)
# ===========================================================================

class MitreTechnique(BaseModel):
    """
    One immutable ATT&CK technique record.

    Identity
    --------
    techniqueKey : SHA256(mitreId.upper())[:32]
    techniqueId  : UUIDv5(_MITRE_ATTACK_NS, techniqueKey)

    Fields
    ------
    techniqueId   : deterministic UUID derived from techniqueKey.
    techniqueKey  : 32-char SHA-256 key.
    mitreId       : ATT&CK technique ID string (e.g. "T1059", "T1059.001").
    name          : technique name (e.g. "Command and Scripting Interpreter").
    tactic        : TacticEnum — primary tactic this technique belongs to.
    description   : human-readable description.
    platforms     : sorted tuple of applicable platform strings.
    detection     : detection guidance string.
    mitigations   : sorted tuple of mitigation guidance strings.
    references    : sorted tuple of reference URL strings.
    createdAt     : ISO-8601 timestamp (caller-supplied for determinism).
    """
    techniqueId  : str
    techniqueKey : str
    mitreId      : str
    name         : str
    tactic       : TacticEnum
    description  : str
    platforms    : Tuple[str, ...]
    detection    : str
    mitigations  : Tuple[str, ...]
    references   : Tuple[str, ...]
    createdAt    : str

    class Config:
        frozen = True


class MitreMapping(BaseModel):
    """
    One immutable mapping linking investigation objects to ATT&CK techniques.

    Identity
    --------
    mappingKey         : SHA256(findingId + alertId + reasoningId +
                                sorted(matchedTechniqueIds))[:32]
    mappingId          : UUIDv5(_MITRE_ATTACK_NS, mappingKey)
    mappingFingerprint : SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(matchedTechniqueIds))[:32]

    Fields
    ------
    mappingId           : deterministic UUID.
    mappingKey          : 32-char SHA-256 key.
    mappingFingerprint  : deterministic 32-char content fingerprint.
    findingId           : ID of the linked Finding (may be empty).
    alertId             : ID of the linked Alert (may be empty).
    reasoningId         : ID of the linked ReasoningResult (may be empty).
    matchedTechniques   : sorted tuple of MitreTechnique objects matched.
    confidence          : 0.0–100.0 caller-assessed confidence (clamped).
    createdAt           : ISO-8601 timestamp.
    """
    mappingId          : str
    mappingKey         : str
    mappingFingerprint : str
    findingId          : str
    alertId            : str
    reasoningId        : str
    matchedTechniques  : Tuple[MitreTechnique, ...]
    confidence         : float
    createdAt          : str

    class Config:
        frozen = True


class MitreStatistics(BaseModel):
    """
    Aggregate statistics over a collection of MitreMapping objects.

    Fields
    ------
    totalTechniques  : count of distinct technique mitreIds across all mappings.
    mappedTechniques : count of distinct techniqueIds across all mappings.
    tacticsCovered   : sorted tuple of TacticEnum values seen across all mappings.
    averageConfidence: mean mapping.confidence across all mappings (0.0 if empty).
    """
    totalTechniques  : int
    mappedTechniques : int
    tacticsCovered   : Tuple[str, ...]
    averageConfidence: float

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
    """UUIDv5(_MITRE_ATTACK_NS, key) as canonical lowercase UUID string."""
    return str(uuid.uuid5(_MITRE_ATTACK_NS, key))


def _norm(s: str) -> str:
    """Strip and return a string."""
    return s.strip() if s else ""


def _norm_lower(s: str) -> str:
    """Lowercase + strip a string."""
    return s.strip().lower() if s else ""


def _norm_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip() for s in items if s and s.strip()}))


def _norm_lower_strings(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, lowercase, strip, and sort a list of strings."""
    if not items:
        return ()
    return tuple(sorted({s.strip().lower() for s in items if s and s.strip()}))


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    """Clamp a float to [lo, hi]."""
    return float(max(lo, min(hi, v)))


# ---------------------------------------------------------------------------
# Key derivation functions (public — named per spec)
# ---------------------------------------------------------------------------

def techniqueKey(mitre_id: str) -> str:
    """
    techniqueKey = SHA256(mitreId.upper())[:32]

    Identical mitreId always produces the same key regardless of caller.
    """
    return _sha256_32(mitre_id.strip().upper())


def mappingKey(
    finding_id            : str,
    alert_id              : str,
    reasoning_id          : str,
    matched_technique_ids : Tuple[str, ...],
) -> str:
    """
    mappingKey = SHA256(findingId + alertId + reasoningId +
                        sorted(matchedTechniqueIds))[:32]

    Null-byte-separated to prevent cross-field collisions.
    techniqueIds sorted before joining for order-independence.
    """
    sorted_techs = "\x01".join(sorted(matched_technique_ids))
    return _sha256_32(
        finding_id.strip(),
        alert_id.strip(),
        reasoning_id.strip(),
        sorted_techs,
    )


def mappingFingerprint(
    m_key        : str,
    finding_id   : str,
    alert_id     : str,
    reasoning_id : str,
    matched_technique_ids: Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(matchedTechniqueIds))[:32]
    """
    sorted_techs = "\x01".join(sorted(matched_technique_ids))
    return _sha256_32(
        m_key,
        finding_id.strip(),
        alert_id.strip(),
        reasoning_id.strip(),
        sorted_techs,
    )


# ===========================================================================
# Validation
# ===========================================================================

def validate_technique(
    mitre_id   : str,
    name       : str,
    tactic     : TacticEnum,
    created_at : str,
) -> None:
    """
    Validate MitreTechnique construction parameters.

    Checks
    ------
    - mitre_id is non-empty and matches ATT&CK ID pattern (starts with "T").
    - name is non-empty.
    - tactic is a valid TacticEnum member.
    - created_at is non-empty.

    Raises
    ------
    InvalidTechniqueError : if any rule is violated.
    InvalidTacticError    : if tactic is not a TacticEnum member.
    """
    errors: List[str] = []

    if not mitre_id or not mitre_id.strip():
        errors.append("mitreId must not be empty.")
    elif not mitre_id.strip().upper().startswith("T"):
        errors.append(
            f"mitreId='{mitre_id}' must start with 'T' (ATT&CK ID pattern)."
        )
    if not name or not name.strip():
        errors.append("name must not be empty.")
    if not created_at or not created_at.strip():
        errors.append("createdAt must not be empty.")

    # Tactic check is separate — raise InvalidTacticError for tactic issues
    if not isinstance(tactic, TacticEnum):
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_technique", "field": "tactic", "value": repr(tactic)},
        )
        raise InvalidTacticError(
            f"tactic must be a TacticEnum member; got {tactic!r}."
        )

    if errors:
        _log.warning(
            "validation_failure",
            extra={"validator": "validate_technique", "errors": errors},
        )
        raise InvalidTechniqueError(
            "\n".join(f"  - {e}" for e in errors)
        )


def validate_mapping(
    finding_id  : str,
    alert_id    : str,
    reasoning_id: str,
    confidence  : float,
    created_at  : str,
) -> None:
    """
    Validate MitreMapping construction parameters.

    Checks
    ------
    - At least one of findingId, alertId, or reasoningId must be non-empty.
    - confidence in [0.0, 100.0].
    - created_at is non-empty.

    Raises
    ------
    InvalidMitreMappingError : if any rule is violated.
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
            extra={"validator": "validate_mapping", "errors": errors},
        )
        raise InvalidMitreMappingError(
            "\n".join(f"  - {e}" for e in errors)
        )


# ===========================================================================
# Builder: build_mitre_technique()
# ===========================================================================

def build_mitre_technique(
    mitre_id    : str,
    name        : str,
    tactic      : TacticEnum,
    created_at  : str,
    description : str                      = "",
    platforms   : Optional[List[str]]      = None,
    detection   : str                      = "",
    mitigations : Optional[List[str]]      = None,
    references  : Optional[List[str]]      = None,
    validate    : bool                     = True,
) -> MitreTechnique:
    """
    Build an immutable MitreTechnique.

    techniqueKey = SHA256(mitreId.upper())[:32]
    techniqueId  = UUIDv5(_MITRE_ATTACK_NS, techniqueKey)

    Parameters
    ----------
    mitre_id    : ATT&CK technique ID (e.g. "T1059", "T1059.001").
    name        : technique name (must be non-empty).
    tactic      : TacticEnum — primary tactic.
    created_at  : ISO-8601 timestamp (caller-supplied for determinism).
    description : human-readable description (may be empty).
    platforms   : applicable platform strings (deduped + sorted).
    detection   : detection guidance (may be empty).
    mitigations : mitigation guidance strings (deduped + sorted).
    references  : reference URL strings (deduped + sorted, case-preserved).
    validate    : if True, run validate_technique() first.

    Returns
    -------
    MitreTechnique (frozen / immutable)

    Raises
    ------
    InvalidTechniqueError : if validate=True and technique validation fails.
    InvalidTacticError    : if validate=True and tactic is not a TacticEnum.
    """
    if validate:
        validate_technique(mitre_id, name, tactic, created_at)

    t_key = techniqueKey(mitre_id)
    t_id  = _uuid5(t_key)

    return MitreTechnique(
        techniqueId  = t_id,
        techniqueKey = t_key,
        mitreId      = mitre_id.strip().upper(),
        name         = name.strip(),
        tactic       = tactic,
        description  = description,
        platforms    = _norm_lower_strings(platforms),
        detection    = detection,
        mitigations  = _norm_strings(mitigations),
        references   = _norm_strings(references),
        createdAt    = created_at,
    )


# ===========================================================================
# Builder: build_mitre_mapping()
# ===========================================================================

def build_mitre_mapping(
    matched_techniques : List[MitreTechnique],
    created_at         : str,
    finding_id         : str                      = "",
    alert_id           : str                      = "",
    reasoning_id       : str                      = "",
    confidence         : float                    = 0.0,
    validate           : bool                     = True,
) -> MitreMapping:
    """
    Build an immutable MitreMapping.

    mappingKey         = SHA256(findingId + alertId + reasoningId +
                                sorted(matchedTechniqueIds))[:32]
    mappingId          = UUIDv5(_MITRE_ATTACK_NS, mappingKey)
    mappingFingerprint = SHA256(mappingKey + findingId + alertId +
                                reasoningId + sorted(matchedTechniqueIds))[:32]

    Parameters
    ----------
    matched_techniques : list of MitreTechnique objects matched.
    created_at         : ISO-8601 timestamp (caller-supplied for determinism).
    finding_id         : ID of the linked Finding (may be empty).
    alert_id           : ID of the linked Alert (may be empty).
    reasoning_id       : ID of the linked ReasoningResult (may be empty).
    confidence         : 0.0–100.0 caller-assessed confidence (clamped).
    validate           : if True, run validate_mapping() first.

    Returns
    -------
    MitreMapping (frozen / immutable)

    Raises
    ------
    InvalidMitreMappingError : if validate=True and validation fails.
    """
    clamped_confidence = _clamp(float(confidence))

    if validate:
        validate_mapping(
            finding_id, alert_id, reasoning_id,
            clamped_confidence, created_at,
        )

    # Deterministic ordering of techniques: by mitreId ASC then techniqueId ASC
    sorted_techniques: Tuple[MitreTechnique, ...] = tuple(
        sorted(
            matched_techniques or [],
            key=lambda t: (t.mitreId, t.techniqueId),
        )
    )

    # Collect technique IDs for key computation
    technique_ids: Tuple[str, ...] = tuple(t.techniqueId for t in sorted_techniques)

    m_key = mappingKey(finding_id, alert_id, reasoning_id, technique_ids)
    m_id  = _uuid5(m_key)
    m_fp  = mappingFingerprint(m_key, finding_id, alert_id, reasoning_id, technique_ids)

    return MitreMapping(
        mappingId          = m_id,
        mappingKey         = m_key,
        mappingFingerprint = m_fp,
        findingId          = finding_id.strip(),
        alertId            = alert_id.strip(),
        reasoningId        = reasoning_id.strip(),
        matchedTechniques  = sorted_techniques,
        confidence         = round(clamped_confidence, 4),
        createdAt          = created_at,
    )


# ===========================================================================
# Builder: build_mitre_statistics()
# ===========================================================================

def build_mitre_statistics(
    mappings: List[MitreMapping],
) -> MitreStatistics:
    """
    Compute MitreStatistics over a list of MitreMapping objects.

    Deterministic: canonical sort (by mappingId ASC) before accumulation
    so floating-point sums are identical across all runs.

    Parameters
    ----------
    mappings : any list of MitreMapping objects.

    Returns
    -------
    MitreStatistics (frozen / immutable)
    """
    if not mappings:
        return MitreStatistics(
            totalTechniques   = 0,
            mappedTechniques  = 0,
            tacticsCovered    = (),
            averageConfidence = 0.0,
        )

    # Canonical order for deterministic accumulation
    ordered = sorted(mappings, key=lambda m: m.mappingId)

    all_techniques: List[MitreTechnique] = [
        t
        for m in ordered
        for t in m.matchedTechniques
    ]

    # Distinct mitre IDs (e.g. "T1059") — totalTechniques
    distinct_mitre_ids = {t.mitreId for t in all_techniques}
    # Distinct technique UUIDs — mappedTechniques
    distinct_tech_ids  = {t.techniqueId for t in all_techniques}
    # Distinct tactics covered
    distinct_tactics   = tuple(
        sorted({t.tactic.value for t in all_techniques})
    )

    n = len(ordered)
    avg_conf = round(sum(m.confidence for m in ordered) / n, 4)

    return MitreStatistics(
        totalTechniques   = len(distinct_mitre_ids),
        mappedTechniques  = len(distinct_tech_ids),
        tacticsCovered    = distinct_tactics,
        averageConfidence = avg_conf,
    )


# ===========================================================================
# Integration helpers — transform Finding, Alert, ReasoningResult into
# MitreMapping objects.  No AI execution.  No internet lookup.
# Transform only.
# ===========================================================================

def finding_to_mitre_mapping(
    finding           : Any,
    matched_techniques: List[MitreTechnique],
    created_at        : str,
    confidence        : float = 0.0,
    validate          : bool  = True,
) -> MitreMapping:
    """
    Convert a Finding (from finding_service) into a MitreMapping.

    Rules
    -----
    - findingId  = finding.findingId
    - alertId    = "" (no alert source)
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    finding            : Finding object from finding_service.
    matched_techniques : list of MitreTechnique objects to map.
    created_at         : ISO-8601 timestamp.
    confidence         : 0.0–100.0 caller-assessed confidence.
    validate           : if True, run validate_mapping().

    Returns
    -------
    MitreMapping (frozen / immutable)
    """
    _log.debug(
        "finding_to_mitre_mapping",
        extra={
            "findingId"        : finding.findingId,
            "techniqueCount"   : len(matched_techniques),
        },
    )
    return build_mitre_mapping(
        matched_techniques = matched_techniques,
        created_at         = created_at,
        finding_id         = finding.findingId,
        alert_id           = "",
        reasoning_id       = "",
        confidence         = confidence,
        validate           = validate,
    )


def alert_to_mitre_mapping(
    alert             : Any,
    matched_techniques: List[MitreTechnique],
    created_at        : str,
    confidence        : float = 0.0,
    validate          : bool  = True,
) -> MitreMapping:
    """
    Convert an Alert (from alert_service) into a MitreMapping.

    Rules
    -----
    - findingId  = alert.findingId  (Alert always has a source findingId)
    - alertId    = alert.alertId
    - reasoningId = "" (no reasoning source)
    - confidence passed through (clamped internally)

    Parameters
    ----------
    alert              : Alert object from alert_service.
    matched_techniques : list of MitreTechnique objects to map.
    created_at         : ISO-8601 timestamp.
    confidence         : 0.0–100.0 caller-assessed confidence.
    validate           : if True, run validate_mapping().

    Returns
    -------
    MitreMapping (frozen / immutable)
    """
    _log.debug(
        "alert_to_mitre_mapping",
        extra={
            "alertId"        : alert.alertId,
            "findingId"      : alert.findingId,
            "techniqueCount" : len(matched_techniques),
        },
    )
    return build_mitre_mapping(
        matched_techniques = matched_techniques,
        created_at         = created_at,
        finding_id         = alert.findingId,
        alert_id           = alert.alertId,
        reasoning_id       = "",
        confidence         = confidence,
        validate           = validate,
    )


def reasoning_to_mitre_mapping(
    reasoning         : Any,
    matched_techniques: List[MitreTechnique],
    created_at        : str,
    finding_id        : str   = "",
    alert_id          : str   = "",
    validate          : bool  = True,
) -> MitreMapping:
    """
    Convert a ReasoningResult (from reasoning_service) into a MitreMapping.

    Rules
    -----
    - reasoningId = reasoning.reasoningId
    - confidence  = reasoning.overallConfidence (already 0–100)
    - findingId and alertId are optional caller-supplied context linkages.

    Parameters
    ----------
    reasoning          : ReasoningResult object from reasoning_service.
    matched_techniques : list of MitreTechnique objects to map.
    created_at         : ISO-8601 timestamp.
    finding_id         : optional finding ID for context linkage.
    alert_id           : optional alert ID for context linkage.
    validate           : if True, run validate_mapping().

    Returns
    -------
    MitreMapping (frozen / immutable)
    """
    _log.debug(
        "reasoning_to_mitre_mapping",
        extra={
            "reasoningId"    : reasoning.reasoningId,
            "confidence"     : reasoning.overallConfidence,
            "techniqueCount" : len(matched_techniques),
        },
    )
    return build_mitre_mapping(
        matched_techniques = matched_techniques,
        created_at         = created_at,
        finding_id         = finding_id,
        alert_id           = alert_id,
        reasoning_id       = reasoning.reasoningId,
        confidence         = reasoning.overallConfidence,
        validate           = validate,
    )
