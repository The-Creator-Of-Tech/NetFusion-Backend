"""
MITRE ATT&CK Engine
====================
Phase A4.0.9 — Deterministic MITRE ATT&CK tactic/technique/mapping management.

Responsibilities
----------------
- Model immutable MitreTactic, MitreTechnique, MitreSubTechnique objects.
- Build deterministic MitreMapping objects that link Findings, Alerts,
  Relationships, Assets, Evidence, and Timeline Events to ATT&CK techniques.
- Compute mappingFingerprint from upstream fingerprints and sorted linked IDs.
- Expose builder functions: build_tactic, build_technique, build_subtechnique,
  build_mapping, update_mapping, merge_mappings, build_statistics, build_bundle.
- Expose utility functions: sort, filter, group, find, search, statistics.

Design principles
-----------------
- All models are immutable (frozen=True dataclasses).
- All builder functions return NEW objects; nothing is mutated in place.
- Fully deterministic: same inputs → same outputs across every run.
- No AI, no randomness, no uuid4(), no datetime.now() inside ID computation.
- No database, no repository, no API, no HTTP.
- Pure business logic only.
- Engine version from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.constants import MITRE_ENGINE_VERSION

# ── UUIDv5 namespace — fixed forever; changing it invalidates stored IDs ────
_MITRE_NS = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Immutable models
# ===========================================================================

@dataclass(frozen=True)
class MitreTactic:
    """
    An immutable ATT&CK Tactic (the "why" column — e.g. Initial Access).

    Fields
    ------
    tacticId   : UUIDv5(MITRE_NS, tacticKey) — deterministic
    tacticKey  : SHA256(tacticId_code)[:32]   — stable natural key
    name       : full tactic name  (e.g. "Initial Access")
    shortName  : slug used in ATT&CK URLs (e.g. "initial-access")
    description: human-readable description
    order      : display order in the ATT&CK matrix (integer, 1-based)
    createdAt  : ISO-8601 string (caller-supplied — never datetime.now())
    """
    tacticId   : str
    tacticKey  : str
    name       : str
    shortName  : str
    description: str
    order      : int
    createdAt  : str


@dataclass(frozen=True)
class MitreTechnique:
    """
    An immutable ATT&CK Technique (e.g. T1021 — Remote Services).

    Fields
    ------
    techniqueId         : UUIDv5(MITRE_NS, techniqueKey) — deterministic
    techniqueKey        : SHA256(techniqueCode)[:32]
    techniqueCode       : ATT&CK ID string  (e.g. "T1021")
    name                : technique name
    description         : human-readable description
    tacticIds           : sorted tuple of parent tactic IDs
    platforms           : sorted tuple of applicable platform strings
    dataSources         : sorted tuple of data source strings
    permissionsRequired : sorted tuple of required permission strings
    detection           : detection guidance string
    mitigation          : mitigation guidance string
    references          : sorted tuple of reference URLs
    riskScore           : 0–100 float
    confidence          : 0–100 float
    metadata            : arbitrary JSON-serialisable dict
    createdAt           : ISO-8601 string
    """
    techniqueId         : str
    techniqueKey        : str
    techniqueCode       : str
    name                : str
    description         : str
    tacticIds           : Tuple[str, ...]
    platforms           : Tuple[str, ...]
    dataSources         : Tuple[str, ...]
    permissionsRequired : Tuple[str, ...]
    detection           : str
    mitigation          : str
    references          : Tuple[str, ...]
    riskScore           : float
    confidence          : float
    metadata            : Dict[str, Any]
    createdAt           : str


@dataclass(frozen=True)
class MitreSubTechnique:
    """
    An immutable ATT&CK Sub-Technique (e.g. T1021.002 — SMB/Windows Admin Shares).

    Fields
    ------
    subTechniqueId   : UUIDv5(MITRE_NS, subTechniqueKey)
    subTechniqueKey  : SHA256(subTechniqueCode)[:32]
    subTechniqueCode : ATT&CK ID string (e.g. "T1021.002")
    parentTechniqueId: techniqueId of the parent MitreTechnique
    name             : sub-technique name
    description      : human-readable description
    riskScore        : 0–100 float
    confidence       : 0–100 float
    metadata         : arbitrary JSON-serialisable dict
    createdAt        : ISO-8601 string
    """
    subTechniqueId   : str
    subTechniqueKey  : str
    subTechniqueCode : str
    parentTechniqueId: str
    name             : str
    description      : str
    riskScore        : float
    confidence       : float
    metadata         : Dict[str, Any]
    createdAt        : str


@dataclass(frozen=True)
class MitreExplanation:
    """
    Structured rationale for a MitreMapping.

    Fields
    ------
    reason             : Why this technique was mapped (factual, no AI).
    matchedEvidence    : Sorted tuple of evidence IDs that triggered the match.
    matchedIndicators  : Sorted tuple of indicator strings (e.g. protocol names).
    recommendedActions : Sorted tuple of recommended remediation steps.
    analystNotes       : Free-text analyst annotation (empty if not set).
    """
    reason             : str
    matchedEvidence    : Tuple[str, ...]
    matchedIndicators  : Tuple[str, ...]
    recommendedActions : Tuple[str, ...]
    analystNotes       : str


@dataclass(frozen=True)
class MitreMapping:
    """
    Deterministic mapping linking investigation objects to ATT&CK techniques.

    Identity
    --------
    mappingId  : UUIDv5(MITRE_NS, mappingKey) — deterministic
    mappingKey : SHA256(findingId + alertId + relationshipId +
                        sorted(techniqueIds))[:32]

    Link collections (sorted tuples for determinism)
    -------------------------------------------------
    assetIds, evidenceIds, timelineEventIds, attackGraphNodeIds,
    techniqueIds, subTechniqueIds

    Fingerprints
    ------------
    findingFingerprint    : opaque string from Finding Engine
    alertFingerprint      : opaque string from Alert Engine
    graphFingerprint      : opaque string from Attack Graph Engine
    timelineFingerprint   : opaque string from Timeline Intelligence Engine
    mappingFingerprint    : SHA256 of all of the above (32 hex chars)

    Explanation
    -----------
    explanation : MitreExplanation — structured rationale (never None)

    Audit
    -----
    auditTrail  : ordered tuple of semantic action strings (no timestamps)
    """
    # ── Identity ─────────────────────────────────────────────────────────
    mappingId  : str
    mappingKey : str

    # ── Source linkage ───────────────────────────────────────────────────
    findingId      : str
    alertId        : str
    relationshipId : str

    # ── Linked IDs (sorted tuples) ───────────────────────────────────────
    assetIds            : Tuple[str, ...]
    evidenceIds         : Tuple[str, ...]
    timelineEventIds    : Tuple[str, ...]
    attackGraphNodeIds  : Tuple[str, ...]
    techniqueIds        : Tuple[str, ...]
    subTechniqueIds     : Tuple[str, ...]

    # ── Scoring ──────────────────────────────────────────────────────────
    confidence : float   # 0–100
    riskScore  : float   # 0–100 (derived from linked techniques)

    # ── Fingerprints ─────────────────────────────────────────────────────
    findingFingerprint  : str
    alertFingerprint    : str
    graphFingerprint    : str
    timelineFingerprint : str
    mappingFingerprint  : str   # 32 hex chars

    # ── Rationale ────────────────────────────────────────────────────────
    mappingReason : str
    explanation   : MitreExplanation

    # ── Metadata ─────────────────────────────────────────────────────────
    metadata      : Dict[str, Any]
    createdAt     : str   # ISO-8601

    # ── Versioning & audit ───────────────────────────────────────────────
    engineVersion : str
    auditTrail    : Tuple[str, ...]


@dataclass(frozen=True)
class MitreStatistics:
    """Aggregate statistics over a MitreBundle."""
    totalTechniques      : int
    totalMappings        : int
    techniquesByTactic   : Dict[str, int]    # tacticId → technique count
    highestRiskTechnique : Optional[str]     # techniqueCode of max riskScore
    averageConfidence    : float             # 0.0 when empty


@dataclass(frozen=True)
class MitreBundle:
    """
    Complete MITRE ATT&CK output for one investigation scope.

    Fields
    ------
    tactics        : all MitreTactic objects (ordered by tactic.order ASC)
    techniques     : all MitreTechnique objects (sorted by riskScore DESC)
    subTechniques  : all MitreSubTechnique objects (sorted by riskScore DESC)
    mappings       : all MitreMapping objects (sorted by confidence DESC)
    statistics     : MitreStatistics over this bundle
    engineVersion  : MITRE_ENGINE_VERSION at construction time
    createdAt      : ISO-8601 string
    """
    tactics       : Tuple["MitreTactic", ...]
    techniques    : Tuple["MitreTechnique", ...]
    subTechniques : Tuple["MitreSubTechnique", ...]
    mappings      : Tuple["MitreMapping", ...]
    statistics    : MitreStatistics
    engineVersion : str
    createdAt     : str


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_technique_key(technique_code: str) -> str:
    """TechniqueKey = SHA256(techniqueCode)[:32] — null-padded for single field."""
    raw = technique_code.strip().upper()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_technique_id(technique_key: str) -> str:
    """TechniqueId = UUIDv5(MITRE_NS, techniqueKey)."""
    return str(uuid.uuid5(_MITRE_NS, technique_key))


def _compute_subtechnique_key(sub_technique_code: str) -> str:
    """SubTechniqueKey = SHA256(subTechniqueCode)[:32]."""
    raw = sub_technique_code.strip().upper()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_subtechnique_id(sub_technique_key: str) -> str:
    """SubTechniqueId = UUIDv5(MITRE_NS, subTechniqueKey)."""
    return str(uuid.uuid5(_MITRE_NS, sub_technique_key))


def _compute_tactic_key(tactic_short_name: str) -> str:
    """TacticKey = SHA256(tacticShortName.lower())[:32]."""
    raw = tactic_short_name.strip().lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_tactic_id(tactic_key: str) -> str:
    """TacticId = UUIDv5(MITRE_NS, tacticKey)."""
    return str(uuid.uuid5(_MITRE_NS, tactic_key))


def _compute_mapping_key(
    finding_id     : str,
    alert_id       : str,
    relationship_id: str,
    technique_ids  : Tuple[str, ...],
) -> str:
    """
    MappingKey = SHA256(findingId + alertId + relationshipId +
                        sorted(techniqueIds))[:32]

    Components are null-byte-separated; technique IDs are \\x01-joined after sorting.
    """
    sorted_tech = "\x01".join(sorted(technique_ids))
    raw = f"{finding_id}\x00{alert_id}\x00{relationship_id}\x00{sorted_tech}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_mapping_id(mapping_key: str) -> str:
    """MappingId = UUIDv5(MITRE_NS, mappingKey)."""
    return str(uuid.uuid5(_MITRE_NS, mapping_key))


def _compute_mapping_fingerprint(
    finding_fingerprint  : str,
    alert_fingerprint    : str,
    graph_fingerprint    : str,
    timeline_fingerprint : str,
    asset_ids            : Tuple[str, ...],
    evidence_ids         : Tuple[str, ...],
) -> str:
    """
    mappingFingerprint = SHA256(
        findingFingerprint,
        alertFingerprint,
        graphFingerprint,
        timelineFingerprint,
        sorted(assetIds),
        sorted(evidenceIds),
    )[:32]

    All ID collections are sorted before hashing — order-independent.
    Parts are null-byte-separated; IDs within a group use \\x01.
    Returns 32 hex characters.
    """
    parts = [
        finding_fingerprint,
        alert_fingerprint,
        graph_fingerprint,
        timeline_fingerprint,
        "\x01".join(sorted(asset_ids)),
        "\x01".join(sorted(evidence_ids)),
    ]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _norm_ids(ids: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip and sort an ID list."""
    if not ids:
        return ()
    return tuple(sorted({i.strip() for i in ids if i and i.strip()}))


def _norm_strs(items: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, lowercase and sort a string list."""
    if not items:
        return ()
    return tuple(sorted({s.strip().lower() for s in items if s and s.strip()}))


def _norm_refs(refs: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip and sort reference URLs (case-preserved)."""
    if not refs:
        return ()
    return tuple(sorted({r.strip() for r in refs if r and r.strip()}))


def _clamp(v: float) -> float:
    return float(max(0.0, min(100.0, v)))


# ===========================================================================
# Builder: build_tactic()
# ===========================================================================

def build_tactic(
    short_name  : str,
    name        : str,
    created_at  : str,
    description : str = "",
    order       : int = 0,
) -> MitreTactic:
    """
    Build a MitreTactic.

    Parameters
    ----------
    short_name  : ATT&CK slug (e.g. "initial-access")
    name        : full name (e.g. "Initial Access")
    created_at  : ISO-8601 string (caller-supplied for determinism)
    description : human-readable description
    order       : display order in the ATT&CK matrix

    Returns
    -------
    MitreTactic (frozen)
    """
    key = _compute_tactic_key(short_name)
    tid = _compute_tactic_id(key)
    return MitreTactic(
        tacticId    = tid,
        tacticKey   = key,
        name        = name,
        shortName   = short_name.strip().lower(),
        description = description,
        order       = order,
        createdAt   = created_at,
    )


# ===========================================================================
# Builder: build_technique()
# ===========================================================================

def build_technique(
    technique_code       : str,
    name                 : str,
    created_at           : str,
    description          : str                      = "",
    tactic_ids           : Optional[List[str]]      = None,
    platforms            : Optional[List[str]]      = None,
    data_sources         : Optional[List[str]]      = None,
    permissions_required : Optional[List[str]]      = None,
    detection            : str                      = "",
    mitigation           : str                      = "",
    references           : Optional[List[str]]      = None,
    risk_score           : float                    = 0.0,
    confidence           : float                    = 0.0,
    metadata             : Optional[Dict[str, Any]] = None,
) -> MitreTechnique:
    """
    Build a MitreTechnique.

    techniqueKey = SHA256(techniqueCode.upper())[:32]
    techniqueId  = UUIDv5(MITRE_NS, techniqueKey)

    Parameters
    ----------
    technique_code       : ATT&CK ID (e.g. "T1021")
    name                 : technique name
    created_at           : ISO-8601 string (caller-supplied)
    description          : free-text description
    tactic_ids           : parent tactic IDs (deduped + sorted)
    platforms            : applicable platforms (deduped + lowercased + sorted)
    data_sources         : data source strings (deduped + lowercased + sorted)
    permissions_required : permission level strings (deduped + lowercased + sorted)
    detection            : detection guidance
    mitigation           : mitigation guidance
    references           : reference URLs (deduped + sorted)
    risk_score           : 0–100 (clamped)
    confidence           : 0–100 (clamped)
    metadata             : arbitrary JSON-serialisable dict

    Returns
    -------
    MitreTechnique (frozen)
    """
    key = _compute_technique_key(technique_code)
    tid = _compute_technique_id(key)
    return MitreTechnique(
        techniqueId         = tid,
        techniqueKey        = key,
        techniqueCode       = technique_code.strip().upper(),
        name                = name,
        description         = description,
        tacticIds           = _norm_ids(tactic_ids),
        platforms           = _norm_strs(platforms),
        dataSources         = _norm_strs(data_sources),
        permissionsRequired = _norm_strs(permissions_required),
        detection           = detection,
        mitigation          = mitigation,
        references          = _norm_refs(references),
        riskScore           = _clamp(risk_score),
        confidence          = _clamp(confidence),
        metadata            = dict(metadata) if metadata else {},
        createdAt           = created_at,
    )


# ===========================================================================
# Builder: build_subtechnique()
# ===========================================================================

def build_subtechnique(
    sub_technique_code  : str,
    parent_technique_id : str,
    name                : str,
    created_at          : str,
    description         : str                      = "",
    risk_score          : float                    = 0.0,
    confidence          : float                    = 0.0,
    metadata            : Optional[Dict[str, Any]] = None,
) -> MitreSubTechnique:
    """
    Build a MitreSubTechnique.

    subTechniqueKey = SHA256(subTechniqueCode.upper())[:32]
    subTechniqueId  = UUIDv5(MITRE_NS, subTechniqueKey)

    Parameters
    ----------
    sub_technique_code  : ATT&CK sub-technique ID (e.g. "T1021.002")
    parent_technique_id : techniqueId of the parent MitreTechnique
    name                : sub-technique name
    created_at          : ISO-8601 string
    description         : free-text description
    risk_score          : 0–100 (clamped)
    confidence          : 0–100 (clamped)
    metadata            : arbitrary JSON-serialisable dict

    Returns
    -------
    MitreSubTechnique (frozen)
    """
    key = _compute_subtechnique_key(sub_technique_code)
    sid = _compute_subtechnique_id(key)
    return MitreSubTechnique(
        subTechniqueId    = sid,
        subTechniqueKey   = key,
        subTechniqueCode  = sub_technique_code.strip().upper(),
        parentTechniqueId = parent_technique_id,
        name              = name,
        description       = description,
        riskScore         = _clamp(risk_score),
        confidence        = _clamp(confidence),
        metadata          = dict(metadata) if metadata else {},
        createdAt         = created_at,
    )


# ===========================================================================
# Builder: build_mapping()
# ===========================================================================

def build_mapping(
    finding_id           : str,
    alert_id             : str,
    relationship_id      : str,
    created_at           : str,
    technique_ids        : Optional[List[str]]      = None,
    sub_technique_ids    : Optional[List[str]]      = None,
    asset_ids            : Optional[List[str]]      = None,
    evidence_ids         : Optional[List[str]]      = None,
    timeline_event_ids   : Optional[List[str]]      = None,
    attack_graph_node_ids: Optional[List[str]]      = None,
    confidence           : float                    = 0.0,
    risk_score           : float                    = 0.0,
    finding_fingerprint  : str                      = "",
    alert_fingerprint    : str                      = "",
    graph_fingerprint    : str                      = "",
    timeline_fingerprint : str                      = "",
    mapping_reason       : str                      = "",
    # explanation fields
    reason               : str                      = "",
    matched_evidence     : Optional[List[str]]      = None,
    matched_indicators   : Optional[List[str]]      = None,
    recommended_actions  : Optional[List[str]]      = None,
    analyst_notes        : str                      = "",
    metadata             : Optional[Dict[str, Any]] = None,
) -> MitreMapping:
    """
    Create a new MitreMapping.

    mappingKey = SHA256(findingId + alertId + relationshipId +
                        sorted(techniqueIds))[:32]
    mappingId  = UUIDv5(MITRE_NS, mappingKey)

    mappingFingerprint = SHA256(findingFP + alertFP + graphFP + timelineFP +
                                sorted(assetIds) + sorted(evidenceIds))[:32]

    Parameters
    ----------
    finding_id / alert_id / relationship_id : source linkage
    created_at            : ISO-8601 (caller-supplied for determinism)
    technique_ids         : ATT&CK technique IDs being mapped (deduped + sorted)
    sub_technique_ids     : sub-technique IDs (deduped + sorted)
    asset_ids / evidence_ids / timeline_event_ids / attack_graph_node_ids
                          : linked entity IDs (deduped + sorted)
    confidence            : 0–100 (clamped)
    risk_score            : 0–100 (clamped)
    *_fingerprint         : upstream opaque fingerprint strings
    mapping_reason        : short reason string for this mapping
    reason / matched_evidence / matched_indicators /
      recommended_actions / analyst_notes : MitreExplanation fields
    metadata              : arbitrary JSON-serialisable dict

    Returns
    -------
    MitreMapping (frozen)
    """
    norm_tech_ids   = _norm_ids(technique_ids)
    norm_sub_ids    = _norm_ids(sub_technique_ids)
    norm_asset_ids  = _norm_ids(asset_ids)
    norm_ev_ids     = _norm_ids(evidence_ids)
    norm_tl_ids     = _norm_ids(timeline_event_ids)
    norm_node_ids   = _norm_ids(attack_graph_node_ids)

    key = _compute_mapping_key(finding_id, alert_id, relationship_id, norm_tech_ids)
    mid = _compute_mapping_id(key)

    fingerprint = _compute_mapping_fingerprint(
        finding_fingerprint, alert_fingerprint,
        graph_fingerprint, timeline_fingerprint,
        norm_asset_ids, norm_ev_ids,
    )

    explanation = MitreExplanation(
        reason             = reason,
        matchedEvidence    = _norm_ids(matched_evidence),
        matchedIndicators  = _norm_strs(matched_indicators),
        recommendedActions = tuple(recommended_actions) if recommended_actions else (),
        analystNotes       = analyst_notes,
    )

    return MitreMapping(
        mappingId             = mid,
        mappingKey            = key,
        findingId             = finding_id,
        alertId               = alert_id,
        relationshipId        = relationship_id,
        assetIds              = norm_asset_ids,
        evidenceIds           = norm_ev_ids,
        timelineEventIds      = norm_tl_ids,
        attackGraphNodeIds    = norm_node_ids,
        techniqueIds          = norm_tech_ids,
        subTechniqueIds       = norm_sub_ids,
        confidence            = _clamp(confidence),
        riskScore             = _clamp(risk_score),
        findingFingerprint    = finding_fingerprint,
        alertFingerprint      = alert_fingerprint,
        graphFingerprint      = graph_fingerprint,
        timelineFingerprint   = timeline_fingerprint,
        mappingFingerprint    = fingerprint,
        mappingReason         = mapping_reason,
        explanation           = explanation,
        metadata              = dict(metadata) if metadata else {},
        createdAt             = created_at,
        engineVersion         = MITRE_ENGINE_VERSION,
        auditTrail            = ("Created",),
    )


# ===========================================================================
# Builder: update_mapping()
# ===========================================================================

def update_mapping(
    mapping              : MitreMapping,
    technique_ids        : Optional[List[str]]      = None,
    sub_technique_ids    : Optional[List[str]]      = None,
    asset_ids            : Optional[List[str]]      = None,
    evidence_ids         : Optional[List[str]]      = None,
    timeline_event_ids   : Optional[List[str]]      = None,
    attack_graph_node_ids: Optional[List[str]]      = None,
    confidence           : Optional[float]          = None,
    risk_score           : Optional[float]          = None,
    finding_fingerprint  : Optional[str]            = None,
    alert_fingerprint    : Optional[str]            = None,
    graph_fingerprint    : Optional[str]            = None,
    timeline_fingerprint : Optional[str]            = None,
    mapping_reason       : Optional[str]            = None,
    # explanation overrides
    reason               : Optional[str]            = None,
    matched_evidence     : Optional[List[str]]      = None,
    matched_indicators   : Optional[List[str]]      = None,
    recommended_actions  : Optional[List[str]]      = None,
    analyst_notes        : Optional[str]            = None,
    metadata             : Optional[Dict[str, Any]] = None,
) -> MitreMapping:
    """
    Return a new MitreMapping with supplied fields changed.

    None → keep existing value.
    mappingFingerprint is recomputed whenever any source field changes.
    mappingKey / mappingId are never recomputed — identity is stable.
    auditTrail is extended with "Updated" entry.
    """
    new_tech_ids  = _norm_ids(technique_ids)         if technique_ids         is not None else mapping.techniqueIds
    new_sub_ids   = _norm_ids(sub_technique_ids)     if sub_technique_ids     is not None else mapping.subTechniqueIds
    new_asset_ids = _norm_ids(asset_ids)             if asset_ids             is not None else mapping.assetIds
    new_ev_ids    = _norm_ids(evidence_ids)          if evidence_ids          is not None else mapping.evidenceIds
    new_tl_ids    = _norm_ids(timeline_event_ids)    if timeline_event_ids    is not None else mapping.timelineEventIds
    new_node_ids  = _norm_ids(attack_graph_node_ids) if attack_graph_node_ids is not None else mapping.attackGraphNodeIds

    new_find_fp   = finding_fingerprint  if finding_fingerprint  is not None else mapping.findingFingerprint
    new_alert_fp  = alert_fingerprint    if alert_fingerprint    is not None else mapping.alertFingerprint
    new_graph_fp  = graph_fingerprint    if graph_fingerprint    is not None else mapping.graphFingerprint
    new_tl_fp     = timeline_fingerprint if timeline_fingerprint is not None else mapping.timelineFingerprint

    new_fingerprint = _compute_mapping_fingerprint(
        new_find_fp, new_alert_fp, new_graph_fp, new_tl_fp,
        new_asset_ids, new_ev_ids,
    )

    # Rebuild explanation only when at least one field supplied
    _exp = mapping.explanation
    if any(v is not None for v in (reason, matched_evidence, matched_indicators,
                                    recommended_actions, analyst_notes)):
        _exp = MitreExplanation(
            reason             = reason             if reason             is not None else mapping.explanation.reason,
            matchedEvidence    = _norm_ids(matched_evidence)   if matched_evidence   is not None else mapping.explanation.matchedEvidence,
            matchedIndicators  = _norm_strs(matched_indicators)if matched_indicators is not None else mapping.explanation.matchedIndicators,
            recommendedActions = tuple(recommended_actions)    if recommended_actions is not None else mapping.explanation.recommendedActions,
            analystNotes       = analyst_notes      if analyst_notes      is not None else mapping.explanation.analystNotes,
        )

    return replace(
        mapping,
        techniqueIds         = new_tech_ids,
        subTechniqueIds      = new_sub_ids,
        assetIds             = new_asset_ids,
        evidenceIds          = new_ev_ids,
        timelineEventIds     = new_tl_ids,
        attackGraphNodeIds   = new_node_ids,
        confidence           = _clamp(confidence)  if confidence  is not None else mapping.confidence,
        riskScore            = _clamp(risk_score)  if risk_score  is not None else mapping.riskScore,
        findingFingerprint   = new_find_fp,
        alertFingerprint     = new_alert_fp,
        graphFingerprint     = new_graph_fp,
        timelineFingerprint  = new_tl_fp,
        mappingFingerprint   = new_fingerprint,
        mappingReason        = mapping_reason if mapping_reason is not None else mapping.mappingReason,
        explanation          = _exp,
        metadata             = dict(metadata) if metadata is not None else mapping.metadata,
        auditTrail           = (*mapping.auditTrail, "Updated"),
    )


# ===========================================================================
# Builder: merge_mappings()
# ===========================================================================

def merge_mappings(base: MitreMapping, incoming: MitreMapping) -> MitreMapping:
    """
    Merge *incoming* into *base*, producing a new MitreMapping.

    Merging rules
    -------------
    - techniqueIds, subTechniqueIds, assetIds, evidenceIds,
      timelineEventIds, attackGraphNodeIds: union of both sets (deduped + sorted).
    - confidence / riskScore: take the maximum of the two values.
    - explanation.matchedEvidence, matchedIndicators: union (deduped + sorted).
    - explanation.recommendedActions: union (insertion order preserved, deduped).
    - explanation.analystNotes: concatenate non-empty notes, pipe-separated.
    - mappingFingerprint: recomputed from merged state.
    - mappingKey / mappingId: preserved from *base* — identity is stable.
    - auditTrail: base trail extended with "Merged".
    - metadata: shallow-merge (incoming wins on key conflicts).

    Parameters
    ----------
    base     : the primary MitreMapping to merge into.
    incoming : the secondary MitreMapping whose fields are merged into base.

    Returns
    -------
    MitreMapping (frozen)
    """
    def _union(a: Tuple[str, ...], b: Tuple[str, ...]) -> Tuple[str, ...]:
        return tuple(sorted(set(a) | set(b)))

    merged_tech     = _union(base.techniqueIds,       incoming.techniqueIds)
    merged_sub      = _union(base.subTechniqueIds,    incoming.subTechniqueIds)
    merged_assets   = _union(base.assetIds,           incoming.assetIds)
    merged_ev       = _union(base.evidenceIds,        incoming.evidenceIds)
    merged_tl       = _union(base.timelineEventIds,   incoming.timelineEventIds)
    merged_nodes    = _union(base.attackGraphNodeIds, incoming.attackGraphNodeIds)

    new_conf   = max(base.confidence, incoming.confidence)
    new_risk   = max(base.riskScore,  incoming.riskScore)

    # Fingerprint uses the base upstream FPs (identity is from base)
    new_fingerprint = _compute_mapping_fingerprint(
        base.findingFingerprint, base.alertFingerprint,
        base.graphFingerprint,   base.timelineFingerprint,
        merged_assets, merged_ev,
    )

    # Merge explanation
    merged_ev_exp   = _union(base.explanation.matchedEvidence,   incoming.explanation.matchedEvidence)
    merged_ind      = _union(base.explanation.matchedIndicators, incoming.explanation.matchedIndicators)
    # recommendedActions: order-preserving union
    seen_actions: dict = {}
    for a in (*base.explanation.recommendedActions, *incoming.explanation.recommendedActions):
        seen_actions[a] = None
    merged_actions = tuple(seen_actions.keys())

    notes_parts = [n for n in (base.explanation.analystNotes, incoming.explanation.analystNotes) if n]
    merged_notes = " | ".join(notes_parts)

    merged_explanation = MitreExplanation(
        reason             = base.explanation.reason or incoming.explanation.reason,
        matchedEvidence    = merged_ev_exp,
        matchedIndicators  = merged_ind,
        recommendedActions = merged_actions,
        analystNotes       = merged_notes,
    )

    # Metadata: shallow merge (incoming wins)
    merged_meta = {**base.metadata, **incoming.metadata}

    return replace(
        base,
        techniqueIds         = merged_tech,
        subTechniqueIds      = merged_sub,
        assetIds             = merged_assets,
        evidenceIds          = merged_ev,
        timelineEventIds     = merged_tl,
        attackGraphNodeIds   = merged_nodes,
        confidence           = _clamp(new_conf),
        riskScore            = _clamp(new_risk),
        mappingFingerprint   = new_fingerprint,
        explanation          = merged_explanation,
        metadata             = merged_meta,
        auditTrail           = (*base.auditTrail, "Merged"),
    )


# ===========================================================================
# Builder: build_statistics()
# ===========================================================================

def build_statistics(
    techniques: List[MitreTechnique],
    mappings  : List[MitreMapping],
) -> MitreStatistics:
    """
    Compute MitreStatistics over a technique + mapping collection.

    Deterministic: canonical sort applied before numeric accumulation.

    techniquesByTactic : { tacticId → count of techniques that reference it }
    highestRiskTechnique : techniqueCode with the maximum riskScore
                           (first in alphabetical order on tie)
    averageConfidence  : mean technique confidence (0.0 when empty)
    """
    # Canonical sort before numeric accumulation
    ordered_tech = sort_techniques(techniques, by="riskScore", ascending=False)

    total_tech = len(ordered_tech)
    total_map  = len(mappings)

    # techniquesByTactic
    by_tactic: Dict[str, int] = {}
    for t in ordered_tech:
        for tid in t.tacticIds:
            by_tactic[tid] = by_tactic.get(tid, 0) + 1

    # highestRiskTechnique — max riskScore, tie-break by techniqueCode ASC
    highest: Optional[str] = None
    if ordered_tech:
        max_risk = ordered_tech[0].riskScore
        candidates = [t.techniqueCode for t in ordered_tech if t.riskScore == max_risk]
        highest = sorted(candidates)[0]

    avg_conf = (
        sum(t.confidence for t in ordered_tech) / total_tech
        if total_tech else 0.0
    )

    return MitreStatistics(
        totalTechniques      = total_tech,
        totalMappings        = total_map,
        techniquesByTactic   = by_tactic,
        highestRiskTechnique = highest,
        averageConfidence    = round(avg_conf, 4),
    )


# ===========================================================================
# Builder: build_bundle()
# ===========================================================================

def build_bundle(
    tactics       : List[MitreTactic],
    techniques    : List[MitreTechnique],
    sub_techniques: List[MitreSubTechnique],
    mappings      : List[MitreMapping],
    created_at    : str,
) -> MitreBundle:
    """
    Assemble a MitreBundle from component collections.

    Ordering applied inside the bundle:
    - tactics       : order ASC (ATT&CK matrix column order)
    - techniques    : riskScore DESC, techniqueCode ASC
    - subTechniques : riskScore DESC, subTechniqueCode ASC
    - mappings      : confidence DESC, mappingId ASC

    Parameters
    ----------
    tactics        : list of MitreTactic objects
    techniques     : list of MitreTechnique objects
    sub_techniques : list of MitreSubTechnique objects
    mappings       : list of MitreMapping objects
    created_at     : ISO-8601 string (caller-supplied)

    Returns
    -------
    MitreBundle (frozen)
    """
    sorted_tactics  = tuple(sorted(tactics, key=lambda t: (t.order, t.shortName)))
    sorted_techs    = tuple(sort_techniques(techniques,    by="riskScore", ascending=False))
    sorted_subs     = tuple(sort_subtechniques(sub_techniques, ascending=False))
    sorted_mappings = tuple(sort_mappings(mappings, by="confidence", ascending=False))

    stats = build_statistics(list(techniques), list(mappings))

    return MitreBundle(
        tactics       = sorted_tactics,
        techniques    = sorted_techs,
        subTechniques = sorted_subs,
        mappings      = sorted_mappings,
        statistics    = stats,
        engineVersion = MITRE_ENGINE_VERSION,
        createdAt     = created_at,
    )


# ===========================================================================
# Utility: sort_techniques()
# ===========================================================================

_VALID_TECH_SORT_KEYS = frozenset({
    "riskScore", "confidence", "techniqueCode", "name",
})


def sort_techniques(
    techniques: List[MitreTechnique],
    by        : str  = "riskScore",
    ascending : bool = False,
) -> List[MitreTechnique]:
    """
    Return a new sorted list of MitreTechnique objects.

    Parameters
    ----------
    by        : "riskScore" (default) | "confidence" | "techniqueCode" | "name"
    ascending : False = descending (highest first, default)

    Tie-breaking is always by techniqueCode ASC for determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_TECH_SORT_KEYS:
        raise ValueError(
            f"sort_techniques: unknown key '{by}'. Valid: {sorted(_VALID_TECH_SORT_KEYS)}"
        )

    def _key(t: MitreTechnique):
        primary = getattr(t, by)
        return (primary, t.techniqueCode)

    return sorted(techniques, key=_key, reverse=not ascending)


def sort_subtechniques(
    sub_techniques: List[MitreSubTechnique],
    ascending     : bool = False,
) -> List[MitreSubTechnique]:
    """
    Sort sub-techniques by riskScore DESC (or ASC), tie-break by subTechniqueCode ASC.
    """
    return sorted(
        sub_techniques,
        key=lambda s: (s.riskScore, s.subTechniqueCode),
        reverse=not ascending,
    )


def sort_mappings(
    mappings  : List[MitreMapping],
    by        : str  = "confidence",
    ascending : bool = False,
) -> List[MitreMapping]:
    """
    Sort mappings by confidence or riskScore.

    by        : "confidence" (default) | "riskScore"
    Tie-break : mappingId ASC.
    """
    valid = frozenset({"confidence", "riskScore"})
    if by not in valid:
        raise ValueError(f"sort_mappings: unknown key '{by}'. Valid: {sorted(valid)}")

    def _key(m: MitreMapping):
        return (getattr(m, by), m.mappingId)

    return sorted(mappings, key=_key, reverse=not ascending)


# ===========================================================================
# Utility: filter_techniques()
# ===========================================================================

def filter_techniques(
    techniques       : List[MitreTechnique],
    tactic_id        : Optional[str]   = None,
    platform         : Optional[str]   = None,
    min_risk_score   : Optional[float] = None,
    max_risk_score   : Optional[float] = None,
    min_confidence   : Optional[float] = None,
    technique_code   : Optional[str]   = None,
    asset_id         : Optional[str]   = None,   # reserved — future use
    finding_id       : Optional[str]   = None,   # reserved — future use
    alert_id         : Optional[str]   = None,   # reserved — future use
    relationship_id  : Optional[str]   = None,   # reserved — future use
) -> List[MitreTechnique]:
    """
    Return a filtered subset of MitreTechnique objects.

    All supplied filters are ANDed.  None = no filter on that field.
    platform and tactic_id are exact-membership filters against the
    respective Tuple fields.

    Parameters
    ----------
    tactic_id       : keep only techniques whose tacticIds contains this value
    platform        : keep only techniques whose platforms contains this value (lowercase)
    min_risk_score  : keep only techniques with riskScore >= this
    max_risk_score  : keep only techniques with riskScore <= this
    min_confidence  : keep only techniques with confidence >= this
    technique_code  : keep only the technique with this exact code (case-insensitive)
    asset_id / finding_id / alert_id / relationship_id :
                      reserved for future linkage filtering (no-ops currently)
    """
    result: List[MitreTechnique] = []
    norm_platform = platform.strip().lower() if platform else None
    norm_code     = technique_code.strip().upper() if technique_code else None

    for t in techniques:
        if tactic_id      is not None and tactic_id           not in t.tacticIds:        continue
        if norm_platform  is not None and norm_platform        not in t.platforms:        continue
        if min_risk_score is not None and t.riskScore          <  min_risk_score:         continue
        if max_risk_score is not None and t.riskScore          >  max_risk_score:         continue
        if min_confidence is not None and t.confidence         <  min_confidence:         continue
        if norm_code      is not None and t.techniqueCode      != norm_code:              continue
        result.append(t)

    return result


# ===========================================================================
# Utility: filter_mappings()
# ===========================================================================

def filter_mappings(
    mappings         : List[MitreMapping],
    technique_id     : Optional[str]   = None,
    sub_technique_id : Optional[str]   = None,
    finding_id       : Optional[str]   = None,
    alert_id         : Optional[str]   = None,
    relationship_id  : Optional[str]   = None,
    asset_id         : Optional[str]   = None,
    min_confidence   : Optional[float] = None,
    min_risk_score   : Optional[float] = None,
) -> List[MitreMapping]:
    """
    Return a filtered subset of MitreMapping objects.

    All supplied filters are ANDed.
    Technique/subTechnique/asset filters check membership in the respective tuple.
    """
    result: List[MitreMapping] = []
    for m in mappings:
        if technique_id      is not None and technique_id      not in m.techniqueIds:     continue
        if sub_technique_id  is not None and sub_technique_id  not in m.subTechniqueIds:  continue
        if finding_id        is not None and m.findingId       != finding_id:             continue
        if alert_id          is not None and m.alertId         != alert_id:               continue
        if relationship_id   is not None and m.relationshipId  != relationship_id:        continue
        if asset_id          is not None and asset_id          not in m.assetIds:         continue
        if min_confidence    is not None and m.confidence      <  min_confidence:         continue
        if min_risk_score    is not None and m.riskScore       <  min_risk_score:         continue
        result.append(m)
    return result


# ===========================================================================
# Utility: group_techniques()
# ===========================================================================

def group_techniques(
    techniques: List[MitreTechnique],
    by        : str = "tactic",
) -> Dict[str, List[MitreTechnique]]:
    """
    Group techniques by tactic, platform, risk bucket, or confidence bucket.

    Parameters
    ----------
    by : "tactic" (default) — one group per tacticId; technique appears in ALL
                              of its tactic groups.
         "platform"         — one group per platform string; technique appears
                              in ALL of its platform groups.
         "technique"        — identity group (one technique per group key =
                              techniqueCode; useful for index building).
         "risk_bucket"      — "critical" (>=80), "high" (>=60), "medium" (>=40),
                              "low" (<40).
         "confidence_bucket"— "high" (>=80), "medium" (>=50), "low" (<50).

    Raises ValueError for unknown *by* values.
    """
    valid = {"tactic", "platform", "technique", "risk_bucket", "confidence_bucket"}
    if by not in valid:
        raise ValueError(f"group_techniques: unknown key '{by}'. Valid: {sorted(valid)}")

    groups: Dict[str, List[MitreTechnique]] = {}

    for t in techniques:
        if by == "tactic":
            keys = list(t.tacticIds) if t.tacticIds else ["unassigned"]
        elif by == "platform":
            keys = list(t.platforms) if t.platforms else ["unknown"]
        elif by == "technique":
            keys = [t.techniqueCode]
        elif by == "risk_bucket":
            r = t.riskScore
            if r >= 80:   keys = ["critical"]
            elif r >= 60: keys = ["high"]
            elif r >= 40: keys = ["medium"]
            else:         keys = ["low"]
        else:  # confidence_bucket
            c = t.confidence
            if c >= 80:   keys = ["high"]
            elif c >= 50: keys = ["medium"]
            else:         keys = ["low"]

        for key in keys:
            groups.setdefault(key, []).append(t)

    return groups


def group_mappings(
    mappings: List[MitreMapping],
    by      : str = "techniqueId",
) -> Dict[str, List[MitreMapping]]:
    """
    Group mappings by techniqueId, findingId, alertId, or relationshipId.

    Each mapping appears once per key it matches.

    Raises ValueError for unknown *by* values.
    """
    valid = {"techniqueId", "findingId", "alertId", "relationshipId"}
    if by not in valid:
        raise ValueError(f"group_mappings: unknown key '{by}'. Valid: {sorted(valid)}")

    groups: Dict[str, List[MitreMapping]] = {}
    for m in mappings:
        if by == "techniqueId":
            keys = list(m.techniqueIds) if m.techniqueIds else ["unassigned"]
        elif by == "findingId":
            keys = [m.findingId]
        elif by == "alertId":
            keys = [m.alertId]
        else:
            keys = [m.relationshipId]
        for key in keys:
            groups.setdefault(key, []).append(m)
    return groups


# ===========================================================================
# Utility: find_technique() / find_mapping()
# ===========================================================================

def find_technique(
    techniques     : List[MitreTechnique],
    technique_id   : Optional[str] = None,
    technique_key  : Optional[str] = None,
    technique_code : Optional[str] = None,
    name           : Optional[str] = None,
) -> Optional[MitreTechnique]:
    """
    Return the first technique matching the lookup criterion.

    Priority: techniqueId > techniqueKey > techniqueCode > name (exact match).
    Returns None if nothing matches or no criterion is supplied.
    """
    if technique_id:
        needle = technique_id.strip()
        for t in techniques:
            if t.techniqueId == needle:
                return t
        return None
    if technique_key:
        needle = technique_key.strip()
        for t in techniques:
            if t.techniqueKey == needle:
                return t
        return None
    if technique_code:
        needle = technique_code.strip().upper()
        for t in techniques:
            if t.techniqueCode == needle:
                return t
        return None
    if name:
        needle = name.strip()
        for t in techniques:
            if t.name == needle:
                return t
        return None
    return None


def find_mapping(
    mappings   : List[MitreMapping],
    mapping_id : Optional[str] = None,
    mapping_key: Optional[str] = None,
) -> Optional[MitreMapping]:
    """
    Return the first mapping matching the lookup criterion.

    Priority: mappingId > mappingKey.
    Returns None if nothing matches.
    """
    if mapping_id:
        needle = mapping_id.strip()
        for m in mappings:
            if m.mappingId == needle:
                return m
        return None
    if mapping_key:
        needle = mapping_key.strip()
        for m in mappings:
            if m.mappingKey == needle:
                return m
        return None
    return None


# ===========================================================================
# Utility: search_techniques()
# ===========================================================================

def search_techniques(
    techniques : List[MitreTechnique],
    query      : str,
) -> List[MitreTechnique]:
    """
    Full-text search across technique name, code, description, and data sources.

    Case-insensitive substring match.  Canonical sort applied before searching
    so the result order is deterministic for any given query string.

    Parameters
    ----------
    techniques : list to search
    query      : non-empty search string (stripped + lowercased internally)

    Returns
    -------
    Matching MitreTechnique objects sorted by riskScore DESC, techniqueCode ASC.
    Returns empty list for empty query.
    """
    q = query.strip().lower()
    if not q:
        return []

    result: List[MitreTechnique] = []
    for t in techniques:
        haystack = " ".join([
            t.techniqueCode.lower(),
            t.name.lower(),
            t.description.lower(),
            " ".join(t.dataSources),
        ])
        if q in haystack:
            result.append(t)

    return sort_techniques(result, by="riskScore", ascending=False)


# ===========================================================================
# Utility: calculate_statistics()
# ===========================================================================

def calculate_statistics(
    techniques: List[MitreTechnique],
    mappings  : List[MitreMapping],
) -> MitreStatistics:
    """
    Compute MitreStatistics — thin public alias for build_statistics().

    Applies canonical sort before any numeric accumulation.
    """
    return build_statistics(techniques, mappings)


# ===========================================================================
# Extension points
# ===========================================================================

def _hook_on_mapping_created(mapping: MitreMapping) -> None:
    """
    Extension point → Future Report Engine + AI Copilot.
    Called after build_mapping() produces a new MitreMapping.
    May trigger: report section generation, AI technique enrichment.
    """
    # TODO (future phase): Report Engine / AI Copilot integration


def _hook_on_mapping_updated(mapping: MitreMapping) -> None:
    """
    Extension point → Future Report Engine.
    Called after update_mapping().
    """
    # TODO (future phase): Report Engine integration


def _hook_on_mappings_merged(mapping: MitreMapping) -> None:
    """
    Extension point → Future Alert Engine.
    Called after merge_mappings() produces a merged result.
    May trigger: de-duplicate alerts, update MITRE coverage metrics.
    """
    # TODO (future phase): Alert Engine integration
