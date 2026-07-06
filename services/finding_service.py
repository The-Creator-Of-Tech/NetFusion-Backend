"""
Findings Engine
===============
Phase A4.0.7 — Deterministic finding lifecycle management.

Responsibilities
----------------
- Convert evidence, relationships, attack-graph nodes, timeline events and
  investigations into immutable Finding objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute findingFingerprint from all linked source collections so caching
  and replay are reliable.
- Carry a structured FindingExplanation so AI Copilot never reconstructs it.
- Expose builder functions: build, update, close, confirm, suppress, reopen,
  clone.
- Expose utility functions: sort, filter, group, find, statistics.

Design principles
-----------------
- All models are immutable (frozen=True dataclasses).
- All builder functions return NEW objects; nothing is mutated in place.
- Fully deterministic: same inputs → same outputs across every run.
- No database access, no repository, no API, no AI, no heuristics.
- Pure business logic only.
- All engine versions come from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.constants import FINDING_ENGINE_VERSION

# ── UUIDv5 namespace — fixed forever; changing it invalidates stored IDs ────
_FINDING_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class FindingSeverity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    OPEN           = "OPEN"
    CONFIRMED      = "CONFIRMED"
    SUPPRESSED     = "SUPPRESSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED       = "RESOLVED"
    CLOSED         = "CLOSED"


class FindingCategory(str, Enum):
    NETWORK       = "NETWORK"
    HOST          = "HOST"
    IDENTITY      = "IDENTITY"
    TRAFFIC       = "TRAFFIC"
    ATTACK_GRAPH  = "ATTACK_GRAPH"
    TIMELINE      = "TIMELINE"
    RELATIONSHIP  = "RELATIONSHIP"
    EVIDENCE      = "EVIDENCE"
    SYSTEM        = "SYSTEM"
    OTHER         = "OTHER"


# ===========================================================================
# FindingExplanation — structured rationale carried on every Finding
# ===========================================================================

@dataclass(frozen=True)
class FindingExplanation:
    """
    Human-readable and machine-parseable rationale for a Finding.

    Fields
    ------
    reason               : Why this finding was raised (factual, no AI).
    evidenceSummary      : What evidence supports this finding.
    affectedAssets       : Sorted tuple of asset IDs implicated.
    affectedRelationships: Sorted tuple of relationship IDs implicated.
    recommendedAction    : Concrete remediation or investigation step.

    AI Copilot should consume this directly; it must never reconstruct it.
    """
    reason                : str
    evidenceSummary       : str
    affectedAssets        : Tuple[str, ...]
    affectedRelationships : Tuple[str, ...]
    recommendedAction     : str


# ===========================================================================
# Immutable Finding model
# ===========================================================================

@dataclass(frozen=True)
class Finding:
    """
    Core finding record — immutable after construction.

    Identity
    --------
    findingId  : UUIDv5 derived from findingKey (deterministic).
    findingKey : SHA256(projectId + title + category + investigationId)[:32]

    Lifecycle
    ---------
    status    : current FindingStatus
    severity  : current FindingSeverity
    closedAt  : ISO-8601 string when RESOLVED / CLOSED / SUPPRESSED, else None

    Link collections (sorted tuples for determinism)
    -------------------------------------------------
    assetIds, relationshipIds, evidenceIds, timelineEventIds,
    graphNodeIds, mitreTechniqueIds

    Fingerprints
    ------------
    graphFingerprint           : opaque string from Attack Graph Engine
    timelineFingerprint        : opaque string from Timeline Intelligence Engine
    investigationFingerprint   : opaque string from Investigation Engine
    findingFingerprint         : SHA256 of all of the above (32 hex chars)

    Explanation
    -----------
    explanation : FindingExplanation — structured rationale (never None)

    Scoring
    -------
    riskScore  : 0–100 float
    confidence : 0–100 float

    Metadata
    --------
    tags          : sorted tuple of lowercase tag strings
    metadata      : arbitrary JSON-serialisable dict
    engineVersion : pinned at build time from FINDING_ENGINE_VERSION

    Audit
    -----
    auditTrail : ordered tuple of semantic action strings (no timestamps)
    """
    # ── Identity ────────────────────────────────────────────────────────────
    findingId  : str
    findingKey : str
    projectId  : str

    # ── Ownership / linkage ─────────────────────────────────────────────────
    investigationId : str

    # ── Core descriptors ────────────────────────────────────────────────────
    title       : str
    description : str
    category    : FindingCategory
    severity    : FindingSeverity
    status      : FindingStatus

    # ── Scoring ─────────────────────────────────────────────────────────────
    confidence : float   # 0–100
    riskScore  : float   # 0–100

    # ── Linked IDs (sorted tuples) ──────────────────────────────────────────
    assetIds          : Tuple[str, ...]
    relationshipIds   : Tuple[str, ...]
    evidenceIds       : Tuple[str, ...]
    timelineEventIds  : Tuple[str, ...]
    graphNodeIds      : Tuple[str, ...]
    mitreTechniqueIds : Tuple[str, ...]

    # ── Fingerprints ────────────────────────────────────────────────────────
    graphFingerprint         : str
    timelineFingerprint      : str
    investigationFingerprint : str
    findingFingerprint       : str   # 32 hex chars

    # ── Structured explanation (required) ───────────────────────────────────
    explanation : FindingExplanation

    # ── Classification ──────────────────────────────────────────────────────
    tags     : Tuple[str, ...]
    metadata : Dict[str, Any]

    # ── Lifecycle timestamps ─────────────────────────────────────────────────
    createdBy : str
    createdAt : str           # ISO-8601
    updatedAt : str           # ISO-8601
    closedAt  : Optional[str] # ISO-8601 or None

    # ── Versioning & audit ──────────────────────────────────────────────────
    engineVersion : str
    auditTrail    : Tuple[str, ...]


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_finding_key(
    project_id      : str,
    title           : str,
    category        : FindingCategory,
    investigation_id: str,
) -> str:
    """
    findingKey = SHA256(projectId + title + category.value + investigationId)[:32]

    Components are null-byte-separated to prevent cross-field collisions.
    """
    raw = f"{project_id}\x00{title}\x00{category.value}\x00{investigation_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_finding_id(finding_key: str) -> str:
    """findingId = UUIDv5(FINDING_NS, findingKey) as lowercase string."""
    return str(uuid.uuid5(_FINDING_NS, finding_key))


def _compute_finding_fingerprint(
    graph_fingerprint         : str,
    timeline_fingerprint      : str,
    investigation_fingerprint : str,
    asset_ids                 : Tuple[str, ...],
    evidence_ids              : Tuple[str, ...],
    relationship_ids          : Tuple[str, ...],
    graph_node_ids            : Tuple[str, ...],
) -> str:
    """
    findingFingerprint = SHA256(
        graphFingerprint,
        timelineFingerprint,
        investigationFingerprint,
        sorted(assetIds),
        sorted(evidenceIds),
        sorted(relationshipIds),
        sorted(graphNodeIds),
    )[:32]

    All ID collections are sorted before hashing — order-independent.
    Components are null-byte-separated; IDs within a group use \\x01.
    Returns 32 hex characters.
    """
    parts = [
        graph_fingerprint,
        timeline_fingerprint,
        investigation_fingerprint,
        "\x01".join(sorted(asset_ids)),
        "\x01".join(sorted(evidence_ids)),
        "\x01".join(sorted(relationship_ids)),
        "\x01".join(sorted(graph_node_ids)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _norm_ids(ids: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip and sort an ID list."""
    if not ids:
        return ()
    return tuple(sorted({i.strip() for i in ids if i and i.strip()}))


def _norm_tags(tags: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, lowercase, strip and sort tag strings."""
    if not tags:
        return ()
    return tuple(sorted({t.strip().lower() for t in tags if t and t.strip()}))


def _clamp(value: float) -> float:
    """Clamp a score to [0.0, 100.0]."""
    return float(max(0.0, min(100.0, value)))


def _build_explanation(
    reason                : str,
    evidence_summary      : str,
    affected_assets       : Optional[List[str]],
    affected_relationships: Optional[List[str]],
    recommended_action    : str,
) -> FindingExplanation:
    return FindingExplanation(
        reason                = reason,
        evidenceSummary       = evidence_summary,
        affectedAssets        = _norm_ids(affected_assets),
        affectedRelationships = _norm_ids(affected_relationships),
        recommendedAction     = recommended_action,
    )


# ===========================================================================
# Builder: build_finding()
# ===========================================================================

def build_finding(
    project_id               : str,
    investigation_id         : str,
    title                    : str,
    created_by               : str,
    created_at               : str,
    category                 : FindingCategory           = FindingCategory.OTHER,
    severity                 : FindingSeverity           = FindingSeverity.MEDIUM,
    description              : str                       = "",
    confidence               : float                     = 0.0,
    risk_score               : float                     = 0.0,
    asset_ids                : Optional[List[str]]       = None,
    relationship_ids         : Optional[List[str]]       = None,
    evidence_ids             : Optional[List[str]]       = None,
    timeline_event_ids       : Optional[List[str]]       = None,
    graph_node_ids           : Optional[List[str]]       = None,
    mitre_technique_ids      : Optional[List[str]]       = None,
    graph_fingerprint        : str                       = "",
    timeline_fingerprint     : str                       = "",
    investigation_fingerprint: str                       = "",
    reason                   : str                       = "",
    evidence_summary         : str                       = "",
    affected_assets          : Optional[List[str]]       = None,
    affected_relationships   : Optional[List[str]]       = None,
    recommended_action       : str                       = "",
    tags                     : Optional[List[str]]       = None,
    metadata                 : Optional[Dict[str, Any]]  = None,
) -> Finding:
    """
    Create a new Finding in OPEN status.

    Parameters
    ----------
    project_id                : owning project
    investigation_id          : parent investigation
    title                     : human-readable finding title
    created_by                : analyst / system identifier
    created_at                : ISO-8601 creation timestamp (caller-supplied)
    category                  : FindingCategory
    severity                  : FindingSeverity (default MEDIUM)
    description               : free-text description
    confidence                : 0–100 (clamped)
    risk_score                : 0–100 (clamped)
    asset_ids / relationship_ids / evidence_ids /
      timeline_event_ids / graph_node_ids / mitre_technique_ids
                              : linked IDs (deduped + sorted)
    graph_fingerprint         : opaque string from Attack Graph Engine
    timeline_fingerprint      : opaque string from Timeline Intelligence Engine
    investigation_fingerprint : opaque string from Investigation Engine
    reason                    : explanation — why this finding was raised
    evidence_summary          : explanation — supporting evidence summary
    affected_assets           : explanation — implicated asset IDs
    affected_relationships    : explanation — implicated relationship IDs
    recommended_action        : explanation — remediation / investigation step
    tags                      : classification tags
    metadata                  : arbitrary JSON-serialisable dict

    Returns
    -------
    Finding (frozen)
    """
    norm_asset_ids   = _norm_ids(asset_ids)
    norm_rel_ids     = _norm_ids(relationship_ids)
    norm_ev_ids      = _norm_ids(evidence_ids)
    norm_tl_ids      = _norm_ids(timeline_event_ids)
    norm_node_ids    = _norm_ids(graph_node_ids)
    norm_mitre_ids   = _norm_ids(mitre_technique_ids)

    key    = _compute_finding_key(project_id, title, category, investigation_id)
    fid    = _compute_finding_id(key)

    fingerprint = _compute_finding_fingerprint(
        graph_fingerprint,
        timeline_fingerprint,
        investigation_fingerprint,
        norm_asset_ids,
        norm_ev_ids,
        norm_rel_ids,
        norm_node_ids,
    )

    explanation = _build_explanation(
        reason, evidence_summary,
        affected_assets, affected_relationships, recommended_action,
    )

    return Finding(
        findingId                = fid,
        findingKey               = key,
        projectId                = project_id,
        investigationId          = investigation_id,
        title                    = title,
        description              = description,
        category                 = category,
        severity                 = severity,
        status                   = FindingStatus.OPEN,
        confidence               = _clamp(confidence),
        riskScore                = _clamp(risk_score),
        assetIds                 = norm_asset_ids,
        relationshipIds          = norm_rel_ids,
        evidenceIds              = norm_ev_ids,
        timelineEventIds         = norm_tl_ids,
        graphNodeIds             = norm_node_ids,
        mitreTechniqueIds        = norm_mitre_ids,
        graphFingerprint         = graph_fingerprint,
        timelineFingerprint      = timeline_fingerprint,
        investigationFingerprint = investigation_fingerprint,
        findingFingerprint       = fingerprint,
        explanation              = explanation,
        tags                     = _norm_tags(tags),
        metadata                 = dict(metadata) if metadata else {},
        createdBy                = created_by,
        createdAt                = created_at,
        updatedAt                = created_at,
        closedAt                 = None,
        engineVersion            = FINDING_ENGINE_VERSION,
        auditTrail               = ("Created",),
    )


# ===========================================================================
# Builder: update_finding()
# ===========================================================================

def update_finding(
    finding                  : Finding,
    updated_at               : str,
    title                    : Optional[str]              = None,
    description              : Optional[str]              = None,
    category                 : Optional[FindingCategory]  = None,
    severity                 : Optional[FindingSeverity]  = None,
    status                   : Optional[FindingStatus]    = None,
    confidence               : Optional[float]            = None,
    risk_score               : Optional[float]            = None,
    asset_ids                : Optional[List[str]]        = None,
    relationship_ids         : Optional[List[str]]        = None,
    evidence_ids             : Optional[List[str]]        = None,
    timeline_event_ids       : Optional[List[str]]        = None,
    graph_node_ids           : Optional[List[str]]        = None,
    mitre_technique_ids      : Optional[List[str]]        = None,
    graph_fingerprint        : Optional[str]              = None,
    timeline_fingerprint     : Optional[str]              = None,
    investigation_fingerprint: Optional[str]              = None,
    reason                   : Optional[str]              = None,
    evidence_summary         : Optional[str]              = None,
    affected_assets          : Optional[List[str]]        = None,
    affected_relationships   : Optional[List[str]]        = None,
    recommended_action       : Optional[str]              = None,
    tags                     : Optional[List[str]]        = None,
    metadata                 : Optional[Dict[str, Any]]   = None,
) -> Finding:
    """
    Return a new Finding with supplied fields changed.

    None arguments → keep existing value.
    findingFingerprint is recomputed whenever any source field changes.
    auditTrail is extended with semantic entries.
    findingKey and findingId are never recomputed — identity is stable.
    """
    audit = list(finding.auditTrail)

    new_status   = status   if status   is not None else finding.status
    new_severity = severity if severity is not None else finding.severity
    new_category = category if category is not None else finding.category

    if status   is not None and status   != finding.status:
        audit.append(f"Status changed to {status.value}")
    if severity is not None and severity != finding.severity:
        audit.append(f"Severity changed to {severity.value}")
    if category is not None and category != finding.category:
        audit.append(f"Category changed to {category.value}")

    new_asset_ids  = _norm_ids(asset_ids)         if asset_ids         is not None else finding.assetIds
    new_rel_ids    = _norm_ids(relationship_ids)   if relationship_ids  is not None else finding.relationshipIds
    new_ev_ids     = _norm_ids(evidence_ids)       if evidence_ids      is not None else finding.evidenceIds
    new_tl_ids     = _norm_ids(timeline_event_ids) if timeline_event_ids is not None else finding.timelineEventIds
    new_node_ids   = _norm_ids(graph_node_ids)     if graph_node_ids    is not None else finding.graphNodeIds
    new_mitre_ids  = _norm_ids(mitre_technique_ids)if mitre_technique_ids is not None else finding.mitreTechniqueIds

    new_graph_fp   = graph_fingerprint         if graph_fingerprint         is not None else finding.graphFingerprint
    new_tl_fp      = timeline_fingerprint      if timeline_fingerprint      is not None else finding.timelineFingerprint
    new_inv_fp     = investigation_fingerprint if investigation_fingerprint is not None else finding.investigationFingerprint

    new_fingerprint = _compute_finding_fingerprint(
        new_graph_fp, new_tl_fp, new_inv_fp,
        new_asset_ids, new_ev_ids, new_rel_ids, new_node_ids,
    )

    # Rebuild explanation only when at least one explanation field is supplied
    _exp = finding.explanation
    if any(v is not None for v in (reason, evidence_summary, affected_assets,
                                    affected_relationships, recommended_action)):
        _exp = _build_explanation(
            reason                 if reason                 is not None else finding.explanation.reason,
            evidence_summary       if evidence_summary       is not None else finding.explanation.evidenceSummary,
            list(affected_assets)  if affected_assets        is not None else list(finding.explanation.affectedAssets),
            list(affected_relationships) if affected_relationships is not None else list(finding.explanation.affectedRelationships),
            recommended_action     if recommended_action     is not None else finding.explanation.recommendedAction,
        )

    new_conf  = _clamp(confidence)  if confidence  is not None else finding.confidence
    new_risk  = _clamp(risk_score)  if risk_score  is not None else finding.riskScore
    new_tags  = _norm_tags(tags)    if tags        is not None else finding.tags
    new_meta  = dict(metadata)      if metadata    is not None else finding.metadata
    new_title = title               if title       is not None else finding.title
    new_desc  = description         if description is not None else finding.description

    return replace(
        finding,
        title                    = new_title,
        description              = new_desc,
        category                 = new_category,
        severity                 = new_severity,
        status                   = new_status,
        confidence               = new_conf,
        riskScore                = new_risk,
        updatedAt                = updated_at,
        assetIds                 = new_asset_ids,
        relationshipIds          = new_rel_ids,
        evidenceIds              = new_ev_ids,
        timelineEventIds         = new_tl_ids,
        graphNodeIds             = new_node_ids,
        mitreTechniqueIds        = new_mitre_ids,
        graphFingerprint         = new_graph_fp,
        timelineFingerprint      = new_tl_fp,
        investigationFingerprint = new_inv_fp,
        findingFingerprint       = new_fingerprint,
        explanation              = _exp,
        tags                     = new_tags,
        metadata                 = new_meta,
        auditTrail               = tuple(audit),
    )


# ===========================================================================
# Builders: close / confirm / suppress / reopen / clone
# ===========================================================================

def close_finding(finding: Finding, closed_at: str) -> Finding:
    """
    Transition finding to CLOSED and stamp closedAt.

    - Already CLOSED / RESOLVED → returns unchanged (idempotent).
    - Appends "Closed" to auditTrail.
    """
    if finding.status in (FindingStatus.CLOSED, FindingStatus.RESOLVED):
        return finding
    return replace(
        finding,
        status     = FindingStatus.CLOSED,
        closedAt   = closed_at,
        updatedAt  = closed_at,
        auditTrail = (*finding.auditTrail, "Closed"),
    )


def confirm_finding(finding: Finding, updated_at: str) -> Finding:
    """
    Transition finding to CONFIRMED.

    - Already CONFIRMED → returns unchanged.
    - Appends "Confirmed" to auditTrail.
    """
    if finding.status == FindingStatus.CONFIRMED:
        return finding
    return replace(
        finding,
        status     = FindingStatus.CONFIRMED,
        updatedAt  = updated_at,
        auditTrail = (*finding.auditTrail, "Confirmed"),
    )


def suppress_finding(finding: Finding, updated_at: str, reason: str = "") -> Finding:
    """
    Transition finding to SUPPRESSED and stamp closedAt.

    - Already SUPPRESSED → returns unchanged.
    - Appends "Suppressed" + optional reason to auditTrail.
    - closedAt is set if not already present.
    """
    if finding.status == FindingStatus.SUPPRESSED:
        return finding
    entry      = "Suppressed" if not reason else f"Suppressed: {reason}"
    closed_at  = finding.closedAt or updated_at
    return replace(
        finding,
        status     = FindingStatus.SUPPRESSED,
        closedAt   = closed_at,
        updatedAt  = updated_at,
        auditTrail = (*finding.auditTrail, entry),
    )


def reopen_finding(finding: Finding, updated_at: str) -> Finding:
    """
    Reopen a CLOSED / SUPPRESSED / FALSE_POSITIVE / RESOLVED finding → OPEN.

    - Already OPEN / CONFIRMED → returns unchanged.
    - Clears closedAt.
    - Appends "Reopened" to auditTrail.
    """
    if finding.status in (FindingStatus.OPEN, FindingStatus.CONFIRMED):
        return finding
    return replace(
        finding,
        status     = FindingStatus.OPEN,
        closedAt   = None,
        updatedAt  = updated_at,
        auditTrail = (*finding.auditTrail, "Reopened"),
    )


def clone_finding(
    finding        : Finding,
    new_project_id : str,
    new_investigation_id: str,
    new_created_by : str,
    new_created_at : str,
    new_title      : Optional[str] = None,
) -> Finding:
    """
    Produce a new OPEN Finding cloned from *finding*.

    The clone:
    - Gets a fresh findingKey / findingId derived from
      (new_project_id, new_title or original title, category, new_investigation_id).
    - Resets status to OPEN and clears closedAt.
    - Resets auditTrail to ("Created",).
    - Inherits all linked IDs, fingerprints, scores, explanation, tags, metadata.
    - engineVersion is pinned to the current FINDING_ENGINE_VERSION.
    """
    title  = new_title if new_title else finding.title
    key    = _compute_finding_key(new_project_id, title, finding.category, new_investigation_id)
    fid    = _compute_finding_id(key)

    new_fingerprint = _compute_finding_fingerprint(
        finding.graphFingerprint,
        finding.timelineFingerprint,
        finding.investigationFingerprint,
        finding.assetIds,
        finding.evidenceIds,
        finding.relationshipIds,
        finding.graphNodeIds,
    )

    return replace(
        finding,
        findingId                = fid,
        findingKey               = key,
        projectId                = new_project_id,
        investigationId          = new_investigation_id,
        title                    = title,
        status                   = FindingStatus.OPEN,
        createdBy                = new_created_by,
        createdAt                = new_created_at,
        updatedAt                = new_created_at,
        closedAt                 = None,
        findingFingerprint       = new_fingerprint,
        engineVersion            = FINDING_ENGINE_VERSION,
        auditTrail               = ("Created",),
    )


# ===========================================================================
# Utility: sort_findings()
# ===========================================================================

_SEVERITY_ORDER: Dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL : 5,
    FindingSeverity.HIGH     : 4,
    FindingSeverity.MEDIUM   : 3,
    FindingSeverity.LOW      : 2,
    FindingSeverity.INFO     : 1,
}

_STATUS_ORDER: Dict[FindingStatus, int] = {
    FindingStatus.CONFIRMED      : 6,
    FindingStatus.OPEN           : 5,
    FindingStatus.RESOLVED       : 4,
    FindingStatus.SUPPRESSED     : 3,
    FindingStatus.FALSE_POSITIVE : 2,
    FindingStatus.CLOSED         : 1,
}

_VALID_SORT_KEYS = frozenset({
    "severity", "status", "riskScore", "confidence",
    "createdAt", "updatedAt", "title", "category",
})


def sort_findings(
    findings  : List[Finding],
    by        : str  = "severity",
    ascending : bool = False,
) -> List[Finding]:
    """
    Return a new sorted list of findings.

    Parameters
    ----------
    by        : "severity" (default) | "status" | "riskScore" | "confidence"
                "createdAt" | "updatedAt" | "title" | "category"
    ascending : False = descending (highest priority first, default)

    Tie-breaking is always by findingId ASC for determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_SORT_KEYS:
        raise ValueError(
            f"sort_findings: unknown key '{by}'. Valid: {sorted(_VALID_SORT_KEYS)}"
        )

    def _key(f: Finding):
        if by == "severity":
            primary = _SEVERITY_ORDER.get(f.severity, 0)
        elif by == "status":
            primary = _STATUS_ORDER.get(f.status, 0)
        elif by == "riskScore":
            primary = f.riskScore
        elif by == "confidence":
            primary = f.confidence
        elif by == "category":
            primary = f.category.value
        else:
            primary = getattr(f, by, "")
        return (primary, f.findingId)

    return sorted(findings, key=_key, reverse=not ascending)


# ===========================================================================
# Utility: filter_findings()
# ===========================================================================

def filter_findings(
    findings        : List[Finding],
    status          : Optional[FindingStatus]   = None,
    severity        : Optional[FindingSeverity] = None,
    category        : Optional[FindingCategory] = None,
    project_id      : Optional[str]             = None,
    investigation_id: Optional[str]             = None,
    created_by      : Optional[str]             = None,
    tags            : Optional[List[str]]        = None,
    min_risk_score  : Optional[float]            = None,
    max_risk_score  : Optional[float]            = None,
    min_confidence  : Optional[float]            = None,
    engine_version  : Optional[str]              = None,
    mitre_technique : Optional[str]              = None,
) -> List[Finding]:
    """
    Return a filtered subset of findings.

    All supplied filters are ANDed.  None = no filter on that field.
    Tag filtering requires ALL supplied tags to be present (AND semantics).
    mitre_technique filters by exact membership in finding.mitreTechniqueIds.
    """
    filter_tags = _norm_tags(tags) if tags else None
    result: List[Finding] = []

    for f in findings:
        if status          is not None and f.status          != status:          continue
        if severity        is not None and f.severity        != severity:        continue
        if category        is not None and f.category        != category:        continue
        if project_id      is not None and f.projectId       != project_id:      continue
        if investigation_id is not None and f.investigationId != investigation_id: continue
        if created_by      is not None and f.createdBy       != created_by:      continue
        if engine_version  is not None and f.engineVersion   != engine_version:  continue
        if min_risk_score  is not None and f.riskScore       <  min_risk_score:  continue
        if max_risk_score  is not None and f.riskScore       >  max_risk_score:  continue
        if min_confidence  is not None and f.confidence      <  min_confidence:  continue
        if mitre_technique is not None and mitre_technique.strip() not in f.mitreTechniqueIds: continue
        if filter_tags is not None:
            if not all(t in f.tags for t in filter_tags):
                continue
        result.append(f)

    return result


# ===========================================================================
# Utility: group_findings()
# ===========================================================================

_VALID_GROUP_KEYS = frozenset({
    "status", "severity", "category",
    "projectId", "investigationId", "createdBy", "engineVersion",
})


def group_findings(
    findings: List[Finding],
    by      : str = "severity",
) -> Dict[str, List[Finding]]:
    """
    Group findings into a dict keyed by the requested field value.

    Parameters
    ----------
    by : "severity" (default) | "status" | "category" | "projectId"
         "investigationId" | "createdBy" | "engineVersion"

    Within each group, insertion order from *findings* is preserved.

    Raises ValueError for unknown *by* values.
    """
    if by not in _VALID_GROUP_KEYS:
        raise ValueError(
            f"group_findings: unknown key '{by}'. Valid: {sorted(_VALID_GROUP_KEYS)}"
        )

    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        raw = getattr(f, by)
        key = raw.value if isinstance(raw, Enum) else str(raw)
        groups.setdefault(key, []).append(f)
    return groups


# ===========================================================================
# Utility: find_finding()
# ===========================================================================

def find_finding(
    findings     : List[Finding],
    finding_id   : Optional[str] = None,
    finding_key  : Optional[str] = None,
    title        : Optional[str] = None,
) -> Optional[Finding]:
    """
    Return the first finding matching the lookup criterion.

    Priority: findingId > findingKey > title (exact match).
    Returns None if nothing matches or no criterion is supplied.
    """
    if finding_id:
        needle = finding_id.strip()
        for f in findings:
            if f.findingId == needle:
                return f
        return None

    if finding_key:
        needle = finding_key.strip()
        for f in findings:
            if f.findingKey == needle:
                return f
        return None

    if title:
        needle = title.strip()
        for f in findings:
            if f.title == needle:
                return f
        return None

    return None


# ===========================================================================
# Statistics
# ===========================================================================

@dataclass(frozen=True)
class FindingStatistics:
    """Aggregate statistics over a collection of findings."""
    totalFindings      : int
    openFindings       : int   # OPEN + CONFIRMED
    criticalFindings   : int   # severity == CRITICAL
    resolvedFindings   : int   # RESOLVED + CLOSED
    averageRisk        : float  # 0.0 when empty
    averageConfidence  : float  # 0.0 when empty
    findingsBySeverity : Dict[str, int]   # severity.value → count
    findingsByCategory : Dict[str, int]   # category.value → count


def calculate_statistics(findings: List[Finding]) -> FindingStatistics:
    """
    Compute aggregate statistics over *findings*.

    Deterministic: applies canonical sort before numeric accumulation so that
    floating-point summation order is identical across all runs.

    Definitions
    -----------
    openFindings     : OPEN + CONFIRMED
    resolvedFindings : RESOLVED + CLOSED
    criticalFindings : severity == CRITICAL
    averageRisk      : mean riskScore (0.0 if empty)
    averageConfidence: mean confidence (0.0 if empty)
    findingsBySeverity / findingsByCategory: full counts for all enum values
    """
    # Canonical sort — ensures summation order is run-independent
    ordered = sort_findings(findings, by="severity", ascending=True)
    total   = len(ordered)

    open_c     = sum(1 for f in ordered if f.status in (FindingStatus.OPEN, FindingStatus.CONFIRMED))
    critical_c = sum(1 for f in ordered if f.severity == FindingSeverity.CRITICAL)
    resolved_c = sum(1 for f in ordered if f.status in (FindingStatus.RESOLVED, FindingStatus.CLOSED))

    avg_risk = sum(f.riskScore  for f in ordered) / total if total else 0.0
    avg_conf = sum(f.confidence for f in ordered) / total if total else 0.0

    # Per-severity counts — include all enum values (zero-fill missing)
    by_severity: Dict[str, int] = {s.value: 0 for s in FindingSeverity}
    for f in ordered:
        by_severity[f.severity.value] += 1

    # Per-category counts — include all enum values (zero-fill missing)
    by_category: Dict[str, int] = {c.value: 0 for c in FindingCategory}
    for f in ordered:
        by_category[f.category.value] += 1

    return FindingStatistics(
        totalFindings      = total,
        openFindings       = open_c,
        criticalFindings   = critical_c,
        resolvedFindings   = resolved_c,
        averageRisk        = round(avg_risk, 4),
        averageConfidence  = round(avg_conf, 4),
        findingsBySeverity = by_severity,
        findingsByCategory = by_category,
    )


# ===========================================================================
# Extension points
# ===========================================================================
# Stubs — mark future integration contracts; intentionally do nothing.

def _hook_on_finding_created(finding: Finding) -> None:
    """
    Extension point → Future Alert Engine.
    Called after build_finding() produces a new Finding.
    May trigger: alert creation, notification bus, AI triage queue.
    """
    # TODO (future phase): Alert Engine integration


def _hook_on_finding_confirmed(finding: Finding) -> None:
    """
    Extension point → Future MITRE Engine + AI Copilot.
    Called after confirm_finding().
    May trigger: MITRE technique enrichment, AI confidence update.
    """
    # TODO (future phase): MITRE Engine / AI Copilot integration


def _hook_on_finding_closed(finding: Finding) -> None:
    """
    Extension point → Future Report Engine.
    Called after close_finding() / suppress_finding().
    May trigger: report section generation, closure metrics update.
    """
    # TODO (future phase): Report Engine integration


def _hook_on_finding_reopened(finding: Finding) -> None:
    """
    Extension point → Future Alert Engine.
    Called after reopen_finding().
    May trigger: re-alert, clear suppression cache.
    """
    # TODO (future phase): Alert Engine integration
