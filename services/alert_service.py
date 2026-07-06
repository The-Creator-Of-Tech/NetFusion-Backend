"""
Alert Engine
============
Phase A4.0.8 — Deterministic alert lifecycle management.

Responsibilities
----------------
- Generate immutable Alert objects from Findings.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute alertFingerprint from finding/investigation/graph fingerprints and
  sorted linked ID collections — stable across runs for cache / replay.
- Carry a structured AlertExplanation and AlertCorrelation on every Alert.
- Expose builder functions: build, update, acknowledge, start, resolve,
  close, suppress, reopen, clone.
- Expose utility functions: sort, filter, group, find, statistics.

Design principles
-----------------
- All models are immutable (frozen=True dataclasses).
- All builder functions return NEW objects; nothing is mutated in place.
- Fully deterministic: same inputs → same outputs across every run.
- No database, no repository, no API, no AI.
- Pure business logic only.
- All engine versions come from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.constants import ALERT_ENGINE_VERSION

# ── UUIDv5 namespace — fixed forever; changing it invalidates stored IDs ────
_ALERT_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


# ===========================================================================
# Enumerations
# ===========================================================================

class AlertSeverity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    NEW         = "NEW"
    OPEN        = "OPEN"
    ACKNOWLEDGED= "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED    = "RESOLVED"
    CLOSED      = "CLOSED"
    SUPPRESSED  = "SUPPRESSED"


class AlertSource(str, Enum):
    FINDING = "FINDING"
    MANUAL  = "MANUAL"
    RULE    = "RULE"
    SYSTEM  = "SYSTEM"


# ===========================================================================
# AlertExplanation — structured rationale on every Alert
# ===========================================================================

@dataclass(frozen=True)
class AlertExplanation:
    """
    Human-readable and machine-parseable rationale for an Alert.

    Fields
    ------
    reason           : Why this alert was raised (factual, no AI).
    findingSummary   : Summary of the source Finding.
    affectedAssets   : Sorted tuple of asset IDs implicated.
    recommendedAction: Concrete triage or remediation step.
    escalationReason : Why this alert was escalated (empty if not escalated).
    """
    reason           : str
    findingSummary   : str
    affectedAssets   : Tuple[str, ...]
    recommendedAction: str
    escalationReason : str


# ===========================================================================
# AlertCorrelation — deterministic cross-alert linkage
# ===========================================================================

@dataclass(frozen=True)
class AlertCorrelation:
    """
    Deterministic cross-alert / cross-finding correlation metadata.

    No AI, no scoring heuristics — all fields are caller-supplied or
    derived from shared ID set intersections.

    Fields
    ------
    correlationId     : deterministic ID for this correlation group
                        (SHA256 of sorted relatedAlertIds)[:32]
    relatedAlertIds   : sorted tuple of correlated alert IDs
    relatedFindingIds : sorted tuple of related finding IDs
    sharedEvidenceIds : sorted tuple of evidence IDs shared across alerts
    sharedAssets      : sorted tuple of asset IDs shared across alerts
    correlationScore  : 0–100 float — fraction of shared assets/evidence
                        relative to total linked; deterministic, no ML
    """
    correlationId     : str
    relatedAlertIds   : Tuple[str, ...]
    relatedFindingIds : Tuple[str, ...]
    sharedEvidenceIds : Tuple[str, ...]
    sharedAssets      : Tuple[str, ...]
    correlationScore  : float   # 0–100


# ===========================================================================
# Immutable Alert model
# ===========================================================================

@dataclass(frozen=True)
class Alert:
    """
    Core alert record — immutable after construction.

    Identity
    --------
    alertId  : UUIDv5 derived from alertKey (deterministic).
    alertKey : SHA256(projectId + findingId + title + source.value)[:32]

    Lifecycle timestamps
    --------------------
    createdAt      : ISO-8601 creation time
    updatedAt      : ISO-8601 last update time
    closedAt       : ISO-8601 or None
    acknowledgedAt : ISO-8601 or None
    resolvedAt     : ISO-8601 or None

    Link collections (sorted tuples — deterministic iteration)
    ----------------------------------------------------------
    assetIds, relationshipIds, evidenceIds, graphNodeIds, timelineEventIds

    Fingerprints
    ------------
    findingFingerprint       : opaque string from the Finding Engine
    investigationFingerprint : opaque string from the Investigation Engine
    graphFingerprint         : opaque string from the Attack Graph Engine
    alertFingerprint         : SHA256 of all of the above (32 hex chars)

    Structured payloads
    -------------------
    explanation : AlertExplanation — rationale (never None)
    correlation : AlertCorrelation — cross-alert linkage (never None)

    Audit
    -----
    auditTrail : ordered tuple of semantic action strings (no timestamps)
    """
    # ── Identity ─────────────────────────────────────────────────────────
    alertId  : str
    alertKey : str
    projectId: str

    # ── Source linkage ───────────────────────────────────────────────────
    findingId      : str
    investigationId: str

    # ── Core descriptors ─────────────────────────────────────────────────
    title      : str
    description: str
    severity   : AlertSeverity
    status     : AlertStatus
    source     : AlertSource

    # ── Scoring ──────────────────────────────────────────────────────────
    confidence: float   # 0–100
    riskScore : float   # 0–100

    # ── Linked IDs (sorted tuples) ───────────────────────────────────────
    assetIds        : Tuple[str, ...]
    relationshipIds : Tuple[str, ...]
    evidenceIds     : Tuple[str, ...]
    graphNodeIds    : Tuple[str, ...]
    timelineEventIds: Tuple[str, ...]

    # ── Fingerprints ─────────────────────────────────────────────────────
    findingFingerprint      : str
    investigationFingerprint: str
    graphFingerprint        : str
    alertFingerprint        : str   # 32 hex chars

    # ── Classification ───────────────────────────────────────────────────
    tags    : Tuple[str, ...]
    metadata: Dict[str, Any]

    # ── Ownership ────────────────────────────────────────────────────────
    createdBy : str
    assignedTo: Optional[str]

    # ── Lifecycle timestamps ─────────────────────────────────────────────
    createdAt     : str           # ISO-8601
    updatedAt     : str           # ISO-8601
    closedAt      : Optional[str]
    acknowledgedAt: Optional[str]
    resolvedAt    : Optional[str]

    # ── Structured payloads ──────────────────────────────────────────────
    explanation: AlertExplanation
    correlation: AlertCorrelation

    # ── Versioning & audit ───────────────────────────────────────────────
    engineVersion: str
    auditTrail   : Tuple[str, ...]


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_alert_key(
    project_id: str,
    finding_id: str,
    title     : str,
    source    : AlertSource,
) -> str:
    """
    alertKey = SHA256(projectId + findingId + title + source.value)[:32]

    Null-byte-separated to prevent cross-field collisions.
    """
    raw = f"{project_id}\x00{finding_id}\x00{title}\x00{source.value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_alert_id(alert_key: str) -> str:
    """alertId = UUIDv5(ALERT_NS, alertKey) as lowercase canonical string."""
    return str(uuid.uuid5(_ALERT_NS, alert_key))


def _compute_alert_fingerprint(
    finding_fingerprint      : str,
    investigation_fingerprint: str,
    graph_fingerprint        : str,
    asset_ids                : Tuple[str, ...],
    evidence_ids             : Tuple[str, ...],
    graph_node_ids           : Tuple[str, ...],
) -> str:
    """
    alertFingerprint = SHA256(
        findingFingerprint,
        investigationFingerprint,
        graphFingerprint,
        sorted(assetIds),
        sorted(evidenceIds),
        sorted(graphNodeIds),
    )[:32]

    Returns 32 hex characters.
    """
    parts = [
        finding_fingerprint,
        investigation_fingerprint,
        graph_fingerprint,
        "\x01".join(sorted(asset_ids)),
        "\x01".join(sorted(evidence_ids)),
        "\x01".join(sorted(graph_node_ids)),
    ]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:32]


def _compute_correlation_id(related_alert_ids: Tuple[str, ...]) -> str:
    """
    correlationId = SHA256(sorted relatedAlertIds joined with \\x01)[:32]

    Empty tuple → SHA256 of empty string prefix.
    """
    raw = "\x01".join(sorted(related_alert_ids))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ===========================================================================
# Internal normalisation helpers
# ===========================================================================

def _norm_ids(ids: Optional[List[str]]) -> Tuple[str, ...]:
    if not ids:
        return ()
    return tuple(sorted({i.strip() for i in ids if i and i.strip()}))


def _norm_tags(tags: Optional[List[str]]) -> Tuple[str, ...]:
    if not tags:
        return ()
    return tuple(sorted({t.strip().lower() for t in tags if t and t.strip()}))


def _clamp(v: float) -> float:
    return float(max(0.0, min(100.0, v)))


def _build_explanation(
    reason            : str,
    finding_summary   : str,
    affected_assets   : Optional[List[str]],
    recommended_action: str,
    escalation_reason : str,
) -> AlertExplanation:
    return AlertExplanation(
        reason            = reason,
        findingSummary    = finding_summary,
        affectedAssets    = _norm_ids(affected_assets),
        recommendedAction = recommended_action,
        escalationReason  = escalation_reason,
    )


def _build_correlation(
    related_alert_ids  : Optional[List[str]],
    related_finding_ids: Optional[List[str]],
    shared_evidence_ids: Optional[List[str]],
    shared_assets      : Optional[List[str]],
    correlation_score  : float,
) -> AlertCorrelation:
    norm_alert_ids   = _norm_ids(related_alert_ids)
    norm_finding_ids = _norm_ids(related_finding_ids)
    norm_ev_ids      = _norm_ids(shared_evidence_ids)
    norm_assets      = _norm_ids(shared_assets)
    return AlertCorrelation(
        correlationId     = _compute_correlation_id(norm_alert_ids),
        relatedAlertIds   = norm_alert_ids,
        relatedFindingIds = norm_finding_ids,
        sharedEvidenceIds = norm_ev_ids,
        sharedAssets      = norm_assets,
        correlationScore  = _clamp(correlation_score),
    )


# ===========================================================================
# Builder: build_alert()
# ===========================================================================

def build_alert(
    project_id               : str,
    finding_id               : str,
    investigation_id         : str,
    title                    : str,
    created_by               : str,
    created_at               : str,
    source                   : AlertSource              = AlertSource.FINDING,
    severity                 : AlertSeverity            = AlertSeverity.MEDIUM,
    description              : str                      = "",
    confidence               : float                    = 0.0,
    risk_score               : float                    = 0.0,
    assigned_to              : Optional[str]            = None,
    asset_ids                : Optional[List[str]]      = None,
    relationship_ids         : Optional[List[str]]      = None,
    evidence_ids             : Optional[List[str]]      = None,
    graph_node_ids           : Optional[List[str]]      = None,
    timeline_event_ids       : Optional[List[str]]      = None,
    finding_fingerprint      : str                      = "",
    investigation_fingerprint: str                      = "",
    graph_fingerprint        : str                      = "",
    # explanation fields
    reason                   : str                      = "",
    finding_summary          : str                      = "",
    affected_assets          : Optional[List[str]]      = None,
    recommended_action       : str                      = "",
    escalation_reason        : str                      = "",
    # correlation fields
    related_alert_ids        : Optional[List[str]]      = None,
    related_finding_ids      : Optional[List[str]]      = None,
    shared_evidence_ids      : Optional[List[str]]      = None,
    shared_assets            : Optional[List[str]]      = None,
    correlation_score        : float                    = 0.0,
    tags                     : Optional[List[str]]      = None,
    metadata                 : Optional[Dict[str, Any]] = None,
) -> Alert:
    """
    Create a new Alert in NEW status.

    The alert is always initialised as NEW — callers must explicitly
    transition it via acknowledge_alert / start_alert / resolve_alert.

    Parameters
    ----------
    project_id / finding_id / investigation_id : source linkage
    title        : human-readable alert title
    created_by   : analyst / system identifier
    created_at   : ISO-8601 timestamp (caller-supplied for determinism)
    source       : AlertSource (default FINDING)
    severity     : AlertSeverity (default MEDIUM)
    description  : free-text description
    confidence   : 0–100 (clamped)
    risk_score   : 0–100 (clamped)
    assigned_to  : optional analyst
    *_ids        : linked entity IDs (deduped + sorted)
    *_fingerprint: opaque strings from upstream engines
    reason / finding_summary / affected_assets /
      recommended_action / escalation_reason  : AlertExplanation fields
    related_alert_ids / related_finding_ids /
      shared_evidence_ids / shared_assets /
      correlation_score                       : AlertCorrelation fields
    tags         : classification tags
    metadata     : arbitrary JSON-serialisable dict

    Returns
    -------
    Alert (frozen)
    """
    norm_asset_ids = _norm_ids(asset_ids)
    norm_rel_ids   = _norm_ids(relationship_ids)
    norm_ev_ids    = _norm_ids(evidence_ids)
    norm_node_ids  = _norm_ids(graph_node_ids)
    norm_tl_ids    = _norm_ids(timeline_event_ids)

    key    = _compute_alert_key(project_id, finding_id, title, source)
    aid    = _compute_alert_id(key)

    fingerprint = _compute_alert_fingerprint(
        finding_fingerprint, investigation_fingerprint, graph_fingerprint,
        norm_asset_ids, norm_ev_ids, norm_node_ids,
    )

    explanation = _build_explanation(
        reason, finding_summary, affected_assets,
        recommended_action, escalation_reason,
    )
    correlation = _build_correlation(
        related_alert_ids, related_finding_ids,
        shared_evidence_ids, shared_assets, correlation_score,
    )

    return Alert(
        alertId                  = aid,
        alertKey                 = key,
        projectId                = project_id,
        findingId                = finding_id,
        investigationId          = investigation_id,
        title                    = title,
        description              = description,
        severity                 = severity,
        status                   = AlertStatus.NEW,
        source                   = source,
        confidence               = _clamp(confidence),
        riskScore                = _clamp(risk_score),
        assetIds                 = norm_asset_ids,
        relationshipIds          = norm_rel_ids,
        evidenceIds              = norm_ev_ids,
        graphNodeIds             = norm_node_ids,
        timelineEventIds         = norm_tl_ids,
        findingFingerprint       = finding_fingerprint,
        investigationFingerprint = investigation_fingerprint,
        graphFingerprint         = graph_fingerprint,
        alertFingerprint         = fingerprint,
        tags                     = _norm_tags(tags),
        metadata                 = dict(metadata) if metadata else {},
        createdBy                = created_by,
        assignedTo               = assigned_to,
        createdAt                = created_at,
        updatedAt                = created_at,
        closedAt                 = None,
        acknowledgedAt           = None,
        resolvedAt               = None,
        explanation              = explanation,
        correlation              = correlation,
        engineVersion            = ALERT_ENGINE_VERSION,
        auditTrail               = ("Created",),
    )


# ===========================================================================
# Builder: update_alert()
# ===========================================================================

def update_alert(
    alert                    : Alert,
    updated_at               : str,
    title                    : Optional[str]             = None,
    description              : Optional[str]             = None,
    severity                 : Optional[AlertSeverity]   = None,
    status                   : Optional[AlertStatus]     = None,
    confidence               : Optional[float]           = None,
    risk_score               : Optional[float]           = None,
    assigned_to              : Optional[str]             = None,
    asset_ids                : Optional[List[str]]       = None,
    relationship_ids         : Optional[List[str]]       = None,
    evidence_ids             : Optional[List[str]]       = None,
    graph_node_ids           : Optional[List[str]]       = None,
    timeline_event_ids       : Optional[List[str]]       = None,
    finding_fingerprint      : Optional[str]             = None,
    investigation_fingerprint: Optional[str]             = None,
    graph_fingerprint        : Optional[str]             = None,
    # explanation overrides
    reason                   : Optional[str]             = None,
    finding_summary          : Optional[str]             = None,
    affected_assets          : Optional[List[str]]       = None,
    recommended_action       : Optional[str]             = None,
    escalation_reason        : Optional[str]             = None,
    # correlation overrides
    related_alert_ids        : Optional[List[str]]       = None,
    related_finding_ids      : Optional[List[str]]       = None,
    shared_evidence_ids      : Optional[List[str]]       = None,
    shared_assets            : Optional[List[str]]       = None,
    correlation_score        : Optional[float]           = None,
    tags                     : Optional[List[str]]       = None,
    metadata                 : Optional[Dict[str, Any]]  = None,
) -> Alert:
    """
    Return a new Alert with supplied fields changed.

    None → keep existing value.
    alertFingerprint is recomputed whenever any source field changes.
    alertKey / alertId are never recomputed — identity is stable.
    auditTrail is extended with semantic change entries.
    """
    audit = list(alert.auditTrail)

    new_status   = status   if status   is not None else alert.status
    new_severity = severity if severity is not None else alert.severity

    if status   is not None and status   != alert.status:
        audit.append(f"Status changed to {status.value}")
    if severity is not None and severity != alert.severity:
        audit.append(f"Severity changed to {severity.value}")
    if assigned_to is not None and assigned_to != alert.assignedTo:
        audit.append("Assigned")

    new_asset_ids = _norm_ids(asset_ids)          if asset_ids          is not None else alert.assetIds
    new_rel_ids   = _norm_ids(relationship_ids)    if relationship_ids   is not None else alert.relationshipIds
    new_ev_ids    = _norm_ids(evidence_ids)        if evidence_ids       is not None else alert.evidenceIds
    new_node_ids  = _norm_ids(graph_node_ids)      if graph_node_ids     is not None else alert.graphNodeIds
    new_tl_ids    = _norm_ids(timeline_event_ids)  if timeline_event_ids is not None else alert.timelineEventIds

    new_find_fp   = finding_fingerprint       if finding_fingerprint       is not None else alert.findingFingerprint
    new_inv_fp    = investigation_fingerprint if investigation_fingerprint is not None else alert.investigationFingerprint
    new_graph_fp  = graph_fingerprint         if graph_fingerprint         is not None else alert.graphFingerprint

    new_fingerprint = _compute_alert_fingerprint(
        new_find_fp, new_inv_fp, new_graph_fp,
        new_asset_ids, new_ev_ids, new_node_ids,
    )

    # Explanation — rebuild only when at least one field supplied
    _exp = alert.explanation
    if any(v is not None for v in (reason, finding_summary, affected_assets,
                                    recommended_action, escalation_reason)):
        _exp = _build_explanation(
            reason              if reason              is not None else alert.explanation.reason,
            finding_summary     if finding_summary     is not None else alert.explanation.findingSummary,
            list(affected_assets)  if affected_assets  is not None else list(alert.explanation.affectedAssets),
            recommended_action  if recommended_action  is not None else alert.explanation.recommendedAction,
            escalation_reason   if escalation_reason   is not None else alert.explanation.escalationReason,
        )

    # Correlation — rebuild only when at least one field supplied
    _cor = alert.correlation
    if any(v is not None for v in (related_alert_ids, related_finding_ids,
                                    shared_evidence_ids, shared_assets, correlation_score)):
        _cor = _build_correlation(
            list(related_alert_ids)   if related_alert_ids   is not None else list(alert.correlation.relatedAlertIds),
            list(related_finding_ids) if related_finding_ids is not None else list(alert.correlation.relatedFindingIds),
            list(shared_evidence_ids) if shared_evidence_ids is not None else list(alert.correlation.sharedEvidenceIds),
            list(shared_assets)       if shared_assets       is not None else list(alert.correlation.sharedAssets),
            correlation_score         if correlation_score   is not None else alert.correlation.correlationScore,
        )

    return replace(
        alert,
        title                    = title        if title        is not None else alert.title,
        description              = description  if description  is not None else alert.description,
        severity                 = new_severity,
        status                   = new_status,
        confidence               = _clamp(confidence)  if confidence  is not None else alert.confidence,
        riskScore                = _clamp(risk_score)  if risk_score  is not None else alert.riskScore,
        assignedTo               = assigned_to  if assigned_to  is not None else alert.assignedTo,
        updatedAt                = updated_at,
        assetIds                 = new_asset_ids,
        relationshipIds          = new_rel_ids,
        evidenceIds              = new_ev_ids,
        graphNodeIds             = new_node_ids,
        timelineEventIds         = new_tl_ids,
        findingFingerprint       = new_find_fp,
        investigationFingerprint = new_inv_fp,
        graphFingerprint         = new_graph_fp,
        alertFingerprint         = new_fingerprint,
        explanation              = _exp,
        correlation              = _cor,
        tags                     = _norm_tags(tags)   if tags     is not None else alert.tags,
        metadata                 = dict(metadata)     if metadata is not None else alert.metadata,
        auditTrail               = tuple(audit),
    )


# ===========================================================================
# Lifecycle builders
# ===========================================================================

def acknowledge_alert(alert: Alert, acknowledged_at: str, assigned_to: Optional[str] = None) -> Alert:
    """
    Transition NEW or OPEN → ACKNOWLEDGED.
    Stamps acknowledgedAt.  Optionally assigns to an analyst.
    Idempotent if already ACKNOWLEDGED.
    """
    if alert.status == AlertStatus.ACKNOWLEDGED:
        return alert
    audit  = (*alert.auditTrail, "Acknowledged")
    return replace(
        alert,
        status         = AlertStatus.ACKNOWLEDGED,
        acknowledgedAt = acknowledged_at,
        assignedTo     = assigned_to if assigned_to is not None else alert.assignedTo,
        updatedAt      = acknowledged_at,
        auditTrail     = audit,
    )


def start_alert(alert: Alert, updated_at: str, assigned_to: Optional[str] = None) -> Alert:
    """
    Transition → IN_PROGRESS (active investigation of the alert).
    Optionally assigns to an analyst.
    Idempotent if already IN_PROGRESS.
    """
    if alert.status == AlertStatus.IN_PROGRESS:
        return alert
    audit = (*alert.auditTrail, "Investigation started")
    return replace(
        alert,
        status     = AlertStatus.IN_PROGRESS,
        assignedTo = assigned_to if assigned_to is not None else alert.assignedTo,
        updatedAt  = updated_at,
        auditTrail = audit,
    )


def resolve_alert(alert: Alert, resolved_at: str) -> Alert:
    """
    Transition → RESOLVED and stamp resolvedAt.
    Already RESOLVED or CLOSED → returns unchanged (idempotent).
    """
    if alert.status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
        return alert
    return replace(
        alert,
        status     = AlertStatus.RESOLVED,
        resolvedAt = resolved_at,
        updatedAt  = resolved_at,
        auditTrail = (*alert.auditTrail, "Resolved"),
    )


def close_alert(alert: Alert, closed_at: str) -> Alert:
    """
    Transition → CLOSED and stamp closedAt.
    Already CLOSED → returns unchanged (idempotent).
    Sets resolvedAt if not already stamped.
    """
    if alert.status == AlertStatus.CLOSED:
        return alert
    resolved_at = alert.resolvedAt or closed_at
    return replace(
        alert,
        status     = AlertStatus.CLOSED,
        closedAt   = closed_at,
        resolvedAt = resolved_at,
        updatedAt  = closed_at,
        auditTrail = (*alert.auditTrail, "Closed"),
    )


def suppress_alert(alert: Alert, updated_at: str, reason: str = "") -> Alert:
    """
    Transition → SUPPRESSED and stamp closedAt.
    Already SUPPRESSED → returns unchanged (idempotent).
    Appends "Suppressed" + optional reason to auditTrail.
    """
    if alert.status == AlertStatus.SUPPRESSED:
        return alert
    entry     = "Suppressed" if not reason else f"Suppressed: {reason}"
    closed_at = alert.closedAt or updated_at
    return replace(
        alert,
        status     = AlertStatus.SUPPRESSED,
        closedAt   = closed_at,
        updatedAt  = updated_at,
        auditTrail = (*alert.auditTrail, entry),
    )


def reopen_alert(alert: Alert, updated_at: str) -> Alert:
    """
    Reopen CLOSED / SUPPRESSED / RESOLVED → OPEN.
    Clears closedAt and resolvedAt.
    Already OPEN / NEW / ACKNOWLEDGED / IN_PROGRESS → returns unchanged (idempotent).
    """
    _active = (AlertStatus.NEW, AlertStatus.OPEN,
               AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS)
    if alert.status in _active:
        return alert
    return replace(
        alert,
        status     = AlertStatus.OPEN,
        closedAt   = None,
        resolvedAt = None,
        updatedAt  = updated_at,
        auditTrail = (*alert.auditTrail, "Reopened"),
    )


def clone_alert(
    alert          : Alert,
    new_project_id : str,
    new_finding_id : str,
    new_created_by : str,
    new_created_at : str,
    new_title      : Optional[str] = None,
) -> Alert:
    """
    Produce a new NEW-status Alert cloned from *alert*.

    - Fresh alertKey + alertId from (new_project_id, new_finding_id,
      new_title or original title, source).
    - Resets status to NEW, clears all timestamp fields.
    - Resets auditTrail to ("Created",).
    - Inherits all linked IDs, fingerprints, scores, explanation,
      correlation, tags, metadata.
    """
    title  = new_title if new_title else alert.title
    key    = _compute_alert_key(new_project_id, new_finding_id, title, alert.source)
    aid    = _compute_alert_id(key)

    new_fingerprint = _compute_alert_fingerprint(
        alert.findingFingerprint,
        alert.investigationFingerprint,
        alert.graphFingerprint,
        alert.assetIds,
        alert.evidenceIds,
        alert.graphNodeIds,
    )

    return replace(
        alert,
        alertId        = aid,
        alertKey       = key,
        projectId      = new_project_id,
        findingId      = new_finding_id,
        title          = title,
        status         = AlertStatus.NEW,
        createdBy      = new_created_by,
        createdAt      = new_created_at,
        updatedAt      = new_created_at,
        closedAt       = None,
        acknowledgedAt = None,
        resolvedAt     = None,
        alertFingerprint = new_fingerprint,
        engineVersion  = ALERT_ENGINE_VERSION,
        auditTrail     = ("Created",),
    )


# ===========================================================================
# Utility: sort_alerts()
# ===========================================================================

_SEVERITY_ORDER: Dict[AlertSeverity, int] = {
    AlertSeverity.CRITICAL: 5,
    AlertSeverity.HIGH    : 4,
    AlertSeverity.MEDIUM  : 3,
    AlertSeverity.LOW     : 2,
    AlertSeverity.INFO    : 1,
}

_STATUS_ORDER: Dict[AlertStatus, int] = {
    AlertStatus.IN_PROGRESS : 7,
    AlertStatus.ACKNOWLEDGED: 6,
    AlertStatus.OPEN        : 5,
    AlertStatus.NEW         : 4,
    AlertStatus.RESOLVED    : 3,
    AlertStatus.SUPPRESSED  : 2,
    AlertStatus.CLOSED      : 1,
}

_VALID_SORT_KEYS = frozenset({
    "severity", "status", "riskScore", "confidence",
    "createdAt", "updatedAt", "title", "source",
})


def sort_alerts(
    alerts    : List[Alert],
    by        : str  = "severity",
    ascending : bool = False,
) -> List[Alert]:
    """
    Return a new sorted list of alerts.

    Parameters
    ----------
    by        : "severity" (default) | "status" | "riskScore" | "confidence"
                "createdAt" | "updatedAt" | "title" | "source"
    ascending : False = descending (highest first, default)

    Tie-breaking is always by alertId ASC for determinism.

    Raises ValueError for unknown sort key.
    """
    if by not in _VALID_SORT_KEYS:
        raise ValueError(
            f"sort_alerts: unknown key '{by}'. Valid: {sorted(_VALID_SORT_KEYS)}"
        )

    def _key(a: Alert):
        if by == "severity":
            primary = _SEVERITY_ORDER.get(a.severity, 0)
        elif by == "status":
            primary = _STATUS_ORDER.get(a.status, 0)
        elif by == "riskScore":
            primary = a.riskScore
        elif by == "confidence":
            primary = a.confidence
        elif by == "source":
            primary = a.source.value
        else:
            primary = getattr(a, by, "")
        return (primary, a.alertId)

    return sorted(alerts, key=_key, reverse=not ascending)


# ===========================================================================
# Utility: filter_alerts()
# ===========================================================================

def filter_alerts(
    alerts          : List[Alert],
    status          : Optional[AlertStatus]   = None,
    severity        : Optional[AlertSeverity] = None,
    source          : Optional[AlertSource]   = None,
    project_id      : Optional[str]           = None,
    finding_id      : Optional[str]           = None,
    investigation_id: Optional[str]           = None,
    assigned_to     : Optional[str]           = None,
    created_by      : Optional[str]           = None,
    tags            : Optional[List[str]]      = None,
    min_risk_score  : Optional[float]          = None,
    max_risk_score  : Optional[float]          = None,
    min_confidence  : Optional[float]          = None,
    engine_version  : Optional[str]            = None,
) -> List[Alert]:
    """
    Return a filtered subset of alerts.

    All supplied filters are ANDed.  None = no filter on that field.
    Tag filtering requires ALL supplied tags to be present (AND semantics).
    """
    filter_tags = _norm_tags(tags) if tags else None
    result: List[Alert] = []

    for a in alerts:
        if status          is not None and a.status          != status:          continue
        if severity        is not None and a.severity        != severity:        continue
        if source          is not None and a.source          != source:          continue
        if project_id      is not None and a.projectId       != project_id:      continue
        if finding_id      is not None and a.findingId       != finding_id:      continue
        if investigation_id is not None and a.investigationId != investigation_id: continue
        if assigned_to     is not None and a.assignedTo      != assigned_to:     continue
        if created_by      is not None and a.createdBy       != created_by:      continue
        if engine_version  is not None and a.engineVersion   != engine_version:  continue
        if min_risk_score  is not None and a.riskScore       <  min_risk_score:  continue
        if max_risk_score  is not None and a.riskScore       >  max_risk_score:  continue
        if min_confidence  is not None and a.confidence      <  min_confidence:  continue
        if filter_tags is not None:
            if not all(t in a.tags for t in filter_tags):
                continue
        result.append(a)

    return result


# ===========================================================================
# Utility: group_alerts()
# ===========================================================================

_VALID_GROUP_KEYS = frozenset({
    "status", "severity", "source",
    "projectId", "findingId", "investigationId",
    "assignedTo", "createdBy", "engineVersion",
})


def group_alerts(
    alerts: List[Alert],
    by    : str = "severity",
) -> Dict[str, List[Alert]]:
    """
    Group alerts into a dict keyed by the requested field value.

    Parameters
    ----------
    by : "severity" (default) | "status" | "source" | "projectId"
         "findingId" | "investigationId" | "assignedTo" | "createdBy"
         "engineVersion"

    Insertion order from *alerts* is preserved within each group.

    Raises ValueError for unknown *by* values.
    """
    if by not in _VALID_GROUP_KEYS:
        raise ValueError(
            f"group_alerts: unknown key '{by}'. Valid: {sorted(_VALID_GROUP_KEYS)}"
        )

    groups: Dict[str, List[Alert]] = {}
    for a in alerts:
        raw = getattr(a, by)
        key = raw.value if isinstance(raw, Enum) else str(raw) if raw is not None else ""
        groups.setdefault(key, []).append(a)
    return groups


# ===========================================================================
# Utility: find_alert()
# ===========================================================================

def find_alert(
    alerts   : List[Alert],
    alert_id : Optional[str] = None,
    alert_key: Optional[str] = None,
    title    : Optional[str] = None,
) -> Optional[Alert]:
    """
    Return the first alert matching the lookup criterion.

    Priority: alertId > alertKey > title (exact match).
    Returns None if nothing matches or no criterion is supplied.
    """
    if alert_id:
        needle = alert_id.strip()
        for a in alerts:
            if a.alertId == needle:
                return a
        return None

    if alert_key:
        needle = alert_key.strip()
        for a in alerts:
            if a.alertKey == needle:
                return a
        return None

    if title:
        needle = title.strip()
        for a in alerts:
            if a.title == needle:
                return a
        return None

    return None


# ===========================================================================
# Statistics
# ===========================================================================

@dataclass(frozen=True)
class AlertStatistics:
    """Aggregate statistics over a collection of alerts."""
    totalAlerts      : int
    newAlerts        : int   # status == NEW
    openAlerts       : int   # NEW + OPEN + ACKNOWLEDGED + IN_PROGRESS
    criticalAlerts   : int   # severity == CRITICAL
    resolvedAlerts   : int   # RESOLVED + CLOSED
    suppressedAlerts : int   # SUPPRESSED
    averageRisk      : float
    averageConfidence: float
    alertsBySeverity : Dict[str, int]   # severity.value → count
    alertsByStatus   : Dict[str, int]   # status.value   → count
    alertsBySource   : Dict[str, int]   # source.value   → count


_OPEN_STATUSES = frozenset({
    AlertStatus.NEW, AlertStatus.OPEN,
    AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS,
})
_RESOLVED_STATUSES = frozenset({AlertStatus.RESOLVED, AlertStatus.CLOSED})


def calculate_statistics(alerts: List[Alert]) -> AlertStatistics:
    """
    Compute aggregate statistics over *alerts*.

    Deterministic: applies canonical sort before numeric accumulation so
    that floating-point summation order is identical across all runs.

    Definitions
    -----------
    newAlerts        : status == NEW
    openAlerts       : NEW + OPEN + ACKNOWLEDGED + IN_PROGRESS
    criticalAlerts   : severity == CRITICAL
    resolvedAlerts   : RESOLVED + CLOSED
    suppressedAlerts : SUPPRESSED
    alertsBySeverity : zero-filled for all AlertSeverity values
    alertsByStatus   : zero-filled for all AlertStatus values
    alertsBySource   : zero-filled for all AlertSource values
    """
    ordered = sort_alerts(alerts, by="severity", ascending=True)
    total   = len(ordered)

    new_c        = sum(1 for a in ordered if a.status == AlertStatus.NEW)
    open_c       = sum(1 for a in ordered if a.status in _OPEN_STATUSES)
    critical_c   = sum(1 for a in ordered if a.severity == AlertSeverity.CRITICAL)
    resolved_c   = sum(1 for a in ordered if a.status in _RESOLVED_STATUSES)
    suppressed_c = sum(1 for a in ordered if a.status == AlertStatus.SUPPRESSED)

    avg_risk = sum(a.riskScore  for a in ordered) / total if total else 0.0
    avg_conf = sum(a.confidence for a in ordered) / total if total else 0.0

    by_severity: Dict[str, int] = {s.value: 0 for s in AlertSeverity}
    by_status  : Dict[str, int] = {s.value: 0 for s in AlertStatus}
    by_source  : Dict[str, int] = {s.value: 0 for s in AlertSource}

    for a in ordered:
        by_severity[a.severity.value] += 1
        by_status[a.status.value]     += 1
        by_source[a.source.value]     += 1

    return AlertStatistics(
        totalAlerts       = total,
        newAlerts         = new_c,
        openAlerts        = open_c,
        criticalAlerts    = critical_c,
        resolvedAlerts    = resolved_c,
        suppressedAlerts  = suppressed_c,
        averageRisk       = round(avg_risk, 4),
        averageConfidence = round(avg_conf, 4),
        alertsBySeverity  = by_severity,
        alertsByStatus    = by_status,
        alertsBySource    = by_source,
    )


# ===========================================================================
# Extension points
# ===========================================================================

def _hook_on_alert_created(alert: Alert) -> None:
    """
    Extension point → Notification Engine + SOC Dashboard.
    Called after build_alert() produces a new Alert.
    May trigger: push notification, SOC queue insertion, AI triage.
    """
    # TODO (future phase): Notification Engine / SOC Dashboard integration


def _hook_on_alert_acknowledged(alert: Alert) -> None:
    """
    Extension point → SOC Dashboard + AI Copilot.
    Called after acknowledge_alert().
    May trigger: analyst assignment notification, SLA timer start.
    """
    # TODO (future phase): SOC Dashboard / AI Copilot integration


def _hook_on_alert_resolved(alert: Alert) -> None:
    """
    Extension point → Report Engine + MITRE Engine.
    Called after resolve_alert() / close_alert().
    May trigger: report section generation, MITRE technique resolution update.
    """
    # TODO (future phase): Report Engine / MITRE Engine integration


def _hook_on_alert_suppressed(alert: Alert) -> None:
    """
    Extension point → Notification Engine.
    Called after suppress_alert().
    May trigger: suppression cache update, false-positive feedback loop.
    """
    # TODO (future phase): Notification Engine integration


def _hook_on_alert_reopened(alert: Alert) -> None:
    """
    Extension point → SOC Dashboard + Notification Engine.
    Called after reopen_alert().
    May trigger: re-alert, SLA timer reset, escalation check.
    """
    # TODO (future phase): SOC Dashboard / Notification Engine integration
