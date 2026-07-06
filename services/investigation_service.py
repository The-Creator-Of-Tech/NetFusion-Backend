"""
Investigation Engine
====================
Phase A4.0.6 — Backend investigation lifecycle management.

Responsibilities
----------------
- Create, update, close, archive, and clone Investigation objects.
- Provide deterministic IDs (SHA-256 key + UUIDv5 — zero randomness).
- Compute investigationFingerprint from graph/timeline fingerprints and
  sorted ID collections so caching and replay are reliable.
- Maintain an auditTrail of semantic lifecycle events (no timestamps).
- Expose utility functions: sort, filter, group, find, and statistics.

Design principles
-----------------
- All models are immutable (frozen=True dataclasses).
- All builder functions return NEW objects; nothing is mutated in place.
- Fully deterministic: same inputs → same outputs across every run.
- No database access, no repository, no API, no AI.
- Pure business logic only.
- All engine versions come from core/constants.py — never hardcoded.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.constants import INVESTIGATION_ENGINE_VERSION

# ── UUIDv5 namespace for deterministic investigation IDs ────────────────────
# Fixed namespace — must never change; changing it invalidates all stored IDs.
_INVESTIGATION_NS = uuid.UUID("6ba7b814-9dad-11d1-80b4-00c04fd430c8")  # DNS ns


# ===========================================================================
# Enumerations
# ===========================================================================

class InvestigationStatus(str, Enum):
    OPEN      = "OPEN"
    ACTIVE    = "ACTIVE"
    PAUSED    = "PAUSED"
    COMPLETED = "COMPLETED"
    ARCHIVED  = "ARCHIVED"


class InvestigationPriority(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ===========================================================================
# Immutable model
# ===========================================================================

@dataclass(frozen=True)
class Investigation:
    """
    Core investigation record.  All fields are immutable after construction.

    Identity fields
    ---------------
    investigationId  : UUIDv5 derived from investigationKey — deterministic.
    investigationKey : SHA256(projectId + title + createdBy)[:32]

    Lifecycle fields
    ----------------
    status   : current InvestigationStatus
    priority : current InvestigationPriority
    closedAt : ISO-8601 string when status → COMPLETED/ARCHIVED, else None

    Link collections (sorted tuples for determinism)
    -------------------------------------------------
    assetIds, relationshipIds, findingIds, evidenceIds, timelineEventIds

    Fingerprints
    ------------
    graphFingerprint    : opaque string from the Attack Graph Engine
    timelineFingerprint : opaque string from the Timeline Intelligence Engine
    investigationFingerprint : SHA256 of all of the above — for cache/replay

    Scoring
    -------
    riskScore   : 0–100 float
    confidence  : 0–100 float

    Metadata
    --------
    tags         : sorted tuple of lowercase tag strings
    metadata     : arbitrary key→value dict (must be JSON-serialisable)
    engineVersion: pinned at build time from INVESTIGATION_ENGINE_VERSION

    Audit
    -----
    auditTrail : ordered tuple of semantic action strings (no timestamps)
    """
    # ── Identity ────────────────────────────────────────────────────────────
    investigationId  : str
    investigationKey : str
    projectId        : str

    # ── Core descriptors ────────────────────────────────────────────────────
    title       : str
    description : str

    # ── Lifecycle ───────────────────────────────────────────────────────────
    status   : InvestigationStatus
    priority : InvestigationPriority
    createdAt: str        # ISO-8601
    updatedAt: str        # ISO-8601
    closedAt : Optional[str]  # ISO-8601 or None

    # ── Ownership ───────────────────────────────────────────────────────────
    createdBy  : str
    assignedTo : Optional[str]

    # ── Linked IDs (sorted tuples — deterministic iteration) ────────────────
    assetIds         : Tuple[str, ...]
    relationshipIds  : Tuple[str, ...]
    findingIds       : Tuple[str, ...]
    evidenceIds      : Tuple[str, ...]
    timelineEventIds : Tuple[str, ...]

    # ── Fingerprints ────────────────────────────────────────────────────────
    graphFingerprint           : str
    timelineFingerprint        : str
    investigationFingerprint   : str  # derived — see _compute_investigation_fingerprint()

    # ── Scoring ─────────────────────────────────────────────────────────────
    riskScore  : float  # 0–100
    confidence : float  # 0–100

    # ── Classification ──────────────────────────────────────────────────────
    tags     : Tuple[str, ...]       # sorted, lowercase
    metadata : Dict[str, Any]        # arbitrary JSON-serialisable data

    # ── Versioning & audit ──────────────────────────────────────────────────
    engineVersion : str
    auditTrail    : Tuple[str, ...]  # ordered semantic actions


# ===========================================================================
# Deterministic ID helpers
# ===========================================================================

def _compute_investigation_key(project_id: str, title: str, created_by: str) -> str:
    """
    investigationKey = SHA256(projectId + title + createdBy)[:32]

    The three components are joined with a null byte so that
    ("ab", "cd", "ef") and ("a", "bcd", "ef") produce different hashes.
    """
    raw = f"{project_id}\x00{title}\x00{created_by}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_investigation_id(investigation_key: str) -> str:
    """
    investigationId = UUIDv5(DNS_NAMESPACE, investigationKey)

    Returns the UUID as a canonical lowercase string.
    """
    return str(uuid.uuid5(_INVESTIGATION_NS, investigation_key))


def _compute_investigation_fingerprint(
    graph_fingerprint   : str,
    timeline_fingerprint: str,
    asset_ids           : Tuple[str, ...],
    relationship_ids    : Tuple[str, ...],
    finding_ids         : Tuple[str, ...],
) -> str:
    """
    investigationFingerprint = SHA256 of:
        graphFingerprint
        timelineFingerprint
        sorted assetIds
        sorted relationshipIds
        sorted findingIds

    Inputs are sorted before hashing so the fingerprint is order-independent.
    Components are joined with null bytes to prevent cross-field collisions.
    """
    parts = [
        graph_fingerprint,
        timeline_fingerprint,
        "\x01".join(sorted(asset_ids)),
        "\x01".join(sorted(relationship_ids)),
        "\x01".join(sorted(finding_ids)),
    ]
    raw = "\x00".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ===========================================================================
# Internal helpers
# ===========================================================================

def _normalise_tags(tags: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, lowercase, strip, and sort tag strings."""
    if not tags:
        return ()
    return tuple(sorted({t.strip().lower() for t in tags if t and t.strip()}))


def _normalise_ids(ids: Optional[List[str]]) -> Tuple[str, ...]:
    """Deduplicate, strip, and sort an ID collection."""
    if not ids:
        return ()
    return tuple(sorted({i.strip() for i in ids if i and i.strip()}))


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (no microseconds)."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ===========================================================================
# Builder: build_investigation()
# ===========================================================================

def build_investigation(
    project_id          : str,
    title               : str,
    created_by          : str,
    created_at          : str,
    description         : str                  = "",
    priority            : InvestigationPriority = InvestigationPriority.MEDIUM,
    assigned_to         : Optional[str]         = None,
    asset_ids           : Optional[List[str]]   = None,
    relationship_ids    : Optional[List[str]]   = None,
    finding_ids         : Optional[List[str]]   = None,
    evidence_ids        : Optional[List[str]]   = None,
    timeline_event_ids  : Optional[List[str]]   = None,
    graph_fingerprint   : str                  = "",
    timeline_fingerprint: str                  = "",
    risk_score          : float                 = 0.0,
    confidence          : float                 = 0.0,
    tags                : Optional[List[str]]   = None,
    metadata            : Optional[Dict[str, Any]] = None,
) -> Investigation:
    """
    Create a new Investigation in OPEN status.

    Parameters
    ----------
    project_id           : owning project
    title                : human-readable investigation title
    created_by           : analyst / system identifier
    created_at           : ISO-8601 creation timestamp (caller-supplied for determinism)
    description          : optional free-text description
    priority             : InvestigationPriority (default MEDIUM)
    assigned_to          : optional analyst assignment
    asset_ids            : linked asset IDs
    relationship_ids     : linked relationship IDs
    finding_ids          : linked finding IDs
    evidence_ids         : linked evidence IDs
    timeline_event_ids   : linked timeline event IDs
    graph_fingerprint    : opaque fingerprint from Attack Graph Engine
    timeline_fingerprint : opaque fingerprint from Timeline Intelligence Engine
    risk_score           : 0–100 float
    confidence           : 0–100 float
    tags                 : classification tags
    metadata             : arbitrary JSON-serialisable key→value pairs

    Returns
    -------
    Investigation (frozen)
    """
    key      = _compute_investigation_key(project_id, title, created_by)
    inv_id   = _compute_investigation_id(key)

    norm_asset_ids   = _normalise_ids(asset_ids)
    norm_rel_ids     = _normalise_ids(relationship_ids)
    norm_finding_ids = _normalise_ids(finding_ids)
    norm_ev_ids      = _normalise_ids(evidence_ids)
    norm_tl_ids      = _normalise_ids(timeline_event_ids)

    fingerprint = _compute_investigation_fingerprint(
        graph_fingerprint,
        timeline_fingerprint,
        norm_asset_ids,
        norm_rel_ids,
        norm_finding_ids,
    )

    audit: Tuple[str, ...] = ("Created",)

    return Investigation(
        investigationId            = inv_id,
        investigationKey           = key,
        projectId                  = project_id,
        title                      = title,
        description                = description,
        status                     = InvestigationStatus.OPEN,
        priority                   = priority,
        createdAt                  = created_at,
        updatedAt                  = created_at,
        closedAt                   = None,
        createdBy                  = created_by,
        assignedTo                 = assigned_to,
        assetIds                   = norm_asset_ids,
        relationshipIds            = norm_rel_ids,
        findingIds                 = norm_finding_ids,
        evidenceIds                = norm_ev_ids,
        timelineEventIds           = norm_tl_ids,
        graphFingerprint           = graph_fingerprint,
        timelineFingerprint        = timeline_fingerprint,
        investigationFingerprint   = fingerprint,
        riskScore                  = float(max(0.0, min(100.0, risk_score))),
        confidence                 = float(max(0.0, min(100.0, confidence))),
        tags                       = _normalise_tags(tags),
        metadata                   = dict(metadata) if metadata else {},
        engineVersion              = INVESTIGATION_ENGINE_VERSION,
        auditTrail                 = audit,
    )


# ===========================================================================
# Builder: update_investigation()
# ===========================================================================

def update_investigation(
    investigation       : Investigation,
    updated_at          : str,
    title               : Optional[str]                = None,
    description         : Optional[str]                = None,
    status              : Optional[InvestigationStatus] = None,
    priority            : Optional[InvestigationPriority] = None,
    assigned_to         : Optional[str]                = None,
    asset_ids           : Optional[List[str]]          = None,
    relationship_ids    : Optional[List[str]]          = None,
    finding_ids         : Optional[List[str]]          = None,
    evidence_ids        : Optional[List[str]]          = None,
    timeline_event_ids  : Optional[List[str]]          = None,
    graph_fingerprint   : Optional[str]                = None,
    timeline_fingerprint: Optional[str]                = None,
    risk_score          : Optional[float]              = None,
    confidence          : Optional[float]              = None,
    tags                : Optional[List[str]]          = None,
    metadata            : Optional[Dict[str, Any]]     = None,
) -> Investigation:
    """
    Return a new Investigation with the supplied fields changed.

    Only non-None arguments are applied — None means "keep existing value".
    The investigationFingerprint is recomputed whenever any of its source
    fields change.  The auditTrail is extended with semantic change entries.
    """
    audit = list(investigation.auditTrail)

    new_status   = status   if status   is not None else investigation.status
    new_priority = priority if priority is not None else investigation.priority
    new_assigned = assigned_to if assigned_to is not None else investigation.assignedTo

    if status is not None and status != investigation.status:
        audit.append(f"Status changed to {status.value}")
    if priority is not None and priority != investigation.priority:
        audit.append(f"Priority changed to {priority.value}")
    if assigned_to is not None and assigned_to != investigation.assignedTo:
        audit.append("Assigned")

    new_asset_ids   = _normalise_ids(asset_ids)          if asset_ids          is not None else investigation.assetIds
    new_rel_ids     = _normalise_ids(relationship_ids)    if relationship_ids   is not None else investigation.relationshipIds
    new_finding_ids = _normalise_ids(finding_ids)         if finding_ids        is not None else investigation.findingIds
    new_ev_ids      = _normalise_ids(evidence_ids)        if evidence_ids       is not None else investigation.evidenceIds
    new_tl_ids      = _normalise_ids(timeline_event_ids)  if timeline_event_ids is not None else investigation.timelineEventIds

    new_graph_fp    = graph_fingerprint    if graph_fingerprint    is not None else investigation.graphFingerprint
    new_timeline_fp = timeline_fingerprint if timeline_fingerprint is not None else investigation.timelineFingerprint

    new_fingerprint = _compute_investigation_fingerprint(
        new_graph_fp, new_timeline_fp, new_asset_ids, new_rel_ids, new_finding_ids
    )

    new_risk   = float(max(0.0, min(100.0, risk_score)))  if risk_score  is not None else investigation.riskScore
    new_conf   = float(max(0.0, min(100.0, confidence)))  if confidence  is not None else investigation.confidence
    new_tags   = _normalise_tags(tags)       if tags     is not None else investigation.tags
    new_meta   = dict(metadata)              if metadata is not None else investigation.metadata
    new_title  = title                       if title    is not None else investigation.title
    new_desc   = description                 if description is not None else investigation.description

    # closedAt is managed exclusively by close_investigation() / archive_investigation()
    new_closed = investigation.closedAt

    return replace(
        investigation,
        title                    = new_title,
        description              = new_desc,
        status                   = new_status,
        priority                 = new_priority,
        updatedAt                = updated_at,
        closedAt                 = new_closed,
        assignedTo               = new_assigned,
        assetIds                 = new_asset_ids,
        relationshipIds          = new_rel_ids,
        findingIds               = new_finding_ids,
        evidenceIds              = new_ev_ids,
        timelineEventIds         = new_tl_ids,
        graphFingerprint         = new_graph_fp,
        timelineFingerprint      = new_timeline_fp,
        investigationFingerprint = new_fingerprint,
        riskScore                = new_risk,
        confidence               = new_conf,
        tags                     = new_tags,
        metadata                 = new_meta,
        auditTrail               = tuple(audit),
    )


# ===========================================================================
# Builder: close_investigation()
# ===========================================================================

def close_investigation(
    investigation: Investigation,
    closed_at    : str,
) -> Investigation:
    """
    Transition investigation to COMPLETED status and stamp closedAt.

    - If already COMPLETED or ARCHIVED, returns the object unchanged.
    - Appends "Closed" to the auditTrail.
    """
    if investigation.status in (InvestigationStatus.COMPLETED, InvestigationStatus.ARCHIVED):
        return investigation

    audit = (*investigation.auditTrail, "Closed")

    return replace(
        investigation,
        status     = InvestigationStatus.COMPLETED,
        closedAt   = closed_at,
        updatedAt  = closed_at,
        auditTrail = audit,
    )


# ===========================================================================
# Builder: archive_investigation()
# ===========================================================================

def archive_investigation(
    investigation: Investigation,
    archived_at  : str,
) -> Investigation:
    """
    Transition investigation to ARCHIVED status.

    - Stamps closedAt if not already set.
    - Appends "Archived" to the auditTrail.
    - Can be called from any status.
    """
    audit      = (*investigation.auditTrail, "Archived")
    closed_at  = investigation.closedAt or archived_at

    return replace(
        investigation,
        status     = InvestigationStatus.ARCHIVED,
        closedAt   = closed_at,
        updatedAt  = archived_at,
        auditTrail = audit,
    )


# ===========================================================================
# Builder: clone_investigation()
# ===========================================================================

def clone_investigation(
    investigation: Investigation,
    new_project_id: str,
    new_created_by: str,
    new_created_at: str,
    new_title     : Optional[str] = None,
) -> Investigation:
    """
    Produce a new OPEN Investigation cloned from *investigation*.

    The clone:
    - Gets a fresh investigationKey and investigationId derived from
      (new_project_id, new_title or original title, new_created_by).
    - Resets status to OPEN and clears closedAt.
    - Resets auditTrail to ("Created",) — clone is a fresh lifecycle.
    - Inherits all linked IDs, fingerprints, scores, tags, and metadata.
    - engineVersion is pinned to the current INVESTIGATION_ENGINE_VERSION.
    """
    title  = new_title if new_title else investigation.title
    key    = _compute_investigation_key(new_project_id, title, new_created_by)
    inv_id = _compute_investigation_id(key)

    new_fingerprint = _compute_investigation_fingerprint(
        investigation.graphFingerprint,
        investigation.timelineFingerprint,
        investigation.assetIds,
        investigation.relationshipIds,
        investigation.findingIds,
    )

    return replace(
        investigation,
        investigationId            = inv_id,
        investigationKey           = key,
        projectId                  = new_project_id,
        title                      = title,
        status                     = InvestigationStatus.OPEN,
        createdAt                  = new_created_at,
        updatedAt                  = new_created_at,
        closedAt                   = None,
        createdBy                  = new_created_by,
        investigationFingerprint   = new_fingerprint,
        engineVersion              = INVESTIGATION_ENGINE_VERSION,
        auditTrail                 = ("Created",),
    )


# ===========================================================================
# Utility: sort_investigations()
# ===========================================================================

# Priority ordering for sort (higher value = higher priority)
_PRIORITY_ORDER: Dict[InvestigationPriority, int] = {
    InvestigationPriority.CRITICAL : 4,
    InvestigationPriority.HIGH     : 3,
    InvestigationPriority.MEDIUM   : 2,
    InvestigationPriority.LOW      : 1,
}

# Status ordering (active work first, archived last)
_STATUS_ORDER: Dict[InvestigationStatus, int] = {
    InvestigationStatus.ACTIVE    : 5,
    InvestigationStatus.OPEN      : 4,
    InvestigationStatus.PAUSED    : 3,
    InvestigationStatus.COMPLETED : 2,
    InvestigationStatus.ARCHIVED  : 1,
}


def sort_investigations(
    investigations: List[Investigation],
    by            : str = "priority",
    ascending     : bool = False,
) -> List[Investigation]:
    """
    Return a new sorted list of investigations.

    Parameters
    ----------
    investigations : list to sort
    by             : sort key — one of:
                       "priority"   (default) — CRITICAL > HIGH > MEDIUM > LOW
                       "status"               — ACTIVE > OPEN > PAUSED > COMPLETED > ARCHIVED
                       "riskScore"            — numeric, highest first by default
                       "confidence"           — numeric, highest first by default
                       "createdAt"            — ISO-8601 string lexicographic
                       "updatedAt"            — ISO-8601 string lexicographic
                       "title"                — alphabetical
    ascending      : True = ascending, False = descending (default)

    Tie-breaking is always by investigationId ASC for determinism.

    Raises
    ------
    ValueError if *by* is not a recognised key.
    """
    valid_keys = {"priority", "status", "riskScore", "confidence",
                  "createdAt", "updatedAt", "title"}
    if by not in valid_keys:
        raise ValueError(f"sort_investigations: unknown key '{by}'. Valid: {sorted(valid_keys)}")

    def _key(inv: Investigation):
        if by == "priority":
            primary = _PRIORITY_ORDER.get(inv.priority, 0)
        elif by == "status":
            primary = _STATUS_ORDER.get(inv.status, 0)
        elif by == "riskScore":
            primary = inv.riskScore
        elif by == "confidence":
            primary = inv.confidence
        else:
            primary = getattr(inv, by, "")
        return (primary, inv.investigationId)

    reverse = not ascending
    return sorted(investigations, key=_key, reverse=reverse)


# ===========================================================================
# Utility: filter_investigations()
# ===========================================================================

def filter_investigations(
    investigations  : List[Investigation],
    status          : Optional[InvestigationStatus]   = None,
    priority        : Optional[InvestigationPriority] = None,
    project_id      : Optional[str]                   = None,
    assigned_to     : Optional[str]                   = None,
    created_by      : Optional[str]                   = None,
    tags            : Optional[List[str]]              = None,
    min_risk_score  : Optional[float]                  = None,
    max_risk_score  : Optional[float]                  = None,
    min_confidence  : Optional[float]                  = None,
    engine_version  : Optional[str]                    = None,
) -> List[Investigation]:
    """
    Return a filtered subset of investigations.

    All supplied filters are ANDed together.  None means "no filter on this
    field".  Tag filtering requires ALL supplied tags to be present (AND).

    Returns a new list; does not mutate the input.
    """
    result: List[Investigation] = []
    filter_tags = _normalise_tags(tags) if tags else None

    for inv in investigations:
        if status        is not None and inv.status    != status:
            continue
        if priority      is not None and inv.priority  != priority:
            continue
        if project_id    is not None and inv.projectId != project_id:
            continue
        if assigned_to   is not None and inv.assignedTo != assigned_to:
            continue
        if created_by    is not None and inv.createdBy  != created_by:
            continue
        if engine_version is not None and inv.engineVersion != engine_version:
            continue
        if min_risk_score is not None and inv.riskScore < min_risk_score:
            continue
        if max_risk_score is not None and inv.riskScore > max_risk_score:
            continue
        if min_confidence is not None and inv.confidence < min_confidence:
            continue
        if filter_tags is not None:
            if not all(t in inv.tags for t in filter_tags):
                continue
        result.append(inv)

    return result


# ===========================================================================
# Utility: group_investigations()
# ===========================================================================

def group_investigations(
    investigations: List[Investigation],
    by            : str = "status",
) -> Dict[str, List[Investigation]]:
    """
    Group investigations into a dict keyed by the requested field value.

    Parameters
    ----------
    by : grouping field — "status" | "priority" | "projectId" |
                          "assignedTo" | "createdBy" | "engineVersion"

    Within each group the order of *investigations* is preserved.

    Raises
    ------
    ValueError for unknown *by* values.
    """
    valid = {"status", "priority", "projectId", "assignedTo", "createdBy", "engineVersion"}
    if by not in valid:
        raise ValueError(f"group_investigations: unknown key '{by}'. Valid: {sorted(valid)}")

    groups: Dict[str, List[Investigation]] = {}
    for inv in investigations:
        key = str(getattr(inv, by) if by not in ("status", "priority") else getattr(inv, by).value)
        groups.setdefault(key, []).append(inv)
    return groups


# ===========================================================================
# Utility: find_investigation()
# ===========================================================================

def find_investigation(
    investigations   : List[Investigation],
    investigation_id : Optional[str] = None,
    investigation_key: Optional[str] = None,
    title            : Optional[str] = None,
) -> Optional[Investigation]:
    """
    Return the first investigation that matches the supplied lookup criterion.

    Priority order: investigationId > investigationKey > title (exact match).
    Returns None if nothing matches or no criterion is supplied.
    """
    if investigation_id:
        needle = investigation_id.strip()
        for inv in investigations:
            if inv.investigationId == needle:
                return inv
        return None

    if investigation_key:
        needle = investigation_key.strip()
        for inv in investigations:
            if inv.investigationKey == needle:
                return inv
        return None

    if title:
        needle = title.strip()
        for inv in investigations:
            if inv.title == needle:
                return inv
        return None

    return None


# ===========================================================================
# Utility: calculate_statistics()
# ===========================================================================

@dataclass(frozen=True)
class InvestigationStatistics:
    """Aggregate statistics over a collection of investigations."""
    totalInvestigations : int
    openCount           : int
    closedCount         : int   # COMPLETED + ARCHIVED
    criticalCount       : int
    averageRisk         : float  # 0.0 when no investigations
    averageConfidence   : float  # 0.0 when no investigations


def calculate_statistics(investigations: List[Investigation]) -> InvestigationStatistics:
    """
    Compute aggregate statistics over *investigations*.

    Deterministic: applies canonical sort before any numeric accumulation so
    that floating-point summation order is identical across all runs.

    Definitions
    -----------
    closedCount   : investigations with status COMPLETED or ARCHIVED
    criticalCount : investigations with priority CRITICAL
    averageRisk   : mean riskScore (0.0 if empty)
    averageConfidence : mean confidence (0.0 if empty)
    """
    # Canonical sort ensures summation order is identical across all runs
    ordered = sort_investigations(investigations, by="priority", ascending=True)

    total   = len(ordered)
    open_c  = sum(1 for i in ordered if i.status == InvestigationStatus.OPEN)
    active_c = sum(1 for i in ordered if i.status == InvestigationStatus.ACTIVE)
    closed_c = sum(
        1 for i in ordered
        if i.status in (InvestigationStatus.COMPLETED, InvestigationStatus.ARCHIVED)
    )
    critical_c = sum(1 for i in ordered if i.priority == InvestigationPriority.CRITICAL)

    avg_risk = (
        sum(i.riskScore  for i in ordered) / total if total > 0 else 0.0
    )
    avg_conf = (
        sum(i.confidence for i in ordered) / total if total > 0 else 0.0
    )

    return InvestigationStatistics(
        totalInvestigations = total,
        openCount           = open_c + active_c,   # OPEN + ACTIVE = "open work"
        closedCount         = closed_c,
        criticalCount       = critical_c,
        averageRisk         = round(avg_risk, 4),
        averageConfidence   = round(avg_conf, 4),
    )


# ===========================================================================
# Extension points
# ===========================================================================
# These stubs mark the integration contracts for upcoming phases.
# They intentionally do nothing and are never called by this engine.

def _hook_on_investigation_created(investigation: Investigation) -> None:
    """
    Extension point: called after a new Investigation is built.

    Future phases may:
    - Emit an event to the notification bus.
    - Trigger an initial AI triage pass.
    - Register the investigation in the audit store.
    """
    # TODO (future phase): implement notification / event emission


def _hook_on_investigation_closed(investigation: Investigation) -> None:
    """
    Extension point: called after close_investigation() produces a result.

    Future phases may:
    - Generate a final evidence summary.
    - Archive linked graph snapshots.
    - Notify stakeholders.
    """
    # TODO (future phase): implement closure notification


def _hook_on_investigation_archived(investigation: Investigation) -> None:
    """
    Extension point: called after archive_investigation() produces a result.

    Future phases may:
    - Move investigation to cold storage.
    - Purge in-memory graph caches.
    """
    # TODO (future phase): implement archival handler
