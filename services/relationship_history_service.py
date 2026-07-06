"""
Enterprise Relationship History Engine
========================================
Phase A.3.1 — Immutable chronological lifecycle history for Relationships.

Responsibilities
----------------
- Track every state change a Relationship passes through:
    state transitions, confidence changes, evidence additions,
    lifecycle events (activated, inactivated, terminated), merges.
- Produce frozen, deterministic RelationshipHistoryEvent objects.
- Build RelationshipHistorySummary, RelationshipHistoryStatistics,
  and RelationshipHistoryBundle from lists of events.

Design constraints
------------------
- PURE: no HTTP, no Prisma, no repositories, no AI calls.
- Immutable output: all models use frozen=True Pydantic config.
- Deterministic: same inputs always produce the same output.
- No circular imports.

Event ID generation
-------------------
UUID v5 derived from:
    relationshipId + eventType + occurredAt (ISO-format)
Same combination always produces the same eventId.

Ordering guarantee
------------------
Events are always sorted by:
    occurredAt ↓ packetNumber ↓ sequenceNumber

Parent chain
------------
Each event references the previous event via parentEventId.
    CREATED → UPDATED → STATE_CHANGED → TERMINATED

Dependency graph (no circular imports)
---------------------------------------
  core.constants
  services.relationship_service   (Relationship, RelationshipState,
                                   RelationshipType, Direction)
  ← services.relationship_history_service   (this file)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from core.constants import RELATIONSHIP_HISTORY_ENGINE_VERSION
from services.relationship_service import (
    Direction,
    Relationship,
    RelationshipState,
    RelationshipType,
)


# ---------------------------------------------------------------------------
# Namespace UUID — fixed; never change (invalidates all existing eventIds).
# ---------------------------------------------------------------------------
_REL_HISTORY_NS = uuid.UUID("fedcba98-fedc-4fec-bfec-fedcba987654")


# ---------------------------------------------------------------------------
# RelationshipEventType
# ---------------------------------------------------------------------------

class RelationshipEventType(str, Enum):
    """
    Lifecycle event types for a Relationship's history.

    CREATED           : Relationship first observed / persisted.
    UPDATED           : One or more mutable fields changed (generic update).
    STATE_CHANGED     : state field transitioned (e.g. NEW → ACTIVE).
    CONFIDENCE_CHANGED: confidence score changed (up or down).
    EVIDENCE_ADDED    : one or more EvidenceRecords linked.
    ACTIVATED         : state transitioned to ACTIVE.
    INACTIVATED       : state transitioned to INACTIVE.
    TERMINATED        : state transitioned to TERMINATED.
    MERGED            : two Relationships collapsed into one.
    """
    CREATED            = "CREATED"
    UPDATED            = "UPDATED"
    STATE_CHANGED      = "STATE_CHANGED"
    CONFIDENCE_CHANGED = "CONFIDENCE_CHANGED"
    EVIDENCE_ADDED     = "EVIDENCE_ADDED"
    ACTIVATED          = "ACTIVATED"
    INACTIVATED        = "INACTIVATED"
    TERMINATED         = "TERMINATED"
    MERGED             = "MERGED"


# ---------------------------------------------------------------------------
# RelationshipHistoryEvent
# ---------------------------------------------------------------------------

class RelationshipHistoryEvent(BaseModel):
    """
    One immutable point-in-time change event for a Relationship.

    Fields
    ------
    eventId             : UUID v5 — deterministic from
                          (relationshipId + eventType + occurredAt).
    relationshipId      : parent Relationship.relationshipId (UUID v5).
    relationshipKey     : parent Relationship.relationshipKey (SHA-256[:32]).
    eventType           : RelationshipEventType.
    previousState       : RelationshipState before the event (None = CREATED).
    currentState        : RelationshipState after the event.
    previousConfidence  : confidence score before the event (None = CREATED).
    currentConfidence   : confidence score after the event.
    evidenceId          : EvidenceRecord.evidenceId linked in this event
                          (populated for EVIDENCE_ADDED; None otherwise).
    packetNumber        : frame index within capture that triggered this event.
    captureId           : CaptureSession.captureId for this event.
    occurredAt          : UTC datetime of the change.
    summary             : deterministic one-line AI-readable description.
    metadata            : arbitrary extension bag.
    sequenceNumber      : monotonic int — third sort key after
                          (occurredAt, packetNumber); guarantees total order.
    parentEventId       : eventId of the preceding event in the chain.
                          None for CREATED (root event).
    """
    eventId             : str
    relationshipId      : str
    relationshipKey     : str
    eventType           : RelationshipEventType
    previousState       : Optional[RelationshipState]  = None
    currentState        : RelationshipState
    previousConfidence  : Optional[int]                = None
    currentConfidence   : int
    evidenceId          : Optional[str]                = None
    packetNumber        : Optional[int]                = None
    captureId           : Optional[str]                = None
    occurredAt          : Optional[datetime]           = None
    summary             : str                          = ""
    metadata            : Dict[str, Any]               = Field(default_factory=dict)
    sequenceNumber      : int                          = 0
    parentEventId       : Optional[str]                = None
    relatedEventIds     : List[str]                    = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipHistorySummary
# ---------------------------------------------------------------------------

class RelationshipHistorySummary(BaseModel):
    """
    Aggregate summary computed over a list of RelationshipHistoryEvents.

    Fields
    ------
    firstSeen           : earliest occurredAt across all events.
    lastSeen            : latest occurredAt across all events.
    eventCount          : total number of events.
    stateTransitions    : number of STATE_CHANGED / ACTIVATED /
                          INACTIVATED / TERMINATED events.
    confidenceChanges   : number of CONFIDENCE_CHANGED events.
    evidenceAdditions   : number of EVIDENCE_ADDED events.
    initialState        : state from the CREATED event (None if no CREATED).
    finalState          : currentState of the most-recent event.
    initialConfidence   : confidence from the CREATED event.
    finalConfidence     : currentConfidence of the most-recent event.
    """
    firstSeen           : Optional[datetime]           = None
    lastSeen            : Optional[datetime]           = None
    eventCount          : int                          = 0
    stateTransitions    : int                          = 0
    confidenceChanges   : int                          = 0
    evidenceAdditions   : int                          = 0
    initialState        : Optional[RelationshipState]  = None
    finalState          : Optional[RelationshipState]  = None
    initialConfidence   : Optional[int]                = None
    finalConfidence     : Optional[int]                = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipHistoryStatistics
# ---------------------------------------------------------------------------

class RelationshipHistoryStatistics(BaseModel):
    """
    Frequency breakdowns over a list of RelationshipHistoryEvents.

    Fields
    ------
    totalEvents     : total event count.
    eventsByType    : { RelationshipEventType.value → count }
    eventsByDay     : { "YYYY-MM-DD" → count }
    confidenceDelta : final confidence minus initial confidence (0 if unknown).
    stateFlow       : ordered list of unique state values seen (deduped).
    """
    totalEvents     : int              = 0
    eventsByType    : Dict[str, int]   = Field(default_factory=dict)
    eventsByDay     : Dict[str, int]   = Field(default_factory=dict)
    confidenceDelta : int              = 0
    stateFlow       : List[str]        = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipHistoryBundle
# ---------------------------------------------------------------------------

class RelationshipHistoryBundle(BaseModel):
    """
    Complete history output for one Relationship.

    Fields
    ------
    events        : chronologically sorted list of RelationshipHistoryEvents.
    summary       : RelationshipHistorySummary over all events.
    statistics    : RelationshipHistoryStatistics over all events.
    engineVersion : RELATIONSHIP_HISTORY_ENGINE_VERSION at build time.
    createdAt     : UTC datetime this bundle was built.
    """
    events        : List[RelationshipHistoryEvent]    = Field(default_factory=list)
    summary       : RelationshipHistorySummary        = Field(
                        default_factory=RelationshipHistorySummary
                    )
    statistics    : RelationshipHistoryStatistics     = Field(
                        default_factory=RelationshipHistoryStatistics
                    )
    engineVersion : str                               = RELATIONSHIP_HISTORY_ENGINE_VERSION
    createdAt     : datetime                          = Field(
                        default_factory=lambda: datetime.now(timezone.utc)
                    )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_event_id(
    relationship_id : str,
    event_type      : RelationshipEventType,
    occurred_at     : Optional[datetime],
) -> str:
    """
    Derive a stable UUID v5 for a RelationshipHistoryEvent.
    Input: "<relationshipId>|<eventType>|<occurredAt ISO or ''>"
    Same inputs always produce the same eventId.
    """
    ts   = occurred_at.isoformat() if occurred_at else ""
    name = f"{relationship_id}|{event_type.value}|{ts}"
    return str(uuid.uuid5(_REL_HISTORY_NS, name))


def _infer_event_type(
    previous_state      : Optional[RelationshipState],
    current_state       : RelationshipState,
    previous_confidence : Optional[int],
    current_confidence  : int,
    evidence_id         : Optional[str],
) -> RelationshipEventType:
    """
    Infer the most specific RelationshipEventType from field deltas.

    Priority order (first match wins):
      1. previous_state is None                        → CREATED
      2. current_state == TERMINATED                   → TERMINATED
      3. current_state == INACTIVE, was not INACTIVE   → INACTIVATED
      4. current_state == ACTIVE,   was not ACTIVE     → ACTIVATED
      5. state changed at all                          → STATE_CHANGED
      6. evidence_id present                           → EVIDENCE_ADDED
      7. confidence changed                            → CONFIDENCE_CHANGED
      8. fallback                                      → UPDATED
    """
    if previous_state is None:
        return RelationshipEventType.CREATED
    if current_state == RelationshipState.TERMINATED:
        return RelationshipEventType.TERMINATED
    if current_state == RelationshipState.INACTIVE and previous_state != RelationshipState.INACTIVE:
        return RelationshipEventType.INACTIVATED
    if current_state == RelationshipState.ACTIVE and previous_state != RelationshipState.ACTIVE:
        return RelationshipEventType.ACTIVATED
    if current_state != previous_state:
        return RelationshipEventType.STATE_CHANGED
    if evidence_id is not None:
        return RelationshipEventType.EVIDENCE_ADDED
    if previous_confidence is not None and current_confidence != previous_confidence:
        return RelationshipEventType.CONFIDENCE_CHANGED
    return RelationshipEventType.UPDATED


_STATE_TRANSITION_TYPES = frozenset({
    RelationshipEventType.STATE_CHANGED,
    RelationshipEventType.ACTIVATED,
    RelationshipEventType.INACTIVATED,
    RelationshipEventType.TERMINATED,
})


def _make_summary(
    event_type          : RelationshipEventType,
    relationship_id     : str,
    relationship_key    : str,
    previous_state      : Optional[RelationshipState],
    current_state       : RelationshipState,
    previous_confidence : Optional[int],
    current_confidence  : int,
    evidence_id         : Optional[str],
) -> str:
    """Build a deterministic one-line human-readable summary."""
    key_short = relationship_key[:12] if relationship_key else relationship_id[:12]

    if event_type == RelationshipEventType.CREATED:
        return (
            f"[{key_short}] CREATED — state={current_state.value} "
            f"confidence={current_confidence}"
        )
    if event_type in _STATE_TRANSITION_TYPES:
        prev = previous_state.value if previous_state else "?"
        return (
            f"[{key_short}] {event_type.value} — "
            f"state: {prev} → {current_state.value}"
        )
    if event_type == RelationshipEventType.CONFIDENCE_CHANGED:
        prev_c = previous_confidence if previous_confidence is not None else "?"
        return (
            f"[{key_short}] CONFIDENCE_CHANGED — "
            f"confidence: {prev_c} → {current_confidence}"
        )
    if event_type == RelationshipEventType.EVIDENCE_ADDED:
        ev_short = evidence_id[:12] if evidence_id else "?"
        return f"[{key_short}] EVIDENCE_ADDED — evidenceId={ev_short}"
    if event_type == RelationshipEventType.MERGED:
        return f"[{key_short}] MERGED — confidence={current_confidence}"
    return (
        f"[{key_short}] {event_type.value} — state={current_state.value} "
        f"confidence={current_confidence}"
    )


# ---------------------------------------------------------------------------
# Builder: build_relationship_history_event()
# ---------------------------------------------------------------------------

def build_relationship_history_event(
    relationship_id      : str,
    relationship_key     : str,
    current_state        : RelationshipState,
    current_confidence   : int,
    previous_state       : Optional[RelationshipState]   = None,
    previous_confidence  : Optional[int]                 = None,
    event_type           : Optional[RelationshipEventType] = None,
    evidence_id          : Optional[str]                 = None,
    packet_number        : Optional[int]                 = None,
    capture_id           : Optional[str]                 = None,
    occurred_at          : Optional[datetime]            = None,
    sequence_number      : int                           = 0,
    parent_event_id      : Optional[str]                 = None,
    related_event_ids    : Optional[List[str]]           = None,
    extra_meta           : Optional[Dict[str, Any]]      = None,
) -> RelationshipHistoryEvent:
    """
    Build a single RelationshipHistoryEvent.

    Parameters
    ----------
    relationship_id      : Relationship.relationshipId (UUID v5).
    relationship_key     : Relationship.relationshipKey (SHA-256[:32]).
    current_state        : state after the change.
    current_confidence   : confidence after the change.
    previous_state       : state before the change; None for CREATED events.
    previous_confidence  : confidence before the change; None for CREATED.
    event_type           : explicit override; inferred from deltas if None.
    evidence_id          : EvidenceRecord.evidenceId for EVIDENCE_ADDED events.
    packet_number        : frame index that triggered the event.
    capture_id           : CaptureSession.captureId.
    occurred_at          : UTC datetime; defaults to now().
    sequence_number      : monotonic counter — third sort key.
    parent_event_id      : eventId of the preceding event in the chain.
    related_event_ids    : IDs of cross-domain events causally linked to this
                           one (e.g. evidenceEventId, alertEventId,
                           findingEventId, mitreEventId, timelineEventId).
                           Future AI uses this to build a causal graph instead
                           of a simple linear chain.
    extra_meta           : optional additional metadata.

    Returns
    -------
    RelationshipHistoryEvent (frozen / immutable)
    """
    resolved_at = occurred_at or datetime.now(timezone.utc)

    resolved_event_type = event_type or _infer_event_type(
        previous_state, current_state, previous_confidence,
        current_confidence, evidence_id,
    )

    event_id = _make_event_id(relationship_id, resolved_event_type, resolved_at)

    summary = _make_summary(
        resolved_event_type, relationship_id, relationship_key,
        previous_state, current_state,
        previous_confidence, current_confidence, evidence_id,
    )

    meta: Dict[str, Any] = {"engineVersion": RELATIONSHIP_HISTORY_ENGINE_VERSION}
    if extra_meta:
        meta.update(extra_meta)

    return RelationshipHistoryEvent(
        eventId             = event_id,
        relationshipId      = relationship_id,
        relationshipKey     = relationship_key,
        eventType           = resolved_event_type,
        previousState       = previous_state,
        currentState        = current_state,
        previousConfidence  = previous_confidence,
        currentConfidence   = current_confidence,
        evidenceId          = evidence_id,
        packetNumber        = packet_number,
        captureId           = capture_id,
        occurredAt          = resolved_at,
        summary             = summary,
        metadata            = meta,
        sequenceNumber      = sequence_number,
        parentEventId       = parent_event_id,
        relatedEventIds     = list(related_event_ids) if related_event_ids else [],
    )


# ---------------------------------------------------------------------------
# Builder: build_relationship_history()
# ---------------------------------------------------------------------------

def build_relationship_history(
    relationship    : Relationship,
    transitions     : Sequence[Dict[str, Any]],
) -> List[RelationshipHistoryEvent]:
    """
    Build a chronological list of RelationshipHistoryEvents for one
    Relationship from a sequence of transition dicts.

    Each transition dict represents one atomic state change and may contain:
        previous_state       : RelationshipState | None
        current_state        : RelationshipState  (required)
        previous_confidence  : int | None
        current_confidence   : int                (required)
        event_type           : RelationshipEventType | None  (optional override)
        evidence_id          : str | None
        packet_number        : int | None
        capture_id           : str | None
        occurred_at          : datetime | None
        extra_meta           : dict | None

    The CREATED event (no previous_state) should always be first.
    parentEventId is wired automatically in sequence order.

    Parameters
    ----------
    relationship : Relationship object — supplies id, key, and defaults.
    transitions  : ordered sequence of transition dicts.

    Returns
    -------
    List[RelationshipHistoryEvent] sorted by (occurredAt, packetNumber,
    sequenceNumber).
    """
    if not transitions:
        return []

    events: List[RelationshipHistoryEvent] = []
    last_event_id: Optional[str] = None

    for seq, tx in enumerate(transitions):
        ev = build_relationship_history_event(
            relationship_id      = relationship.relationshipId,
            relationship_key     = relationship.relationshipKey,
            current_state        = tx["current_state"],
            current_confidence   = tx["current_confidence"],
            previous_state       = tx.get("previous_state"),
            previous_confidence  = tx.get("previous_confidence"),
            event_type           = tx.get("event_type"),
            evidence_id          = tx.get("evidence_id"),
            packet_number        = tx.get("packet_number"),
            capture_id           = tx.get("capture_id"),
            occurred_at          = tx.get("occurred_at"),
            sequence_number      = seq,
            parent_event_id      = last_event_id,
            related_event_ids    = tx.get("related_event_ids"),
            extra_meta           = tx.get("extra_meta"),
        )
        last_event_id = ev.eventId
        events.append(ev)

    return sort_relationship_history(events)


# ---------------------------------------------------------------------------
# Builder: build_relationship_history_summary()
# ---------------------------------------------------------------------------

def build_relationship_history_summary(
    events: Sequence[RelationshipHistoryEvent],
) -> RelationshipHistorySummary:
    """
    Compute a RelationshipHistorySummary from a sequence of events.

    Parameters
    ----------
    events : any sequence of RelationshipHistoryEvent objects.

    Returns
    -------
    RelationshipHistorySummary (frozen / immutable)
    """
    if not events:
        return RelationshipHistorySummary()

    timestamps = [e.occurredAt for e in events if e.occurredAt is not None]

    state_transition_count = sum(
        1 for e in events if e.eventType in _STATE_TRANSITION_TYPES
    )
    confidence_change_count = sum(
        1 for e in events if e.eventType == RelationshipEventType.CONFIDENCE_CHANGED
    )
    evidence_count = sum(
        1 for e in events if e.eventType == RelationshipEventType.EVIDENCE_ADDED
    )

    # CREATED event carries the initial values
    created_ev = next(
        (e for e in events if e.eventType == RelationshipEventType.CREATED), None
    )
    # Most recent event carries the final values
    sorted_evs  = sort_relationship_history(list(events))
    final_ev    = sorted_evs[-1] if sorted_evs else None

    return RelationshipHistorySummary(
        firstSeen          = min(timestamps) if timestamps else None,
        lastSeen           = max(timestamps) if timestamps else None,
        eventCount         = len(events),
        stateTransitions   = state_transition_count,
        confidenceChanges  = confidence_change_count,
        evidenceAdditions  = evidence_count,
        initialState       = created_ev.currentState      if created_ev else None,
        finalState         = final_ev.currentState        if final_ev   else None,
        initialConfidence  = created_ev.currentConfidence if created_ev else None,
        finalConfidence    = final_ev.currentConfidence   if final_ev   else None,
    )


# ---------------------------------------------------------------------------
# Builder: build_relationship_history_statistics()
# ---------------------------------------------------------------------------

def build_relationship_history_statistics(
    events: Sequence[RelationshipHistoryEvent],
) -> RelationshipHistoryStatistics:
    """
    Compute RelationshipHistoryStatistics from a sequence of events.

    Parameters
    ----------
    events : any sequence of RelationshipHistoryEvent objects.

    Returns
    -------
    RelationshipHistoryStatistics (frozen / immutable)
    """
    if not events:
        return RelationshipHistoryStatistics()

    by_type : Dict[str, int] = defaultdict(int)
    by_day  : Dict[str, int] = defaultdict(int)

    for ev in events:
        by_type[ev.eventType.value] += 1
        if ev.occurredAt is not None:
            by_day[ev.occurredAt.strftime("%Y-%m-%d")] += 1

    # State flow — ordered unique states from first to last event
    sorted_evs = sort_relationship_history(list(events))
    state_flow: List[str] = []
    for ev in sorted_evs:
        val = ev.currentState.value
        if not state_flow or state_flow[-1] != val:
            state_flow.append(val)

    # Confidence delta — final minus initial (0 when only one event)
    first_ev = sorted_evs[0]  if sorted_evs else None
    last_ev  = sorted_evs[-1] if sorted_evs else None
    confidence_delta = 0
    if first_ev and last_ev:
        confidence_delta = last_ev.currentConfidence - first_ev.currentConfidence

    return RelationshipHistoryStatistics(
        totalEvents     = len(events),
        eventsByType    = dict(by_type),
        eventsByDay     = dict(by_day),
        confidenceDelta = confidence_delta,
        stateFlow       = state_flow,
    )


# ---------------------------------------------------------------------------
# Builder: build_relationship_history_bundle()
# ---------------------------------------------------------------------------

def build_relationship_history_bundle(
    events: List[RelationshipHistoryEvent],
) -> RelationshipHistoryBundle:
    """
    Assemble a RelationshipHistoryBundle from a list of events.

    Parameters
    ----------
    events : list of RelationshipHistoryEvents (any order).

    Returns
    -------
    RelationshipHistoryBundle (frozen / immutable)
    """
    sorted_evs = sort_relationship_history(events)
    summary    = build_relationship_history_summary(sorted_evs)
    statistics = build_relationship_history_statistics(sorted_evs)

    return RelationshipHistoryBundle(
        events        = sorted_evs,
        summary       = summary,
        statistics    = statistics,
        engineVersion = RELATIONSHIP_HISTORY_ENGINE_VERSION,
        createdAt     = datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Utility: sort_relationship_history()
# ---------------------------------------------------------------------------

def sort_relationship_history(
    events     : List[RelationshipHistoryEvent],
    descending : bool = False,
) -> List[RelationshipHistoryEvent]:
    """
    Sort events by (occurredAt, packetNumber, sequenceNumber).

    None occurredAt values sort last (ascending) or first (descending).
    None packetNumber values sort last.

    Parameters
    ----------
    events     : list to sort (not mutated).
    descending : if True, most-recent event first.

    Returns
    -------
    New sorted List[RelationshipHistoryEvent]
    """
    _epoch   = datetime.min.replace(tzinfo=timezone.utc)
    _max_pkt = 10 ** 9  # sentinel for None packetNumber

    def _key(e: RelationshipHistoryEvent) -> tuple:
        ts  = e.occurredAt    if e.occurredAt    is not None else _epoch
        pkt = e.packetNumber  if e.packetNumber  is not None else _max_pkt
        return (ts, pkt, e.sequenceNumber)

    return sorted(events, key=_key, reverse=descending)


# ---------------------------------------------------------------------------
# Utility: group_relationship_history()
# ---------------------------------------------------------------------------

def group_relationship_history(
    events   : Sequence[RelationshipHistoryEvent],
    group_by : str = "eventType",
) -> Dict[str, List[RelationshipHistoryEvent]]:
    """
    Group RelationshipHistoryEvents by a string attribute.

    Parameters
    ----------
    events   : sequence of events.
    group_by : attribute name on RelationshipHistoryEvent.
               Supported: "eventType", "currentState", "captureId",
               "relationshipId".
               Unknown attributes fall back to key "unknown".

    Returns
    -------
    Dict[str, List[RelationshipHistoryEvent]] — each group sorted
    chronologically by (occurredAt, packetNumber, sequenceNumber).
    """
    groups: Dict[str, List[RelationshipHistoryEvent]] = defaultdict(list)

    for ev in events:
        raw = getattr(ev, group_by, None)
        # Unwrap enums to their string value
        key = raw.value if isinstance(raw, (RelationshipEventType, RelationshipState)) \
              else (str(raw) if raw is not None else "unknown")
        groups[key].append(ev)

    return {k: sort_relationship_history(v) for k, v in groups.items()}


# ---------------------------------------------------------------------------
# Utility: filter_relationship_history()
# ---------------------------------------------------------------------------

def filter_relationship_history(
    events          : Sequence[RelationshipHistoryEvent],
    event_type      : Optional[RelationshipEventType] = None,
    current_state   : Optional[RelationshipState]     = None,
    relationship_id : Optional[str]                   = None,
    capture_id      : Optional[str]                   = None,
    from_dt         : Optional[datetime]              = None,
    to_dt           : Optional[datetime]              = None,
) -> List[RelationshipHistoryEvent]:
    """
    Return a filtered subset of RelationshipHistoryEvents.

    All parameters are optional and additive (AND semantics).

    Parameters
    ----------
    events          : source sequence.
    event_type      : keep only events of this RelationshipEventType.
    current_state   : keep only events where currentState matches.
    relationship_id : keep only events for this relationshipId.
    capture_id      : keep only events with this captureId.
    from_dt         : keep only events where occurredAt >= from_dt.
    to_dt           : keep only events where occurredAt <= to_dt.

    Returns
    -------
    List[RelationshipHistoryEvent] sorted chronologically.
    """
    result: List[RelationshipHistoryEvent] = []

    for ev in events:
        if event_type      is not None and ev.eventType      != event_type:
            continue
        if current_state   is not None and ev.currentState   != current_state:
            continue
        if relationship_id is not None and ev.relationshipId != relationship_id:
            continue
        if capture_id      is not None and ev.captureId      != capture_id:
            continue
        if from_dt is not None and ev.occurredAt is not None and ev.occurredAt < from_dt:
            continue
        if to_dt   is not None and ev.occurredAt is not None and ev.occurredAt > to_dt:
            continue
        result.append(ev)

    return sort_relationship_history(result)
