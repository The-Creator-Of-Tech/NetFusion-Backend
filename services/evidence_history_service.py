"""
Enterprise Evidence History Engine
====================================
Phase A.2.2.6.3 — Immutable chronological history derived from EvidenceRecords.

Responsibilities
----------------
- Build HistoryEvents from one or more EvidenceRecords.
- Group, sort, filter, and summarise history events.
- Produce a HistoryBundle with summary + statistics.

Design constraints
------------------
- Pure derivation: no database writes, no repository calls, no HTTP.
- Immutable output: all models are frozen Pydantic objects.
- Deterministic: same inputs always produce structurally identical output.
- No AI, no heuristics, no scoring.

Event ID generation
-------------------
Every HistoryEvent uses a UUID v5 derived from:
    evidenceId + eventType + occurredAt (ISO-format)
Same observation + same event type + same timestamp → same eventId.
Safe to use as a deduplication key downstream (timeline, attack graph, AI).

Dependency graph (no circular imports)
---------------------------------------
  core.constants
  services.evidence_service   (EvidenceRecord, EvidenceBundle)
  ← services.evidence_history_service   (this file)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from core.constants import HISTORY_ENGINE_VERSION
from services.evidence_service import EvidenceBundle, EvidenceRecord


# ---------------------------------------------------------------------------
# Namespace UUID for deterministic eventId generation.
# Fixed — never change; changing invalidates all existing event IDs.
# ---------------------------------------------------------------------------
_HISTORY_NS = uuid.UUID("12345678-1234-5678-1234-567812345678")


# ---------------------------------------------------------------------------
# EventType enum
# ---------------------------------------------------------------------------

class EventType(str, Enum):
    """
    Supported history event types.

    OBSERVED  : a field value was seen for the first time on a packet/capture.
    CREATED   : an EvidenceRecord was formally created in the engine.
    UPDATED   : the same field gained a new value (value drift detected).
    CONFLICT  : two EvidenceRecords disagree on the same field for the same asset.
    VERIFIED  : an existing value was confirmed by a second independent source.
    RESOLVED  : a conflict or ambiguity was resolved (single authoritative value).
    """
    OBSERVED  = "OBSERVED"
    CREATED   = "CREATED"
    UPDATED   = "UPDATED"
    CONFLICT  = "CONFLICT"
    VERIFIED  = "VERIFIED"
    RESOLVED  = "RESOLVED"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class HistoryEvent(BaseModel):
    """
    One immutable point-in-time event derived from an EvidenceRecord.

    Fields
    ------
    eventId           : UUID v5 — deterministic, stable across rebuilds.
                        Derived from (evidenceId + eventType + occurredAt).
    assetId           : Asset the event belongs to (may be None if unresolved).
    evidenceId        : Back-reference to the source EvidenceRecord.
    eventType         : EventType — nature of the observation.
    fieldName         : camelCase field name (e.g. "macAddress").
    fieldValue        : observed value at the time of the event.
    sourceType        : normalised source key (e.g. "pcap", "dhcp").
    captureId         : CaptureSession.captureId (may be None).
    packetNumber      : frame index within capture (may be None).
    sequenceNumber    : monotonically increasing integer assigned during
                        build_history().  Breaks ties when occurredAt and
                        packetNumber are identical.  Sort key is always:
                        (occurredAt, packetNumber, sequenceNumber).
                        Guarantees exact replay order for forensic purposes.
    parentEventId     : eventId of the preceding event in the same
                        (assetId, fieldName) chain.  None for the root
                        OBSERVED event.  Enables full chain traversal:
                        OBSERVED → VERIFIED → UPDATED → RESOLVED.
    occurredAt        : UTC datetime the original observation happened.
    summary           : human-readable one-line description of the event.
    relatedEvidenceIds: other evidenceIds that share the same field/asset
                        context and are relevant to this event.
    metadata          : arbitrary key-value extension bag.
    """
    eventId            : str
    assetId            : Optional[str]       = None
    evidenceId         : str
    eventType          : EventType
    fieldName          : str
    fieldValue         : str
    sourceType         : str
    captureId          : Optional[str]       = None
    packetNumber       : Optional[int]       = None
    sequenceNumber     : int                 = 0
    parentEventId      : Optional[str]       = None
    occurredAt         : Optional[datetime]  = None
    summary            : str                 = ""
    relatedEvidenceIds : List[str]           = Field(default_factory=list)
    metadata           : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        frozen = True   # immutable after construction


class HistorySummary(BaseModel):
    """
    Aggregate summary computed from a list of HistoryEvents.

    Fields
    ------
    firstSeen    : earliest occurredAt across all events (None if no timestamps).
    lastSeen     : latest occurredAt across all events.
    eventCount   : total number of events.
    sourceCount  : number of distinct sourceType values.
    fieldCount   : number of distinct fieldName values.
    captureCount : number of distinct captureId values (excludes None).
    """
    firstSeen    : Optional[datetime] = None
    lastSeen     : Optional[datetime] = None
    eventCount   : int                = 0
    sourceCount  : int                = 0
    fieldCount   : int                = 0
    captureCount : int                = 0

    class Config:
        frozen = True


class HistoryStatistics(BaseModel):
    """
    Fine-grained frequency statistics over a list of HistoryEvents.

    Fields
    ------
    eventsPerType   : { EventType.value → count }
    eventsPerSource : { sourceType → count }
    eventsPerDay    : { "YYYY-MM-DD" → count }  (keyed on occurredAt date)
    """
    eventsPerType   : Dict[str, int] = Field(default_factory=dict)
    eventsPerSource : Dict[str, int] = Field(default_factory=dict)
    eventsPerDay    : Dict[str, int] = Field(default_factory=dict)

    class Config:
        frozen = True


class HistoryBundle(BaseModel):
    """
    Complete history output for one asset or capture scope.

    Fields
    ------
    events        : chronologically sorted list of HistoryEvents.
    summary       : aggregate HistorySummary over all events.
    statistics    : HistoryStatistics over all events.
    engineVersion : HISTORY_ENGINE_VERSION at time of construction.
    createdAt     : UTC datetime this bundle was built.
    """
    events        : List[HistoryEvent] = Field(default_factory=list)
    summary       : HistorySummary     = Field(default_factory=HistorySummary)
    statistics    : HistoryStatistics  = Field(default_factory=HistoryStatistics)
    engineVersion : str                = HISTORY_ENGINE_VERSION
    createdAt     : datetime           = Field(
                        default_factory=lambda: datetime.now(timezone.utc)
                    )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_event_id(evidence_id: str, event_type: EventType, occurred_at: Optional[datetime]) -> str:
    """
    Derive a stable UUID v5 for a HistoryEvent.

    Input string: "<evidenceId>|<eventType.value>|<occurredAt ISO or ''>"
    Same inputs always produce the same eventId.
    """
    ts   = occurred_at.isoformat() if occurred_at else ""
    name = f"{evidence_id}|{event_type.value}|{ts}"
    return str(uuid.uuid5(_HISTORY_NS, name))


def _make_summary_text(
    event_type   : EventType,
    field_name   : str,
    field_value  : str,
    source_type  : str,
    packet_number: Optional[int],
    capture_id   : Optional[str],
) -> str:
    """Build a deterministic one-line human-readable event summary."""
    loc_parts: List[str] = []
    if capture_id:
        loc_parts.append(f"capture={capture_id}")
    if packet_number is not None:
        loc_parts.append(f"pkt={packet_number}")
    location = f" [{', '.join(loc_parts)}]" if loc_parts else ""

    templates: Dict[EventType, str] = {
        EventType.OBSERVED  : f"{field_name}={field_value!r} observed via {source_type}{location}",
        EventType.CREATED   : f"{field_name}={field_value!r} evidence created from {source_type}{location}",
        EventType.UPDATED   : f"{field_name} updated to {field_value!r} via {source_type}{location}",
        EventType.CONFLICT  : f"{field_name} conflict: {field_value!r} from {source_type}{location}",
        EventType.VERIFIED  : f"{field_name}={field_value!r} verified by {source_type}{location}",
        EventType.RESOLVED  : f"{field_name} resolved to {field_value!r} via {source_type}{location}",
    }
    return templates.get(event_type, f"{event_type.value}: {field_name}={field_value!r}")


# ---------------------------------------------------------------------------
# Builder: build_history_event()
# ---------------------------------------------------------------------------

def build_history_event(
    record          : EvidenceRecord,
    event_type      : EventType                  = EventType.OBSERVED,
    related_ids     : Optional[List[str]]        = None,
    extra_meta      : Optional[Dict[str, Any]]   = None,
    sequence_number : int                        = 0,
    parent_event_id : Optional[str]              = None,
) -> HistoryEvent:
    """
    Build a single HistoryEvent from one EvidenceRecord.

    Parameters
    ----------
    record          : EvidenceRecord produced by evidence_service builders.
    event_type      : defaults to OBSERVED (most common case).
    related_ids     : other evidenceIds contextually related to this event.
    extra_meta      : optional additional metadata merged into the event.
    sequence_number : monotonic counter assigned by build_history(); 0 when
                      called directly.  Used as the third sort key after
                      (occurredAt, packetNumber) to guarantee stable replay
                      order when timestamps/packet numbers collide.
    parent_event_id : eventId of the preceding event in the same
                      (assetId, fieldName) chain.  None for root events.

    Returns
    -------
    HistoryEvent (frozen / immutable)
    """
    source    = record.source
    reference = record.reference
    occurred  = record.observedAt or record.createdAt

    event_id = _make_event_id(record.evidenceId, event_type, occurred)

    summary_text = _make_summary_text(
        event_type    = event_type,
        field_name    = record.fieldName,
        field_value   = record.fieldValue,
        source_type   = source.sourceType if source else "unknown",
        packet_number = reference.packetNumber if reference else None,
        capture_id    = reference.captureId    if reference else None,
    )

    meta: Dict[str, Any] = {
        "evidenceHash"  : record.evidenceHash,
        "engineVersion" : record.engineVersion,
        "schemaVersion" : record.schemaVersion,
        "confidence"    : record.confidence,
    }
    if extra_meta:
        meta.update(extra_meta)

    return HistoryEvent(
        eventId            = event_id,
        assetId            = record.assetId,
        evidenceId         = record.evidenceId,
        eventType          = event_type,
        fieldName          = record.fieldName,
        fieldValue         = record.fieldValue,
        sourceType         = source.sourceType if source else "unknown",
        captureId          = reference.captureId    if reference else None,
        packetNumber       = reference.packetNumber if reference else None,
        sequenceNumber     = sequence_number,
        parentEventId      = parent_event_id,
        occurredAt         = occurred,
        summary            = summary_text,
        relatedEvidenceIds = list(related_ids) if related_ids else [],
        metadata           = meta,
    )


# ---------------------------------------------------------------------------
# Builder: build_history()
# ---------------------------------------------------------------------------

def build_history(
    records    : Sequence[EvidenceRecord],
    event_type : EventType = EventType.OBSERVED,
) -> List[HistoryEvent]:
    """
    Build a HistoryEvent for every EvidenceRecord in the input sequence.

    Ordering guarantee
    ------------------
    Records are pre-sorted by (occurredAt, packetNumber) before processing.
    Each resulting event receives a monotonically increasing sequenceNumber
    (0-based, assigned in final sort order).  The final list is sorted by:

        (occurredAt, packetNumber, sequenceNumber)

    This means 30 packets with the same timestamp are always replayed in
    the exact order they were observed in the capture file.

    Parent chain wiring
    -------------------
    For each (assetId, fieldName) pair the builder tracks the eventId of
    the most-recently emitted event.  Every subsequent event on the same
    pair receives that eventId as its parentEventId, forming a traversable
    chain:

        OBSERVED → VERIFIED → CONFLICT → RESOLVED …

    Callers can reconstruct the complete field history by following
    parentEventId links backwards from any event.

    Event type auto-classification
    --------------------------------
    When event_type is OBSERVED (default), events are auto-classified:

      - First record for a (assetId, fieldName)    → OBSERVED
      - Same value, different source               → VERIFIED
      - Different value, same field                → CONFLICT

    Passing any explicit type other than OBSERVED disables auto-classification
    and stamps every record with that type.

    Parameters
    ----------
    records    : sequence of EvidenceRecords (any order).
    event_type : explicit override; OBSERVED enables auto-classification.

    Returns
    -------
    List[HistoryEvent] sorted by (occurredAt, packetNumber, sequenceNumber).
    """
    if not records:
        return []

    auto_classify = (event_type == EventType.OBSERVED)

    _epoch = datetime.min.replace(tzinfo=timezone.utc)
    _max_pkt = 10 ** 9  # sentinel for None packetNumber — sorts last

    # Pre-sort input by (occurredAt, packetNumber) so that auto-classification
    # state is built in chronological order.
    sorted_records = sorted(
        records,
        key=lambda r: (
            r.observedAt or r.createdAt or _epoch,
            (r.reference.packetNumber if r.reference and r.reference.packetNumber is not None else _max_pkt),
        ),
    )

    # Per-(assetId, fieldName) tracking for auto-classification and chain.
    # Value: { "firstValue": str, "evidenceIds": [str], "lastEventId": str }
    seen: Dict[tuple, Dict[str, Any]] = {}

    # Unsorted accumulator — we assign sequenceNumber after the final sort.
    raw_events: List[HistoryEvent] = []

    for rec in sorted_records:
        reference = rec.reference
        pkt       = reference.packetNumber if reference and reference.packetNumber is not None else None

        if auto_classify:
            key   = (rec.assetId or "", rec.fieldName)
            prior = seen.get(key)

            if prior is None:
                etype          = EventType.OBSERVED
                related        : List[str] = []
                parent_ev_id   : Optional[str] = None
                seen[key] = {
                    "firstValue"  : rec.fieldValue,
                    "evidenceIds" : [rec.evidenceId],
                    "lastEventId" : None,   # filled in after event is built
                }
            elif prior["firstValue"] == rec.fieldValue:
                etype        = EventType.VERIFIED
                related      = list(prior["evidenceIds"])
                parent_ev_id = prior["lastEventId"]
                prior["evidenceIds"].append(rec.evidenceId)
            else:
                etype        = EventType.CONFLICT
                related      = list(prior["evidenceIds"])
                parent_ev_id = prior["lastEventId"]
                prior["evidenceIds"].append(rec.evidenceId)
        else:
            key          = (rec.assetId or "", rec.fieldName)
            prior        = seen.get(key)
            etype        = event_type
            related      = []
            parent_ev_id = prior["lastEventId"] if prior else None
            if prior is None:
                seen[key] = {
                    "firstValue"  : rec.fieldValue,
                    "evidenceIds" : [rec.evidenceId],
                    "lastEventId" : None,
                }
            else:
                prior["evidenceIds"].append(rec.evidenceId)

        ev = build_history_event(
            record          = rec,
            event_type      = etype,
            related_ids     = related or None,
            sequence_number = 0,          # placeholder — assigned below
            parent_event_id = parent_ev_id,
        )

        # Record the eventId of this event as the new chain tail.
        seen[key]["lastEventId"] = ev.eventId

        raw_events.append(ev)

    # Final sort: (occurredAt, packetNumber, original insertion index).
    # We use the index as the stable tiebreaker BEFORE assigning sequenceNumber
    # so that sequenceNumber itself reflects the final canonical order.
    def _sort_key(item: tuple) -> tuple:
        idx, ev = item
        ts  = ev.occurredAt if ev.occurredAt is not None else _epoch
        pkt = ev.packetNumber if ev.packetNumber is not None else _max_pkt
        return (ts, pkt, idx)

    ordered_pairs = sorted(enumerate(raw_events), key=_sort_key)

    # Rebuild events with correct sequenceNumber (frozen model — must reconstruct).
    final: List[HistoryEvent] = []
    for seq, (_, ev) in enumerate(ordered_pairs):
        # model_copy is the Pydantic v1 API; use dict round-trip for v1/v2 compat.
        data = ev.dict()
        data["sequenceNumber"] = seq
        final.append(HistoryEvent(**data))

    return final


# ---------------------------------------------------------------------------
# Builder: build_asset_history()
# ---------------------------------------------------------------------------

def build_asset_history(
    asset_id : str,
    records  : Sequence[EvidenceRecord],
) -> HistoryBundle:
    """
    Build a complete HistoryBundle for one Asset from its EvidenceRecords.

    Filters out any records whose assetId does not match the given asset_id,
    then delegates to build_history() for event construction.

    Parameters
    ----------
    asset_id : Asset primary key to scope the history.
    records  : all EvidenceRecords available (may include other assets).

    Returns
    -------
    HistoryBundle (frozen / immutable)
    """
    scoped = [r for r in records if r.assetId == asset_id]
    events = build_history(scoped, event_type=EventType.OBSERVED)
    return _assemble_bundle(events)


# ---------------------------------------------------------------------------
# Builder: build_capture_history()
# ---------------------------------------------------------------------------

def build_capture_history(
    capture_id : str,
    records    : Sequence[EvidenceRecord],
) -> HistoryBundle:
    """
    Build a complete HistoryBundle for one CaptureSession from its
    EvidenceRecords.

    Filters to records where reference.captureId == capture_id.

    Parameters
    ----------
    capture_id : CaptureSession.captureId to scope the history.
    records    : all EvidenceRecords available.

    Returns
    -------
    HistoryBundle (frozen / immutable)
    """
    scoped = [
        r for r in records
        if r.reference and r.reference.captureId == capture_id
    ]
    events = build_history(scoped, event_type=EventType.OBSERVED)
    return _assemble_bundle(events)


# ---------------------------------------------------------------------------
# Builder: build_history_summary()
# ---------------------------------------------------------------------------

def build_history_summary(events: Sequence[HistoryEvent]) -> HistorySummary:
    """
    Compute a HistorySummary from a sequence of HistoryEvents.

    Parameters
    ----------
    events : any sequence of HistoryEvent objects.

    Returns
    -------
    HistorySummary (frozen / immutable)
    """
    if not events:
        return HistorySummary()

    timestamps   = [e.occurredAt for e in events if e.occurredAt is not None]
    sources      = {e.sourceType for e in events}
    fields       = {e.fieldName  for e in events}
    captures     = {e.captureId  for e in events if e.captureId is not None}

    return HistorySummary(
        firstSeen    = min(timestamps) if timestamps else None,
        lastSeen     = max(timestamps) if timestamps else None,
        eventCount   = len(events),
        sourceCount  = len(sources),
        fieldCount   = len(fields),
        captureCount = len(captures),
    )


# ---------------------------------------------------------------------------
# Builder: build_history_statistics()
# ---------------------------------------------------------------------------

def build_history_statistics(events: Sequence[HistoryEvent]) -> HistoryStatistics:
    """
    Compute HistoryStatistics (frequency breakdowns) from a sequence of
    HistoryEvents.

    Parameters
    ----------
    events : any sequence of HistoryEvent objects.

    Returns
    -------
    HistoryStatistics (frozen / immutable)
    """
    per_type   : Dict[str, int] = defaultdict(int)
    per_source : Dict[str, int] = defaultdict(int)
    per_day    : Dict[str, int] = defaultdict(int)

    for ev in events:
        per_type[ev.eventType.value] += 1
        per_source[ev.sourceType]    += 1
        if ev.occurredAt is not None:
            day_key = ev.occurredAt.strftime("%Y-%m-%d")
            per_day[day_key] += 1

    return HistoryStatistics(
        eventsPerType   = dict(per_type),
        eventsPerSource = dict(per_source),
        eventsPerDay    = dict(per_day),
    )


# ---------------------------------------------------------------------------
# Internal: _assemble_bundle()
# ---------------------------------------------------------------------------

def _assemble_bundle(events: List[HistoryEvent]) -> HistoryBundle:
    """Combine sorted events, summary, and statistics into a HistoryBundle."""
    summary    = build_history_summary(events)
    statistics = build_history_statistics(events)
    return HistoryBundle(
        events        = events,
        summary       = summary,
        statistics    = statistics,
        engineVersion = HISTORY_ENGINE_VERSION,
        createdAt     = datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Utility: sort_history()
# ---------------------------------------------------------------------------

def sort_history(
    events     : List[HistoryEvent],
    descending : bool = False,
) -> List[HistoryEvent]:
    """
    Return a new list of HistoryEvents sorted by the canonical three-key order:

        (occurredAt, packetNumber, sequenceNumber)

    - occurredAt   : primary — UTC wall-clock time of the observation.
    - packetNumber : secondary — frame index within the capture file.
                     Breaks timestamp ties so packets are replayed in wire
                     order even when two frames share a sub-millisecond ts.
    - sequenceNumber: tertiary — monotonic counter assigned by build_history().
                     Guarantees a total order when both timestamp and packet
                     number collide (e.g. synthesised or non-packet evidence).

    None values sort last (ascending) or first (descending).

    Parameters
    ----------
    events     : list to sort (not mutated).
    descending : if True, most-recent event first.

    Returns
    -------
    New sorted List[HistoryEvent]
    """
    _epoch   = datetime.min.replace(tzinfo=timezone.utc)
    _max_pkt = 10 ** 9

    def _key(e: HistoryEvent) -> tuple:
        ts  = e.occurredAt    if e.occurredAt    is not None else _epoch
        pkt = e.packetNumber  if e.packetNumber  is not None else _max_pkt
        return (ts, pkt, e.sequenceNumber)

    return sorted(events, key=_key, reverse=descending)


# ---------------------------------------------------------------------------
# Utility: group_history()
# ---------------------------------------------------------------------------

def group_history(
    events   : Sequence[HistoryEvent],
    group_by : str = "fieldName",
) -> Dict[str, List[HistoryEvent]]:
    """
    Group HistoryEvents by a string attribute.

    Parameters
    ----------
    events   : sequence of events.
    group_by : attribute name on HistoryEvent.
               Supported: "fieldName", "sourceType", "captureId",
               "eventType", "assetId".
               Unknown attributes fall back to "unknown".

    Returns
    -------
    Dict[str, List[HistoryEvent]] — key is the group value, value is the
    list of events in that group, each group sorted chronologically.
    """
    groups: Dict[str, List[HistoryEvent]] = defaultdict(list)

    for ev in events:
        raw  = getattr(ev, group_by, None)
        key  = raw.value if isinstance(raw, EventType) else (str(raw) if raw is not None else "unknown")
        groups[key].append(ev)

    # Sort each group chronologically.
    return {k: sort_history(v) for k, v in groups.items()}


# ---------------------------------------------------------------------------
# Utility: filter_history()
# ---------------------------------------------------------------------------

def filter_history(
    events      : Sequence[HistoryEvent],
    event_type  : Optional[EventType]  = None,
    field_name  : Optional[str]        = None,
    source_type : Optional[str]        = None,
    asset_id    : Optional[str]        = None,
    capture_id  : Optional[str]        = None,
    from_dt     : Optional[datetime]   = None,
    to_dt       : Optional[datetime]   = None,
) -> List[HistoryEvent]:
    """
    Return a filtered subset of HistoryEvents.

    All filter parameters are optional and additive (AND semantics).
    Omitting a parameter means "no filter on that field".

    Parameters
    ----------
    events      : source sequence.
    event_type  : keep only events of this EventType.
    field_name  : keep only events with this fieldName.
    source_type : keep only events with this sourceType.
    asset_id    : keep only events for this assetId.
    capture_id  : keep only events from this captureId.
    from_dt     : keep only events where occurredAt >= from_dt.
    to_dt       : keep only events where occurredAt <= to_dt.

    Returns
    -------
    List[HistoryEvent] sorted chronologically.
    """
    result: List[HistoryEvent] = []

    for ev in events:
        if event_type  is not None and ev.eventType  != event_type:
            continue
        if field_name  is not None and ev.fieldName  != field_name:
            continue
        if source_type is not None and ev.sourceType != source_type:
            continue
        if asset_id    is not None and ev.assetId    != asset_id:
            continue
        if capture_id  is not None and ev.captureId  != capture_id:
            continue
        if from_dt is not None and ev.occurredAt is not None and ev.occurredAt < from_dt:
            continue
        if to_dt   is not None and ev.occurredAt is not None and ev.occurredAt > to_dt:
            continue
        result.append(ev)

    return sort_history(result)


# ---------------------------------------------------------------------------
# Utility: summarize_history()
# ---------------------------------------------------------------------------

def summarize_history(events: Sequence[HistoryEvent]) -> HistoryBundle:
    """
    Build a full HistoryBundle (events + summary + statistics) from any
    sequence of HistoryEvents.

    Useful when the caller already has a list of events (e.g. after
    filter_history()) and wants to re-summarise the filtered set.

    Parameters
    ----------
    events : any sequence of HistoryEvent objects.

    Returns
    -------
    HistoryBundle (frozen / immutable)
    """
    return _assemble_bundle(sort_history(list(events)))
