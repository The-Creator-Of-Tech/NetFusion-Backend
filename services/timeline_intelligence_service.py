"""
Timeline Intelligence Engine
==============================
Phase A4.0.5 — Unified chronological investigation timeline.

Responsibilities
----------------
- Convert every forensic object into one unified TimelineEvent.
- Produce a deterministic, replay-safe TimelineBundle.
- Serve as the primary source for: AI Copilot, Incident Reconstruction,
  Report Generator, Attack Replay, Investigation View, Threat Hunting.

Design constraints (FREEZE BOUNDARY — A4.0.5)
----------------------------------------------
- PURE: no Prisma, no repository, no FastAPI, no database, no HTTP, no filesystem.
- Immutable output: every model uses frozen=True.
- Deterministic: same inputs → same result always.
- No side effects. No global mutable state. No circular imports.
- Never mutates any input object.

Sorting guarantee
-----------------
Events are ALWAYS sorted by: (occurredAt, packetNumber, timelinePosition).
  occurredAt      : primary key — UTC wall-clock timestamp.
  packetNumber    : secondary — wire-order tiebreaker within a capture.
  timelinePosition: tertiary — monotonic integer; total order over all events.

Dependency graph
----------------
  core.constants                               (TIMELINE_INTELLIGENCE_ENGINE_VERSION)
  services.evidence_service                    (EvidenceRecord, EvidenceBundle)
  services.evidence_history_service            (HistoryEvent, HistoryBundle, EventType)
  services.relationship_service                (Relationship, RelationshipBundle)
  services.relationship_history_service        (RelationshipHistoryEvent,
                                               RelationshipHistoryBundle,
                                               RelationshipEventType)
  services.attack_graph_intelligence_service   (AttackChain, AttackPattern,
                                               IntelligenceFinding, BlastRadius,
                                               SeverityEnum)
  pydantic, typing, hashlib, collections, time, datetime
  ← services.timeline_intelligence_service      (this file)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from core.constants import TIMELINE_INTELLIGENCE_ENGINE_VERSION

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TimelineEventType(str, Enum):
    """All supported timeline event types."""
    OBSERVED              = "OBSERVED"
    IDENTITY_MATCH        = "IDENTITY_MATCH"
    IDENTITY_CREATED      = "IDENTITY_CREATED"
    RELATIONSHIP_CREATED  = "RELATIONSHIP_CREATED"
    RELATIONSHIP_UPDATED  = "RELATIONSHIP_UPDATED"
    EVIDENCE_ADDED        = "EVIDENCE_ADDED"
    HISTORY_CREATED       = "HISTORY_CREATED"
    ALERT_GENERATED       = "ALERT_GENERATED"
    FINDING_CREATED       = "FINDING_CREATED"
    MITRE_MAPPED          = "MITRE_MAPPED"
    ATTACK_PATTERN        = "ATTACK_PATTERN"
    ATTACK_CHAIN          = "ATTACK_CHAIN"
    BLAST_RADIUS          = "BLAST_RADIUS"
    LATERAL_MOVEMENT      = "LATERAL_MOVEMENT"
    PIVOT                 = "PIVOT"
    CHOKE_POINT           = "CHOKE_POINT"
    MANUAL_ACTION         = "MANUAL_ACTION"


class TimelineSeverity(str, Enum):
    """Severity levels used on timeline events."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class TimelineSourceType(str, Enum):
    """Source domain of the timeline event."""
    EVIDENCE             = "EVIDENCE"
    HISTORY              = "HISTORY"
    RELATIONSHIP         = "RELATIONSHIP"
    RELATIONSHIP_HISTORY = "RELATIONSHIP_HISTORY"
    ATTACK_GRAPH         = "ATTACK_GRAPH"
    INTELLIGENCE         = "INTELLIGENCE"
    MANUAL               = "MANUAL"
    UNKNOWN              = "UNKNOWN"


# ---------------------------------------------------------------------------
# Models — all frozen=True
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    """
    One immutable point-in-time event in the unified investigation timeline.

    Sorting key: (occurredAt, packetNumber, timelinePosition).
    timelinePosition is a monotonic integer that guarantees a total order
    even when occurredAt and packetNumber collide.

    Fields
    ------
    eventId          : 32-char SHA-256 hex — deterministic from source identifiers.
    eventKey         : stable natural key; same logical event always → same key.
    eventType        : TimelineEventType — semantic category.
    occurredAt       : UTC datetime of the original observation (None sorts last).
    assetId          : optional asset this event belongs to.
    relationshipId   : optional relationship back-reference.
    evidenceId       : optional evidence back-reference.
    historyEventId   : optional history event back-reference.
    findingId        : optional finding back-reference.
    alertId          : optional alert back-reference.
    mitreTechnique   : optional ATT&CK technique ID (e.g. "T1071.001").
    title            : short human-readable title.
    summary          : one-line machine-readable summary.
    description      : full description (may be multi-sentence).
    severity         : TimelineSeverity.
    confidence       : 0–100.
    sourceType       : TimelineSourceType — which domain produced this event.
    packetNumber     : frame index within capture (None for non-packet sources).
    captureId        : CaptureSession.captureId.
    relatedEventIds  : other eventIds causally or contextually related.
    timelinePosition : monotonic integer assigned during build_timeline().
                       Enables exact event-by-event replay.
    metadata         : arbitrary extension dict.
    """
    eventId          : str
    eventKey         : str
    eventType        : TimelineEventType
    occurredAt       : Optional[datetime]     = None
    assetId          : Optional[str]          = None
    relationshipId   : Optional[str]          = None
    evidenceId       : Optional[str]          = None
    historyEventId   : Optional[str]          = None
    findingId        : Optional[str]          = None
    alertId          : Optional[str]          = None
    mitreTechnique   : Optional[str]          = None
    title            : str                    = ""
    summary          : str                    = ""
    description      : str                    = ""
    severity         : TimelineSeverity       = TimelineSeverity.INFO
    confidence       : int                    = Field(ge=0, le=100, default=0)
    sourceType       : TimelineSourceType     = TimelineSourceType.UNKNOWN
    packetNumber     : Optional[int]          = None
    captureId        : Optional[str]          = None
    relatedEventIds  : List[str]              = Field(default_factory=list)
    timelinePosition : int                    = 0
    metadata         : Dict[str, Any]         = Field(default_factory=dict)

    class Config:
        frozen = True


class TimelineStatistics(BaseModel):
    """
    Aggregate statistics computed over a TimelineBundle.

    Fields
    ------
    firstSeen        : earliest occurredAt across all events.
    lastSeen         : latest occurredAt across all events.
    totalEvents      : total event count.
    eventsByType     : { TimelineEventType.value → count }
    eventsBySeverity : { TimelineSeverity.value → count }
    eventsBySource   : { TimelineSourceType.value → count }
    durationSeconds  : wall-clock seconds between firstSeen and lastSeen.
    """
    firstSeen        : Optional[datetime]   = None
    lastSeen         : Optional[datetime]   = None
    totalEvents      : int                  = 0
    eventsByType     : Dict[str, int]       = Field(default_factory=dict)
    eventsBySeverity : Dict[str, int]       = Field(default_factory=dict)
    eventsBySource   : Dict[str, int]       = Field(default_factory=dict)
    durationSeconds  : float                = 0.0

    class Config:
        frozen = True


class TimelineExplanation(BaseModel):
    """
    Machine-readable explanation of how this TimelineBundle was assembled.

    Fields
    ------
    reasoningSteps   : narrative steps describing the assembly process.
    algorithmsUsed   : names of builder functions invoked.
    processingStages : ordered list of pipeline stage labels.
    processingTimeMs : total wall-clock cost (milliseconds).
    """
    reasoningSteps   : List[str]  = Field(default_factory=list)
    algorithmsUsed   : List[str]  = Field(default_factory=list)
    processingStages : List[str]  = Field(default_factory=list)
    processingTimeMs : int        = 0

    class Config:
        frozen = True


class TimelineBundle(BaseModel):
    """
    Top-level immutable result returned by build_timeline().

    Fields
    ------
    events              : chronologically sorted list of TimelineEvents.
                          Each event has a unique timelinePosition that
                          enables exact event-by-event replay.
    statistics          : TimelineStatistics over all events.
    explanation         : TimelineExplanation — assembly provenance.
    timelineFingerprint : 32-char SHA-256 over ordered eventKeys.
                          Changes iff the set or order of events changes.
                          Used for: cache, diff, forensic verification,
                          AI replay.
    engineVersion       : TIMELINE_INTELLIGENCE_ENGINE_VERSION.
    createdAt           : UTC datetime this bundle was assembled.
    """
    events              : List[TimelineEvent]   = Field(default_factory=list)
    statistics          : TimelineStatistics    = Field(
                              default_factory=TimelineStatistics
                          )
    explanation         : TimelineExplanation   = Field(
                              default_factory=TimelineExplanation
                          )
    timelineFingerprint : str                   = "0" * 32
    engineVersion       : str                   = TIMELINE_INTELLIGENCE_ENGINE_VERSION
    createdAt           : datetime              = Field(
                              default_factory=lambda: datetime.now(timezone.utc)
                          )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    """Current monotonic time in milliseconds."""
    return round(time.monotonic_ns() / 1_000_000)


def _sha256_32(*parts: str) -> str:
    """
    Deterministic 32-char hex key from SHA-256 over '|'-joined parts.
    Same parts always → same key.  Used for eventId and eventKey.
    """
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _timeline_fingerprint(ordered_event_keys: List[str]) -> str:
    """
    Compute a deterministic 32-char timeline fingerprint.

    Algorithm: ordered eventKeys joined by '>' → SHA-256 → first 32 hex chars.
    Changes iff the set or order of events changes.
    Empty timeline → 32 zeros.

    Used for: cache keys, diff detection, forensic verification, AI replay.
    """
    if not ordered_event_keys:
        return "0" * 32
    raw = ">".join(ordered_event_keys)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# Sentinel values for sort stability
_EPOCH    = datetime.min.replace(tzinfo=timezone.utc)
_MAX_PKT  = 10 ** 9   # sorts after any real packet number


def _sort_key(ev: TimelineEvent) -> tuple:
    """
    Three-key sort: (occurredAt, packetNumber, timelinePosition).
    None occurredAt → _EPOCH (sorts first in ascending order but we
    handle None explicitly so they sort LAST by substituting datetime.max).
    """
    ts  = ev.occurredAt   if ev.occurredAt   is not None else datetime.max.replace(tzinfo=timezone.utc)
    pkt = ev.packetNumber if ev.packetNumber is not None else _MAX_PKT
    return (ts, pkt, ev.timelinePosition)


def _severity_from_confidence(confidence: int) -> TimelineSeverity:
    """Map a 0–100 confidence/risk score to a TimelineSeverity."""
    if confidence >= 85:
        return TimelineSeverity.CRITICAL
    if confidence >= 65:
        return TimelineSeverity.HIGH
    if confidence >= 40:
        return TimelineSeverity.MEDIUM
    if confidence >= 15:
        return TimelineSeverity.LOW
    return TimelineSeverity.INFO


def _severity_str_to_enum(sev: str) -> TimelineSeverity:
    """Convert an arbitrary severity string to TimelineSeverity."""
    _MAP: Dict[str, TimelineSeverity] = {
        "critical" : TimelineSeverity.CRITICAL,
        "high"     : TimelineSeverity.HIGH,
        "medium"   : TimelineSeverity.MEDIUM,
        "low"      : TimelineSeverity.LOW,
        "info"     : TimelineSeverity.INFO,
        "unknown"  : TimelineSeverity.INFO,
    }
    return _MAP.get(str(sev).lower().strip(), TimelineSeverity.INFO)


# ---------------------------------------------------------------------------
# Core builder: build_timeline_event()
# ---------------------------------------------------------------------------

def build_timeline_event(
    event_type       : TimelineEventType,
    *,
    occurred_at      : Optional[datetime]        = None,
    title            : str                       = "",
    summary          : str                       = "",
    description      : str                       = "",
    severity         : TimelineSeverity          = TimelineSeverity.INFO,
    confidence       : int                       = 0,
    source_type      : TimelineSourceType        = TimelineSourceType.UNKNOWN,
    asset_id         : Optional[str]             = None,
    relationship_id  : Optional[str]             = None,
    evidence_id      : Optional[str]             = None,
    history_event_id : Optional[str]             = None,
    finding_id       : Optional[str]             = None,
    alert_id         : Optional[str]             = None,
    mitre_technique  : Optional[str]             = None,
    packet_number    : Optional[int]             = None,
    capture_id       : Optional[str]             = None,
    related_event_ids: Optional[List[str]]       = None,
    metadata         : Optional[Dict[str, Any]]  = None,
    # timelinePosition is assigned by sort_timeline() — not set here
) -> TimelineEvent:
    """
    Build a single TimelineEvent with deterministic eventId and eventKey.

    The eventKey is derived from the combination of:
      event_type | occurred_at | evidence_id | relationship_id |
      history_event_id | finding_id | alert_id | packet_number | capture_id

    This ensures that the same logical event always produces the same key,
    enabling deduplication and forensic replay.

    Parameters
    ----------
    event_type        : TimelineEventType.
    occurred_at       : UTC datetime of the original observation.
    title             : short human-readable title.
    summary           : one-line machine-readable summary.
    description       : full description.
    severity          : TimelineSeverity.
    confidence        : 0–100.
    source_type       : TimelineSourceType — source domain.
    asset_id          : optional asset reference.
    relationship_id   : optional relationship reference.
    evidence_id       : optional evidence reference.
    history_event_id  : optional history event reference.
    finding_id        : optional finding reference.
    alert_id          : optional alert reference.
    mitre_technique   : optional ATT&CK technique ID.
    packet_number     : frame index within capture.
    capture_id        : CaptureSession.captureId.
    related_event_ids : other related timeline eventIds.
    metadata          : arbitrary extension dict.

    Returns
    -------
    TimelineEvent (frozen / immutable); timelinePosition defaults to 0
    and is assigned later by sort_timeline() / build_timeline().
    """
    ts_str  = occurred_at.isoformat() if occurred_at else ""
    pkt_str = str(packet_number)      if packet_number is not None else ""
    cap_str = capture_id or ""

    event_key = _sha256_32(
        event_type.value,
        ts_str,
        evidence_id      or "",
        relationship_id  or "",
        history_event_id or "",
        finding_id       or "",
        alert_id         or "",
        pkt_str,
        cap_str,
    )
    event_id = _sha256_32("event", event_key, source_type.value)

    return TimelineEvent(
        eventId          = event_id,
        eventKey         = event_key,
        eventType        = event_type,
        occurredAt       = occurred_at,
        assetId          = asset_id,
        relationshipId   = relationship_id,
        evidenceId       = evidence_id,
        historyEventId   = history_event_id,
        findingId        = finding_id,
        alertId          = alert_id,
        mitreTechnique   = mitre_technique,
        title            = title or event_type.value.replace("_", " ").title(),
        summary          = summary,
        description      = description,
        severity         = severity,
        confidence       = max(0, min(100, int(confidence))),
        sourceType       = source_type,
        packetNumber     = packet_number,
        captureId        = capture_id,
        relatedEventIds  = list(related_event_ids) if related_event_ids else [],
        timelinePosition = 0,   # assigned by sort_timeline()
        metadata         = dict(metadata) if metadata else {},
    )


# ---------------------------------------------------------------------------
# Domain builders
# ---------------------------------------------------------------------------

def build_evidence_events(
    evidence: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build EVIDENCE_ADDED TimelineEvents from EvidenceRecord objects or dicts.

    Accepts both EvidenceRecord Pydantic objects and plain dicts (duck-typed).

    One event is produced per evidence item.  Items with no recoverable
    timestamp get occurredAt=None (sorted last).

    Parameters
    ----------
    evidence : sequence of EvidenceRecord objects or compatible dicts.

    Returns
    -------
    List[TimelineEvent] — unsorted; timelinePosition=0 on all items.
    """
    def _get(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for ev in evidence:
        ev_id     = str(_get(ev, "evidenceId", "evidence_id", "id", default="") or "")
        asset_id  = str(_get(ev, "assetId", "asset_id", default="") or "") or None
        field     = str(_get(ev, "fieldName", "field_name", default="") or "")
        value     = str(_get(ev, "fieldValue", "field_value", default="") or "")
        conf      = int(_get(ev, "confidence", default=0) or 0)
        cap_id    = None
        pkt_num   = None

        # Navigate nested reference/source objects
        ref = _get(ev, "reference")
        if ref is not None:
            cap_id  = str(_get(ref, "captureId", "capture_id", default="") or "") or None
            pkt_raw = _get(ref, "packetNumber", "packet_number")
            pkt_num = int(pkt_raw) if pkt_raw is not None else None

        # Flatten dicts if reference isn't nested
        if cap_id is None:
            cap_id = str(_get(ev, "captureId", "capture_id", default="") or "") or None
        if pkt_num is None:
            pkt_raw = _get(ev, "packetNumber", "packet_number")
            pkt_num = int(pkt_raw) if pkt_raw is not None else None

        # Timestamp
        occurred: Optional[datetime] = (
            _get(ev, "observedAt", "observed_at")
            or _get(ev, "createdAt", "created_at")
        )

        source_type_str = ""
        src_obj = _get(ev, "source")
        if src_obj is not None:
            source_type_str = str(_get(src_obj, "sourceType", "source_type", default="") or "")

        title   = f"Evidence: {field}={value}"[:80] if field else "Evidence Observed"
        summary = f"Field '{field}' observed with value '{value}' (confidence={conf})"

        events.append(build_timeline_event(
            TimelineEventType.EVIDENCE_ADDED,
            occurred_at  = occurred,
            title        = title,
            summary      = summary,
            description  = f"Evidence record {ev_id}: {field}={value} from source '{source_type_str}'.",
            severity     = _severity_from_confidence(conf),
            confidence   = conf,
            source_type  = TimelineSourceType.EVIDENCE,
            asset_id     = asset_id,
            evidence_id  = ev_id or None,
            packet_number= pkt_num,
            capture_id   = cap_id,
            metadata     = {
                "fieldName"  : field,
                "fieldValue" : value,
                "sourceType" : source_type_str,
            },
        ))
    return events


def build_relationship_events(
    relationships: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build RELATIONSHIP_CREATED and RELATIONSHIP_UPDATED TimelineEvents
    from Relationship objects or dicts.

    One RELATIONSHIP_CREATED event is produced per relationship.
    If lastSeen > firstSeen, an additional RELATIONSHIP_UPDATED event is
    produced at lastSeen.

    Parameters
    ----------
    relationships : sequence of Relationship objects or compatible dicts.

    Returns
    -------
    List[TimelineEvent]
    """
    def _get(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for rel in relationships:
        rel_id    = str(_get(rel, "relationshipId", "id", default="") or "")
        src       = str(_get(rel, "sourceAssetId", "source_asset_id", default="") or "")
        tgt       = str(_get(rel, "targetAssetId", "target_asset_id", default="") or "")
        protocol  = str(_get(rel, "protocol", default="UNKNOWN") or "UNKNOWN")
        confidence= int(_get(rel, "confidence", default=0) or 0)
        pkt_count = int(_get(rel, "packetCount", "packet_count", default=1) or 1)
        first_seen: Optional[datetime] = _get(rel, "firstSeen", "first_seen")
        last_seen:  Optional[datetime] = _get(rel, "lastSeen",  "last_seen")
        capture_id = str(_get(rel, "captureId", "capture_id", default="") or "") or None

        # Derive captureId from evidenceIds if available
        ev_ids = _get(rel, "evidenceIds", "evidence_ids", default=[]) or []

        title   = f"Relationship: {src[:12]}… → {tgt[:12]}… [{protocol}]"
        summary = f"{src} communicated with {tgt} via {protocol} ({pkt_count} packets)"

        events.append(build_timeline_event(
            TimelineEventType.RELATIONSHIP_CREATED,
            occurred_at    = first_seen,
            title          = title,
            summary        = summary,
            description    = (
                f"Relationship {rel_id}: {src} → {tgt} via {protocol}. "
                f"Packets: {pkt_count}, confidence={confidence}."
            ),
            severity       = _severity_from_confidence(confidence),
            confidence     = confidence,
            source_type    = TimelineSourceType.RELATIONSHIP,
            relationship_id= rel_id or None,
            capture_id     = capture_id,
            metadata       = {
                "sourceAssetId" : src,
                "targetAssetId" : tgt,
                "protocol"      : protocol,
                "packetCount"   : pkt_count,
                "evidenceIds"   : list(ev_ids)[:5],
            },
        ))

        # Update event when lastSeen differs from firstSeen
        if last_seen and first_seen and last_seen > first_seen:
            events.append(build_timeline_event(
                TimelineEventType.RELATIONSHIP_UPDATED,
                occurred_at    = last_seen,
                title          = f"Relationship Updated: {src[:12]}… → {tgt[:12]}… [{protocol}]",
                summary        = f"Relationship {rel_id} still active at {last_seen.isoformat()}",
                description    = (
                    f"Relationship {rel_id} between {src} and {tgt} "
                    f"updated — last seen at {last_seen.isoformat()}."
                ),
                severity       = _severity_from_confidence(confidence),
                confidence     = confidence,
                source_type    = TimelineSourceType.RELATIONSHIP,
                relationship_id= rel_id or None,
                capture_id     = capture_id,
                metadata       = {"lastSeen": last_seen.isoformat()},
            ))
    return events


def build_history_events(
    history_events: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build HISTORY_CREATED TimelineEvents from HistoryEvent objects or dicts.

    Accepts both HistoryEvent Pydantic objects and plain dicts.

    Parameters
    ----------
    history_events : sequence of HistoryEvent objects or compatible dicts.

    Returns
    -------
    List[TimelineEvent]
    """
    def _get(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for he in history_events:
        h_id      = str(_get(he, "eventId", "event_id", "id", default="") or "")
        asset_id  = str(_get(he, "assetId", "asset_id", default="") or "") or None
        ev_id     = str(_get(he, "evidenceId", "evidence_id", default="") or "") or None
        field     = str(_get(he, "fieldName", "field_name", default="") or "")
        value     = str(_get(he, "fieldValue", "field_value", default="") or "")
        etype_raw = _get(he, "eventType", "event_type", default="OBSERVED")
        etype_str = etype_raw.value if hasattr(etype_raw, "value") else str(etype_raw)
        source    = str(_get(he, "sourceType", "source_type", default="unknown") or "unknown")
        cap_id    = str(_get(he, "captureId", "capture_id", default="") or "") or None
        pkt_raw   = _get(he, "packetNumber", "packet_number")
        pkt_num   = int(pkt_raw) if pkt_raw is not None else None
        occurred  = _get(he, "occurredAt", "occurred_at")
        summary_t = str(_get(he, "summary", default="") or "")
        conf_raw  = _get(he, "metadata", default={})
        conf      = 0
        if isinstance(conf_raw, dict):
            conf  = int(conf_raw.get("confidence", 0) or 0)

        title = f"History [{etype_str}]: {field}={value}"[:80] if field else f"History Event [{etype_str}]"

        events.append(build_timeline_event(
            TimelineEventType.HISTORY_CREATED,
            occurred_at      = occurred,
            title            = title,
            summary          = summary_t or f"History event: {etype_str} on {field}={value}",
            description      = f"History event {h_id}: {etype_str} — {field}={value} from {source}.",
            severity         = _severity_from_confidence(conf),
            confidence       = conf,
            source_type      = TimelineSourceType.HISTORY,
            asset_id         = asset_id,
            evidence_id      = ev_id,
            history_event_id = h_id or None,
            packet_number    = pkt_num,
            capture_id       = cap_id,
            metadata         = {
                "historyEventType" : etype_str,
                "fieldName"        : field,
                "fieldValue"       : value,
                "sourceType"       : source,
            },
        ))
    return events


def build_attack_events(
    attack_chains   : Optional[Sequence[Any]] = None,
    attack_patterns : Optional[Sequence[Any]] = None,
    blast_radii     : Optional[Sequence[Any]] = None,
    intel_findings  : Optional[Sequence[Any]] = None,
) -> List[TimelineEvent]:
    """
    Build attack-graph-derived TimelineEvents.

    Converts:
      - AttackChain     → ATTACK_CHAIN events
      - AttackPattern   → ATTACK_PATTERN events, with specific sub-type mapping:
            LATERAL_MOVEMENT → LATERAL_MOVEMENT
            PIVOT            → PIVOT
            (others)         → ATTACK_PATTERN
      - BlastRadius     → BLAST_RADIUS events
      - IntelligenceFinding whose title contains "Choke" → CHOKE_POINT
      - IntelligenceFinding whose title contains "Pivot" → PIVOT
      - IntelligenceFinding whose title contains "Lateral" → LATERAL_MOVEMENT
      - Other IntelligenceFinding → FINDING_CREATED

    Parameters
    ----------
    attack_chains   : sequence of AttackChain objects or dicts.
    attack_patterns : sequence of AttackPattern objects or dicts.
    blast_radii     : sequence of BlastRadius objects or dicts.
    intel_findings  : sequence of IntelligenceFinding objects or dicts.

    Returns
    -------
    List[TimelineEvent]
    """
    def _g(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    # Sentinel: None — attack/intelligence events have no natural timestamp;
    # we leave occurred_at=None so they sort LAST and produce a stable eventKey.
    _no_ts: Optional[datetime] = None

    # ── AttackChain events ────────────────────────────────────────────────
    for chain in (attack_chains or []):
        chain_id  = str(_g(chain, "chainId", "chain_id", "id", default="") or "")
        name      = str(_g(chain, "name", default="Attack Chain") or "Attack Chain")
        total_risk= int(_g(chain, "totalRisk", "total_risk", default=0) or 0)
        confidence= int(_g(chain, "confidence", default=0) or 0)
        fp        = str(_g(chain, "chainFingerprint", "chain_fingerprint", default="") or "")
        ev_ids    = list(_g(chain, "evidenceIds", "evidence_ids", default=[]) or [])
        stages_raw= _g(chain, "attackStages", "attack_stages", default=[]) or []
        stages    = [s.value if hasattr(s, "value") else str(s) for s in stages_raw]

        events.append(build_timeline_event(
            TimelineEventType.ATTACK_CHAIN,
            occurred_at  = _no_ts,
            title        = f"Attack Chain: {name}",
            summary      = f"Attack chain '{name}' — risk={total_risk}, confidence={confidence}",
            description  = (
                f"Attack chain {chain_id}: '{name}'. "
                f"Stages: {stages}. Fingerprint: {fp}."
            ),
            severity     = _severity_from_confidence(total_risk),
            confidence   = confidence,
            source_type  = TimelineSourceType.INTELLIGENCE,
            finding_id   = chain_id or None,
            metadata     = {
                "chainId"         : chain_id,
                "chainFingerprint": fp,
                "totalRisk"       : total_risk,
                "attackStages"    : stages,
                "evidenceIds"     : ev_ids[:5],
            },
        ))

    # ── AttackPattern events ───────────────────────────────────────────────
    for pat in (attack_patterns or []):
        pat_id   = str(_g(pat, "patternId", "pattern_id", "id", default="") or "")
        ptype_raw= _g(pat, "patternType", "pattern_type", default="UNKNOWN")
        ptype    = ptype_raw.value if hasattr(ptype_raw, "value") else str(ptype_raw)
        title    = str(_g(pat, "title", default=ptype) or ptype)
        desc     = str(_g(pat, "description", default="") or "")
        confidence = int(_g(pat, "confidence", default=0) or 0)
        sev_raw  = _g(pat, "severity", default="MEDIUM")
        sev_str  = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
        mitres   = list(_g(pat, "mitreTechniques", "mitre_techniques", default=[]) or [])

        # Map pattern type to event type
        _ptype_map = {
            "LATERAL_MOVEMENT": TimelineEventType.LATERAL_MOVEMENT,
            "PIVOT"           : TimelineEventType.PIVOT,
        }
        ev_type = _ptype_map.get(ptype, TimelineEventType.ATTACK_PATTERN)

        events.append(build_timeline_event(
            ev_type,
            occurred_at     = _no_ts,
            title           = title,
            summary         = f"Pattern [{ptype}]: {title} (confidence={confidence})",
            description     = desc,
            severity        = _severity_str_to_enum(sev_str),
            confidence      = confidence,
            source_type     = TimelineSourceType.INTELLIGENCE,
            finding_id      = pat_id or None,
            mitre_technique = mitres[0] if mitres else None,
            metadata        = {
                "patternId"     : pat_id,
                "patternType"   : ptype,
                "mitreTechniques": mitres[:5],
            },
        ))

    # ── BlastRadius events ─────────────────────────────────────────────────
    for br in (blast_radii or []):
        src_node  = str(_g(br, "sourceNode", "source_node", default="") or "")
        reachable = list(_g(br, "reachableNodes", "reachable_nodes", default=[]) or [])
        impact    = str(_g(br, "estimatedImpact", "estimated_impact", default="NONE") or "NONE")
        risk      = int(_g(br, "riskScore", "risk_score", default=0) or 0)
        depth     = int(_g(br, "maximumDepth", "maximum_depth", default=0) or 0)

        events.append(build_timeline_event(
            TimelineEventType.BLAST_RADIUS,
            occurred_at  = _no_ts,
            title        = f"Blast Radius: {src_node[:20]}…",
            summary      = f"Node '{src_node}' can reach {len(reachable)} nodes. Impact={impact}.",
            description  = (
                f"Blast radius from '{src_node}': {len(reachable)} reachable nodes, "
                f"depth={depth}, impact={impact}, riskScore={risk}."
            ),
            severity     = _severity_str_to_enum(impact),
            confidence   = min(100, risk),
            source_type  = TimelineSourceType.INTELLIGENCE,
            asset_id     = src_node or None,
            metadata     = {
                "sourceNode"    : src_node,
                "reachableCount": len(reachable),
                "maximumDepth"  : depth,
                "estimatedImpact": impact,
                "riskScore"     : risk,
            },
        ))

    # ── IntelligenceFinding events ─────────────────────────────────────────
    for f in (intel_findings or []):
        f_id     = str(_g(f, "findingId", "finding_id", "id", default="") or "")
        title_f  = str(_g(f, "title", default="Intelligence Finding") or "Intelligence Finding")
        desc_f   = str(_g(f, "description", default="") or "")
        conf_f   = int(_g(f, "confidence", default=0) or 0)
        sev_raw  = _g(f, "severity", default="MEDIUM")
        sev_str  = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
        mitres_f = list(_g(f, "mitreTechniques", "mitre_techniques", default=[]) or [])
        rec      = str(_g(f, "recommendation", default="") or "")

        title_lc = title_f.lower()
        if "choke" in title_lc:
            ev_type_f = TimelineEventType.CHOKE_POINT
        elif "pivot" in title_lc:
            ev_type_f = TimelineEventType.PIVOT
        elif "lateral" in title_lc:
            ev_type_f = TimelineEventType.LATERAL_MOVEMENT
        elif "mitre" in title_lc:
            ev_type_f = TimelineEventType.MITRE_MAPPED
        else:
            ev_type_f = TimelineEventType.FINDING_CREATED

        events.append(build_timeline_event(
            ev_type_f,
            occurred_at     = _no_ts,
            title           = title_f,
            summary         = f"{title_f} (confidence={conf_f})",
            description     = desc_f + (f" Recommendation: {rec}" if rec else ""),
            severity        = _severity_str_to_enum(sev_str),
            confidence      = conf_f,
            source_type     = TimelineSourceType.INTELLIGENCE,
            finding_id      = f_id or None,
            mitre_technique = mitres_f[0] if mitres_f else None,
            metadata        = {
                "findingId"      : f_id,
                "mitreTechniques": mitres_f[:5],
                "recommendation" : rec,
            },
        ))

    return events


def build_alert_events(
    alerts: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build ALERT_GENERATED TimelineEvents from alert dicts or objects.

    Parameters
    ----------
    alerts : sequence of alert dicts or Pydantic objects.

    Returns
    -------
    List[TimelineEvent]
    """
    def _g(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for alert in alerts:
        a_id    = str(_g(alert, "id", "alertId", "alert_id", default="") or "")
        title_a = str(_g(alert, "title", "type", default="Alert") or "Alert")
        desc_a  = str(_g(alert, "description", default="") or "")
        sev_raw = _g(alert, "severity", default="medium")
        sev_str = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
        asset   = str(_g(alert, "asset", "assetId", "asset_id", default="") or "") or None
        occurred= _g(alert, "occurredAt", "occurred_at", "createdAt", "created_at")

        events.append(build_timeline_event(
            TimelineEventType.ALERT_GENERATED,
            occurred_at  = occurred,
            title        = f"Alert: {title_a}",
            summary      = f"[{sev_str.upper()}] {title_a}",
            description  = desc_a,
            severity     = _severity_str_to_enum(sev_str),
            confidence   = 75,
            source_type  = TimelineSourceType.INTELLIGENCE,
            asset_id     = asset,
            alert_id     = a_id or None,
            metadata     = {"severity": sev_str, "alertId": a_id},
        ))
    return events


def build_finding_events(
    findings: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build FINDING_CREATED TimelineEvents from finding dicts or objects.

    Parameters
    ----------
    findings : sequence of finding dicts or Pydantic objects.

    Returns
    -------
    List[TimelineEvent]
    """
    def _g(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for f in findings:
        f_id    = str(_g(f, "id", "findingId", "finding_id", default="") or "")
        title_f = str(_g(f, "type", "title", default="Finding") or "Finding")
        desc_f  = str(_g(f, "description", default="") or "")
        sev_raw = _g(f, "severity", default="unknown")
        sev_str = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
        asset_f = str(_g(f, "asset", "assetId", "asset_id", default="") or "") or None
        occurred= _g(f, "occurredAt", "occurred_at", "createdAt", "created_at")

        events.append(build_timeline_event(
            TimelineEventType.FINDING_CREATED,
            occurred_at  = occurred,
            title        = f"Finding: {title_f}",
            summary      = f"[{sev_str.upper()}] {title_f}",
            description  = desc_f,
            severity     = _severity_str_to_enum(sev_str),
            confidence   = 70,
            source_type  = TimelineSourceType.INTELLIGENCE,
            asset_id     = asset_f,
            finding_id   = f_id or None,
            metadata     = {"severity": sev_str, "findingId": f_id},
        ))
    return events


def build_mitre_events(
    mitre: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build MITRE_MAPPED TimelineEvents from technique dicts or objects.

    Parameters
    ----------
    mitre : sequence of technique dicts or Pydantic objects.

    Returns
    -------
    List[TimelineEvent]
    """
    def _g(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for t in mitre:
        tid   = str(_g(t, "id", "techniqueId", "technique_id", default="") or "")
        name  = str(_g(t, "name", default=tid) or tid)
        tactic= str(_g(t, "tactic", default="") or "")
        occurred = _g(t, "occurredAt", "occurred_at", "createdAt", "created_at")

        events.append(build_timeline_event(
            TimelineEventType.MITRE_MAPPED,
            occurred_at     = occurred,
            title           = f"MITRE {tid}: {name}",
            summary         = f"ATT&CK technique {tid} ({name}) mapped. Tactic: {tactic}.",
            description     = f"MITRE technique {tid} — {name}. Tactic: {tactic}.",
            severity        = TimelineSeverity.HIGH,
            confidence      = 85,
            source_type     = TimelineSourceType.INTELLIGENCE,
            mitre_technique = tid or None,
            metadata        = {
                "techniqueId" : tid,
                "name"        : name,
                "tactic"      : tactic,
            },
        ))
    return events


def build_relationship_history_events(
    rel_history_events: Sequence[Any],
) -> List[TimelineEvent]:
    """
    Build RELATIONSHIP_CREATED / RELATIONSHIP_UPDATED TimelineEvents
    from RelationshipHistoryEvent objects or dicts.

    Parameters
    ----------
    rel_history_events : sequence of RelationshipHistoryEvent objects or dicts.

    Returns
    -------
    List[TimelineEvent]
    """
    def _g(obj: Any, *keys: str, default: Any = None) -> Any:
        for k in keys:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is not None:
                return v
        return default

    events: List[TimelineEvent] = []
    for rhe in rel_history_events:
        h_id       = str(_g(rhe, "eventId", "event_id", "id", default="") or "")
        rel_id     = str(_g(rhe, "relationshipId", "relationship_id", default="") or "")
        etype_raw  = _g(rhe, "eventType", "event_type", default="CREATED")
        etype_str  = etype_raw.value if hasattr(etype_raw, "value") else str(etype_raw)
        conf       = int(_g(rhe, "currentConfidence", "current_confidence", default=0) or 0)
        occurred   = _g(rhe, "occurredAt", "occurred_at")
        cap_id     = str(_g(rhe, "captureId", "capture_id", default="") or "") or None
        pkt_raw    = _g(rhe, "packetNumber", "packet_number")
        pkt_num    = int(pkt_raw) if pkt_raw is not None else None
        summary_t  = str(_g(rhe, "summary", default="") or "")

        ev_type = (
            TimelineEventType.RELATIONSHIP_CREATED
            if etype_str == "CREATED"
            else TimelineEventType.RELATIONSHIP_UPDATED
        )

        events.append(build_timeline_event(
            ev_type,
            occurred_at      = occurred,
            title            = f"Relationship History [{etype_str}]: {rel_id[:16]}…",
            summary          = summary_t or f"Relationship {rel_id} — {etype_str}",
            description      = f"Relationship history event {h_id}: {etype_str} on {rel_id}.",
            severity         = _severity_from_confidence(conf),
            confidence       = conf,
            source_type      = TimelineSourceType.RELATIONSHIP_HISTORY,
            relationship_id  = rel_id or None,
            history_event_id = h_id or None,
            packet_number    = pkt_num,
            capture_id       = cap_id,
            metadata         = {
                "historyEventType": etype_str,
                "relationshipId"  : rel_id,
            },
        ))
    return events


# ---------------------------------------------------------------------------
# Sorting — assigns timelinePosition
# ---------------------------------------------------------------------------

def sort_timeline(events: List[TimelineEvent]) -> List[TimelineEvent]:
    """
    Sort TimelineEvents by (occurredAt, packetNumber, timelinePosition) and
    assign a monotonically increasing timelinePosition to every event.

    Sorting rules
    -------------
    - occurredAt None → sorts LAST (datetime.max sentinel).
    - packetNumber None → sorts after any numbered packet (_MAX_PKT sentinel).
    - timelinePosition is the existing value used as a tiebreaker, then
      overwritten with the new monotonic index.

    This function is idempotent: calling it twice on the same list always
    produces the same result and the same timelinePosition values.

    Parameters
    ----------
    events : list of TimelineEvent objects (not mutated).

    Returns
    -------
    New List[TimelineEvent] with corrected timelinePosition values.

    Complexity: O(n log n)
    """
    if not events:
        return []

    # Sort by sort key (timelinePosition used as tertiary tiebreaker)
    ordered = sorted(events, key=_sort_key)

    # Rebuild with correct monotonic timelinePosition
    result: List[TimelineEvent] = []
    for pos, ev in enumerate(ordered):
        data = ev.dict()
        data["timelinePosition"] = pos
        result.append(TimelineEvent(**data))
    return result


# ---------------------------------------------------------------------------
# Statistics builder
# ---------------------------------------------------------------------------

def build_timeline_statistics(events: Sequence[TimelineEvent]) -> TimelineStatistics:
    """
    Compute TimelineStatistics from a sequence of TimelineEvents.

    Parameters
    ----------
    events : sequence of TimelineEvent objects.

    Returns
    -------
    TimelineStatistics (frozen / immutable).

    Complexity: O(n)
    """
    if not events:
        return TimelineStatistics()

    by_type: Dict[str, int]     = defaultdict(int)
    by_sev:  Dict[str, int]     = defaultdict(int)
    by_src:  Dict[str, int]     = defaultdict(int)

    timestamps = [ev.occurredAt for ev in events if ev.occurredAt is not None]

    for ev in events:
        by_type[ev.eventType.value]   += 1
        by_sev[ev.severity.value]     += 1
        by_src[ev.sourceType.value]   += 1

    first = min(timestamps) if timestamps else None
    last  = max(timestamps) if timestamps else None
    duration = (last - first).total_seconds() if first and last else 0.0

    return TimelineStatistics(
        firstSeen        = first,
        lastSeen         = last,
        totalEvents      = len(events),
        eventsByType     = dict(by_type),
        eventsBySeverity = dict(by_sev),
        eventsBySource   = dict(by_src),
        durationSeconds  = round(duration, 3),
    )


# ---------------------------------------------------------------------------
# Main entry point: build_timeline()
# ---------------------------------------------------------------------------

def build_timeline(
    *,
    evidence             : Optional[Sequence[Any]] = None,
    relationships        : Optional[Sequence[Any]] = None,
    history_events       : Optional[Sequence[Any]] = None,
    relationship_history : Optional[Sequence[Any]] = None,
    attack_chains        : Optional[Sequence[Any]] = None,
    attack_patterns      : Optional[Sequence[Any]] = None,
    blast_radii          : Optional[Sequence[Any]] = None,
    intel_findings       : Optional[Sequence[Any]] = None,
    alerts               : Optional[Sequence[Any]] = None,
    findings             : Optional[Sequence[Any]] = None,
    mitre                : Optional[Sequence[Any]] = None,
) -> TimelineBundle:
    """
    Build a complete, deterministic TimelineBundle from any combination of
    forensic objects.

    Pipeline
    --------
    1. build_evidence_events()           → EVIDENCE_ADDED events
    2. build_relationship_events()       → RELATIONSHIP_CREATED / _UPDATED events
    3. build_history_events()            → HISTORY_CREATED events
    4. build_relationship_history_events() → RELATIONSHIP_CREATED / _UPDATED events
    5. build_attack_events()             → ATTACK_CHAIN / ATTACK_PATTERN /
                                           BLAST_RADIUS / LATERAL_MOVEMENT /
                                           PIVOT / CHOKE_POINT / FINDING_CREATED
    6. build_alert_events()              → ALERT_GENERATED events
    7. build_finding_events()            → FINDING_CREATED events
    8. build_mitre_events()              → MITRE_MAPPED events
    9. Merge all events, deduplicate by eventKey
    10. sort_timeline()                  → assign timelinePosition
    11. build_timeline_statistics()
    12. _timeline_fingerprint()
    13. Assemble TimelineExplanation + TimelineBundle

    All inputs are optional — missing collections behave as empty lists.

    Parameters
    ----------
    evidence             : EvidenceRecord objects or dicts.
    relationships        : Relationship objects or dicts.
    history_events       : HistoryEvent objects or dicts.
    relationship_history : RelationshipHistoryEvent objects or dicts.
    attack_chains        : AttackChain objects or dicts.
    attack_patterns      : AttackPattern objects or dicts.
    blast_radii          : BlastRadius objects or dicts.
    intel_findings       : IntelligenceFinding objects or dicts.
    alerts               : alert dicts.
    findings             : finding dicts.
    mitre                : technique dicts.

    Returns
    -------
    TimelineBundle (frozen / immutable).

    Complexity: O(n + m) where n = events, m = edges (linear in input size).
    """
    t0 = _now_ms()
    stages:           List[str] = []
    algorithms_used:  List[str] = []
    reasoning_steps:  List[str] = []

    # ── Stage 1: Collect events from all sources ───────────────────────────
    all_raw: List[TimelineEvent] = []

    stages.append("Build evidence events")
    algorithms_used.append("build_evidence_events")
    ev_evts = build_evidence_events(list(evidence or []))
    all_raw.extend(ev_evts)
    reasoning_steps.append(f"Built {len(ev_evts)} evidence event(s).")

    stages.append("Build relationship events")
    algorithms_used.append("build_relationship_events")
    rel_evts = build_relationship_events(list(relationships or []))
    all_raw.extend(rel_evts)
    reasoning_steps.append(f"Built {len(rel_evts)} relationship event(s).")

    stages.append("Build history events")
    algorithms_used.append("build_history_events")
    h_evts = build_history_events(list(history_events or []))
    all_raw.extend(h_evts)
    reasoning_steps.append(f"Built {len(h_evts)} history event(s).")

    stages.append("Build relationship history events")
    algorithms_used.append("build_relationship_history_events")
    rh_evts = build_relationship_history_events(list(relationship_history or []))
    all_raw.extend(rh_evts)
    reasoning_steps.append(f"Built {len(rh_evts)} relationship history event(s).")

    stages.append("Build attack events")
    algorithms_used.append("build_attack_events")
    atk_evts = build_attack_events(
        attack_chains   = list(attack_chains   or []),
        attack_patterns = list(attack_patterns or []),
        blast_radii     = list(blast_radii     or []),
        intel_findings  = list(intel_findings  or []),
    )
    all_raw.extend(atk_evts)
    reasoning_steps.append(f"Built {len(atk_evts)} attack intelligence event(s).")

    stages.append("Build alert events")
    algorithms_used.append("build_alert_events")
    a_evts = build_alert_events(list(alerts or []))
    all_raw.extend(a_evts)
    reasoning_steps.append(f"Built {len(a_evts)} alert event(s).")

    stages.append("Build finding events")
    algorithms_used.append("build_finding_events")
    f_evts = build_finding_events(list(findings or []))
    all_raw.extend(f_evts)
    reasoning_steps.append(f"Built {len(f_evts)} finding event(s).")

    stages.append("Build MITRE events")
    algorithms_used.append("build_mitre_events")
    m_evts = build_mitre_events(list(mitre or []))
    all_raw.extend(m_evts)
    reasoning_steps.append(f"Built {len(m_evts)} MITRE event(s).")

    # ── Stage 2: Deduplicate by eventKey ──────────────────────────────────
    stages.append("Deduplicate by eventKey")
    seen_keys: Dict[str, TimelineEvent] = {}
    for ev in all_raw:
        if ev.eventKey not in seen_keys:
            seen_keys[ev.eventKey] = ev
    unique_events = list(seen_keys.values())
    reasoning_steps.append(
        f"Deduplicated {len(all_raw)} → {len(unique_events)} unique event(s)."
    )

    # ── Stage 3: Sort and assign timelinePosition ─────────────────────────
    stages.append("Sort timeline and assign timelinePosition")
    algorithms_used.append("sort_timeline")
    sorted_events = sort_timeline(unique_events)
    reasoning_steps.append(
        f"Sorted {len(sorted_events)} event(s); "
        f"timelinePosition 0–{len(sorted_events)-1} assigned."
    )

    # ── Stage 4: Statistics ───────────────────────────────────────────────
    stages.append("Compute timeline statistics")
    algorithms_used.append("build_timeline_statistics")
    statistics = build_timeline_statistics(sorted_events)
    reasoning_steps.append(
        f"Statistics: firstSeen={statistics.firstSeen}, "
        f"lastSeen={statistics.lastSeen}, "
        f"totalEvents={statistics.totalEvents}."
    )

    # ── Stage 5: Fingerprint ──────────────────────────────────────────────
    stages.append("Compute timeline fingerprint (SHA-256)")
    algorithms_used.append("_timeline_fingerprint")
    fp = _timeline_fingerprint([ev.eventKey for ev in sorted_events])
    reasoning_steps.append(f"Timeline fingerprint: {fp}.")

    t1 = _now_ms()

    explanation = TimelineExplanation(
        reasoningSteps   = reasoning_steps,
        algorithmsUsed   = list(dict.fromkeys(algorithms_used)),
        processingStages = stages,
        processingTimeMs = t1 - t0,
    )

    return TimelineBundle(
        events              = sorted_events,
        statistics          = statistics,
        explanation         = explanation,
        timelineFingerprint = fp,
        engineVersion       = TIMELINE_INTELLIGENCE_ENGINE_VERSION,
        createdAt           = datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Utility: filter_timeline()
# ---------------------------------------------------------------------------

def filter_timeline(
    events      : Sequence[TimelineEvent],
    *,
    event_type  : Optional[TimelineEventType]  = None,
    source_type : Optional[TimelineSourceType] = None,
    severity    : Optional[TimelineSeverity]   = None,
    asset_id    : Optional[str]                = None,
    capture_id  : Optional[str]                = None,
    from_dt     : Optional[datetime]           = None,
    to_dt       : Optional[datetime]           = None,
    min_confidence : Optional[int]             = None,
) -> List[TimelineEvent]:
    """
    Return a filtered subset of TimelineEvents.

    All filter parameters are optional; AND semantics (all must match).
    The result is re-sorted by the canonical sort order.

    Parameters
    ----------
    events         : source sequence.
    event_type     : keep only events of this type.
    source_type    : keep only events from this source domain.
    severity       : keep only events with this severity.
    asset_id       : keep only events for this asset.
    capture_id     : keep only events from this capture.
    from_dt        : keep only events where occurredAt >= from_dt.
    to_dt          : keep only events where occurredAt <= to_dt.
    min_confidence : keep only events with confidence >= min_confidence.

    Returns
    -------
    List[TimelineEvent] — sorted, timelinePosition NOT reassigned.

    Complexity: O(n log n)
    """
    result: List[TimelineEvent] = []
    for ev in events:
        if event_type  is not None and ev.eventType  != event_type:
            continue
        if source_type is not None and ev.sourceType != source_type:
            continue
        if severity    is not None and ev.severity   != severity:
            continue
        if asset_id    is not None and ev.assetId    != asset_id:
            continue
        if capture_id  is not None and ev.captureId  != capture_id:
            continue
        if from_dt     is not None and ev.occurredAt is not None and ev.occurredAt < from_dt:
            continue
        if to_dt       is not None and ev.occurredAt is not None and ev.occurredAt > to_dt:
            continue
        if min_confidence is not None and ev.confidence < min_confidence:
            continue
        result.append(ev)
    return sorted(result, key=_sort_key)


# ---------------------------------------------------------------------------
# Utility: group_timeline()
# ---------------------------------------------------------------------------

def group_timeline(
    events   : Sequence[TimelineEvent],
    group_by : str = "eventType",
) -> Dict[str, List[TimelineEvent]]:
    """
    Group TimelineEvents by a string attribute.

    Parameters
    ----------
    events   : sequence of events.
    group_by : attribute name on TimelineEvent.
               Common choices: "eventType", "sourceType", "severity",
               "assetId", "captureId".
               Unknown attributes fall back to key "unknown".

    Returns
    -------
    Dict[str, List[TimelineEvent]] — each group sorted chronologically.

    Complexity: O(n log n)
    """
    groups: Dict[str, List[TimelineEvent]] = defaultdict(list)
    for ev in events:
        raw = getattr(ev, group_by, None)
        key = (
            raw.value
            if isinstance(raw, (TimelineEventType, TimelineSourceType, TimelineSeverity))
            else (str(raw) if raw is not None else "unknown")
        )
        groups[key].append(ev)
    return {k: sorted(v, key=_sort_key) for k, v in groups.items()}


# ---------------------------------------------------------------------------
# Utility: search_timeline()
# ---------------------------------------------------------------------------

def search_timeline(
    events  : Sequence[TimelineEvent],
    query   : str,
    *,
    fields  : Optional[List[str]] = None,
    limit   : Optional[int]       = None,
) -> List[TimelineEvent]:
    """
    Case-insensitive substring search across TimelineEvent text fields.

    Parameters
    ----------
    events : sequence of events to search.
    query  : search string (case-insensitive substring match).
    fields : list of attribute names to search; defaults to
             ["title", "summary", "description", "assetId", "captureId",
              "evidenceId", "mitreTechnique"].
    limit  : maximum number of results to return.

    Returns
    -------
    List[TimelineEvent] — matching events in chronological order.

    Complexity: O(n * F) where F = len(fields)
    """
    if not query:
        return sorted(list(events), key=_sort_key)

    search_fields = fields or [
        "title", "summary", "description",
        "assetId", "captureId", "evidenceId", "mitreTechnique",
    ]
    lc_query = query.lower()
    result: List[TimelineEvent] = []

    for ev in events:
        for field in search_fields:
            val = getattr(ev, field, None)
            if val and lc_query in str(val).lower():
                result.append(ev)
                break

    sorted_result = sorted(result, key=_sort_key)
    return sorted_result[:limit] if limit is not None else sorted_result


# ---------------------------------------------------------------------------
# Utility: timeline_between()
# ---------------------------------------------------------------------------

def timeline_between(
    events   : Sequence[TimelineEvent],
    from_dt  : datetime,
    to_dt    : datetime,
) -> List[TimelineEvent]:
    """
    Return events whose occurredAt falls within [from_dt, to_dt] (inclusive).

    Events with occurredAt=None are excluded.

    Parameters
    ----------
    events  : source sequence.
    from_dt : inclusive lower bound (UTC).
    to_dt   : inclusive upper bound (UTC).

    Returns
    -------
    List[TimelineEvent] — sorted chronologically.

    Complexity: O(n log n)
    """
    result = [
        ev for ev in events
        if ev.occurredAt is not None
        and from_dt <= ev.occurredAt <= to_dt
    ]
    return sorted(result, key=_sort_key)


# ---------------------------------------------------------------------------
# Utility: timeline_for_asset()
# ---------------------------------------------------------------------------

def timeline_for_asset(
    events   : Sequence[TimelineEvent],
    asset_id : str,
) -> List[TimelineEvent]:
    """
    Return all events whose assetId matches asset_id.

    Parameters
    ----------
    events   : source sequence.
    asset_id : exact match on TimelineEvent.assetId.

    Returns
    -------
    List[TimelineEvent] — sorted chronologically.

    Complexity: O(n log n)
    """
    result = [ev for ev in events if ev.assetId == asset_id]
    return sorted(result, key=_sort_key)


# ---------------------------------------------------------------------------
# Utility: timeline_for_capture()
# ---------------------------------------------------------------------------

def timeline_for_capture(
    events     : Sequence[TimelineEvent],
    capture_id : str,
) -> List[TimelineEvent]:
    """
    Return all events whose captureId matches capture_id.

    Parameters
    ----------
    events     : source sequence.
    capture_id : exact match on TimelineEvent.captureId.

    Returns
    -------
    List[TimelineEvent] — sorted chronologically.

    Complexity: O(n log n)
    """
    result = [ev for ev in events if ev.captureId == capture_id]
    return sorted(result, key=_sort_key)


# ---------------------------------------------------------------------------
# Utility: timeline_for_relationship()
# ---------------------------------------------------------------------------

def timeline_for_relationship(
    events          : Sequence[TimelineEvent],
    relationship_id : str,
) -> List[TimelineEvent]:
    """
    Return all events whose relationshipId matches relationship_id.

    Parameters
    ----------
    events          : source sequence.
    relationship_id : exact match on TimelineEvent.relationshipId.

    Returns
    -------
    List[TimelineEvent] — sorted chronologically.

    Complexity: O(n log n)
    """
    result = [ev for ev in events if ev.relationshipId == relationship_id]
    return sorted(result, key=_sort_key)
