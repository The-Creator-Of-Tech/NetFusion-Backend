"""
Enterprise Relationship Engine
================================
Phase A.3.1 — Pure derivation of Asset relationships from packet observations.

Responsibilities
----------------
- Derive directed Relationship objects from EvidenceRecords or raw packet dicts.
- Group, sort, filter, merge, and summarise relationships.
- Produce a RelationshipBundle with statistics.

Design constraints
------------------
- PURE: no database writes, no repository calls, no HTTP, no AI.
- Immutable output: all models are frozen Pydantic objects.
- Deterministic: same inputs always produce the same output.
- No heuristics beyond protocol/packet-count confidence scoring.

Relationship ID generation
--------------------------
Every Relationship uses a UUID v5 derived from:
    sourceAssetId + targetAssetId + relationshipType + protocol + port

Same asset pair + same type + same protocol + same port → same relationshipId.
Safe as a deduplication key downstream (DB, attack graph, AI).

Confidence scoring
------------------
confidence = min(100,
    packet_count_score      (capped at RELATIONSHIP_MAX_PACKET_CONFIDENCE)
  + protocol_bonus          (from RELATIONSHIP_PROTOCOL_BONUS)
  + evidence_bonus          (capped at RELATIONSHIP_MAX_EVIDENCE_BONUS)
)

Dependency graph (no circular imports)
---------------------------------------
  core.constants
  ← services.relationship_service   (this file)
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from core.constants import (
    RELATIONSHIP_CONFIDENCE_PER_PACKET,
    RELATIONSHIP_ENGINE_VERSION,
    RELATIONSHIP_EVIDENCE_BONUS_PER_RECORD,
    RELATIONSHIP_MAX_EVIDENCE_BONUS,
    RELATIONSHIP_MAX_PACKET_CONFIDENCE,
    RELATIONSHIP_PROTOCOL_BONUS,
)


# ---------------------------------------------------------------------------
# Namespace UUID for deterministic relationshipId generation.
# Fixed — never change; changing invalidates all existing IDs.
# ---------------------------------------------------------------------------
_RELATIONSHIP_NS = uuid.UUID("abcdef12-abcd-4abc-8abc-abcdef123456")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RelationshipType(str, Enum):
    """Supported inter-asset relationship types."""
    COMMUNICATED_WITH = "COMMUNICATED_WITH"
    DNS_QUERY         = "DNS_QUERY"
    HTTP_REQUEST      = "HTTP_REQUEST"
    HTTPS_REQUEST     = "HTTPS_REQUEST"
    TLS_SESSION       = "TLS_SESSION"
    ARP               = "ARP"
    DHCP              = "DHCP"
    ICMP              = "ICMP"
    SMB               = "SMB"
    RDP               = "RDP"
    SSH               = "SSH"
    FTP               = "FTP"
    UNKNOWN           = "UNKNOWN"


class Direction(str, Enum):
    """
    Traffic direction relative to the sourceAssetId.

    OUTBOUND      : sourceAssetId initiated the connection to targetAssetId.
    INBOUND       : targetAssetId initiated the connection to sourceAssetId.
    BIDIRECTIONAL : traffic observed in both directions between the two assets.
    UNKNOWN       : direction could not be determined from available data.
    """
    OUTBOUND      = "OUTBOUND"
    INBOUND       = "INBOUND"
    BIDIRECTIONAL = "BIDIRECTIONAL"
    UNKNOWN       = "UNKNOWN"


class RelationshipState(str, Enum):
    """
    Lifecycle state of a Relationship.

    NEW        : first time this relationship has been observed.
    ACTIVE     : relationship is currently ongoing (traffic seen recently).
    INACTIVE   : relationship was observed previously but no recent traffic.
    TERMINATED : relationship explicitly ended (e.g. TCP FIN/RST observed,
                 or the asset went offline).

    State is set by the caller based on temporal context.  The engine itself
    defaults to NEW.  Downstream services (timeline, AI) update state as new
    captures are processed.
    """
    NEW        = "NEW"
    ACTIVE     = "ACTIVE"
    INACTIVE   = "INACTIVE"
    TERMINATED = "TERMINATED"


# ---------------------------------------------------------------------------
# RelationshipSignal — one raw observation that implies a relationship
# ---------------------------------------------------------------------------

class RelationshipSignal(BaseModel):
    """
    A single raw observation that implies a relationship between two assets.

    Callers build these from packet dicts or EvidenceRecords and feed them
    into build_relationships() / build_relationship().

    Fields
    ------
    sourceAssetId    : Asset that initiated / sent traffic.
    targetAssetId    : Asset that received / responded.
    protocol         : observed protocol (e.g. "DNS", "HTTP", "ARP").
    port             : destination port; None for layer-2/ICMP observations.
    direction        : Direction enum — OUTBOUND / INBOUND / BIDIRECTIONAL.
    packetNumber     : frame index within capture file.
    byteCount        : frame length in bytes (frame.len).
    captureId        : CaptureSession.captureId.
    observedAt       : UTC datetime of the packet.
    evidenceIds      : EvidenceRecord IDs already linked to this observation.
    metadata         : arbitrary extension dict.
    """
    sourceAssetId : str
    targetAssetId : str
    protocol      : str                   = "UNKNOWN"
    port          : Optional[int]         = None
    direction     : Direction             = Direction.UNKNOWN
    packetNumber  : Optional[int]         = None
    byteCount     : int                   = 0
    captureId     : Optional[str]         = None
    observedAt    : Optional[datetime]    = None
    evidenceIds   : List[str]             = Field(default_factory=list)
    metadata      : Dict[str, Any]        = Field(default_factory=dict)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Relationship — the canonical derived object
# ---------------------------------------------------------------------------

class Relationship(BaseModel):
    """
    A derived, immutable relationship between two Assets.

    Fields
    ------
    relationshipId   : UUID v5 — deterministic from
                       (sourceAssetId + targetAssetId + relationshipType
                        + protocol + port).
    relationshipKey  : SHA-256[:32] hex — stable natural key that encodes
                       (projectId + sourceAssetId + targetAssetId +
                        relationshipType + protocol + port).
                       Generated once at build time; never recomputed.
                       Used for: fast DB lookup, Redis/cache key,
                       Neo4j property, short AI prompt IDs.
    sourceAssetId    : originating Asset.
    targetAssetId    : destination Asset.
    relationshipType : RelationshipType enum.
    protocol         : normalised uppercase protocol string.
    port             : destination port (None for ICMP/ARP/DHCP etc.).
    direction        : Direction enum — OUTBOUND / INBOUND / BIDIRECTIONAL.
    state            : RelationshipState — NEW / ACTIVE / INACTIVE / TERMINATED.
                       Defaults to NEW; updated by temporal context downstream.
    packetCount      : total packets observed for this relationship.
    byteCount        : total bytes observed.
    firstSeen        : earliest observation timestamp.
    lastSeen         : latest observation timestamp.
    confidence       : 0–100 score derived from packet count, protocol, and
                       number of linked evidence records.
    evidenceIds      : all EvidenceRecord IDs linked to this relationship
                       (insertion order = observation order).
    lastEvidenceId   : evidenceId of the most-recently observed EvidenceRecord
                       for this relationship.  Allows instant jump to the
                       latest evidence → packet without scanning evidenceIds[].
                       None when no evidence has been linked yet.
    metadata         : arbitrary extension dict.
    """
    relationshipId   : str                                     # UUID v5 from (src+tgt+type+proto+port)
    relationshipKey  : str                                     # SHA-256[:32] from (project+src+tgt+type+proto+port)
    sourceAssetId    : str
    targetAssetId    : str
    relationshipType : RelationshipType
    protocol         : str
    port             : Optional[int]         = None
    direction        : Direction             = Direction.UNKNOWN
    state            : RelationshipState     = RelationshipState.NEW
    packetCount      : int                   = 0
    byteCount        : int                   = 0
    firstSeen        : Optional[datetime]    = None
    lastSeen         : Optional[datetime]    = None
    confidence       : int                   = Field(ge=0, le=100, default=0)
    evidenceIds      : List[str]             = Field(default_factory=list)
    lastEvidenceId   : Optional[str]         = None
    metadata         : Dict[str, Any]        = Field(default_factory=dict)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipStatistics
# ---------------------------------------------------------------------------

class RelationshipStatistics(BaseModel):
    """
    Frequency breakdowns computed over a list of Relationships.

    Fields
    ------
    totalRelationships    : total count.
    relationshipsByType   : { RelationshipType.value → count }
    relationshipsByProto  : { protocol → count }
    relationshipsByDir    : { Direction.value → count }
    topPairs              : top-10 (sourceAssetId, targetAssetId) pairs by
                            packetCount, as list of dicts.
    """
    totalRelationships   : int                = 0
    relationshipsByType  : Dict[str, int]     = Field(default_factory=dict)
    relationshipsByProto : Dict[str, int]     = Field(default_factory=dict)
    relationshipsByDir   : Dict[str, int]     = Field(default_factory=dict)
    topPairs             : List[Dict[str, Any]] = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipBundle
# ---------------------------------------------------------------------------

class RelationshipBundle(BaseModel):
    """
    Complete relationship output for one asset or capture scope.

    Fields
    ------
    relationships : list of Relationship objects.
    statistics    : RelationshipStatistics over all relationships.
    engineVersion : RELATIONSHIP_ENGINE_VERSION at construction time.
    createdAt     : UTC datetime this bundle was built.
    """
    relationships : List[Relationship]    = Field(default_factory=list)
    statistics    : RelationshipStatistics = Field(
                        default_factory=RelationshipStatistics
                    )
    engineVersion : str                   = RELATIONSHIP_ENGINE_VERSION
    createdAt     : datetime              = Field(
                        default_factory=lambda: datetime.now(timezone.utc)
                    )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_relationship_id(
    source_asset_id    : str,
    target_asset_id    : str,
    relationship_type  : RelationshipType,
    protocol           : str,
    port               : Optional[int],
) -> str:
    """
    Derive a deterministic UUID v5 for a Relationship.

    Input: "<src>|<tgt>|<type>|<proto>|<port>"
    Same combination always produces the same ID.
    """
    port_str = str(port) if port is not None else ""
    name     = "|".join([
        source_asset_id,
        target_asset_id,
        relationship_type.value,
        protocol.upper().strip(),
        port_str,
    ])
    return str(uuid.uuid5(_RELATIONSHIP_NS, name))


def compute_relationship_key(
    project_id         : str,
    source_asset_id    : str,
    target_asset_id    : str,
    relationship_type  : "RelationshipType | str",
    protocol           : str,
    port               : Optional[int],
) -> str:
    """
    Compute a short, stable SHA-256 hex key for a Relationship.

    The key encodes the full natural key:
        projectId + sourceAssetId + targetAssetId +
        relationshipType + protocol + port

    Format: first 32 hex chars of SHA-256 (128 bits — collision-safe for
    enterprise scale, short enough for AI prompts, Redis keys, Neo4j props).

    Benefits
    --------
    - Faster DB lookup — single indexed column vs 6-column composite query.
    - Cache key — Redis / memcached without escaping.
    - AI prompts — short opaque ID that the model can reference by value.
    - Neo4j migration — natural property key for relationship nodes.
    - Generated once at engine time; never recomputed downstream.

    Parameters
    ----------
    project_id        : project scope.
    source_asset_id   : originating Asset.id.
    target_asset_id   : receiving Asset.id.
    relationship_type : RelationshipType enum or its .value string.
    protocol          : normalised uppercase protocol (e.g. "DNS").
    port              : destination port; None for ICMP/ARP/DHCP.

    Returns
    -------
    str — 32-character lowercase hex string (first 128 bits of SHA-256).
    """
    rtype_str = (
        relationship_type.value
        if hasattr(relationship_type, "value")
        else str(relationship_type)
    )
    port_str = str(port) if port is not None else ""
    raw = "|".join([
        project_id.strip(),
        source_asset_id.strip(),
        target_asset_id.strip(),
        rtype_str.strip().upper(),
        protocol.strip().upper(),
        port_str,
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _infer_relationship_type(protocol: str) -> RelationshipType:
    """Map a normalised protocol string to the closest RelationshipType."""
    _MAP: Dict[str, RelationshipType] = {
        "DNS"    : RelationshipType.DNS_QUERY,
        "MDNS"   : RelationshipType.DNS_QUERY,
        "LLMNR"  : RelationshipType.DNS_QUERY,
        "HTTP"   : RelationshipType.HTTP_REQUEST,
        "HTTPS"  : RelationshipType.HTTPS_REQUEST,
        "TLS"    : RelationshipType.TLS_SESSION,
        "SSL"    : RelationshipType.TLS_SESSION,
        "ARP"    : RelationshipType.ARP,
        "DHCP"   : RelationshipType.DHCP,
        "BOOTP"  : RelationshipType.DHCP,
        "ICMP"   : RelationshipType.ICMP,
        "ICMPV6" : RelationshipType.ICMP,
        "SMB"    : RelationshipType.SMB,
        "SMB2"   : RelationshipType.SMB,
        "RDP"    : RelationshipType.RDP,
        "SSH"    : RelationshipType.SSH,
        "FTP"    : RelationshipType.FTP,
        "FTP-DATA": RelationshipType.FTP,
    }
    return _MAP.get(protocol.upper().strip(), RelationshipType.COMMUNICATED_WITH)


def _merge_direction(a: Direction, b: Direction) -> Direction:
    """
    Combine two Direction values when merging signals for the same pair.

    Rules:
    - Same direction twice → keep that direction.
    - OUTBOUND + INBOUND (or reverse) → BIDIRECTIONAL.
    - Either is BIDIRECTIONAL → BIDIRECTIONAL.
    - Any UNKNOWN → keep the known side if only one is UNKNOWN.
    - Both UNKNOWN → UNKNOWN.
    """
    if a == b:
        return a
    if Direction.BIDIRECTIONAL in (a, b):
        return Direction.BIDIRECTIONAL
    if {a, b} == {Direction.OUTBOUND, Direction.INBOUND}:
        return Direction.BIDIRECTIONAL
    # One is UNKNOWN — return the known one
    if a == Direction.UNKNOWN:
        return b
    if b == Direction.UNKNOWN:
        return a
    return Direction.BIDIRECTIONAL


def _compute_confidence(
    packet_count  : int,
    protocol      : str,
    evidence_count: int,
) -> int:
    """
    Derive a 0–100 confidence score for a Relationship.

    Score = packet_score + protocol_bonus + evidence_bonus
    """
    pkt_score = min(
        packet_count * RELATIONSHIP_CONFIDENCE_PER_PACKET,
        RELATIONSHIP_MAX_PACKET_CONFIDENCE,
    )
    proto_bonus = RELATIONSHIP_PROTOCOL_BONUS.get(protocol.upper().strip(), 0)
    ev_bonus = min(
        evidence_count * RELATIONSHIP_EVIDENCE_BONUS_PER_RECORD,
        RELATIONSHIP_MAX_EVIDENCE_BONUS,
    )
    return min(100, pkt_score + proto_bonus + ev_bonus)


# ---------------------------------------------------------------------------
# Builder: build_relationship()
# ---------------------------------------------------------------------------

def build_relationship(
    source_asset_id    : str,
    target_asset_id    : str,
    protocol           : str                        = "UNKNOWN",
    port               : Optional[int]              = None,
    direction          : Direction                  = Direction.UNKNOWN,
    state              : RelationshipState          = RelationshipState.NEW,
    relationship_type  : Optional[RelationshipType] = None,
    project_id         : str                        = "",
    packet_count       : int                        = 1,
    byte_count         : int                        = 0,
    first_seen         : Optional[datetime]         = None,
    last_seen          : Optional[datetime]         = None,
    evidence_ids       : Optional[List[str]]        = None,
    last_evidence_id   : Optional[str]              = None,
    extra_meta         : Optional[Dict[str, Any]]   = None,
) -> Relationship:
    """
    Build a single Relationship from raw parameters.

    Parameters
    ----------
    source_asset_id   : Asset that originated the traffic.
    target_asset_id   : Asset that received the traffic.
    protocol          : observed protocol; normalised to uppercase.
    port              : destination port (None for ICMP/ARP/DHCP).
    direction         : Direction enum value.
    state             : RelationshipState — lifecycle state; defaults to NEW.
    relationship_type : explicit override; inferred from protocol if None.
    packet_count      : number of packets observed for this relationship.
    byte_count        : total bytes observed.
    first_seen        : earliest timestamp.
    last_seen         : latest timestamp.
    evidence_ids      : linked EvidenceRecord IDs (insertion order preserved).
    last_evidence_id  : evidenceId of the most-recently observed evidence.
                        If None and evidence_ids is non-empty, the last
                        element of evidence_ids is used automatically.
    extra_meta        : optional metadata dict.

    Returns
    -------
    Relationship (frozen / immutable)
    """
    norm_proto = protocol.upper().strip() if protocol else "UNKNOWN"
    rtype      = relationship_type or _infer_relationship_type(norm_proto)
    ev_ids     = list(dict.fromkeys(evidence_ids)) if evidence_ids else []

    # Derive lastEvidenceId: explicit arg wins; fall back to last in list.
    resolved_last_ev = last_evidence_id or (ev_ids[-1] if ev_ids else None)

    rel_id  = _make_relationship_id(
        source_asset_id, target_asset_id, rtype, norm_proto, port
    )
    rel_key = compute_relationship_key(
        project_id, source_asset_id, target_asset_id, rtype, norm_proto, port
    )

    confidence = _compute_confidence(packet_count, norm_proto, len(ev_ids))

    return Relationship(
        relationshipId   = rel_id,
        relationshipKey  = rel_key,
        sourceAssetId    = source_asset_id,
        targetAssetId    = target_asset_id,
        relationshipType = rtype,
        protocol         = norm_proto,
        port             = port,
        direction        = direction,
        state            = state,
        packetCount      = packet_count,
        byteCount        = byte_count,
        firstSeen        = first_seen,
        lastSeen         = last_seen,
        confidence       = confidence,
        evidenceIds      = ev_ids,
        lastEvidenceId   = resolved_last_ev,
        metadata         = dict(extra_meta) if extra_meta else {},
    )


# ---------------------------------------------------------------------------
# Builder: build_relationships()
# ---------------------------------------------------------------------------

def build_relationships(
    signals    : Sequence[RelationshipSignal],
    project_id : str = "",
) -> List[Relationship]:
    """
    Derive a deduplicated list of Relationships from a sequence of
    RelationshipSignals.

    Merging logic
    -------------
    Signals that share the same (sourceAssetId, targetAssetId,
    relationshipType, protocol, port) key are merged into one Relationship:
      - packetCount and byteCount are summed.
      - firstSeen / lastSeen are min/max of all signal timestamps.
      - direction is resolved via _merge_direction().
      - evidenceIds are union-deduplicated (insertion order preserved).

    Parameters
    ----------
    signals : any sequence of RelationshipSignal objects.

    Returns
    -------
    List[Relationship] sorted by confidence descending, then by firstSeen.
    """
    if not signals:
        return []

    # Accumulator keyed on the relationship ID tuple.
    # Value: mutable working dict that we collapse into a Relationship at end.
    accum: Dict[str, Dict[str, Any]] = {}

    for sig in signals:
        norm_proto = sig.protocol.upper().strip() if sig.protocol else "UNKNOWN"
        rtype      = _infer_relationship_type(norm_proto)
        rel_id     = _make_relationship_id(
            sig.sourceAssetId, sig.targetAssetId, rtype, norm_proto, sig.port
        )
        rel_key    = compute_relationship_key(
            project_id,
            sig.sourceAssetId, sig.targetAssetId, rtype, norm_proto, sig.port
        )

        if rel_id not in accum:
            accum[rel_id] = {
                "relationshipId"   : rel_id,
                "relationshipKey"  : rel_key,
                "sourceAssetId"    : sig.sourceAssetId,
                "targetAssetId"    : sig.targetAssetId,
                "relationshipType" : rtype,
                "protocol"         : norm_proto,
                "port"             : sig.port,
                "direction"        : sig.direction,
                "state"            : RelationshipState.NEW,
                "packetCount"      : 0,
                "byteCount"        : 0,
                "firstSeen"        : None,
                "lastSeen"         : None,
                "evidenceIds"      : [],
                "lastEvidenceId"   : None,
                "metadata"         : dict(sig.metadata),
            }

        entry = accum[rel_id]
        entry["packetCount"] += 1
        entry["byteCount"]   += sig.byteCount
        entry["direction"]    = _merge_direction(entry["direction"], sig.direction)

        # Timestamp min/max
        if sig.observedAt is not None:
            if entry["firstSeen"] is None or sig.observedAt < entry["firstSeen"]:
                entry["firstSeen"] = sig.observedAt
            if entry["lastSeen"] is None or sig.observedAt > entry["lastSeen"]:
                entry["lastSeen"] = sig.observedAt

        # Evidence IDs — preserve insertion order, no duplicates
        seen_ev: set = set(entry["evidenceIds"])
        for eid in sig.evidenceIds:
            if eid not in seen_ev:
                entry["evidenceIds"].append(eid)
                seen_ev.add(eid)
        # lastEvidenceId = last evidence appended (most recent observation)
        if entry["evidenceIds"]:
            entry["lastEvidenceId"] = entry["evidenceIds"][-1]

    # Collapse accumulators into frozen Relationship objects
    result: List[Relationship] = []
    for entry in accum.values():
        confidence = _compute_confidence(
            entry["packetCount"],
            entry["protocol"],
            len(entry["evidenceIds"]),
        )
        result.append(Relationship(
            relationshipId   = entry["relationshipId"],
            relationshipKey  = entry["relationshipKey"],
            sourceAssetId    = entry["sourceAssetId"],
            targetAssetId    = entry["targetAssetId"],
            relationshipType = entry["relationshipType"],
            protocol         = entry["protocol"],
            port             = entry["port"],
            direction        = entry["direction"],
            state            = entry["state"],
            packetCount      = entry["packetCount"],
            byteCount        = entry["byteCount"],
            firstSeen        = entry["firstSeen"],
            lastSeen         = entry["lastSeen"],
            confidence       = confidence,
            evidenceIds      = list(entry["evidenceIds"]),
            lastEvidenceId   = entry["lastEvidenceId"],
            metadata         = entry["metadata"],
        ))

    return sort_relationships(result)


# ---------------------------------------------------------------------------
# Builder: build_asset_relationships()
# ---------------------------------------------------------------------------

def build_asset_relationships(
    asset_id   : str,
    signals    : Sequence[RelationshipSignal],
    project_id : str = "",
) -> RelationshipBundle:
    """
    Build a RelationshipBundle scoped to one Asset.

    Filters signals where sourceAssetId OR targetAssetId equals asset_id,
    then delegates to build_relationships().

    Parameters
    ----------
    asset_id   : Asset primary key to scope the result.
    signals    : full list of RelationshipSignals (may include other assets).
    project_id : project scope — forwarded to build_relationships() so that
                 each Relationship receives a correct relationshipKey.

    Returns
    -------
    RelationshipBundle (frozen / immutable)
    """
    scoped = [
        s for s in signals
        if s.sourceAssetId == asset_id or s.targetAssetId == asset_id
    ]
    rels = build_relationships(scoped, project_id=project_id)
    return _assemble_bundle(rels)


# ---------------------------------------------------------------------------
# Builder: build_capture_relationships()
# ---------------------------------------------------------------------------

def build_capture_relationships(
    capture_id : str,
    signals    : Sequence[RelationshipSignal],
    project_id : str = "",
) -> RelationshipBundle:
    """
    Build a RelationshipBundle scoped to one CaptureSession.

    Filters signals where captureId == capture_id.

    Parameters
    ----------
    capture_id : CaptureSession.captureId to scope the result.
    signals    : full list of RelationshipSignals.
    project_id : project scope — forwarded so relationshipKey is correct.

    Returns
    -------
    RelationshipBundle (frozen / immutable)
    """
    scoped = [s for s in signals if s.captureId == capture_id]
    rels   = build_relationships(scoped, project_id=project_id)
    return _assemble_bundle(rels)


# ---------------------------------------------------------------------------
# Builder: build_relationship_statistics()
# ---------------------------------------------------------------------------

def build_relationship_statistics(
    relationships: Sequence[Relationship],
) -> RelationshipStatistics:
    """
    Compute RelationshipStatistics from a sequence of Relationships.

    Parameters
    ----------
    relationships : any sequence of Relationship objects.

    Returns
    -------
    RelationshipStatistics (frozen / immutable)
    """
    if not relationships:
        return RelationshipStatistics()

    by_type  : Dict[str, int] = defaultdict(int)
    by_proto : Dict[str, int] = defaultdict(int)
    by_dir   : Dict[str, int] = defaultdict(int)

    # For top-pairs: key = (src, tgt), value = total packetCount
    pair_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    for rel in relationships:
        by_type[rel.relationshipType.value] += 1
        by_proto[rel.protocol]              += 1
        by_dir[rel.direction.value]         += 1
        pair_counts[(rel.sourceAssetId, rel.targetAssetId)] += rel.packetCount

    # Top-10 pairs by packet count
    top_pairs = [
        {"sourceAssetId": src, "targetAssetId": tgt, "packetCount": cnt}
        for (src, tgt), cnt in sorted(
            pair_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
    ]

    return RelationshipStatistics(
        totalRelationships   = len(relationships),
        relationshipsByType  = dict(by_type),
        relationshipsByProto = dict(by_proto),
        relationshipsByDir   = dict(by_dir),
        topPairs             = top_pairs,
    )


# ---------------------------------------------------------------------------
# Internal: _assemble_bundle()
# ---------------------------------------------------------------------------

def _assemble_bundle(relationships: List[Relationship]) -> RelationshipBundle:
    """Combine relationships and statistics into a RelationshipBundle."""
    stats = build_relationship_statistics(relationships)
    return RelationshipBundle(
        relationships = relationships,
        statistics    = stats,
        engineVersion = RELATIONSHIP_ENGINE_VERSION,
        createdAt     = datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Utility: sort_relationships()
# ---------------------------------------------------------------------------

def sort_relationships(
    relationships : List[Relationship],
    by            : str  = "confidence",
    descending    : bool = True,
) -> List[Relationship]:
    """
    Return a new sorted list of Relationships.

    Parameters
    ----------
    relationships : list to sort (not mutated).
    by            : sort key — "confidence", "packetCount", "firstSeen",
                    "lastSeen", "protocol", "relationshipType".
                    Unknown keys fall back to "confidence".
    descending    : True = highest first (default).

    Returns
    -------
    New sorted List[Relationship]
    """
    _epoch = datetime.min.replace(tzinfo=timezone.utc)

    key_fns: Dict[str, Any] = {
        "confidence"       : lambda r: r.confidence,
        "packetCount"      : lambda r: r.packetCount,
        "byteCount"        : lambda r: r.byteCount,
        "firstSeen"        : lambda r: r.firstSeen or _epoch,
        "lastSeen"         : lambda r: r.lastSeen  or _epoch,
        "protocol"         : lambda r: r.protocol,
        "relationshipType" : lambda r: r.relationshipType.value,
    }
    fn = key_fns.get(by, key_fns["confidence"])
    return sorted(relationships, key=fn, reverse=descending)


# ---------------------------------------------------------------------------
# Utility: group_relationships()
# ---------------------------------------------------------------------------

def group_relationships(
    relationships : Sequence[Relationship],
    group_by      : str = "relationshipType",
) -> Dict[str, List[Relationship]]:
    """
    Group Relationships by a string attribute.

    Parameters
    ----------
    relationships : sequence of Relationship objects.
    group_by      : attribute name — "relationshipType", "protocol",
                    "direction", "sourceAssetId", "targetAssetId".
                    Unknown attributes fall back to "unknown".

    Returns
    -------
    Dict[str, List[Relationship]] — each group sorted by confidence desc.
    """
    groups: Dict[str, List[Relationship]] = defaultdict(list)

    for rel in relationships:
        raw = getattr(rel, group_by, None)
        if isinstance(raw, (RelationshipType, Direction)):
            key = raw.value
        elif raw is not None:
            key = str(raw)
        else:
            key = "unknown"
        groups[key].append(rel)

    return {k: sort_relationships(v) for k, v in groups.items()}


# ---------------------------------------------------------------------------
# Utility: filter_relationships()
# ---------------------------------------------------------------------------

def filter_relationships(
    relationships     : Sequence[Relationship],
    relationship_type : Optional[RelationshipType] = None,
    protocol          : Optional[str]              = None,
    direction         : Optional[Direction]        = None,
    source_asset_id   : Optional[str]              = None,
    target_asset_id   : Optional[str]              = None,
    min_confidence    : Optional[int]              = None,
    min_packet_count  : Optional[int]              = None,
    from_dt           : Optional[datetime]         = None,
    to_dt             : Optional[datetime]         = None,
) -> List[Relationship]:
    """
    Return a filtered subset of Relationships.

    All parameters are optional and additive (AND semantics).

    Parameters
    ----------
    relationships     : source sequence.
    relationship_type : keep only this type.
    protocol          : keep only this protocol (case-insensitive).
    direction         : keep only this direction.
    source_asset_id   : keep only relationships FROM this asset.
    target_asset_id   : keep only relationships TO this asset.
    min_confidence    : keep only relationships with confidence >= this.
    min_packet_count  : keep only relationships with packetCount >= this.
    from_dt           : keep only where firstSeen >= from_dt.
    to_dt             : keep only where lastSeen <= to_dt.

    Returns
    -------
    List[Relationship] sorted by confidence descending.
    """
    result: List[Relationship] = []

    for rel in relationships:
        if relationship_type is not None and rel.relationshipType != relationship_type:
            continue
        if protocol is not None and rel.protocol != protocol.upper().strip():
            continue
        if direction is not None and rel.direction != direction:
            continue
        if source_asset_id is not None and rel.sourceAssetId != source_asset_id:
            continue
        if target_asset_id is not None and rel.targetAssetId != target_asset_id:
            continue
        if min_confidence is not None and rel.confidence < min_confidence:
            continue
        if min_packet_count is not None and rel.packetCount < min_packet_count:
            continue
        if from_dt is not None and rel.firstSeen is not None and rel.firstSeen < from_dt:
            continue
        if to_dt is not None and rel.lastSeen is not None and rel.lastSeen > to_dt:
            continue
        result.append(rel)

    return sort_relationships(result)


# ---------------------------------------------------------------------------
# Utility: merge_relationships()
# ---------------------------------------------------------------------------

def merge_relationships(
    base     : Sequence[Relationship],
    incoming : Sequence[Relationship],
) -> List[Relationship]:
    """
    Merge two lists of Relationships into one deduplicated list.

    Relationships with the same relationshipId are merged:
      - packetCount and byteCount are summed.
      - firstSeen is the minimum of both.
      - lastSeen is the maximum of both.
      - direction is resolved via _merge_direction().
      - evidenceIds are union-deduplicated.
      - metadata is shallow-merged (incoming wins on key conflicts).

    Used when combining relationships from multiple captures or time windows.

    Parameters
    ----------
    base     : existing list of Relationships.
    incoming : new list of Relationships to merge in.

    Returns
    -------
    List[Relationship] sorted by confidence descending.
    """
    # Index base by relationshipId
    index: Dict[str, Dict[str, Any]] = {}

    for rel in base:
        index[rel.relationshipId] = {
            "rel"           : rel,
            "packetCount"   : rel.packetCount,
            "byteCount"     : rel.byteCount,
            "firstSeen"     : rel.firstSeen,
            "lastSeen"      : rel.lastSeen,
            "direction"     : rel.direction,
            "state"         : rel.state,
            "evidenceIds"   : list(rel.evidenceIds),
            "lastEvidenceId": rel.lastEvidenceId,
            "metadata"      : dict(rel.metadata),
        }

    for rel in incoming:
        rid = rel.relationshipId
        if rid not in index:
            index[rid] = {
                "rel"           : rel,
                "packetCount"   : rel.packetCount,
                "byteCount"     : rel.byteCount,
                "firstSeen"     : rel.firstSeen,
                "lastSeen"      : rel.lastSeen,
                "direction"     : rel.direction,
                "state"         : rel.state,
                "evidenceIds"   : list(rel.evidenceIds),
                "lastEvidenceId": rel.lastEvidenceId,
                "metadata"      : dict(rel.metadata),
            }
        else:
            entry             = index[rid]
            entry["packetCount"] += rel.packetCount
            entry["byteCount"]   += rel.byteCount
            entry["direction"]    = _merge_direction(entry["direction"], rel.direction)

            # State: incoming state takes precedence if it carries more info
            # Priority: TERMINATED > INACTIVE > ACTIVE > NEW
            _STATE_PRIORITY = {
                RelationshipState.NEW        : 0,
                RelationshipState.ACTIVE     : 1,
                RelationshipState.INACTIVE   : 2,
                RelationshipState.TERMINATED : 3,
            }
            if _STATE_PRIORITY.get(rel.state, 0) > _STATE_PRIORITY.get(entry["state"], 0):
                entry["state"] = rel.state

            if rel.firstSeen is not None:
                if entry["firstSeen"] is None or rel.firstSeen < entry["firstSeen"]:
                    entry["firstSeen"] = rel.firstSeen
            if rel.lastSeen is not None:
                if entry["lastSeen"] is None or rel.lastSeen > entry["lastSeen"]:
                    entry["lastSeen"] = rel.lastSeen

            seen_ev: set = set(entry["evidenceIds"])
            for eid in rel.evidenceIds:
                if eid not in seen_ev:
                    entry["evidenceIds"].append(eid)
                    seen_ev.add(eid)
            # lastEvidenceId = tail of merged evidence list
            if entry["evidenceIds"]:
                entry["lastEvidenceId"] = entry["evidenceIds"][-1]

            entry["metadata"].update(rel.metadata)

    result: List[Relationship] = []
    for entry in index.values():
        orig = entry["rel"]
        confidence = _compute_confidence(
            entry["packetCount"],
            orig.protocol,
            len(entry["evidenceIds"]),
        )
        result.append(Relationship(
            relationshipId   = orig.relationshipId,
            relationshipKey  = orig.relationshipKey,
            sourceAssetId    = orig.sourceAssetId,
            targetAssetId    = orig.targetAssetId,
            relationshipType = orig.relationshipType,
            protocol         = orig.protocol,
            port             = orig.port,
            direction        = entry["direction"],
            state            = entry["state"],
            packetCount      = entry["packetCount"],
            byteCount        = entry["byteCount"],
            firstSeen        = entry["firstSeen"],
            lastSeen         = entry["lastSeen"],
            confidence       = confidence,
            evidenceIds      = list(entry["evidenceIds"]),
            lastEvidenceId   = entry["lastEvidenceId"],
            metadata         = entry["metadata"],
        ))

    return sort_relationships(result)
