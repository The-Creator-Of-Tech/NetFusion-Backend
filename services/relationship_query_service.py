"""
Relationship Query Layer
=========================
Phase A.3.3 — High-performance querying, filtering, aggregation, and graph
traversal over Relationship objects.

Responsibilities
----------------
- Accept structured RelationshipQuery / RelationshipFilter inputs.
- Apply single-pass filtering, sorting, and pagination.
- Build RelationshipGraph (nodes + edges) with depth-1 and depth-2 traversal.
- Produce aggregation counts (protocols, states, types).
- Emit a QueryExplanation for every result so AI Copilot, Attack Graph,
  Timeline, and Reports never need to re-derive what was applied.

Design constraints
------------------
- PURE: no HTTP, no Prisma, no repositories, no AI calls.
- Immutable output: all models use frozen=True Pydantic config.
- Deterministic: same inputs always produce the same output.
- Single-pass filtering whenever possible — O(n) over the input list.
- No unnecessary copying — reuse existing Relationship objects.
- No circular imports.

Dependency graph (no circular imports)
---------------------------------------
  core.constants
  services.relationship_service   (Relationship, RelationshipState,
                                   RelationshipType, Direction)
  services.relationship_resolution_service   (compute_relationship_fingerprint)
  ← services.relationship_query_service   (this file)
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from core.constants import RELATIONSHIP_ENGINE_VERSION
from services.relationship_service import (
    Direction,
    Relationship,
    RelationshipState,
    RelationshipType,
)
from services.relationship_resolution_service import compute_relationship_fingerprint


# ---------------------------------------------------------------------------
# Engine version
# ---------------------------------------------------------------------------
RELATIONSHIP_QUERY_ENGINE_VERSION: str = "relationship-query-v1"

# Hard cap on returned rows when caller omits limit.
_DEFAULT_LIMIT: int = 500
_MAX_LIMIT:     int = 10_000


# ---------------------------------------------------------------------------
# Supporting value objects
# ---------------------------------------------------------------------------

class ConfidenceRange(BaseModel):
    """Inclusive confidence band [minimum, maximum]."""
    minimum: int = Field(ge=0, le=100, default=0)
    maximum: int = Field(ge=0, le=100, default=100)

    class Config:
        frozen = True


class TimeRange(BaseModel):
    """Inclusive UTC datetime band [start, end]."""
    start: Optional[datetime] = None
    end:   Optional[datetime] = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipFilter
# ---------------------------------------------------------------------------

class RelationshipFilter(BaseModel):
    """
    Declarative filter applied over a Relationship pool.

    All fields are optional and combine with AND semantics.

    Fields
    ------
    protocol         : keep only relationships with this protocol (uppercase).
    relationshipType : keep only this RelationshipType.
    state            : keep only this RelationshipState.
    direction        : keep only this Direction.
    confidenceRange  : keep only relationships whose confidence falls within
                       [minimum, maximum] (inclusive).
    timeRange        : keep only relationships where lastSeen falls within
                       [start, end] (inclusive; None = unbounded).
    assetIds         : keep only relationships where sourceAssetId OR
                       targetAssetId is in this set.
    """
    protocol         : Optional[str]               = None
    relationshipType : Optional[RelationshipType]  = None
    state            : Optional[RelationshipState] = None
    direction        : Optional[Direction]         = None
    confidenceRange  : Optional[ConfidenceRange]   = None
    timeRange        : Optional[TimeRange]         = None
    assetIds         : Optional[List[str]]         = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipSort
# ---------------------------------------------------------------------------

class RelationshipSort(BaseModel):
    """
    Single sort key for a Relationship query.

    Fields
    ------
    field      : Relationship attribute name to sort by.
                 Supported: "confidence", "packetCount", "byteCount",
                 "firstSeen", "lastSeen", "protocol", "relationshipType",
                 "state".  Unknown fields are silently ignored.
    descending : True = highest/latest first (default).
    """
    field      : str  = "confidence"
    descending : bool = True

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipQuery
# ---------------------------------------------------------------------------

class RelationshipQuery(BaseModel):
    """
    Structured query over a Relationship pool.

    Fields
    ------
    assetId          : scope result to relationships involving this asset.
    projectId        : project scope (informational; not used for filtering
                       here because the caller already provides a scoped pool).
    relationshipType : shortcut filter on type (overrides filter.relationshipType
                       when both are present — query-level wins).
    protocol         : shortcut filter on protocol.
    port             : keep only relationships on this port.
    state            : shortcut filter on state.
    direction        : shortcut filter on direction.
    minimumConfidence: shortcut lower bound (overrides filter.confidenceRange
                       when both present).
    maximumConfidence: shortcut upper bound.
    startTime        : shortcut time range start.
    endTime          : shortcut time range end.
    depth            : graph traversal depth (1 = direct neighbors,
                       2 = neighbors-of-neighbors).  Clamped to [1, 2].
    limit            : max relationships to return (capped at _MAX_LIMIT).
    filter           : optional detailed RelationshipFilter (merged with
                       shortcut fields; shortcut fields take precedence).
    sort             : sort order for results.
    """
    assetId          : Optional[str]               = None
    projectId        : Optional[str]               = None
    relationshipType : Optional[RelationshipType]  = None
    protocol         : Optional[str]               = None
    port             : Optional[int]               = None
    state            : Optional[RelationshipState] = None
    direction        : Optional[Direction]         = None
    minimumConfidence: Optional[int]               = Field(default=None, ge=0, le=100)
    maximumConfidence: Optional[int]               = Field(default=None, ge=0, le=100)
    startTime        : Optional[datetime]          = None
    endTime          : Optional[datetime]          = None
    depth            : int                         = Field(default=1, ge=1, le=2)
    limit            : int                         = Field(default=_DEFAULT_LIMIT, ge=1)
    filter           : Optional[RelationshipFilter] = None
    sort             : Optional[RelationshipSort]  = None

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# QueryExplanation  (Mandatory Recommendation)
# ---------------------------------------------------------------------------

class QueryExplanation(BaseModel):
    """
    Full transparency record for one query execution.

    Future AI Copilot reads this directly — no re-parsing needed.

    Fields
    ------
    filtersApplied   : human-readable list of filters that were active,
                       e.g. ["protocol = DNS", "confidence >= 70",
                             "state = ACTIVE"].
    recordsScanned   : total relationships in the input pool.
    recordsReturned  : relationships in the final result page.
    processingStages : ordered list of stages executed,
                       e.g. ["Normalize Query", "Filter", "Sort",
                             "Pagination", "Graph Build"].
    executionTimeMs  : wall-clock ms for the full query pipeline.
    """
    filtersApplied  : List[str]  = Field(default_factory=list)
    recordsScanned  : int        = 0
    recordsReturned : int        = 0
    processingStages: List[str]  = Field(default_factory=list)
    executionTimeMs : float      = 0.0

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Graph models
# ---------------------------------------------------------------------------

class RelationshipGraphNode(BaseModel):
    """
    One asset vertex in a RelationshipGraph.

    Fields
    ------
    assetId           : Asset primary key.
    deviceName        : human-readable label (hostname / IP / MAC).
    riskScore         : 0–100 risk score (caller-supplied; 0 if unknown).
    relationshipCount : number of edges incident on this node in the graph.
    """
    assetId           : str
    deviceName        : str  = ""
    riskScore         : int  = Field(ge=0, le=100, default=0)
    relationshipCount : int  = 0

    class Config:
        frozen = True


class RelationshipGraphEdge(BaseModel):
    """
    One directed relationship edge in a RelationshipGraph.

    Fields
    ------
    relationshipId          : Relationship.relationshipId.
    relationshipKey         : Relationship.relationshipKey (SHA-256[:32]).
    relationshipFingerprint : compute_relationship_fingerprint() result.
    sourceAssetId           : origin vertex.
    targetAssetId           : destination vertex.
    relationshipType        : RelationshipType enum value string.
    protocol                : normalised protocol string.
    port                    : destination port (None for ICMP/ARP/DHCP).
    confidence              : 0–100 score.
    direction               : Direction enum value string.
    """
    relationshipId          : str
    relationshipKey         : str
    relationshipFingerprint : str
    sourceAssetId           : str
    targetAssetId           : str
    relationshipType        : str
    protocol                : str
    port                    : Optional[int]  = None
    confidence              : int            = Field(ge=0, le=100, default=0)
    direction               : str            = Direction.UNKNOWN.value

    class Config:
        frozen = True


class RelationshipGraph(BaseModel):
    """
    Graph result: nodes (assets) + edges (relationships).

    Nodes and edges are deduplicated — same assetId / relationshipId
    appears at most once regardless of traversal depth.

    Fields
    ------
    nodes : list of RelationshipGraphNode.
    edges : list of RelationshipGraphEdge.
    """
    nodes : List[RelationshipGraphNode] = Field(default_factory=list)
    edges : List[RelationshipGraphEdge] = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# RelationshipQueryResult
# ---------------------------------------------------------------------------

class RelationshipQueryResult(BaseModel):
    """
    Complete output of one RelationshipQuery execution.

    Fields
    ------
    relationships  : filtered, sorted, paginated Relationship list.
    totalCount     : total relationships in the input pool (pre-filter).
    filteredCount  : relationships that survived all filters (pre-pagination).
    graph          : RelationshipGraph built from the result set.
    statistics     : aggregation counts over the result set.
    processingTimeMs: wall-clock ms for the full pipeline.
    engineVersion  : RELATIONSHIP_QUERY_ENGINE_VERSION.
    explanation    : QueryExplanation for AI / reporting consumers.
    """
    relationships   : List[Relationship]          = Field(default_factory=list)
    totalCount      : int                         = 0
    filteredCount   : int                         = 0
    graph           : RelationshipGraph           = Field(
                          default_factory=RelationshipGraph
                      )
    statistics      : Dict[str, Any]              = Field(default_factory=dict)
    processingTimeMs: float                       = 0.0
    engineVersion   : str                         = RELATIONSHIP_QUERY_ENGINE_VERSION
    explanation     : QueryExplanation            = Field(
                          default_factory=QueryExplanation
                      )

    class Config:
        frozen = True


# ===========================================================================
# UTILITY FUNCTIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# normalize_query()
# ---------------------------------------------------------------------------

def normalize_query(query: RelationshipQuery) -> Tuple[RelationshipFilter, RelationshipSort, int, List[str]]:
    """
    Merge query-level shortcut fields with the embedded RelationshipFilter.

    Shortcut fields on RelationshipQuery take precedence over the equivalent
    fields on query.filter when both are set.

    Returns
    -------
    (merged_filter, sort, effective_limit, filters_applied_labels)
    """
    base = query.filter or RelationshipFilter()

    # Shortcut precedence: query-level overrides filter-level.
    protocol  = query.protocol  or base.protocol
    rel_type  = query.relationshipType  or base.relationshipType
    state     = query.state     or base.state
    direction = query.direction or base.direction
    asset_ids = ([query.assetId] if query.assetId else None) or base.assetIds

    # Confidence range — merge shortcut min/max with filter range.
    base_cr = base.confidenceRange or ConfidenceRange()
    conf_min = query.minimumConfidence if query.minimumConfidence is not None else base_cr.minimum
    conf_max = query.maximumConfidence if query.maximumConfidence is not None else base_cr.maximum
    conf_range = ConfidenceRange(minimum=conf_min, maximum=conf_max)

    # Time range — merge shortcut start/end with filter range.
    base_tr = base.timeRange or TimeRange()
    t_start = query.startTime or base_tr.start
    t_end   = query.endTime   or base_tr.end
    time_range = TimeRange(start=t_start, end=t_end) if (t_start or t_end) else None

    # Port — query-level only (no equivalent on RelationshipFilter).
    # Stored in merged filter metadata via assetIds workaround is wrong;
    # port filtering is applied separately in filter_relationships().
    merged_filter = RelationshipFilter(
        protocol         = protocol.upper().strip() if protocol else None,
        relationshipType = rel_type,
        state            = state,
        direction        = direction,
        confidenceRange  = conf_range,
        timeRange        = time_range,
        assetIds         = list(asset_ids) if asset_ids else None,
    )

    sort = query.sort or RelationshipSort()

    effective_limit = min(query.limit, _MAX_LIMIT)

    # Build human-readable filter labels for QueryExplanation.
    labels: List[str] = []
    if merged_filter.protocol:
        labels.append(f"protocol = {merged_filter.protocol}")
    if merged_filter.relationshipType:
        labels.append(f"relationshipType = {merged_filter.relationshipType.value}")
    if merged_filter.state:
        labels.append(f"state = {merged_filter.state.value}")
    if merged_filter.direction:
        labels.append(f"direction = {merged_filter.direction.value}")
    if conf_range.minimum > 0 or conf_range.maximum < 100:
        labels.append(f"confidence ∈ [{conf_range.minimum}, {conf_range.maximum}]")
    if time_range:
        if time_range.start:
            labels.append(f"lastSeen >= {time_range.start.isoformat()}")
        if time_range.end:
            labels.append(f"lastSeen <= {time_range.end.isoformat()}")
    if merged_filter.assetIds:
        labels.append(f"assetIds ∈ {merged_filter.assetIds}")
    if query.port is not None:
        labels.append(f"port = {query.port}")

    return merged_filter, sort, effective_limit, labels


# ---------------------------------------------------------------------------
# filter_relationships()
# ---------------------------------------------------------------------------

def filter_relationships(
    relationships : Sequence[Relationship],
    fltr          : RelationshipFilter,
    port          : Optional[int] = None,
) -> List[Relationship]:
    """
    Single-pass filter over a Relationship pool.

    All active filter predicates must pass (AND semantics).

    Parameters
    ----------
    relationships : source pool (not mutated).
    fltr          : merged RelationshipFilter to apply.
    port          : optional port filter (query-level shortcut, no Filter equiv).

    Returns
    -------
    List[Relationship] — filtered subset (same objects, no copies).
    """
    result: List[Relationship] = []

    proto_filter   = fltr.protocol.upper().strip() if fltr.protocol else None
    asset_set      = set(fltr.assetIds) if fltr.assetIds else None
    conf_min       = fltr.confidenceRange.minimum if fltr.confidenceRange else 0
    conf_max       = fltr.confidenceRange.maximum if fltr.confidenceRange else 100
    tr_start       = fltr.timeRange.start if fltr.timeRange else None
    tr_end         = fltr.timeRange.end   if fltr.timeRange else None

    for rel in relationships:
        # protocol
        if proto_filter and rel.protocol.upper().strip() != proto_filter:
            continue
        # relationshipType
        if fltr.relationshipType and rel.relationshipType != fltr.relationshipType:
            continue
        # state
        if fltr.state and rel.state != fltr.state:
            continue
        # direction
        if fltr.direction and rel.direction != fltr.direction:
            continue
        # confidence range
        if not (conf_min <= rel.confidence <= conf_max):
            continue
        # assetIds
        if asset_set and rel.sourceAssetId not in asset_set and rel.targetAssetId not in asset_set:
            continue
        # port
        if port is not None and rel.port != port:
            continue
        # time range (uses lastSeen)
        if tr_start and rel.lastSeen and rel.lastSeen < tr_start:
            continue
        if tr_end and rel.lastSeen and rel.lastSeen > tr_end:
            continue

        result.append(rel)

    return result


# ---------------------------------------------------------------------------
# sort_relationships()
# ---------------------------------------------------------------------------

_SORT_SENTINEL_DT  = datetime.min
_SORT_SENTINEL_INT = -1

def sort_relationships(
    relationships : List[Relationship],
    sort          : RelationshipSort,
) -> List[Relationship]:
    """
    Sort a Relationship list by a single field.

    Supported fields: confidence, packetCount, byteCount, firstSeen,
    lastSeen, protocol, relationshipType, state.
    Unknown fields are silently ignored (original order preserved).

    Parameters
    ----------
    relationships : list to sort (not mutated).
    sort          : RelationshipSort specifying field and direction.

    Returns
    -------
    New sorted List[Relationship].
    """
    field = sort.field

    def _key(r: Relationship) -> Any:
        if field == "confidence":
            return r.confidence
        if field == "packetCount":
            return r.packetCount
        if field == "byteCount":
            return r.byteCount
        if field == "firstSeen":
            return r.firstSeen or _SORT_SENTINEL_DT
        if field == "lastSeen":
            return r.lastSeen or _SORT_SENTINEL_DT
        if field == "protocol":
            return r.protocol
        if field == "relationshipType":
            return r.relationshipType.value
        if field == "state":
            return r.state.value
        return _SORT_SENTINEL_INT  # unknown field — stable fallback

    return sorted(relationships, key=_key, reverse=sort.descending)


# ---------------------------------------------------------------------------
# paginate_relationships()
# ---------------------------------------------------------------------------

def paginate_relationships(
    relationships : List[Relationship],
    limit         : int,
    offset        : int = 0,
) -> List[Relationship]:
    """
    Return a slice of the relationship list.

    Parameters
    ----------
    relationships : sorted list to paginate (not mutated).
    limit         : max items to return.
    offset        : starting index (default 0).

    Returns
    -------
    List[Relationship] slice.
    """
    return relationships[offset : offset + limit]


# ===========================================================================
# AGGREGATION FUNCTIONS
# ===========================================================================

def count_relationships(relationships: Sequence[Relationship]) -> int:
    """Return total count of relationships."""
    return len(relationships)


def count_protocols(relationships: Sequence[Relationship]) -> Dict[str, int]:
    """
    Return a { protocol → count } mapping over the given relationships.

    Parameters
    ----------
    relationships : any sequence of Relationship objects.

    Returns
    -------
    Dict[str, int] sorted by count descending.
    """
    counts: Dict[str, int] = defaultdict(int)
    for rel in relationships:
        counts[rel.protocol] += 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def count_states(relationships: Sequence[Relationship]) -> Dict[str, int]:
    """
    Return a { RelationshipState.value → count } mapping.

    Parameters
    ----------
    relationships : any sequence of Relationship objects.

    Returns
    -------
    Dict[str, int] sorted by count descending.
    """
    counts: Dict[str, int] = defaultdict(int)
    for rel in relationships:
        counts[rel.state.value] += 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def calculate_graph_statistics(
    relationships: Sequence[Relationship],
) -> Dict[str, Any]:
    """
    Compute aggregated statistics over a Relationship list.

    Returns a dict with:
        totalRelationships    : int
        protocolCounts        : { protocol → count }
        stateCounts           : { state → count }
        typeCounts            : { relationshipType → count }
        directionCounts       : { direction → count }
        avgConfidence         : float
        totalPackets          : int
        totalBytes            : int
        uniqueAssets          : int  (distinct sourceAssetId + targetAssetId)
    """
    if not relationships:
        return {
            "totalRelationships": 0,
            "protocolCounts":     {},
            "stateCounts":        {},
            "typeCounts":         {},
            "directionCounts":    {},
            "avgConfidence":      0.0,
            "totalPackets":       0,
            "totalBytes":         0,
            "uniqueAssets":       0,
        }

    proto_counts: Dict[str, int] = defaultdict(int)
    type_counts:  Dict[str, int] = defaultdict(int)
    dir_counts:   Dict[str, int] = defaultdict(int)
    asset_ids:    set            = set()
    total_conf    = 0
    total_pkts    = 0
    total_bytes   = 0

    for rel in relationships:
        proto_counts[rel.protocol]                 += 1
        type_counts[rel.relationshipType.value]    += 1
        dir_counts[rel.direction.value]            += 1
        asset_ids.add(rel.sourceAssetId)
        asset_ids.add(rel.targetAssetId)
        total_conf  += rel.confidence
        total_pkts  += rel.packetCount
        total_bytes += rel.byteCount

    n = len(relationships)
    return {
        "totalRelationships": n,
        "protocolCounts":     dict(sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)),
        "stateCounts":        count_states(relationships),
        "typeCounts":         dict(sorted(type_counts.items(),  key=lambda x: x[1], reverse=True)),
        "directionCounts":    dict(sorted(dir_counts.items(),   key=lambda x: x[1], reverse=True)),
        "avgConfidence":      round(total_conf / n, 2),
        "totalPackets":       total_pkts,
        "totalBytes":         total_bytes,
        "uniqueAssets":       len(asset_ids),
    }


# ===========================================================================
# GRAPH FUNCTIONS
# ===========================================================================

def _make_edge(rel: Relationship) -> RelationshipGraphEdge:
    """Build a RelationshipGraphEdge from a Relationship (no copies)."""
    return RelationshipGraphEdge(
        relationshipId          = rel.relationshipId,
        relationshipKey         = rel.relationshipKey,
        relationshipFingerprint = compute_relationship_fingerprint(
            rel.sourceAssetId,
            rel.targetAssetId,
            rel.relationshipType,
            rel.protocol,
            rel.port,
        ),
        sourceAssetId    = rel.sourceAssetId,
        targetAssetId    = rel.targetAssetId,
        relationshipType = rel.relationshipType.value,
        protocol         = rel.protocol,
        port             = rel.port,
        confidence       = rel.confidence,
        direction        = rel.direction.value,
    )


def _build_adjacency(
    relationships: Sequence[Relationship],
) -> Dict[str, List[Relationship]]:
    """
    Build { assetId → [Relationship, ...] } adjacency index in O(n).
    Both sourceAssetId and targetAssetId are indexed.
    """
    adj: Dict[str, List[Relationship]] = defaultdict(list)
    for rel in relationships:
        adj[rel.sourceAssetId].append(rel)
        adj[rel.targetAssetId].append(rel)
    return adj


def build_relationship_graph(
    relationships  : Sequence[Relationship],
    asset_labels   : Optional[Dict[str, str]] = None,
    asset_scores   : Optional[Dict[str, int]] = None,
) -> RelationshipGraph:
    """
    Build a RelationshipGraph from a flat list of Relationships.

    Deduplicates nodes and edges.  Every unique assetId becomes a node;
    every Relationship becomes one edge.

    Parameters
    ----------
    relationships : Relationships to include (caller already filtered/paged).
    asset_labels  : optional { assetId → deviceName } map.
    asset_scores  : optional { assetId → riskScore } map.

    Returns
    -------
    RelationshipGraph (frozen / immutable).
    """
    labels = asset_labels or {}
    scores = asset_scores or {}

    seen_assets: Dict[str, int] = defaultdict(int)   # assetId → edge count
    seen_rel_ids: set            = set()
    edges: List[RelationshipGraphEdge] = []

    for rel in relationships:
        if rel.relationshipId in seen_rel_ids:
            continue
        seen_rel_ids.add(rel.relationshipId)
        edges.append(_make_edge(rel))
        seen_assets[rel.sourceAssetId] += 1
        seen_assets[rel.targetAssetId] += 1

    nodes: List[RelationshipGraphNode] = [
        RelationshipGraphNode(
            assetId           = aid,
            deviceName        = labels.get(aid, aid),
            riskScore         = scores.get(aid, 0),
            relationshipCount = cnt,
        )
        for aid, cnt in sorted(seen_assets.items())
    ]

    return RelationshipGraph(nodes=nodes, edges=edges)


# ---------------------------------------------------------------------------
# build_asset_neighbors()
# ---------------------------------------------------------------------------

def build_asset_neighbors(
    asset_id      : str,
    relationships : Sequence[Relationship],
) -> List[str]:
    """
    Return all assetIds that share at least one Relationship with asset_id.

    Parameters
    ----------
    asset_id      : anchor asset.
    relationships : full pool to search (O(n) single pass).

    Returns
    -------
    Sorted list of neighbor assetIds (excludes asset_id itself).
    """
    neighbors: set = set()
    for rel in relationships:
        if rel.sourceAssetId == asset_id:
            neighbors.add(rel.targetAssetId)
        elif rel.targetAssetId == asset_id:
            neighbors.add(rel.sourceAssetId)
    return sorted(neighbors)


# ---------------------------------------------------------------------------
# build_one_hop_graph()
# ---------------------------------------------------------------------------

def build_one_hop_graph(
    asset_id       : str,
    relationships  : Sequence[Relationship],
    asset_labels   : Optional[Dict[str, str]] = None,
    asset_scores   : Optional[Dict[str, int]] = None,
) -> RelationshipGraph:
    """
    Build a depth-1 graph: anchor asset + all its direct neighbors.

    Includes only edges where sourceAssetId OR targetAssetId == asset_id.

    Parameters
    ----------
    asset_id      : anchor asset.
    relationships : full pool (O(n) single pass).
    asset_labels  : optional { assetId → deviceName }.
    asset_scores  : optional { assetId → riskScore }.

    Returns
    -------
    RelationshipGraph (frozen / immutable).
    """
    direct = [
        r for r in relationships
        if r.sourceAssetId == asset_id or r.targetAssetId == asset_id
    ]
    return build_relationship_graph(direct, asset_labels, asset_scores)


# ---------------------------------------------------------------------------
# build_two_hop_graph()
# ---------------------------------------------------------------------------

def build_two_hop_graph(
    asset_id       : str,
    relationships  : Sequence[Relationship],
    asset_labels   : Optional[Dict[str, str]] = None,
    asset_scores   : Optional[Dict[str, int]] = None,
) -> RelationshipGraph:
    """
    Build a depth-2 graph: anchor + direct neighbors + neighbors-of-neighbors.

    Traversal rules:
    - Depth-1 edges: sourceAssetId or targetAssetId == asset_id.
    - Depth-2 edges: sourceAssetId or targetAssetId is a depth-1 neighbor.
    - Nodes and edges are deduplicated — no duplicates regardless of overlap.

    Parameters
    ----------
    asset_id      : anchor asset.
    relationships : full pool; scanned twice (O(2n) worst case).
    asset_labels  : optional { assetId → deviceName }.
    asset_scores  : optional { assetId → riskScore }.

    Returns
    -------
    RelationshipGraph (frozen / immutable).
    """
    # Pass 1 — collect depth-1 neighbors and edges.
    d1_neighbors: set                  = set()
    d1_rel_ids:   set                  = set()
    included_rels: List[Relationship]  = []

    for rel in relationships:
        if rel.sourceAssetId == asset_id or rel.targetAssetId == asset_id:
            if rel.relationshipId not in d1_rel_ids:
                d1_rel_ids.add(rel.relationshipId)
                included_rels.append(rel)
            peer = rel.targetAssetId if rel.sourceAssetId == asset_id else rel.sourceAssetId
            d1_neighbors.add(peer)

    # Pass 2 — collect depth-2 edges (neighbor ↔ neighbor-of-neighbor).
    for rel in relationships:
        if rel.relationshipId in d1_rel_ids:
            continue  # already included
        src_is_d1 = rel.sourceAssetId in d1_neighbors
        tgt_is_d1 = rel.targetAssetId in d1_neighbors
        if src_is_d1 or tgt_is_d1:
            included_rels.append(rel)

    return build_relationship_graph(included_rels, asset_labels, asset_scores)


# ===========================================================================
# QUERY BUILDER FUNCTIONS
# ===========================================================================

def _run_pipeline(
    relationships  : Sequence[Relationship],
    query          : RelationshipQuery,
    asset_labels   : Optional[Dict[str, str]] = None,
    asset_scores   : Optional[Dict[str, int]] = None,
) -> RelationshipQueryResult:
    """
    Internal: full pipeline — normalize → filter → sort → paginate → graph.
    Returns RelationshipQueryResult.
    """
    t_start  = time.monotonic()
    stages   : List[str] = []
    total    = len(relationships)

    # Stage 1 — Normalize
    stages.append("Normalize Query")
    merged_filter, sort, effective_limit, filter_labels = normalize_query(query)

    # Stage 2 — Filter (single pass)
    stages.append("Filter")
    filtered = filter_relationships(relationships, merged_filter, port=query.port)
    filtered_count = len(filtered)

    # Stage 3 — Sort
    stages.append("Sort")
    sorted_rels = sort_relationships(filtered, sort)

    # Stage 4 — Pagination
    stages.append("Pagination")
    page = paginate_relationships(sorted_rels, limit=effective_limit)

    # Stage 5 — Graph Build
    stages.append("Graph Build")
    if query.assetId and query.depth == 2:
        graph = build_two_hop_graph(query.assetId, page, asset_labels, asset_scores)
    elif query.assetId and query.depth == 1:
        graph = build_one_hop_graph(query.assetId, page, asset_labels, asset_scores)
    else:
        graph = build_relationship_graph(page, asset_labels, asset_scores)

    stats = calculate_graph_statistics(page)

    elapsed_ms = round((time.monotonic() - t_start) * 1000.0, 3)

    explanation = QueryExplanation(
        filtersApplied   = filter_labels,
        recordsScanned   = total,
        recordsReturned  = len(page),
        processingStages = stages,
        executionTimeMs  = elapsed_ms,
    )

    return RelationshipQueryResult(
        relationships    = page,
        totalCount       = total,
        filteredCount    = filtered_count,
        graph            = graph,
        statistics       = stats,
        processingTimeMs = elapsed_ms,
        engineVersion    = RELATIONSHIP_QUERY_ENGINE_VERSION,
        explanation      = explanation,
    )


# ---------------------------------------------------------------------------
# query_relationships()  — primary entry point
# ---------------------------------------------------------------------------

def query_relationships(
    relationships  : Sequence[Relationship],
    query          : RelationshipQuery,
    asset_labels   : Optional[Dict[str, str]] = None,
    asset_scores   : Optional[Dict[str, int]] = None,
) -> RelationshipQueryResult:
    """
    Primary entry point for all relationship queries.

    Runs the full pipeline: normalize → filter → sort → paginate → graph.

    Parameters
    ----------
    relationships : full Relationship pool (caller-supplied).
    query         : structured RelationshipQuery.
    asset_labels  : optional { assetId → deviceName } for graph nodes.
    asset_scores  : optional { assetId → riskScore } for graph nodes.

    Returns
    -------
    RelationshipQueryResult (frozen / immutable).
    """
    return _run_pipeline(relationships, query, asset_labels, asset_scores)


# ---------------------------------------------------------------------------
# query_by_asset()
# ---------------------------------------------------------------------------

def query_by_asset(
    asset_id       : str,
    relationships  : Sequence[Relationship],
    depth          : int = 1,
    limit          : int = _DEFAULT_LIMIT,
    asset_labels   : Optional[Dict[str, str]] = None,
    asset_scores   : Optional[Dict[str, int]] = None,
) -> RelationshipQueryResult:
    """
    Convenience query: all relationships involving a specific asset.

    Parameters
    ----------
    asset_id      : Asset primary key.
    relationships : full pool.
    depth         : graph traversal depth (1 or 2).
    limit         : max relationships to return.
    asset_labels  : optional node labels.
    asset_scores  : optional node risk scores.

    Returns
    -------
    RelationshipQueryResult (frozen / immutable).
    """
    q = RelationshipQuery(assetId=asset_id, depth=depth, limit=limit)
    return _run_pipeline(relationships, q, asset_labels, asset_scores)


# ---------------------------------------------------------------------------
# query_by_protocol()
# ---------------------------------------------------------------------------

def query_by_protocol(
    protocol       : str,
    relationships  : Sequence[Relationship],
    limit          : int = _DEFAULT_LIMIT,
) -> RelationshipQueryResult:
    """
    Convenience query: all relationships with a specific protocol.

    Parameters
    ----------
    protocol      : protocol string (case-insensitive).
    relationships : full pool.
    limit         : max relationships to return.

    Returns
    -------
    RelationshipQueryResult (frozen / immutable).
    """
    q = RelationshipQuery(protocol=protocol, limit=limit)
    return _run_pipeline(relationships, q)


# ---------------------------------------------------------------------------
# query_by_state()
# ---------------------------------------------------------------------------

def query_by_state(
    state          : RelationshipState,
    relationships  : Sequence[Relationship],
    limit          : int = _DEFAULT_LIMIT,
) -> RelationshipQueryResult:
    """
    Convenience query: all relationships in a specific lifecycle state.

    Parameters
    ----------
    state         : RelationshipState enum value.
    relationships : full pool.
    limit         : max relationships to return.

    Returns
    -------
    RelationshipQueryResult (frozen / immutable).
    """
    q = RelationshipQuery(state=state, limit=limit)
    return _run_pipeline(relationships, q)


# ---------------------------------------------------------------------------
# query_by_confidence()
# ---------------------------------------------------------------------------

def query_by_confidence(
    minimum        : int,
    relationships  : Sequence[Relationship],
    maximum        : int = 100,
    limit          : int = _DEFAULT_LIMIT,
) -> RelationshipQueryResult:
    """
    Convenience query: relationships within a confidence band.

    Parameters
    ----------
    minimum       : inclusive lower confidence bound (0–100).
    relationships : full pool.
    maximum       : inclusive upper confidence bound (0–100).
    limit         : max relationships to return.

    Returns
    -------
    RelationshipQueryResult (frozen / immutable).
    """
    q = RelationshipQuery(
        minimumConfidence=minimum,
        maximumConfidence=maximum,
        limit=limit,
    )
    return _run_pipeline(relationships, q)


# ---------------------------------------------------------------------------
# query_by_timerange()
# ---------------------------------------------------------------------------

def query_by_timerange(
    start          : Optional[datetime],
    end            : Optional[datetime],
    relationships  : Sequence[Relationship],
    limit          : int = _DEFAULT_LIMIT,
) -> RelationshipQueryResult:
    """
    Convenience query: relationships whose lastSeen falls within [start, end].

    Parameters
    ----------
    start         : inclusive lower bound (None = unbounded).
    end           : inclusive upper bound (None = unbounded).
    relationships : full pool.
    limit         : max relationships to return.

    Returns
    -------
    RelationshipQueryResult (frozen / immutable).
    """
    q = RelationshipQuery(startTime=start, endTime=end, limit=limit)
    return _run_pipeline(relationships, q)
