"""
Attack Graph Query Engine
==========================
Phase A4.0.2 — Pure read-only analysis and traversal over an existing AttackGraph.

Responsibilities
----------------
- Query, traverse, search, and explain an immutable AttackGraph.
- Never build, modify, or reconstruct a graph.
- Provide deterministic, O(n) or O(n+m) algorithms.
- Expose all results as frozen Pydantic models.

Design constraints (FREEZE BOUNDARY — A4.0.2)
----------------------------------------------
- PURE: no Prisma, no repository, no FastAPI, no database, no HTTP, no filesystem.
- Immutable output: every model uses frozen=True.
- Deterministic: same graph + same query → same result always.
- No side effects. No global mutable state. No circular imports.
- Never mutate AttackGraph, AttackGraphNode, or AttackGraphEdge.

Dependency graph
----------------
  core.constants                        (ATTACK_GRAPH_QUERY_ENGINE_VERSION)
  services.attack_graph_service         (AttackGraph, AttackGraphNode,
                                         AttackGraphEdge, GraphNodeTypeEnum,
                                         GraphEdgeTypeEnum)
  pydantic, typing, hashlib, collections, time
  ← services.attack_graph_query_service  (this file)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from core.constants import ATTACK_GRAPH_QUERY_ENGINE_VERSION
from services.attack_graph_service import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    GraphEdgeTypeEnum,
    GraphNodeTypeEnum,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    """Current monotonic time in milliseconds."""
    return round(time.monotonic_ns() / 1_000_000)


def _path_fingerprint(node_keys: List[str], edge_keys: List[str]) -> str:
    """
    Compute a deterministic 32-char SHA-256 fingerprint for a path.

    Algorithm: ordered nodeKeys joined by '>' then '|' then ordered edgeKeys
    joined by '>'.  Order is preserved (insertion, not lexicographic) so that
    the same traversal sequence always produces the same fingerprint.

    Returns a 32-char lowercase hex string.
    Empty path returns 32 zeros.
    """
    if not node_keys and not edge_keys:
        return "0" * 32
    raw = ">".join(node_keys) + "|" + ">".join(edge_keys)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _build_adjacency(
    graph: AttackGraph,
) -> Tuple[
    Dict[str, AttackGraphNode],          # nodeKey → node
    Dict[str, List[AttackGraphEdge]],    # nodeKey → outgoing edges
    Dict[str, List[AttackGraphEdge]],    # nodeKey → incoming edges
    Dict[str, AttackGraphEdge],          # edgeKey → edge
]:
    """
    Build O(n+m) lookup structures from a frozen AttackGraph.

    Returns
    -------
    node_index   : nodeKey → AttackGraphNode
    out_edges    : nodeKey → list of outgoing AttackGraphEdge
    in_edges     : nodeKey → list of incoming AttackGraphEdge
    edge_index   : edgeKey → AttackGraphEdge
    """
    node_index: Dict[str, AttackGraphNode] = {}
    out_edges:  Dict[str, List[AttackGraphEdge]] = defaultdict(list)
    in_edges:   Dict[str, List[AttackGraphEdge]] = defaultdict(list)
    edge_index: Dict[str, AttackGraphEdge] = {}

    for node in graph.nodes:
        node_index[node.nodeKey] = node

    for edge in graph.edges:
        edge_index[edge.edgeKey] = edge
        out_edges[edge.sourceNodeId].append(edge)
        in_edges[edge.targetNodeId].append(edge)

    return node_index, out_edges, in_edges, edge_index


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class GraphQuery(BaseModel):
    """
    Immutable query descriptor.  All fields are optional filters; omitted
    fields are not applied.  AND semantics: every supplied filter must match.
    """
    nodeId              : Optional[str]                     = None
    nodeKey             : Optional[str]                     = None
    nodeType            : Optional[GraphNodeTypeEnum]       = None
    edgeType            : Optional[GraphEdgeTypeEnum]       = None
    label               : Optional[str]                     = None  # substring
    labelContains       : Optional[str]                     = None  # alias
    minimumRisk         : Optional[int]                     = None  # 0-100
    minimumConfidence   : Optional[int]                     = None  # 0-100
    maximumDepth        : int                               = Field(default=10, ge=1)
    includeIncoming     : bool                              = True
    includeOutgoing     : bool                              = True
    includeIsolated     : bool                              = True
    includeDisconnected : bool                              = True
    limit               : Optional[int]                     = None  # max results

    class Config:
        frozen = True


class GraphPath(BaseModel):
    """An ordered path through the graph with accumulated metrics."""
    nodes           : List[AttackGraphNode]
    edges           : List[AttackGraphEdge]
    totalRisk       : int   = 0
    totalConfidence : int   = 0
    pathLength      : int   = 0
    pathFingerprint : str   = "0" * 32   # SHA-256 over ordered nodeKeys+edgeKeys

    class Config:
        frozen = True


class GraphNeighborhood(BaseModel):
    """Neighborhood of a center node up to two hops."""
    centerNode : AttackGraphNode
    oneHop     : List[AttackGraphNode]  = Field(default_factory=list)
    twoHop     : List[AttackGraphNode]  = Field(default_factory=list)
    incoming   : List[AttackGraphNode]  = Field(default_factory=list)
    outgoing   : List[AttackGraphNode]  = Field(default_factory=list)

    class Config:
        frozen = True


class GraphTraversalResult(BaseModel):
    """Full result of a BFS or DFS traversal."""
    visitedNodes    : List[AttackGraphNode]
    visitedEdges    : List[AttackGraphEdge]
    traversalOrder  : List[str]   # ordered list of nodeKeys
    maxDepthReached : int
    visitedNodeCount: int
    visitedEdgeCount: int
    processingTimeMs: int

    class Config:
        frozen = True


class GraphMetrics(BaseModel):
    """Computed graph-level metrics."""
    averageDegree       : float
    highestDegree       : int
    lowestDegree        : int
    connectedComponents : int
    isolatedNodes       : int
    graphDensity        : float   # edges / (nodes * (nodes-1)), 0 for n<2
    averageRisk         : float
    averageConfidence   : float

    class Config:
        frozen = True


class GraphSearchResult(BaseModel):
    """Result of a search operation."""
    nodes : List[AttackGraphNode] = Field(default_factory=list)
    edges : List[AttackGraphEdge] = Field(default_factory=list)
    count : int = 0

    class Config:
        frozen = True


class GraphQueryExplanation(BaseModel):
    """Human-readable and machine-parseable explanation of a query execution."""
    querySummary     : str
    filtersApplied   : List[str]
    algorithmsUsed   : List[str]
    recordsVisited   : int
    processingStages : List[str]
    executionTimeMs  : int

    class Config:
        frozen = True


class GraphQueryResult(BaseModel):
    """Top-level result returned by query_graph()."""
    graph           : AttackGraph
    metrics         : GraphMetrics
    searchResult    : GraphSearchResult
    traversal       : Optional[GraphTraversalResult]    = None
    explanation     : GraphQueryExplanation
    processingTimeMs: int
    engineVersion   : str = ATTACK_GRAPH_QUERY_ENGINE_VERSION

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def filter_nodes(
    nodes             : Sequence[AttackGraphNode],
    *,
    node_type         : Optional[GraphNodeTypeEnum] = None,
    minimum_risk      : Optional[int]               = None,
    minimum_confidence: Optional[int]               = None,
    label_contains    : Optional[str]               = None,
) -> List[AttackGraphNode]:
    """
    Filter nodes with AND semantics.  O(n).

    Supported filters
    -----------------
    node_type          : exact match on nodeType
    minimum_risk       : riskScore >= minimum_risk
    minimum_confidence : confidence >= minimum_confidence
    label_contains     : case-insensitive substring match on label
    """
    result: List[AttackGraphNode] = []
    lc_label = label_contains.lower() if label_contains else None

    for n in nodes:
        if node_type is not None and n.nodeType != node_type:
            continue
        if minimum_risk is not None and n.riskScore < minimum_risk:
            continue
        if minimum_confidence is not None and n.confidence < minimum_confidence:
            continue
        if lc_label is not None and lc_label not in n.label.lower():
            continue
        result.append(n)

    return result


def filter_edges(
    edges              : Sequence[AttackGraphEdge],
    *,
    edge_type          : Optional[GraphEdgeTypeEnum] = None,
    source_node_id     : Optional[str]               = None,
    target_node_id     : Optional[str]               = None,
    minimum_confidence : Optional[int]               = None,
) -> List[AttackGraphEdge]:
    """
    Filter edges with AND semantics.  O(m).

    Supported filters
    -----------------
    edge_type          : exact match on edgeType
    source_node_id     : exact match on sourceNodeId
    target_node_id     : exact match on targetNodeId
    minimum_confidence : confidence >= minimum_confidence
    """
    result: List[AttackGraphEdge] = []
    for e in edges:
        if edge_type is not None and e.edgeType != edge_type:
            continue
        if source_node_id is not None and e.sourceNodeId != source_node_id:
            continue
        if target_node_id is not None and e.targetNodeId != target_node_id:
            continue
        if minimum_confidence is not None and e.confidence < minimum_confidence:
            continue
        result.append(e)
    return result


# ---------------------------------------------------------------------------
# Sorting helpers
# ---------------------------------------------------------------------------

def sort_nodes(
    nodes   : List[AttackGraphNode],
    *,
    by      : str = "risk",   # "risk" | "confidence" | "degree" | "label"
    degrees : Optional[Dict[str, int]] = None,
) -> List[AttackGraphNode]:
    """
    Sort nodes by the requested criterion (DESC for numeric, ASC for label).

    Parameters
    ----------
    nodes   : list to sort (not mutated).
    by      : "risk" | "confidence" | "degree" | "label"
    degrees : required when by=="degree"; nodeKey → degree map.
    """
    if by == "risk":
        return sorted(nodes, key=lambda n: (-n.riskScore, n.label.lower()))
    if by == "confidence":
        return sorted(nodes, key=lambda n: (-n.confidence, n.label.lower()))
    if by == "label":
        return sorted(nodes, key=lambda n: n.label.lower())
    if by == "degree":
        deg = degrees or {}
        return sorted(nodes, key=lambda n: (-deg.get(n.nodeKey, 0), n.label.lower()))
    # default fallback
    return sorted(nodes, key=lambda n: (-n.riskScore, n.label.lower()))


def sort_edges(
    edges : List[AttackGraphEdge],
    *,
    by    : str = "confidence",   # "confidence" | "edgeType"
) -> List[AttackGraphEdge]:
    """
    Sort edges by the requested criterion.

    Parameters
    ----------
    edges : list to sort (not mutated).
    by    : "confidence" | "edgeType"
    """
    if by == "edgeType":
        return sorted(edges, key=lambda e: (e.edgeType.value, -e.confidence))
    # default: confidence DESC
    return sorted(edges, key=lambda e: (-e.confidence, e.edgeType.value))


# ---------------------------------------------------------------------------
# Single-node queries
# ---------------------------------------------------------------------------

def query_by_node(
    graph   : AttackGraph,
    node_key: str,
) -> Optional[AttackGraphNode]:
    """
    Return the single node whose nodeKey (or nodeId) matches exactly.
    O(n) — linear scan over graph.nodes.
    """
    for n in graph.nodes:
        if n.nodeKey == node_key or n.nodeId == node_key:
            return n
    return None


def query_by_type(
    graph     : AttackGraph,
    node_type : GraphNodeTypeEnum,
) -> List[AttackGraphNode]:
    """Return all nodes whose nodeType matches.  O(n)."""
    return [n for n in graph.nodes if n.nodeType == node_type]


def query_by_risk(
    graph       : AttackGraph,
    minimum_risk: int,
) -> List[AttackGraphNode]:
    """Return all nodes with riskScore >= minimum_risk.  O(n)."""
    return [n for n in graph.nodes if n.riskScore >= minimum_risk]


def query_by_confidence(
    graph              : AttackGraph,
    minimum_confidence : int,
) -> List[AttackGraphNode]:
    """Return all nodes with confidence >= minimum_confidence.  O(n)."""
    return [n for n in graph.nodes if n.confidence >= minimum_confidence]


def query_by_label(
    graph   : AttackGraph,
    label   : str,
) -> List[AttackGraphNode]:
    """
    Return all nodes whose label contains `label` (case-insensitive).
    O(n).
    """
    lc = label.lower()
    return [n for n in graph.nodes if lc in n.label.lower()]


# ---------------------------------------------------------------------------
# Search utilities
# ---------------------------------------------------------------------------

def search_nodes(
    graph          : AttackGraph,
    *,
    node_type      : Optional[GraphNodeTypeEnum] = None,
    minimum_risk   : Optional[int]               = None,
    min_confidence : Optional[int]               = None,
    label_contains : Optional[str]               = None,
    limit          : Optional[int]               = None,
) -> GraphSearchResult:
    """
    Search nodes with AND semantics across all supplied filters.  O(n).
    """
    matched = filter_nodes(
        graph.nodes,
        node_type=node_type,
        minimum_risk=minimum_risk,
        minimum_confidence=min_confidence,
        label_contains=label_contains,
    )
    if limit is not None:
        matched = matched[:limit]
    return GraphSearchResult(nodes=matched, edges=[], count=len(matched))


def search_edges(
    graph          : AttackGraph,
    *,
    edge_type      : Optional[GraphEdgeTypeEnum] = None,
    source_node_id : Optional[str]               = None,
    target_node_id : Optional[str]               = None,
    min_confidence : Optional[int]               = None,
    limit          : Optional[int]               = None,
) -> GraphSearchResult:
    """
    Search edges with AND semantics across all supplied filters.  O(m).
    """
    matched = filter_edges(
        graph.edges,
        edge_type=edge_type,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        minimum_confidence=min_confidence,
    )
    if limit is not None:
        matched = matched[:limit]
    return GraphSearchResult(nodes=[], edges=matched, count=len(matched))


def search_metadata(
    graph : AttackGraph,
    key   : str,
    value : Optional[Any] = None,
) -> GraphSearchResult:
    """
    Search nodes and edges whose metadata contains `key` (and optionally
    whose metadata[key] == value).  O(n+m).
    """
    matched_nodes: List[AttackGraphNode] = []
    matched_edges: List[AttackGraphEdge] = []

    for n in graph.nodes:
        if key in n.metadata:
            if value is None or n.metadata[key] == value:
                matched_nodes.append(n)

    for e in graph.edges:
        if key in e.metadata:
            if value is None or e.metadata[key] == value:
                matched_edges.append(e)

    total = len(matched_nodes) + len(matched_edges)
    return GraphSearchResult(nodes=matched_nodes, edges=matched_edges, count=total)


# ---------------------------------------------------------------------------
# Graph traversal
# ---------------------------------------------------------------------------

def find_neighbors(
    graph    : AttackGraph,
    node_key : str,
    *,
    include_incoming : bool = True,
    include_outgoing : bool = True,
) -> List[AttackGraphNode]:
    """
    Return direct (one-hop) neighbors of a node.  O(m).

    Parameters
    ----------
    include_incoming : include nodes that have an edge pointing TO node_key.
    include_outgoing : include nodes that have an edge FROM node_key.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)
    neighbor_keys: set = set()

    if include_outgoing:
        for e in out_edges.get(node_key, []):
            neighbor_keys.add(e.targetNodeId)
    if include_incoming:
        for e in in_edges.get(node_key, []):
            neighbor_keys.add(e.sourceNodeId)

    neighbor_keys.discard(node_key)
    return [node_index[k] for k in neighbor_keys if k in node_index]


def find_two_hop_neighbors(
    graph    : AttackGraph,
    node_key : str,
    *,
    include_incoming : bool = True,
    include_outgoing : bool = True,
) -> GraphNeighborhood:
    """
    Return a GraphNeighborhood with one-hop and two-hop neighbors.  O(n+m).
    """
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)
    center = node_index.get(node_key)
    if center is None:
        # Return empty neighborhood — node not in graph
        dummy_nodes: List[AttackGraphNode] = []
        return GraphNeighborhood(
            centerNode=center,  # type: ignore[arg-type]
            oneHop=[], twoHop=[], incoming=[], outgoing=[],
        )

    one_hop_keys: set = set()
    outgoing_keys: set = set()
    incoming_keys: set = set()

    if include_outgoing:
        for e in out_edges.get(node_key, []):
            if e.targetNodeId != node_key:
                one_hop_keys.add(e.targetNodeId)
                outgoing_keys.add(e.targetNodeId)
    if include_incoming:
        for e in in_edges.get(node_key, []):
            if e.sourceNodeId != node_key:
                one_hop_keys.add(e.sourceNodeId)
                incoming_keys.add(e.sourceNodeId)

    two_hop_keys: set = set()
    for hop1_key in one_hop_keys:
        if include_outgoing:
            for e in out_edges.get(hop1_key, []):
                two_hop_keys.add(e.targetNodeId)
        if include_incoming:
            for e in in_edges.get(hop1_key, []):
                two_hop_keys.add(e.sourceNodeId)
    two_hop_keys -= one_hop_keys
    two_hop_keys.discard(node_key)

    def _resolve(keys: set) -> List[AttackGraphNode]:
        return [node_index[k] for k in keys if k in node_index]

    return GraphNeighborhood(
        centerNode=center,
        oneHop=_resolve(one_hop_keys),
        twoHop=_resolve(two_hop_keys),
        incoming=_resolve(incoming_keys),
        outgoing=_resolve(outgoing_keys),
    )


def breadth_first_search(
    graph     : AttackGraph,
    start_key : str,
    *,
    max_depth         : int  = 10,
    include_incoming  : bool = True,
    include_outgoing  : bool = True,
) -> GraphTraversalResult:
    """
    BFS from start_key up to max_depth hops.  O(n+m).

    Returns GraphTraversalResult including:
      visitedNodeCount, visitedEdgeCount, maxDepthReached
    for instant AI narration.
    """
    t0 = _now_ms()
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)

    if start_key not in node_index:
        return GraphTraversalResult(
            visitedNodes=[], visitedEdges=[], traversalOrder=[],
            maxDepthReached=0, visitedNodeCount=0, visitedEdgeCount=0,
            processingTimeMs=_now_ms() - t0,
        )

    visited_node_keys: List[str] = []
    visited_edge_keys: List[str] = []
    seen_nodes: set = {start_key}
    seen_edges: set = set()
    queue: deque = deque([(start_key, 0)])
    max_depth_reached = 0

    while queue:
        current_key, depth = queue.popleft()
        visited_node_keys.append(current_key)
        if depth > max_depth_reached:
            max_depth_reached = depth
        if depth >= max_depth:
            continue

        adjacent: List[AttackGraphEdge] = []
        if include_outgoing:
            adjacent.extend(out_edges.get(current_key, []))
        if include_incoming:
            adjacent.extend(in_edges.get(current_key, []))

        for e in adjacent:
            neighbor = e.targetNodeId if e.sourceNodeId == current_key else e.sourceNodeId
            if e.edgeKey not in seen_edges:
                seen_edges.add(e.edgeKey)
                visited_edge_keys.append(e.edgeKey)
            if neighbor not in seen_nodes:
                seen_nodes.add(neighbor)
                queue.append((neighbor, depth + 1))

    visited_nodes = [node_index[k] for k in visited_node_keys if k in node_index]
    _, _, _, edge_index = _build_adjacency(graph)
    visited_edges = [edge_index[k] for k in visited_edge_keys if k in edge_index]

    return GraphTraversalResult(
        visitedNodes=visited_nodes,
        visitedEdges=visited_edges,
        traversalOrder=visited_node_keys,
        maxDepthReached=max_depth_reached,
        visitedNodeCount=len(visited_nodes),
        visitedEdgeCount=len(visited_edges),
        processingTimeMs=_now_ms() - t0,
    )


def depth_first_search(
    graph     : AttackGraph,
    start_key : str,
    *,
    max_depth         : int  = 10,
    include_incoming  : bool = True,
    include_outgoing  : bool = True,
) -> GraphTraversalResult:
    """
    Iterative DFS from start_key up to max_depth hops.  O(n+m).

    Returns GraphTraversalResult with visitedNodeCount, visitedEdgeCount,
    maxDepthReached for instant AI narration.
    """
    t0 = _now_ms()
    node_index, out_edges, in_edges, edge_index = _build_adjacency(graph)

    if start_key not in node_index:
        return GraphTraversalResult(
            visitedNodes=[], visitedEdges=[], traversalOrder=[],
            maxDepthReached=0, visitedNodeCount=0, visitedEdgeCount=0,
            processingTimeMs=_now_ms() - t0,
        )

    visited_node_keys: List[str] = []
    visited_edge_keys: List[str] = []
    seen_nodes: set = set()
    seen_edges: set = set()
    # Stack items: (nodeKey, depth)
    stack: List[Tuple[str, int]] = [(start_key, 0)]
    max_depth_reached = 0

    while stack:
        current_key, depth = stack.pop()
        if current_key in seen_nodes:
            continue
        seen_nodes.add(current_key)
        visited_node_keys.append(current_key)
        if depth > max_depth_reached:
            max_depth_reached = depth
        if depth >= max_depth:
            continue

        adjacent: List[AttackGraphEdge] = []
        if include_outgoing:
            adjacent.extend(out_edges.get(current_key, []))
        if include_incoming:
            adjacent.extend(in_edges.get(current_key, []))

        for e in adjacent:
            neighbor = e.targetNodeId if e.sourceNodeId == current_key else e.sourceNodeId
            if e.edgeKey not in seen_edges:
                seen_edges.add(e.edgeKey)
                visited_edge_keys.append(e.edgeKey)
            if neighbor not in seen_nodes:
                stack.append((neighbor, depth + 1))

    visited_nodes = [node_index[k] for k in visited_node_keys if k in node_index]
    visited_edges = [edge_index[k] for k in visited_edge_keys if k in edge_index]

    return GraphTraversalResult(
        visitedNodes=visited_nodes,
        visitedEdges=visited_edges,
        traversalOrder=visited_node_keys,
        maxDepthReached=max_depth_reached,
        visitedNodeCount=len(visited_nodes),
        visitedEdgeCount=len(visited_edges),
        processingTimeMs=_now_ms() - t0,
    )


def reachable_nodes(
    graph     : AttackGraph,
    start_key : str,
    *,
    max_depth         : int  = 10,
    include_incoming  : bool = False,
    include_outgoing  : bool = True,
) -> List[AttackGraphNode]:
    """
    Return all nodes reachable from start_key following directed edges.
    Default: outgoing only (directed reachability).  O(n+m).
    """
    result = breadth_first_search(
        graph, start_key,
        max_depth=max_depth,
        include_incoming=include_incoming,
        include_outgoing=include_outgoing,
    )
    # Exclude the start node itself
    return [n for n in result.visitedNodes if n.nodeKey != start_key]


def connected_components(
    graph: AttackGraph,
) -> List[List[AttackGraphNode]]:
    """
    Return all weakly connected components as lists of nodes.
    Edges treated as undirected.  O(n+m).
    """
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)
    node_key_set = set(node_index.keys())
    visited: set = set()
    components: List[List[AttackGraphNode]] = []

    for key in node_key_set:
        if key in visited:
            continue
        component_keys: List[str] = []
        queue: deque = deque([key])
        visited.add(key)
        while queue:
            cur = queue.popleft()
            component_keys.append(cur)
            neighbors: set = set()
            for e in out_edges.get(cur, []):
                neighbors.add(e.targetNodeId)
            for e in in_edges.get(cur, []):
                neighbors.add(e.sourceNodeId)
            for nb in neighbors:
                if nb not in visited and nb in node_key_set:
                    visited.add(nb)
                    queue.append(nb)
        components.append([node_index[k] for k in component_keys])

    # Sort components largest-first for deterministic output
    return sorted(components, key=lambda c: -len(c))


def isolated_nodes(graph: AttackGraph) -> List[AttackGraphNode]:
    """
    Return all nodes with degree 0 (no edges).  O(n+m).
    """
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)
    result: List[AttackGraphNode] = []
    for key, node in node_index.items():
        if not out_edges.get(key) and not in_edges.get(key):
            result.append(node)
    return result


# ---------------------------------------------------------------------------
# Path algorithms
# ---------------------------------------------------------------------------

def shortest_path(
    graph      : AttackGraph,
    source_key : str,
    target_key : str,
    *,
    include_incoming : bool = False,
    include_outgoing : bool = True,
) -> Optional[GraphPath]:
    """
    BFS shortest path from source_key to target_key.  O(n+m).
    Returns None if no path exists.
    Default: directed (outgoing only).
    """
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)

    if source_key not in node_index or target_key not in node_index:
        return None
    if source_key == target_key:
        n = node_index[source_key]
        fp = _path_fingerprint([n.nodeKey], [])
        return GraphPath(nodes=[n], edges=[], totalRisk=n.riskScore,
                         totalConfidence=n.confidence, pathLength=0,
                         pathFingerprint=fp)

    # BFS — parent tracking: nodeKey → (parent_key, edge)
    parent: Dict[str, Tuple[Optional[str], Optional[AttackGraphEdge]]] = {
        source_key: (None, None)
    }
    queue: deque = deque([source_key])

    while queue:
        cur = queue.popleft()
        if cur == target_key:
            break

        adjacent: List[AttackGraphEdge] = []
        if include_outgoing:
            adjacent.extend(out_edges.get(cur, []))
        if include_incoming:
            adjacent.extend(in_edges.get(cur, []))

        for e in adjacent:
            nb = e.targetNodeId if e.sourceNodeId == cur else e.sourceNodeId
            if nb not in parent and nb in node_index:
                parent[nb] = (cur, e)
                queue.append(nb)

    if target_key not in parent:
        return None

    # Reconstruct path
    path_nodes: List[AttackGraphNode] = []
    path_edges: List[AttackGraphEdge] = []
    cur = target_key
    while cur is not None:
        path_nodes.append(node_index[cur])
        par_key, par_edge = parent[cur]
        if par_edge is not None:
            path_edges.append(par_edge)
        cur = par_key  # type: ignore[assignment]

    path_nodes.reverse()
    path_edges.reverse()

    total_risk = sum(n.riskScore for n in path_nodes)
    total_conf = sum(e.confidence for e in path_edges) if path_edges else 0
    fp = _path_fingerprint(
        [n.nodeKey for n in path_nodes],
        [e.edgeKey for e in path_edges],
    )

    return GraphPath(
        nodes=path_nodes,
        edges=path_edges,
        totalRisk=total_risk,
        totalConfidence=total_conf,
        pathLength=len(path_edges),
        pathFingerprint=fp,
    )


def all_paths(
    graph      : AttackGraph,
    source_key : str,
    target_key : str,
    *,
    maximum_depth    : int  = 6,
    include_incoming : bool = False,
    include_outgoing : bool = True,
) -> List[GraphPath]:
    """
    Find all simple paths from source to target up to maximum_depth hops.
    Uses iterative DFS with visited-set per path.  O(n+m) per path.
    Bounded by maximum_depth to prevent combinatorial explosion.
    """
    node_index, out_edges, in_edges, _ = _build_adjacency(graph)

    if source_key not in node_index or target_key not in node_index:
        return []

    results: List[GraphPath] = []
    # Stack: (current_key, path_nodes, path_edges, visited)
    stack: List[Tuple[str, List[str], List[AttackGraphEdge], FrozenSet[str]]] = [
        (source_key, [source_key], [], frozenset([source_key]))
    ]

    while stack:
        cur, node_path, edge_path, visited = stack.pop()

        if cur == target_key and len(node_path) > 1:
            path_nodes = [node_index[k] for k in node_path if k in node_index]
            total_risk = sum(n.riskScore for n in path_nodes)
            total_conf = sum(e.confidence for e in edge_path)
            fp = _path_fingerprint(
                [n.nodeKey for n in path_nodes],
                [e.edgeKey for e in edge_path],
            )
            results.append(GraphPath(
                nodes=path_nodes,
                edges=list(edge_path),
                totalRisk=total_risk,
                totalConfidence=total_conf,
                pathLength=len(edge_path),
                pathFingerprint=fp,
            ))
            continue

        if len(node_path) - 1 >= maximum_depth:
            continue

        adjacent: List[AttackGraphEdge] = []
        if include_outgoing:
            adjacent.extend(out_edges.get(cur, []))
        if include_incoming:
            adjacent.extend(in_edges.get(cur, []))

        for e in adjacent:
            nb = e.targetNodeId if e.sourceNodeId == cur else e.sourceNodeId
            if nb not in visited and nb in node_index:
                stack.append((
                    nb,
                    node_path + [nb],
                    edge_path + [e],
                    visited | {nb},
                ))

    return results


def highest_risk_path(
    graph      : AttackGraph,
    source_key : str,
    target_key : str,
    *,
    maximum_depth    : int  = 6,
    include_incoming : bool = False,
    include_outgoing : bool = True,
) -> Optional[GraphPath]:
    """
    Return the path from source to target with the highest accumulated
    node riskScore sum.  Evaluates all_paths() then selects maximum.
    """
    paths = all_paths(
        graph, source_key, target_key,
        maximum_depth=maximum_depth,
        include_incoming=include_incoming,
        include_outgoing=include_outgoing,
    )
    if not paths:
        return None
    return max(paths, key=lambda p: p.totalRisk)


def lowest_confidence_path(
    graph      : AttackGraph,
    source_key : str,
    target_key : str,
    *,
    maximum_depth    : int  = 6,
    include_incoming : bool = False,
    include_outgoing : bool = True,
) -> Optional[GraphPath]:
    """
    Return the path from source to target with the lowest accumulated
    edge confidence sum (weakest-link path).  Evaluates all_paths().
    """
    paths = all_paths(
        graph, source_key, target_key,
        maximum_depth=maximum_depth,
        include_incoming=include_incoming,
        include_outgoing=include_outgoing,
    )
    if not paths:
        return None
    return min(paths, key=lambda p: p.totalConfidence)


# ---------------------------------------------------------------------------
# Graph metrics
# ---------------------------------------------------------------------------

def calculate_graph_metrics(graph: AttackGraph) -> GraphMetrics:
    """
    Compute full graph metrics in O(n+m).

    Metrics
    -------
    averageDegree       : mean (in+out) degree across all nodes.
    highestDegree       : max degree of any node.
    lowestDegree        : min degree of any node.
    connectedComponents : count of weakly connected components.
    isolatedNodes       : count of nodes with degree 0.
    graphDensity        : |E| / (|V| * (|V|-1)).  0 for |V| < 2.
    averageRisk         : mean riskScore across nodes.
    averageConfidence   : mean confidence across nodes.
    """
    node_count = len(graph.nodes)
    edge_count = len(graph.edges)

    if node_count == 0:
        return GraphMetrics(
            averageDegree=0.0, highestDegree=0, lowestDegree=0,
            connectedComponents=0, isolatedNodes=0, graphDensity=0.0,
            averageRisk=0.0, averageConfidence=0.0,
        )

    # Degree per node (undirected)
    degree: Dict[str, int] = {n.nodeKey: 0 for n in graph.nodes}
    node_key_set = set(degree.keys())
    for e in graph.edges:
        if e.sourceNodeId in degree:
            degree[e.sourceNodeId] += 1
        if e.targetNodeId in degree:
            degree[e.targetNodeId] += 1

    degrees_list = list(degree.values())
    avg_degree    = sum(degrees_list) / node_count
    highest       = max(degrees_list)
    lowest        = min(degrees_list)
    isolated      = sum(1 for d in degrees_list if d == 0)

    # Weakly connected components via BFS
    adj: Dict[str, set] = defaultdict(set)
    for e in graph.edges:
        if e.sourceNodeId in node_key_set and e.targetNodeId in node_key_set:
            adj[e.sourceNodeId].add(e.targetNodeId)
            adj[e.targetNodeId].add(e.sourceNodeId)

    visited: set = set()
    components = 0
    for key in node_key_set:
        if key not in visited:
            components += 1
            q: deque = deque([key])
            visited.add(key)
            while q:
                cur = q.popleft()
                for nb in adj[cur]:
                    if nb not in visited:
                        visited.add(nb)
                        q.append(nb)

    # Density: directed graph — max edges = n*(n-1)
    max_edges    = node_count * (node_count - 1)
    graph_density = edge_count / max_edges if max_edges > 0 else 0.0

    avg_risk = sum(n.riskScore for n in graph.nodes) / node_count
    avg_conf = sum(n.confidence for n in graph.nodes) / node_count

    return GraphMetrics(
        averageDegree=round(avg_degree, 4),
        highestDegree=highest,
        lowestDegree=lowest,
        connectedComponents=components,
        isolatedNodes=isolated,
        graphDensity=round(graph_density, 6),
        averageRisk=round(avg_risk, 2),
        averageConfidence=round(avg_conf, 2),
    )


# ---------------------------------------------------------------------------
# Main entry point: query_graph()
# ---------------------------------------------------------------------------

def query_graph(
    graph : AttackGraph,
    query : GraphQuery,
) -> GraphQueryResult:
    """
    Main query entry point.  Applies all filters from GraphQuery, runs
    BFS traversal from the first matched node (if nodeId/nodeKey supplied),
    computes metrics, and returns a full GraphQueryResult.

    O(n+m) complexity.
    """
    t0_abs = _now_ms()
    stages: List[str] = []
    filters_applied: List[str] = []
    algorithms_used: List[str] = []
    records_visited = 0

    # ── 1. Build adjacency index ────────────────────────────────────────────
    stages.append("Build adjacency index")
    node_index, out_edges, in_edges, edge_index = _build_adjacency(graph)
    records_visited += len(graph.nodes) + len(graph.edges)

    # ── 2. Apply node filters ───────────────────────────────────────────────
    stages.append("Apply node filters")
    label_sub = query.label or query.labelContains

    # Exact node lookup shortcut
    if query.nodeId or query.nodeKey:
        lookup_key = query.nodeId or query.nodeKey
        matched_node = query_by_node(graph, lookup_key)  # type: ignore[arg-type]
        matched_nodes = [matched_node] if matched_node else []
        filters_applied.append(f"nodeKey={lookup_key}")
        algorithms_used.append("exact_key_lookup")
    else:
        matched_nodes = filter_nodes(
            graph.nodes,
            node_type=query.nodeType,
            minimum_risk=query.minimumRisk,
            minimum_confidence=query.minimumConfidence,
            label_contains=label_sub,
        )
        if query.nodeType:
            filters_applied.append(f"nodeType={query.nodeType.value}")
        if query.minimumRisk is not None:
            filters_applied.append(f"minimumRisk>={query.minimumRisk}")
        if query.minimumConfidence is not None:
            filters_applied.append(f"minimumConfidence>={query.minimumConfidence}")
        if label_sub:
            filters_applied.append(f"label~={label_sub!r}")
        algorithms_used.append("filter_nodes")

    # ── 3. Isolation / disconnection filters ───────────────────────────────
    stages.append("Isolation/disconnection filter")
    node_key_set = set(node_index.keys())
    if not query.includeIsolated or not query.includeDisconnected:
        def _has_edges(nk: str) -> bool:
            return bool(out_edges.get(nk) or in_edges.get(nk))
        filtered: List[AttackGraphNode] = []
        for n in matched_nodes:
            has_e = _has_edges(n.nodeKey)
            if not has_e and not query.includeIsolated:
                continue
            if not has_e and not query.includeDisconnected:
                continue
            filtered.append(n)
        matched_nodes = filtered

    # ── 4. Apply edge filter ────────────────────────────────────────────────
    stages.append("Apply edge filters")
    matched_edges = filter_edges(
        graph.edges,
        edge_type=query.edgeType,
    )
    if query.edgeType:
        filters_applied.append(f"edgeType={query.edgeType.value}")

    # ── 5. Apply limit ──────────────────────────────────────────────────────
    if query.limit is not None:
        matched_nodes = matched_nodes[:query.limit]
        matched_edges = matched_edges[:query.limit]

    search_result = GraphSearchResult(
        nodes=matched_nodes,
        edges=matched_edges,
        count=len(matched_nodes) + len(matched_edges),
    )

    # ── 6. BFS traversal from first matched node (if available) ────────────
    traversal: Optional[GraphTraversalResult] = None
    if matched_nodes:
        stages.append("BFS traversal from primary node")
        algorithms_used.append("breadth_first_search")
        traversal = breadth_first_search(
            graph,
            matched_nodes[0].nodeKey,
            max_depth=query.maximumDepth,
            include_incoming=query.includeIncoming,
            include_outgoing=query.includeOutgoing,
        )
        records_visited += traversal.visitedNodeCount + traversal.visitedEdgeCount

    # ── 7. Metrics ──────────────────────────────────────────────────────────
    stages.append("Calculate graph metrics")
    algorithms_used.append("calculate_graph_metrics")
    metrics = calculate_graph_metrics(graph)

    # ── 8. Explanation ──────────────────────────────────────────────────────
    exec_ms = _now_ms() - t0_abs

    traversal_summary = ""
    if traversal:
        traversal_summary = (
            f" Traversal visited {traversal.visitedNodeCount} nodes, "
            f"{traversal.visitedEdgeCount} edges, reached depth {traversal.maxDepthReached}."
        )

    query_summary = (
        f"Queried graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges. "
        f"Matched {len(matched_nodes)} nodes and {len(matched_edges)} edges."
        f"{traversal_summary}"
    )

    explanation = GraphQueryExplanation(
        querySummary=query_summary,
        filtersApplied=filters_applied,
        algorithmsUsed=algorithms_used,
        recordsVisited=records_visited,
        processingStages=stages,
        executionTimeMs=exec_ms,
    )

    return GraphQueryResult(
        graph=graph,
        metrics=metrics,
        searchResult=search_result,
        traversal=traversal,
        explanation=explanation,
        processingTimeMs=exec_ms,
        engineVersion=ATTACK_GRAPH_QUERY_ENGINE_VERSION,
    )
