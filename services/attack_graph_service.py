"""
Enterprise Attack Graph Engine
================================
Phase A4.0.1 — Pure in-memory graph foundation.

Responsibilities
----------------
- Represent the investigation as a directed graph of nodes and edges.
- Every node is an observable entity (asset, evidence, finding, domain, etc.).
- Every edge is a typed relationship between two nodes.
- Provide deterministic, stable IDs (SHA-256 truncated to 32 chars).
- Compute graph statistics: degrees, components, risk distribution.
- Expose pure utility functions for sorting, grouping, and filtering.

Design constraints (FREEZE BOUNDARY — A4.0.1 only)
----------------------------------------------------
- PURE: no Prisma, no repository, no FastAPI, no database, no HTTP.
- Immutable output: every model uses frozen=True.
- Deterministic: same inputs → same nodeKey / edgeKey always.
- No side effects in any builder or utility function.
- No global mutable state.
- No circular imports.

Dependency graph
----------------
  core.constants                 (ATTACK_GRAPH_ENGINE_VERSION)
  pydantic, typing, datetime, hashlib, collections
  ← services.attack_graph_service   (this file)
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from core.constants import ATTACK_GRAPH_ENGINE_VERSION


# ---------------------------------------------------------------------------
# Deterministic key helpers
# ---------------------------------------------------------------------------

def _sha256_key(*parts: str) -> str:
    """
    Compute a deterministic 32-character hex key (first 128 bits of SHA-256).

    Parts are joined with "|" and encoded as UTF-8.  The same set of parts
    always produces the same key.  Safe as a deduplication key.

    Parameters
    ----------
    *parts : str components that together uniquely identify the object.

    Returns
    -------
    str — 32 lowercase hex characters.
    """
    raw = "|".join(str(p).strip() for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _compute_graph_fingerprint(
    nodes : Sequence["AttackGraphNode"],
    edges : Sequence["AttackGraphEdge"],
) -> str:
    """
    Compute a deterministic 32-character fingerprint for an entire graph.

    Algorithm
    ---------
    1. Collect all nodeKeys and sort them lexicographically.
    2. Collect all edgeKeys and sort them lexicographically.
    3. Concatenate as ``"N:<key>,…|E:<key>,…"`` and SHA-256 hash the result.
    4. Return the first 32 hex characters (128 bits — collision-safe).

    Why sorted?
    -----------
    Insertion order must not affect the fingerprint.  Two graphs with the
    exact same nodes and edges (regardless of the order they were added)
    must always produce the same fingerprint.  This makes the fingerprint
    safe for:

    - **AI diff detection** — compare two fingerprints to know instantly
      whether a graph changed without iterating over every node/edge.
    - **Timeline snapshots** — store the fingerprint alongside each graph
      version; a changed fingerprint means a topology change occurred.
    - **Report deduplication** — identical fingerprint → identical graph →
      no need to re-render or re-analyse.
    - **Cache keys** — use as a Redis / in-memory cache key for derived
      products (attack paths, risk summaries, MITRE mappings).

    Empty graph
    -----------
    Returns a stable all-zero 32-char string: ``"00000000000000000000000000000000"``.
    This is intentional — it is a valid fingerprint that means "empty graph"
    and is distinct from any non-empty graph's fingerprint.

    Parameters
    ----------
    nodes : sequence of AttackGraphNode.
    edges : sequence of AttackGraphEdge.

    Returns
    -------
    str — 32 lowercase hex characters.
    """
    if not nodes and not edges:
        return "0" * 32

    sorted_node_keys = sorted(n.nodeKey for n in nodes)
    sorted_edge_keys = sorted(e.edgeKey for e in edges)

    node_part = "N:" + ",".join(sorted_node_keys)
    edge_part = "E:" + ",".join(sorted_edge_keys)
    raw       = node_part + "|" + edge_part

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class GraphNodeTypeEnum(str, Enum):
    """
    All supported graph node types.

    Each value represents a category of observable entity in the
    investigation.  Nodes are typed so that rendering, risk scoring, and
    AI reasoning can behave differently per category.
    """
    ASSET         = "ASSET"
    EVIDENCE      = "EVIDENCE"
    FINDING       = "FINDING"
    ALERT         = "ALERT"
    MITRE         = "MITRE"
    DOMAIN        = "DOMAIN"
    IP            = "IP"
    URL           = "URL"
    HASH          = "HASH"
    EMAIL         = "EMAIL"
    USER          = "USER"
    PROCESS       = "PROCESS"
    SERVICE       = "SERVICE"
    PORT          = "PORT"
    EXTERNAL_HOST = "EXTERNAL_HOST"
    UNKNOWN       = "UNKNOWN"


class GraphEdgeTypeEnum(str, Enum):
    """
    All supported graph edge types.

    Each value represents a semantic relationship between two nodes.
    Edge types are designed to cover the full MITRE ATT&CK and network
    forensics vocabulary without overlapping.
    """
    COMMUNICATES_WITH  = "COMMUNICATES_WITH"
    RESOLVES_TO        = "RESOLVES_TO"
    GENERATED          = "GENERATED"
    USES               = "USES"
    DOWNLOADS          = "DOWNLOADS"
    CONNECTS_TO        = "CONNECTS_TO"
    AUTHENTICATES_TO   = "AUTHENTICATES_TO"
    SCANNED            = "SCANNED"
    TRIGGERED          = "TRIGGERED"
    RELATED_TO         = "RELATED_TO"
    OBSERVED_IN        = "OBSERVED_IN"
    INDICATES          = "INDICATES"
    EXPLOITS           = "EXPLOITS"
    HOSTS              = "HOSTS"


# ---------------------------------------------------------------------------
# AttackGraphNode
# ---------------------------------------------------------------------------

class AttackGraphNode(BaseModel):
    """
    A single, immutable node in the attack graph.

    Every observable entity — asset, evidence, finding, indicator, etc. —
    is represented as one AttackGraphNode.

    Fields
    ------
    nodeId       : 32-char SHA-256 hex key (same as nodeKey for direct lookup).
    nodeKey      : 32-char deterministic SHA-256 key derived from nodeType
                   and the natural identity of the entity.
                   Same logical entity always receives the same key.
                   Used as the canonical deduplication key.
    nodeType     : GraphNodeTypeEnum — semantic category of this node.
    label        : short machine-readable label (e.g. "192.168.1.1", "cmd.exe").
    displayName  : human-readable display name shown in UI.
    riskScore    : 0–100 risk score.  Higher = more dangerous.
    confidence   : 0–100 confidence that this node's identity is correct.
    metadata     : arbitrary extension dict.  Never mutated after construction.
    createdAt    : UTC datetime this node was constructed.
    """
    nodeId      : str
    nodeKey     : str
    nodeType    : GraphNodeTypeEnum
    label       : str
    displayName : str
    riskScore   : int                   = Field(ge=0, le=100, default=0)
    confidence  : int                   = Field(ge=0, le=100, default=0)
    metadata    : Dict[str, Any]        = Field(default_factory=dict)
    createdAt   : datetime              = Field(
                      default_factory=lambda: datetime.now(timezone.utc)
                  )

    class Config:
        frozen = True   # immutable after construction


# ---------------------------------------------------------------------------
# AttackGraphEdge
# ---------------------------------------------------------------------------

class AttackGraphEdge(BaseModel):
    """
    A single, immutable directed edge in the attack graph.

    An edge connects two AttackGraphNode objects and carries a typed
    semantic relationship and optional back-references to source data.

    Fields
    ------
    edgeId         : 32-char SHA-256 hex key (same as edgeKey).
    edgeKey        : 32-char deterministic SHA-256 key derived from
                     (sourceNodeId, targetNodeId, edgeType).
                     Same source → target with same type always produces the
                     same key.
    sourceNodeId   : nodeKey of the originating node.
    targetNodeId   : nodeKey of the destination node.
    edgeType       : GraphEdgeTypeEnum — semantic type of the relationship.
    confidence     : 0–100 confidence in this edge's validity.
    relationshipId : optional back-reference to a Relationship record.
    evidenceId     : optional back-reference to an EvidenceRecord.
    findingId      : optional back-reference to a Finding record.
    metadata       : arbitrary extension dict.
    createdAt      : UTC datetime this edge was constructed.
    """
    edgeId         : str
    edgeKey        : str
    sourceNodeId   : str
    targetNodeId   : str
    edgeType       : GraphEdgeTypeEnum
    confidence     : int                = Field(ge=0, le=100, default=0)
    relationshipId : Optional[str]      = None
    evidenceId     : Optional[str]      = None
    findingId      : Optional[str]      = None
    metadata       : Dict[str, Any]     = Field(default_factory=dict)
    createdAt      : datetime           = Field(
                         default_factory=lambda: datetime.now(timezone.utc)
                     )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# AttackGraphStatistics
# ---------------------------------------------------------------------------

class AttackGraphStatistics(BaseModel):
    """
    Aggregate statistics computed over an AttackGraph.

    Fields
    ------
    totalNodes          : total node count.
    totalEdges          : total edge count.
    nodesByType         : { GraphNodeTypeEnum.value → count }
    edgesByType         : { GraphEdgeTypeEnum.value → count }
    highestRiskNode     : nodeKey of the node with the highest riskScore,
                          or None if the graph has no nodes.
    averageDegree       : mean (in-degree + out-degree) across all nodes.
                          0.0 for empty graphs.
    connectedComponents : number of weakly connected components.
                          (Edges are treated as undirected for this count.)
    isolatedNodes       : count of nodes with degree 0 (no edges at all).
    """
    totalNodes          : int               = 0
    totalEdges          : int               = 0
    nodesByType         : Dict[str, int]    = Field(default_factory=dict)
    edgesByType         : Dict[str, int]    = Field(default_factory=dict)
    highestRiskNode     : Optional[str]     = None
    averageDegree       : float             = 0.0
    connectedComponents : int               = 0
    isolatedNodes       : int               = 0

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# GraphBuildMetadata — provenance and performance record for one graph build
# ---------------------------------------------------------------------------

class GraphBuildMetadata(BaseModel):
    """
    Records how and from what source data a graph was assembled.

    This model gives the AI Copilot and human analysts a precise,
    machine-readable description of a graph's provenance — e.g.
    "Graph built from 12 Assets, 97 Evidence, 43 Relationships, 6 Findings,
    2 MITRE techniques" — without having to count nodes by type at query time.

    It also records the wall-clock cost of each build phase so that
    performance regressions can be detected during CI or live analysis.

    Fields
    ------
    buildDurationMs    : total wall-clock time to assemble the graph (ms).
                         Includes node build, edge build, and statistics.
    nodeBuildCount     : number of nodes fed into build_graph().
                         May differ from statistics.totalNodes if duplicates
                         were resolved before calling build_graph().
    edgeBuildCount     : number of edges fed into build_graph().
    statisticsBuildMs  : wall-clock time spent in build_statistics() (ms).
    builderVersion     : ATTACK_GRAPH_ENGINE_VERSION at build time.
    sourceCount        : breakdown of source-object counts keyed by source
                         type name.  Callers populate this to explain what
                         went into the graph.  Recommended keys:

                           "assets"        — Asset records included
                           "evidence"      — EvidenceRecord objects linked
                           "relationships" — Relationship objects translated
                           "findings"      — Finding objects represented
                           "alerts"        — Alert objects included
                           "mitre"         — MITRE technique nodes added

                         Any key is valid; the schema is intentionally open.
                         AI Copilot reads this dict to generate the
                         "Graph built from …" summary line.

    Example
    -------
    GraphBuildMetadata(
        buildDurationMs   = 42,
        nodeBuildCount    = 112,
        edgeBuildCount    = 87,
        statisticsBuildMs = 3,
        builderVersion    = "attack-graph-v1",
        sourceCount       = {
            "assets"        : 12,
            "evidence"      : 97,
            "relationships" : 43,
            "findings"      : 6,
            "mitre"         : 2,
        },
    )
    """
    buildDurationMs   : int              = 0
    nodeBuildCount    : int              = 0
    edgeBuildCount    : int              = 0
    statisticsBuildMs : int              = 0
    builderVersion    : str              = ATTACK_GRAPH_ENGINE_VERSION
    sourceCount       : Dict[str, int]   = Field(default_factory=dict)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# AttackGraph — root container
# ---------------------------------------------------------------------------

class AttackGraph(BaseModel):
    """
    The canonical, immutable attack graph produced by this engine.

    This object is the single source of truth for the investigation graph
    and will be consumed by all future AI features (A4.0.2+).

    Fields
    ------
    nodes            : list of AttackGraphNode objects.
    edges            : list of AttackGraphEdge objects.
    statistics       : AttackGraphStatistics computed at build time.
    graphFingerprint : 32-char deterministic SHA-256 key over the graph's
                       topology (sorted nodeKeys + sorted edgeKeys).
                       Changes if and only if the set of nodes or edges
                       changes.  Used for:
                         - AI diff detection ("did the graph change?")
                         - Timeline snapshots (fingerprint per version)
                         - Report / cache deduplication
                       Same nodes + same edges → same fingerprint, always.
    buildMetadata    : GraphBuildMetadata — provenance, performance, and
                       source-object breakdown for this build.
    engineVersion    : ATTACK_GRAPH_ENGINE_VERSION at construction.
    createdAt        : UTC datetime this graph was assembled.
    """
    nodes            : List[AttackGraphNode]   = Field(default_factory=list)
    edges            : List[AttackGraphEdge]   = Field(default_factory=list)
    statistics       : AttackGraphStatistics   = Field(
                           default_factory=AttackGraphStatistics
                       )
    graphFingerprint : str                     = "0" * 32
    buildMetadata    : GraphBuildMetadata      = Field(
                           default_factory=GraphBuildMetadata
                       )
    engineVersion    : str                     = ATTACK_GRAPH_ENGINE_VERSION
    createdAt        : datetime                = Field(
                           default_factory=lambda: datetime.now(timezone.utc)
                       )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Builder: build_node()
# ---------------------------------------------------------------------------

def build_node(
    node_type    : GraphNodeTypeEnum,
    label        : str,
    *,
    display_name : Optional[str]        = None,
    risk_score   : int                  = 0,
    confidence   : int                  = 0,
    metadata     : Optional[Dict[str, Any]] = None,
    namespace    : str                  = "",
) -> AttackGraphNode:
    """
    Build a single AttackGraphNode with a deterministic key.

    The nodeKey (and nodeId) are derived from::

        SHA-256(namespace | nodeType.value | label)[:32]

    This guarantees that the same logical entity always receives the same
    key regardless of when or how many times build_node() is called.

    Parameters
    ----------
    node_type    : GraphNodeTypeEnum — category of this node.
    label        : natural identity of the entity (e.g. an IP address, hash,
                   hostname).  Used as the key input.  Must be non-empty.
    display_name : human-readable name; defaults to label if not supplied.
    risk_score   : 0–100 risk score.  Clamped to [0, 100].
    confidence   : 0–100 confidence.  Clamped to [0, 100].
    metadata     : arbitrary extension dict; copied, never mutated.
    namespace    : optional scope prefix that isolates keys across projects
                   or capture sessions (e.g. a project ID or capture UUID).

    Returns
    -------
    AttackGraphNode (frozen / immutable)

    Raises
    ------
    ValueError : if label is empty after stripping.
    """
    clean_label = str(label).strip()
    if not clean_label:
        raise ValueError("build_node: label must not be empty.")

    node_key = _sha256_key(namespace, node_type.value, clean_label)

    return AttackGraphNode(
        nodeId      = node_key,
        nodeKey     = node_key,
        nodeType    = node_type,
        label       = clean_label,
        displayName = str(display_name).strip() if display_name else clean_label,
        riskScore   = max(0, min(100, int(risk_score))),
        confidence  = max(0, min(100, int(confidence))),
        metadata    = dict(metadata) if metadata else {},
    )


# ---------------------------------------------------------------------------
# Builder: build_edge()
# ---------------------------------------------------------------------------

def build_edge(
    source_node_id  : str,
    target_node_id  : str,
    edge_type       : GraphEdgeTypeEnum,
    *,
    confidence      : int                   = 0,
    relationship_id : Optional[str]         = None,
    evidence_id     : Optional[str]         = None,
    finding_id      : Optional[str]         = None,
    metadata        : Optional[Dict[str, Any]] = None,
) -> AttackGraphEdge:
    """
    Build a single AttackGraphEdge with a deterministic key.

    The edgeKey (and edgeId) are derived from::

        SHA-256(sourceNodeId | targetNodeId | edgeType.value)[:32]

    This means that re-adding the same directed relationship between the
    same two nodes always yields the same edge key — safe for deduplication.

    Parameters
    ----------
    source_node_id  : nodeKey of the originating node.
    target_node_id  : nodeKey of the destination node.
    edge_type       : GraphEdgeTypeEnum — semantic type.
    confidence      : 0–100. Clamped to [0, 100].
    relationship_id : optional back-reference to a Relationship record.
    evidence_id     : optional back-reference to an EvidenceRecord.
    finding_id      : optional back-reference to a Finding record.
    metadata        : arbitrary extension dict; copied, never mutated.

    Returns
    -------
    AttackGraphEdge (frozen / immutable)

    Raises
    ------
    ValueError : if source_node_id or target_node_id is empty.
    """
    src = str(source_node_id).strip()
    tgt = str(target_node_id).strip()

    if not src:
        raise ValueError("build_edge: source_node_id must not be empty.")
    if not tgt:
        raise ValueError("build_edge: target_node_id must not be empty.")

    edge_key = _sha256_key(src, tgt, edge_type.value)

    return AttackGraphEdge(
        edgeId         = edge_key,
        edgeKey        = edge_key,
        sourceNodeId   = src,
        targetNodeId   = tgt,
        edgeType       = edge_type,
        confidence     = max(0, min(100, int(confidence))),
        relationshipId = relationship_id,
        evidenceId     = evidence_id,
        findingId      = finding_id,
        metadata       = dict(metadata) if metadata else {},
    )


# ---------------------------------------------------------------------------
# Builder: build_statistics()
# ---------------------------------------------------------------------------

def build_statistics(
    nodes : Sequence[AttackGraphNode],
    edges : Sequence[AttackGraphEdge],
) -> AttackGraphStatistics:
    """
    Compute AttackGraphStatistics from a collection of nodes and edges.

    All computations are O(n) or O(n + m) where n = nodes, m = edges.

    Algorithm
    ---------
    1. Count nodes by type (O(n)).
    2. Count edges by type (O(m)).
    3. Find highest-risk node (O(n)).
    4. Compute degree per node (O(m)).
    5. Compute average degree (O(n)).
    6. Count isolated nodes — degree == 0 (O(n)).
    7. Count weakly connected components via BFS/union-find (O(n + m)).

    Parameters
    ----------
    nodes : sequence of AttackGraphNode.
    edges : sequence of AttackGraphEdge.

    Returns
    -------
    AttackGraphStatistics (frozen / immutable)
    """
    if not nodes:
        return AttackGraphStatistics(
            totalNodes=0,
            totalEdges=len(edges),
        )

    # 1. Count nodes by type
    nodes_by_type: Dict[str, int] = defaultdict(int)
    for n in nodes:
        nodes_by_type[n.nodeType.value] += 1

    # 2. Count edges by type
    edges_by_type: Dict[str, int] = defaultdict(int)
    for e in edges:
        edges_by_type[e.edgeType.value] += 1

    # 3. Highest-risk node (first max in case of tie, stable by iteration order)
    highest_risk_node: Optional[str] = None
    max_risk = -1
    for n in nodes:
        if n.riskScore > max_risk:
            max_risk = n.riskScore
            highest_risk_node = n.nodeKey

    # 4. Degree per node (undirected: count both source and target)
    degree: Dict[str, int] = defaultdict(int)
    # Initialise all nodes at 0 so isolated nodes appear in the map
    node_key_set = {n.nodeKey for n in nodes}
    for key in node_key_set:
        degree[key] = 0
    for e in edges:
        if e.sourceNodeId in node_key_set:
            degree[e.sourceNodeId] += 1
        if e.targetNodeId in node_key_set:
            degree[e.targetNodeId] += 1

    # 5. Average degree
    total_degree = sum(degree[k] for k in node_key_set)
    average_degree = total_degree / len(nodes) if nodes else 0.0

    # 6. Isolated nodes
    isolated_nodes = sum(1 for k in node_key_set if degree[k] == 0)

    # 7. Weakly connected components (BFS over undirected adjacency)
    #    Build adjacency list from edges, treating them as undirected.
    adj: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        if e.sourceNodeId in node_key_set and e.targetNodeId in node_key_set:
            adj[e.sourceNodeId].append(e.targetNodeId)
            adj[e.targetNodeId].append(e.sourceNodeId)

    visited: set = set()
    components = 0
    for key in node_key_set:
        if key not in visited:
            # BFS from this unvisited node
            components += 1
            queue: deque = deque([key])
            visited.add(key)
            while queue:
                current = queue.popleft()
                for neighbour in adj[current]:
                    if neighbour not in visited:
                        visited.add(neighbour)
                        queue.append(neighbour)

    return AttackGraphStatistics(
        totalNodes          = len(nodes),
        totalEdges          = len(edges),
        nodesByType         = dict(nodes_by_type),
        edgesByType         = dict(edges_by_type),
        highestRiskNode     = highest_risk_node,
        averageDegree       = round(average_degree, 4),
        connectedComponents = components,
        isolatedNodes       = isolated_nodes,
    )


# ---------------------------------------------------------------------------
# Builder: build_graph()
# ---------------------------------------------------------------------------

def build_graph(
    nodes         : Sequence[AttackGraphNode],
    edges         : Sequence[AttackGraphEdge],
    *,
    source_count  : Optional[Dict[str, int]] = None,
) -> AttackGraph:
    """
    Assemble an AttackGraph from node and edge collections.

    Nodes are sorted (riskScore DESC, nodeType, displayName).
    Edges are sorted (confidence DESC, edgeType).
    Statistics are computed from the provided inputs.
    A deterministic graphFingerprint is derived from sorted nodeKeys + edgeKeys.
    A GraphBuildMetadata record captures provenance and wall-clock timings.

    Parameters
    ----------
    nodes        : any sequence of AttackGraphNode objects.
    edges        : any sequence of AttackGraphEdge objects.
    source_count : optional dict describing the source objects that produced
                   this graph (e.g. {"assets": 12, "evidence": 97}).
                   Forwarded verbatim into GraphBuildMetadata.sourceCount.
                   AI Copilot uses this to generate the "Graph built from …"
                   summary.  Any keys are accepted; no validation is applied.

    Returns
    -------
    AttackGraph (frozen / immutable)
    """
    t_start = time.monotonic_ns()

    sorted_nodes  = sort_nodes(list(nodes))
    sorted_edges  = sort_edges(list(edges))

    t_stats_start = time.monotonic_ns()
    stats         = build_statistics(sorted_nodes, sorted_edges)
    t_stats_end   = time.monotonic_ns()

    fingerprint   = _compute_graph_fingerprint(sorted_nodes, sorted_edges)

    t_end = time.monotonic_ns()

    build_meta = GraphBuildMetadata(
        buildDurationMs   = max(0, round((t_end - t_start) / 1_000_000)),
        nodeBuildCount    = len(sorted_nodes),
        edgeBuildCount    = len(sorted_edges),
        statisticsBuildMs = max(0, round((t_stats_end - t_stats_start) / 1_000_000)),
        builderVersion    = ATTACK_GRAPH_ENGINE_VERSION,
        sourceCount       = dict(source_count) if source_count else {},
    )

    return AttackGraph(
        nodes            = sorted_nodes,
        edges            = sorted_edges,
        statistics       = stats,
        graphFingerprint = fingerprint,
        buildMetadata    = build_meta,
        engineVersion    = ATTACK_GRAPH_ENGINE_VERSION,
    )


# ---------------------------------------------------------------------------
# Utility: sort_nodes()
# ---------------------------------------------------------------------------

def sort_nodes(nodes: List[AttackGraphNode]) -> List[AttackGraphNode]:
    """
    Sort nodes by: riskScore DESC, nodeType ASC, displayName ASC.

    This ordering surfaces the most dangerous nodes first, then provides
    a stable alphabetical fallback for equal-risk nodes.

    Parameters
    ----------
    nodes : list of AttackGraphNode objects.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        nodes,
        key=lambda n: (-n.riskScore, n.nodeType.value, n.displayName.lower()),
    )


# ---------------------------------------------------------------------------
# Utility: sort_edges()
# ---------------------------------------------------------------------------

def sort_edges(edges: List[AttackGraphEdge]) -> List[AttackGraphEdge]:
    """
    Sort edges by: confidence DESC, edgeType ASC.

    High-confidence edges are prioritised for rendering and AI reasoning.

    Parameters
    ----------
    edges : list of AttackGraphEdge objects.

    Returns
    -------
    New sorted list (input is not mutated).
    """
    return sorted(
        edges,
        key=lambda e: (-e.confidence, e.edgeType.value),
    )


# ---------------------------------------------------------------------------
# Utility: group_nodes()
# ---------------------------------------------------------------------------

def group_nodes(
    nodes : Sequence[AttackGraphNode],
) -> Dict[str, List[AttackGraphNode]]:
    """
    Group nodes by their nodeType value.

    Parameters
    ----------
    nodes : sequence of AttackGraphNode objects.

    Returns
    -------
    Dict mapping GraphNodeTypeEnum.value → list of AttackGraphNode.
    The lists are sorted (riskScore DESC, displayName ASC) within each group.
    """
    groups: Dict[str, List[AttackGraphNode]] = defaultdict(list)
    for n in nodes:
        groups[n.nodeType.value].append(n)
    return {
        k: sorted(v, key=lambda n: (-n.riskScore, n.displayName.lower()))
        for k, v in groups.items()
    }


# ---------------------------------------------------------------------------
# Utility: group_edges()
# ---------------------------------------------------------------------------

def group_edges(
    edges : Sequence[AttackGraphEdge],
) -> Dict[str, List[AttackGraphEdge]]:
    """
    Group edges by their edgeType value.

    Parameters
    ----------
    edges : sequence of AttackGraphEdge objects.

    Returns
    -------
    Dict mapping GraphEdgeTypeEnum.value → list of AttackGraphEdge.
    The lists are sorted (confidence DESC) within each group.
    """
    groups: Dict[str, List[AttackGraphEdge]] = defaultdict(list)
    for e in edges:
        groups[e.edgeType.value].append(e)
    return {
        k: sorted(v, key=lambda e: -e.confidence)
        for k, v in groups.items()
    }


# ---------------------------------------------------------------------------
# Utility: filter_nodes()
# ---------------------------------------------------------------------------

def filter_nodes(
    nodes       : Sequence[AttackGraphNode],
    *,
    node_type   : Optional[GraphNodeTypeEnum] = None,
    min_risk    : Optional[int]               = None,
    max_risk    : Optional[int]               = None,
    min_conf    : Optional[int]               = None,
    label_contains : Optional[str]            = None,
) -> List[AttackGraphNode]:
    """
    Filter nodes by one or more optional predicates.

    All supplied predicates are ANDed together.

    Parameters
    ----------
    nodes          : input sequence.
    node_type      : keep only nodes of this type.
    min_risk       : keep only nodes with riskScore >= min_risk.
    max_risk       : keep only nodes with riskScore <= max_risk.
    min_conf       : keep only nodes with confidence >= min_conf.
    label_contains : keep only nodes whose label contains this substring
                     (case-insensitive).

    Returns
    -------
    New filtered list; original is not mutated.
    """
    result: List[AttackGraphNode] = []
    search = label_contains.lower() if label_contains else None

    for n in nodes:
        if node_type is not None and n.nodeType != node_type:
            continue
        if min_risk is not None and n.riskScore < min_risk:
            continue
        if max_risk is not None and n.riskScore > max_risk:
            continue
        if min_conf is not None and n.confidence < min_conf:
            continue
        if search is not None and search not in n.label.lower():
            continue
        result.append(n)

    return result


# ---------------------------------------------------------------------------
# Utility: filter_edges()
# ---------------------------------------------------------------------------

def filter_edges(
    edges           : Sequence[AttackGraphEdge],
    *,
    edge_type       : Optional[GraphEdgeTypeEnum] = None,
    source_node_id  : Optional[str]               = None,
    target_node_id  : Optional[str]               = None,
    min_confidence  : Optional[int]               = None,
) -> List[AttackGraphEdge]:
    """
    Filter edges by one or more optional predicates.

    All supplied predicates are ANDed together.

    Parameters
    ----------
    edges          : input sequence.
    edge_type      : keep only edges of this type.
    source_node_id : keep only edges originating from this node key.
    target_node_id : keep only edges pointing to this node key.
    min_confidence : keep only edges with confidence >= min_confidence.

    Returns
    -------
    New filtered list; original is not mutated.
    """
    result: List[AttackGraphEdge] = []

    for e in edges:
        if edge_type is not None and e.edgeType != edge_type:
            continue
        if source_node_id is not None and e.sourceNodeId != source_node_id:
            continue
        if target_node_id is not None and e.targetNodeId != target_node_id:
            continue
        if min_confidence is not None and e.confidence < min_confidence:
            continue
        result.append(e)

    return result


# ---------------------------------------------------------------------------
# Utility: find_node()
# ---------------------------------------------------------------------------

def find_node(
    nodes    : Sequence[AttackGraphNode],
    node_key : str,
) -> Optional[AttackGraphNode]:
    """
    Find a node by its nodeKey (exact match).

    O(n) linear scan — suitable for in-memory graphs.  For repeated
    lookups over large graphs, build a dict from group_nodes() instead.

    Parameters
    ----------
    nodes    : sequence of AttackGraphNode.
    node_key : nodeKey to find.

    Returns
    -------
    AttackGraphNode if found, None otherwise.
    """
    target = str(node_key).strip()
    for n in nodes:
        if n.nodeKey == target:
            return n
    return None


# ---------------------------------------------------------------------------
# Utility: find_edge()
# ---------------------------------------------------------------------------

def find_edge(
    edges    : Sequence[AttackGraphEdge],
    edge_key : str,
) -> Optional[AttackGraphEdge]:
    """
    Find an edge by its edgeKey (exact match).

    O(m) linear scan.

    Parameters
    ----------
    edges    : sequence of AttackGraphEdge.
    edge_key : edgeKey to find.

    Returns
    -------
    AttackGraphEdge if found, None otherwise.
    """
    target = str(edge_key).strip()
    for e in edges:
        if e.edgeKey == target:
            return e
    return None


# ===========================================================================
# Phase A4.0.2 — Attack Graph Builder Pipeline
# ===========================================================================
# Extends the A4.0.1 foundation without modifying any existing model.
# Accepts typed Pydantic objects (AssetRecord, Relationship, EvidenceRecord)
# and plain dicts (Finding, Alert, MITRE technique, Timeline event) using
# duck-typed _get() helpers so every input format is handled uniformly.
#
# Inputs accepted:
#   assets        : List[AssetRecord | dict]
#   relationships : List[Relationship | dict]
#   evidence      : List[EvidenceRecord | dict]
#   findings      : List[dict]
#   alerts        : List[dict]
#   mitre         : List[dict]   (from mitre_service.map_to_mitre)
#   timeline      : List[dict]   (from timeline_service)
#
# All inputs are optional — missing collections behave as empty lists.
# No existing service is imported here to avoid circular dependencies.
# ===========================================================================


# ---------------------------------------------------------------------------
# GraphValidationResult — result of validate_graph()
# ---------------------------------------------------------------------------

class GraphValidationResult(BaseModel):
    """
    Result returned by validate_graph().

    Fields
    ------
    valid          : True iff errors is empty.
    errors         : fatal problems (dangling edges, etc.).
    warnings       : non-fatal observations (e.g. isolated nodes).
    duplicateNodes : list of nodeKey values that appeared more than once
                     before deduplication (informational).
    duplicateEdges : list of edgeKey values that appeared more than once
                     before deduplication (informational).
    danglingEdges  : list of edgeKey values whose source or target nodeKey
                     does not exist in the node set.
    """
    valid          : bool       = True
    errors         : List[str]  = Field(default_factory=list)
    warnings       : List[str]  = Field(default_factory=list)
    duplicateNodes : List[str]  = Field(default_factory=list)
    duplicateEdges : List[str]  = Field(default_factory=list)
    danglingEdges  : List[str]  = Field(default_factory=list)

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Internal duck-typed accessor — handles both Pydantic models and plain dicts
# ---------------------------------------------------------------------------

def _get(obj: Any, *keys: str, default: Any = None) -> Any:
    """
    Retrieve a value from a Pydantic model or a plain dict.

    Tries each key in order and returns the first non-None value found.
    Falls back to `default` if no key matches.

    This allows every internal builder to accept both typed objects and
    plain dicts without separate code paths.

    Parameters
    ----------
    obj     : Pydantic BaseModel instance or dict.
    *keys   : attribute / key names to try, in priority order.
    default : value to return if nothing matched.
    """
    for k in keys:
        if isinstance(obj, dict):
            v = obj.get(k)
        else:
            v = getattr(obj, k, None)
        if v is not None:
            return v
    return default


# ---------------------------------------------------------------------------
# Severity → risk score mapping (used for findings and alerts)
# ---------------------------------------------------------------------------

_SEVERITY_RISK: Dict[str, int] = {
    "critical" : 100,
    "high"     : 80,
    "medium"   : 55,
    "low"      : 30,
    "info"     : 10,
    "unknown"  : 20,
}


def _severity_to_risk(severity: Any) -> int:
    """Convert a severity string to a 0–100 risk score."""
    return _SEVERITY_RISK.get(str(severity).lower().strip(), 20)


# ---------------------------------------------------------------------------
# Internal node builders
# ---------------------------------------------------------------------------

def build_asset_nodes(
    assets    : Sequence[Any],
    namespace : str = "",
) -> List[AttackGraphNode]:
    """
    Build one ASSET node per AssetRecord (or asset dict).

    nodeKey = SHA-256(namespace | "ASSET" | asset.id)[:32]
    label   = asset.id
    risk    = asset.riskScore (float coerced to int, clamped 0–100)

    Parameters
    ----------
    assets    : list of AssetRecord Pydantic objects or plain dicts.
    namespace : optional scope prefix forwarded to build_node().

    Returns
    -------
    List[AttackGraphNode] — one node per asset; empty on empty input.
    """
    nodes: List[AttackGraphNode] = []
    for a in assets:
        asset_id = _get(a, "id")
        if not asset_id:
            continue
        risk = int(min(100, max(0, float(_get(a, "riskScore", "risk_score", default=0) or 0))))
        conf = int(min(100, max(0, float(_get(a, "confidence", default=0) or 0))))
        label = asset_id
        display = (
            _get(a, "hostname", "currentIp", "ipAddress", "macAddress")
            or _get(a, "deviceType")
            or asset_id
        )
        nodes.append(build_node(
            GraphNodeTypeEnum.ASSET,
            label,
            display_name = str(display),
            risk_score   = risk,
            confidence   = conf,
            namespace    = namespace,
            metadata     = {
                "assetId"    : asset_id,
                "deviceType" : _get(a, "deviceType"),
                "vendor"     : _get(a, "vendor"),
                "os"         : _get(a, "os"),
            },
        ))
    return nodes


def build_evidence_nodes(
    evidence  : Sequence[Any],
    namespace : str = "",
) -> List[AttackGraphNode]:
    """
    Build one EVIDENCE node per EvidenceRecord (or evidence dict).

    nodeKey = SHA-256(namespace | "EVIDENCE" | evidenceId)[:32]
    label   = evidenceId
    risk    = 0  (evidence carries no inherent risk; risk flows via edges)
    conf    = evidence.confidence

    Parameters
    ----------
    evidence  : list of EvidenceRecord Pydantic objects or plain dicts.
    namespace : optional scope prefix.

    Returns
    -------
    List[AttackGraphNode]
    """
    nodes: List[AttackGraphNode] = []
    for ev in evidence:
        ev_id = _get(ev, "evidenceId", "id", "evidence_id")
        if not ev_id:
            continue
        conf  = int(min(100, max(0, float(_get(ev, "confidence", default=0) or 0))))
        field = _get(ev, "fieldName", "field_name", "fieldValue", "field_value", default="")
        val   = _get(ev, "fieldValue", "field_value", default="")
        nodes.append(build_node(
            GraphNodeTypeEnum.EVIDENCE,
            str(ev_id),
            display_name = f"{field}={val}"[:80] if field else str(ev_id),
            risk_score   = 0,
            confidence   = conf,
            namespace    = namespace,
            metadata     = {
                "evidenceId" : ev_id,
                "fieldName"  : field,
                "fieldValue" : val,
                "assetId"    : _get(ev, "assetId", "asset_id"),
            },
        ))
    return nodes


def build_finding_nodes(
    findings  : Sequence[Any],
    namespace : str = "",
) -> List[AttackGraphNode]:
    """
    Build one FINDING node per finding dict (or Pydantic object).

    Findings come from alert_service.detect_iocs_from_data() as plain dicts
    with keys: severity, type, description, asset (optional).

    nodeKey = SHA-256(namespace | "FINDING" | title | severity)[:32]
    label   = type or title
    risk    = _severity_to_risk(severity)

    Parameters
    ----------
    findings  : list of finding dicts.
    namespace : optional scope prefix.

    Returns
    -------
    List[AttackGraphNode]
    """
    nodes: List[AttackGraphNode] = []
    for f in findings:
        title    = str(_get(f, "type", "title", default="Finding") or "Finding")
        severity = str(_get(f, "severity", default="unknown") or "unknown")
        desc     = str(_get(f, "description", default="") or "")
        label    = title
        nodes.append(build_node(
            GraphNodeTypeEnum.FINDING,
            label,
            display_name = f"[{severity.upper()}] {title}"[:80],
            risk_score   = _severity_to_risk(severity),
            confidence   = 70,
            namespace    = namespace,
            metadata     = {
                "severity"    : severity,
                "description" : desc,
                "asset"       : _get(f, "asset"),
            },
        ))
    return nodes


def build_alert_nodes(
    alerts    : Sequence[Any],
    namespace : str = "",
) -> List[AttackGraphNode]:
    """
    Build one ALERT node per alert dict (or Pydantic object).

    Alerts come from alert_service.generate_alerts_from_data() as plain dicts
    with keys: severity, title, description.

    nodeKey = SHA-256(namespace | "ALERT" | title | severity)[:32]
    label   = title
    risk    = _severity_to_risk(severity)

    Parameters
    ----------
    alerts    : list of alert dicts.
    namespace : optional scope prefix.

    Returns
    -------
    List[AttackGraphNode]
    """
    nodes: List[AttackGraphNode] = []
    for a in alerts:
        title    = str(_get(a, "title", "type", default="Alert") or "Alert")
        severity = str(_get(a, "severity", default="unknown") or "unknown")
        desc     = str(_get(a, "description", default="") or "")
        nodes.append(build_node(
            GraphNodeTypeEnum.ALERT,
            title,
            display_name = f"[{severity.upper()}] {title}"[:80],
            risk_score   = _severity_to_risk(severity),
            confidence   = 80,
            namespace    = namespace,
            metadata     = {
                "severity"    : severity,
                "description" : desc,
            },
        ))
    return nodes


def build_mitre_nodes(
    mitre     : Sequence[Any],
    namespace : str = "",
) -> List[AttackGraphNode]:
    """
    Build one MITRE node per technique dict (or Pydantic object).

    Techniques come from mitre_service.map_to_mitre() as plain dicts with
    keys: id, name, tactic, evidence_source.

    nodeKey = SHA-256(namespace | "MITRE" | technique_id)[:32]
    label   = technique_id  (e.g. "T1071.004")
    risk    = 70 (MITRE mappings are inherently high-signal)

    Parameters
    ----------
    mitre     : list of technique dicts.
    namespace : optional scope prefix.

    Returns
    -------
    List[AttackGraphNode]
    """
    nodes: List[AttackGraphNode] = []
    for t in mitre:
        tech_id = str(_get(t, "id", "technique_id", "techniqueId", default="") or "")
        if not tech_id:
            continue
        name   = str(_get(t, "name", default=tech_id) or tech_id)
        tactic = str(_get(t, "tactic", default="") or "")
        nodes.append(build_node(
            GraphNodeTypeEnum.MITRE,
            tech_id,
            display_name = f"{tech_id} — {name}"[:80],
            risk_score   = 70,
            confidence   = 90,
            namespace    = namespace,
            metadata     = {
                "techniqueId" : tech_id,
                "name"        : name,
                "tactic"      : tactic,
                "sources"     : _get(t, "evidence_source", "sources", default=[]) or [],
            },
        ))
    return nodes


# ---------------------------------------------------------------------------
# Internal edge builders
# ---------------------------------------------------------------------------

def build_relationship_edges(
    relationships : Sequence[Any],
    node_index    : Dict[str, AttackGraphNode],
    namespace     : str = "",
) -> List[AttackGraphEdge]:
    """
    Build COMMUNICATES_WITH edges from Relationship objects.

    Each Relationship maps to one directed edge:
        ASSET(sourceAssetId) → COMMUNICATES_WITH → ASSET(targetAssetId)

    Only emits edges where both source and target asset nodes already exist
    in node_index (keyed by the nodeKey derived from the asset id).

    Parameters
    ----------
    relationships : list of Relationship Pydantic objects or dicts.
    node_index    : dict of nodeKey → AttackGraphNode (built from asset nodes).
    namespace     : optional scope prefix used when computing nodeKeys.

    Returns
    -------
    List[AttackGraphEdge]
    """
    edges: List[AttackGraphEdge] = []
    for rel in relationships:
        src_id  = str(_get(rel, "sourceAssetId", "source_asset_id", "sourceId", default="") or "")
        tgt_id  = str(_get(rel, "targetAssetId", "target_asset_id", "targetId", default="") or "")
        if not src_id or not tgt_id:
            continue

        src_key = _sha256_key(namespace, GraphNodeTypeEnum.ASSET.value, src_id)
        tgt_key = _sha256_key(namespace, GraphNodeTypeEnum.ASSET.value, tgt_id)

        if src_key not in node_index or tgt_key not in node_index:
            continue

        conf     = int(min(100, max(0, float(_get(rel, "confidence", default=0) or 0))))
        rel_id   = str(_get(rel, "relationshipId", "id", default="") or "")
        ev_ids   = _get(rel, "evidenceIds", "evidence_ids", default=[]) or []

        edges.append(build_edge(
            src_key,
            tgt_key,
            GraphEdgeTypeEnum.COMMUNICATES_WITH,
            confidence      = conf,
            relationship_id = rel_id or None,
            metadata        = {
                "protocol"   : _get(rel, "protocol", default="UNKNOWN"),
                "port"       : _get(rel, "port"),
                "direction"  : str(_get(rel, "direction", default="UNKNOWN")),
                "evidenceIds": list(ev_ids)[:10],
            },
        ))
    return edges


def build_evidence_edges(
    evidence   : Sequence[Any],
    node_index : Dict[str, AttackGraphNode],
    namespace  : str = "",
) -> List[AttackGraphEdge]:
    """
    Build OBSERVED_IN edges linking evidence nodes back to their asset nodes.

        EVIDENCE(evidenceId) → OBSERVED_IN → ASSET(assetId)

    Skipped when assetId is None or the ASSET node does not exist.

    Parameters
    ----------
    evidence   : list of EvidenceRecord objects or dicts.
    node_index : nodeKey → AttackGraphNode.
    namespace  : optional scope prefix.

    Returns
    -------
    List[AttackGraphEdge]
    """
    edges: List[AttackGraphEdge] = []
    for ev in evidence:
        ev_id    = str(_get(ev, "evidenceId", "id", "evidence_id", default="") or "")
        asset_id = str(_get(ev, "assetId", "asset_id", default="") or "")
        if not ev_id or not asset_id:
            continue

        ev_key    = _sha256_key(namespace, GraphNodeTypeEnum.EVIDENCE.value, ev_id)
        asset_key = _sha256_key(namespace, GraphNodeTypeEnum.ASSET.value, asset_id)

        if ev_key not in node_index or asset_key not in node_index:
            continue

        conf = int(min(100, max(0, float(_get(ev, "confidence", default=60) or 60))))
        edges.append(build_edge(
            ev_key,
            asset_key,
            GraphEdgeTypeEnum.OBSERVED_IN,
            confidence  = conf,
            evidence_id = ev_id,
        ))
    return edges


def build_finding_edges(
    findings      : Sequence[Any],
    finding_nodes : List[AttackGraphNode],
    evidence_nodes: List[AttackGraphNode],
    node_index    : Dict[str, AttackGraphNode],
) -> List[AttackGraphEdge]:
    """
    Build INDICATES edges from every evidence node to every finding node
    that shares the same label/type text.

        EVIDENCE(ev) → INDICATES → FINDING(finding)

    Since findings are plain dicts with no ID linking them directly to
    evidence records, we emit a cross-product edge from each finding node
    to each evidence node that exists in the graph (bounded: only emitted
    when both finding nodes and evidence nodes are present).

    In practice this is intentionally broad — it tells the AI that the
    captured evidence collectively indicates these findings.

    Returns
    -------
    List[AttackGraphEdge]
    """
    edges: List[AttackGraphEdge] = []
    if not finding_nodes or not evidence_nodes:
        return edges

    for fn in finding_nodes:
        for en in evidence_nodes:
            if fn.nodeKey not in node_index or en.nodeKey not in node_index:
                continue
            edges.append(build_edge(
                en.nodeKey,
                fn.nodeKey,
                GraphEdgeTypeEnum.INDICATES,
                confidence = 60,
                metadata   = {"auto": True},
            ))
    return edges


def build_alert_edges(
    alert_nodes   : List[AttackGraphNode],
    finding_nodes : List[AttackGraphNode],
    node_index    : Dict[str, AttackGraphNode],
) -> List[AttackGraphEdge]:
    """
    Build TRIGGERED edges from finding nodes to alert nodes.

        FINDING(finding) → TRIGGERED → ALERT(alert)

    Emits a cross-product when both collections are non-empty, as alerts
    are generated from findings in the existing pipeline.

    Returns
    -------
    List[AttackGraphEdge]
    """
    edges: List[AttackGraphEdge] = []
    if not alert_nodes or not finding_nodes:
        return edges

    for fn in finding_nodes:
        for an in alert_nodes:
            if fn.nodeKey not in node_index or an.nodeKey not in node_index:
                continue
            edges.append(build_edge(
                fn.nodeKey,
                an.nodeKey,
                GraphEdgeTypeEnum.TRIGGERED,
                confidence = 70,
                metadata   = {"auto": True},
            ))
    return edges


def build_mitre_edges(
    mitre_nodes   : List[AttackGraphNode],
    finding_nodes : List[AttackGraphNode],
    node_index    : Dict[str, AttackGraphNode],
) -> List[AttackGraphEdge]:
    """
    Build USES edges from finding nodes to MITRE technique nodes.

        FINDING(finding) → USES → MITRE(technique)

    Indicates that the detected findings are consistent with the mapped
    MITRE ATT&CK technique.

    Returns
    -------
    List[AttackGraphEdge]
    """
    edges: List[AttackGraphEdge] = []
    if not mitre_nodes or not finding_nodes:
        return edges

    for fn in finding_nodes:
        for mn in mitre_nodes:
            if fn.nodeKey not in node_index or mn.nodeKey not in node_index:
                continue
            edges.append(build_edge(
                fn.nodeKey,
                mn.nodeKey,
                GraphEdgeTypeEnum.USES,
                confidence = 65,
                metadata   = {"auto": True},
            ))
    return edges


# ---------------------------------------------------------------------------
# Utility: merge_nodes()
# ---------------------------------------------------------------------------

def merge_nodes(
    *node_lists: List[AttackGraphNode],
) -> List[AttackGraphNode]:
    """
    Merge multiple node lists, keeping the first occurrence of each nodeKey.

    O(n) via dict insertion order.

    Parameters
    ----------
    *node_lists : any number of List[AttackGraphNode].

    Returns
    -------
    List[AttackGraphNode] — deduplicated, preserving first-seen order.
    """
    seen: Dict[str, AttackGraphNode] = {}
    for lst in node_lists:
        for n in lst:
            if n.nodeKey not in seen:
                seen[n.nodeKey] = n
    return list(seen.values())


# ---------------------------------------------------------------------------
# Utility: merge_edges()
# ---------------------------------------------------------------------------

def merge_edges(
    *edge_lists: List[AttackGraphEdge],
) -> List[AttackGraphEdge]:
    """
    Merge multiple edge lists, keeping the first occurrence of each edgeKey.

    O(m) via dict insertion order.

    Parameters
    ----------
    *edge_lists : any number of List[AttackGraphEdge].

    Returns
    -------
    List[AttackGraphEdge] — deduplicated, preserving first-seen order.
    """
    seen: Dict[str, AttackGraphEdge] = {}
    for lst in edge_lists:
        for e in lst:
            if e.edgeKey not in seen:
                seen[e.edgeKey] = e
    return list(seen.values())


# ---------------------------------------------------------------------------
# Utility: deduplicate_graph()
# ---------------------------------------------------------------------------

def deduplicate_graph(graph: AttackGraph) -> AttackGraph:
    """
    Return a new AttackGraph with all duplicate nodes and edges removed.

    Keeps the first occurrence of each nodeKey / edgeKey.
    Recomputes statistics and fingerprint on the clean collection.

    Parameters
    ----------
    graph : any AttackGraph (frozen).

    Returns
    -------
    New AttackGraph (frozen) with unique nodes and edges.
    """
    clean_nodes = merge_nodes(list(graph.nodes))
    clean_edges = merge_edges(list(graph.edges))
    return build_graph(clean_nodes, clean_edges)


# ---------------------------------------------------------------------------
# Utility: build_source_counts()
# ---------------------------------------------------------------------------

def build_source_counts(
    assets        : Sequence[Any],
    relationships : Sequence[Any],
    evidence      : Sequence[Any],
    findings      : Sequence[Any],
    alerts        : Sequence[Any],
    mitre         : Sequence[Any],
    timeline      : Sequence[Any],
) -> Dict[str, int]:
    """
    Build the GraphBuildMetadata.sourceCount dict from raw input counts.

    Always called by build_attack_graph() — callers never build this manually.

    Returns
    -------
    Dict with keys: assets, relationships, evidence, findings, alerts,
    mitre, timeline.  Zero values are included so the AI always sees the
    full breakdown.
    """
    return {
        "assets"        : len(assets),
        "relationships" : len(relationships),
        "evidence"      : len(evidence),
        "findings"      : len(findings),
        "alerts"        : len(alerts),
        "mitre"         : len(mitre),
        "timeline"      : len(timeline),
    }


# ---------------------------------------------------------------------------
# Utility: validate_graph()
# ---------------------------------------------------------------------------

def validate_graph(graph: AttackGraph) -> GraphValidationResult:
    """
    Validate an AttackGraph for structural integrity.

    Checks performed (all O(n) or O(m)):
    1. Duplicate nodeKeys in graph.nodes.
    2. Duplicate edgeKeys in graph.edges.
    3. Dangling edges — edges whose sourceNodeId or targetNodeId does not
       correspond to any node in graph.nodes.

    Parameters
    ----------
    graph : AttackGraph to validate.

    Returns
    -------
    GraphValidationResult (frozen / immutable).
    """
    errors         : List[str] = []
    warnings       : List[str] = []
    duplicate_nodes: List[str] = []
    duplicate_edges: List[str] = []
    dangling_edges : List[str] = []

    # 1. Check duplicate nodeKeys — O(n)
    seen_node_keys: Dict[str, int] = {}
    for n in graph.nodes:
        seen_node_keys[n.nodeKey] = seen_node_keys.get(n.nodeKey, 0) + 1

    node_key_set: set = set()
    for key, count in seen_node_keys.items():
        node_key_set.add(key)
        if count > 1:
            duplicate_nodes.append(key)
            errors.append(f"Duplicate nodeKey: {key} (appears {count} times)")

    # 2. Check duplicate edgeKeys — O(m)
    seen_edge_keys: Dict[str, int] = {}
    for e in graph.edges:
        seen_edge_keys[e.edgeKey] = seen_edge_keys.get(e.edgeKey, 0) + 1

    for key, count in seen_edge_keys.items():
        if count > 1:
            duplicate_edges.append(key)
            errors.append(f"Duplicate edgeKey: {key} (appears {count} times)")

    # 3. Check dangling edges — O(m)
    for e in graph.edges:
        if e.sourceNodeId not in node_key_set:
            dangling_edges.append(e.edgeKey)
            errors.append(
                f"Dangling edge {e.edgeKey}: sourceNodeId {e.sourceNodeId} not in node set"
            )
        elif e.targetNodeId not in node_key_set:
            dangling_edges.append(e.edgeKey)
            errors.append(
                f"Dangling edge {e.edgeKey}: targetNodeId {e.targetNodeId} not in node set"
            )

    # Warnings (non-fatal)
    if graph.statistics.isolatedNodes > 0:
        warnings.append(
            f"{graph.statistics.isolatedNodes} isolated node(s) have no edges."
        )

    return GraphValidationResult(
        valid          = len(errors) == 0,
        errors         = errors,
        warnings       = warnings,
        duplicateNodes = duplicate_nodes,
        duplicateEdges = duplicate_edges,
        danglingEdges  = deduplicate_list(dangling_edges),
    )


def deduplicate_list(items: List[str]) -> List[str]:
    """Return a deduplicated list preserving first-seen insertion order."""
    seen: Dict[str, None] = {}
    for item in items:
        seen[item] = None
    return list(seen.keys())


# ---------------------------------------------------------------------------
# Primary entry point: build_attack_graph()
# ---------------------------------------------------------------------------

def build_attack_graph(
    *,
    assets        : Optional[Sequence[Any]] = None,
    relationships : Optional[Sequence[Any]] = None,
    evidence      : Optional[Sequence[Any]] = None,
    findings      : Optional[Sequence[Any]] = None,
    alerts        : Optional[Sequence[Any]] = None,
    mitre         : Optional[Sequence[Any]] = None,
    timeline      : Optional[Sequence[Any]] = None,
    namespace     : str                     = "",
) -> AttackGraph:
    """
    Build a complete AttackGraph from any combination of input collections.

    This is the single primary entry point for Phase A4.0.2+.  It runs the
    full deterministic pipeline:

        Assets        → ASSET nodes
        Evidence      → EVIDENCE nodes
        Findings      → FINDING nodes
        Alerts        → ALERT nodes
        MITRE         → MITRE nodes
        Relationships → COMMUNICATES_WITH edges (Asset → Asset)
        Evidence      → OBSERVED_IN edges (Evidence → Asset)
        Findings      → INDICATES edges (Evidence → Finding)
        Alerts        → TRIGGERED edges (Finding → Alert)
        MITRE         → USES edges (Finding → MITRE)
        Deduplication → merge_nodes / merge_edges
        Statistics    → build_statistics()
        Fingerprint   → _compute_graph_fingerprint()
        Metadata      → GraphBuildMetadata (sourceCount + timings)

    All inputs are optional — missing collections behave as empty lists.

    Parameters
    ----------
    assets        : AssetRecord objects or asset dicts.
    relationships : Relationship objects or relationship dicts.
    evidence      : EvidenceRecord objects or evidence dicts.
    findings      : finding dicts from alert_service.detect_iocs_from_data().
    alerts        : alert dicts from alert_service.generate_alerts_from_data().
    mitre         : technique dicts from mitre_service.map_to_mitre().
    timeline      : timeline event dicts from timeline_service.
                    (Timeline events contribute to sourceCount only; they do
                    not currently generate nodes/edges — reserved for A4.0.3.)
    namespace     : optional scope prefix that isolates nodeKeys/edgeKeys
                    across projects or capture sessions.

    Returns
    -------
    AttackGraph (frozen / immutable)
    """
    _assets        = list(assets        or [])
    _relationships = list(relationships or [])
    _evidence      = list(evidence      or [])
    _findings      = list(findings      or [])
    _alerts        = list(alerts        or [])
    _mitre         = list(mitre         or [])
    _timeline      = list(timeline      or [])

    t_start = time.monotonic_ns()

    # ------------------------------------------------------------------
    # Stage 1 — Build all node collections
    # ------------------------------------------------------------------
    asset_nodes    = build_asset_nodes(_assets,    namespace)
    evidence_nodes = build_evidence_nodes(_evidence, namespace)
    finding_nodes  = build_finding_nodes(_findings, namespace)
    alert_nodes    = build_alert_nodes(_alerts,    namespace)
    mitre_nodes    = build_mitre_nodes(_mitre,     namespace)

    # Merge and deduplicate all nodes before building edges
    # (node_index is the O(1) lookup used by all edge builders)
    all_nodes  = merge_nodes(
        asset_nodes, evidence_nodes, finding_nodes, alert_nodes, mitre_nodes
    )
    node_index : Dict[str, AttackGraphNode] = {n.nodeKey: n for n in all_nodes}

    # ------------------------------------------------------------------
    # Stage 2 — Build all edge collections
    # ------------------------------------------------------------------
    rel_edges      = build_relationship_edges(_relationships, node_index, namespace)
    ev_edges       = build_evidence_edges(_evidence, node_index, namespace)
    finding_edges  = build_finding_edges(_findings, finding_nodes, evidence_nodes, node_index)
    alert_edges    = build_alert_edges(alert_nodes, finding_nodes, node_index)
    mitre_edges    = build_mitre_edges(mitre_nodes, finding_nodes, node_index)

    all_edges = merge_edges(
        rel_edges, ev_edges, finding_edges, alert_edges, mitre_edges
    )

    # ------------------------------------------------------------------
    # Stage 3 — sourceCount (automatic, never manual)
    # ------------------------------------------------------------------
    source_count = build_source_counts(
        _assets, _relationships, _evidence,
        _findings, _alerts, _mitre, _timeline,
    )

    t_end = time.monotonic_ns()

    # ------------------------------------------------------------------
    # Stage 4 — Assemble final graph via build_graph()
    # build_graph() handles: sort, statistics, fingerprint, buildMetadata
    # We pass total elapsed time explicitly via source_count; build_graph()
    # measures its own internal time for statisticsBuildMs.
    # ------------------------------------------------------------------
    graph = build_graph(all_nodes, all_edges, source_count=source_count)

    # Patch buildMetadata with the outer pipeline duration.
    # build_graph() only measures its own sort+stats work; we want the
    # full pipeline time from the first stage.
    total_ms = max(0, round((t_end - t_start) / 1_000_000))
    patched_meta = GraphBuildMetadata(
        buildDurationMs   = total_ms,
        nodeBuildCount    = graph.buildMetadata.nodeBuildCount,
        edgeBuildCount    = graph.buildMetadata.edgeBuildCount,
        statisticsBuildMs = graph.buildMetadata.statisticsBuildMs,
        builderVersion    = ATTACK_GRAPH_ENGINE_VERSION,
        sourceCount       = source_count,
    )

    # Re-assemble with corrected buildDurationMs (frozen model — must copy)
    return AttackGraph(
        nodes            = graph.nodes,
        edges            = graph.edges,
        statistics       = graph.statistics,
        graphFingerprint = graph.graphFingerprint,
        buildMetadata    = patched_meta,
        engineVersion    = ATTACK_GRAPH_ENGINE_VERSION,
    )
