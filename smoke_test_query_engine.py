"""
Smoke Test — Attack Graph Query Engine
=======================================
Phase A4.0.2

Builds a synthetic AttackGraph, then exercises every exported function in
attack_graph_query_service.py.  All assertions must pass for a green run.

Run with:
    python smoke_test_query_engine.py
"""

from __future__ import annotations

import sys

from core.constants import ATTACK_GRAPH_QUERY_ENGINE_VERSION
from services.attack_graph_service import (
    GraphEdgeTypeEnum,
    GraphNodeTypeEnum,
    build_edge,
    build_graph,
    build_node,
)
from services.attack_graph_query_service import (
    GraphQuery,
    all_paths,
    breadth_first_search,
    calculate_graph_metrics,
    connected_components,
    depth_first_search,
    filter_edges,
    filter_nodes,
    find_neighbors,
    find_two_hop_neighbors,
    highest_risk_path,
    isolated_nodes,
    lowest_confidence_path,
    query_by_confidence,
    query_by_label,
    query_by_node,
    query_by_risk,
    query_by_type,
    query_graph,
    reachable_nodes,
    search_edges,
    search_metadata,
    search_nodes,
    shortest_path,
    sort_edges,
    sort_nodes,
)

PASS = "\u2713"
FAIL = "\u2717"
_failures: list = []


def _assert(condition: bool, label: str) -> None:
    if condition:
        print(f"  {PASS}  {label}")
    else:
        print(f"  {FAIL}  FAILED: {label}")
        _failures.append(label)


# ---------------------------------------------------------------------------
# Build synthetic graph
# ---------------------------------------------------------------------------

print("\n=== Building synthetic graph ===\n")

# Nodes
n_attacker = build_node(GraphNodeTypeEnum.EXTERNAL_HOST, "10.0.0.1",
                        risk_score=90, confidence=85,
                        metadata={"role": "attacker"})
n_c2       = build_node(GraphNodeTypeEnum.IP,           "192.168.1.100",
                        risk_score=80, confidence=70)
n_victim   = build_node(GraphNodeTypeEnum.ASSET,        "workstation-7",
                        risk_score=60, confidence=90)
n_malware  = build_node(GraphNodeTypeEnum.HASH,         "abc123deadbeef",
                        risk_score=95, confidence=75)
n_domain   = build_node(GraphNodeTypeEnum.DOMAIN,       "evil.corp",
                        risk_score=85, confidence=65)
n_process  = build_node(GraphNodeTypeEnum.PROCESS,      "cmd.exe",
                        risk_score=50, confidence=80)
n_isolated = build_node(GraphNodeTypeEnum.UNKNOWN,      "orphan-node",
                        risk_score=10, confidence=20)
n_evidence = build_node(GraphNodeTypeEnum.EVIDENCE,     "pcap-evidence-1",
                        risk_score=30, confidence=60,
                        metadata={"source": "pcap"})

# Edges
e1 = build_edge(n_attacker.nodeKey, n_c2.nodeKey,
                GraphEdgeTypeEnum.COMMUNICATES_WITH, confidence=80)
e2 = build_edge(n_c2.nodeKey,      n_victim.nodeKey,
                GraphEdgeTypeEnum.CONNECTS_TO, confidence=70)
e3 = build_edge(n_victim.nodeKey,  n_malware.nodeKey,
                GraphEdgeTypeEnum.DOWNLOADS, confidence=60)
e4 = build_edge(n_attacker.nodeKey, n_domain.nodeKey,
                GraphEdgeTypeEnum.RESOLVES_TO, confidence=55)
e5 = build_edge(n_domain.nodeKey,  n_c2.nodeKey,
                GraphEdgeTypeEnum.RESOLVES_TO, confidence=65)
e6 = build_edge(n_victim.nodeKey,  n_process.nodeKey,
                GraphEdgeTypeEnum.USES, confidence=75)
e7 = build_edge(n_evidence.nodeKey, n_victim.nodeKey,
                GraphEdgeTypeEnum.OBSERVED_IN, confidence=50)

nodes = [n_attacker, n_c2, n_victim, n_malware, n_domain, n_process, n_isolated, n_evidence]
edges = [e1, e2, e3, e4, e5, e6, e7]

graph = build_graph(nodes, edges, source_count={"assets": 1, "evidence": 1})

print(f"  Graph nodes: {len(graph.nodes)}")
print(f"  Graph edges: {len(graph.edges)}")
print(f"  Fingerprint: {graph.graphFingerprint}")
print()

# ---------------------------------------------------------------------------
# 1. Node queries
# ---------------------------------------------------------------------------
print("=== 1. Node queries ===\n")

result = query_by_node(graph, n_attacker.nodeKey)
_assert(result is not None and result.nodeKey == n_attacker.nodeKey,
        "query_by_node: finds existing node")

result = query_by_node(graph, "nonexistent_key_000000000000")
_assert(result is None, "query_by_node: returns None for missing key")

# ---------------------------------------------------------------------------
# 2. Type query
# ---------------------------------------------------------------------------
print("\n=== 2. Type query ===\n")

typed = query_by_type(graph, GraphNodeTypeEnum.IP)
_assert(any(n.nodeKey == n_c2.nodeKey for n in typed),
        "query_by_type: finds IP node")
_assert(all(n.nodeType == GraphNodeTypeEnum.IP for n in typed),
        "query_by_type: all returned nodes are IP type")

# ---------------------------------------------------------------------------
# 3. Risk query
# ---------------------------------------------------------------------------
print("\n=== 3. Risk query ===\n")

risky = query_by_risk(graph, 80)
_assert(all(n.riskScore >= 80 for n in risky),
        "query_by_risk: all nodes have riskScore >= 80")
_assert(any(n.nodeKey == n_malware.nodeKey for n in risky),
        "query_by_risk: includes malware node (risk=95)")
_assert(not any(n.nodeKey == n_isolated.nodeKey for n in risky),
        "query_by_risk: excludes isolated node (risk=10)")

# ---------------------------------------------------------------------------
# 4. Confidence query
# ---------------------------------------------------------------------------
print("\n=== 4. Confidence query ===\n")

conf_nodes = query_by_confidence(graph, 80)
_assert(all(n.confidence >= 80 for n in conf_nodes),
        "query_by_confidence: all nodes have confidence >= 80")

# ---------------------------------------------------------------------------
# 5. Label search
# ---------------------------------------------------------------------------
print("\n=== 5. Label search ===\n")

label_hits = query_by_label(graph, "evil")
_assert(any(n.nodeKey == n_domain.nodeKey for n in label_hits),
        "query_by_label: finds domain containing 'evil'")

label_hits_cmd = query_by_label(graph, "cmd")
_assert(any(n.nodeKey == n_process.nodeKey for n in label_hits_cmd),
        "query_by_label: finds process containing 'cmd'")

# ---------------------------------------------------------------------------
# 6. One-hop neighbors
# ---------------------------------------------------------------------------
print("\n=== 6. One-hop neighbors ===\n")

neighbors = find_neighbors(graph, n_victim.nodeKey,
                           include_incoming=True, include_outgoing=True)
neighbor_keys = {n.nodeKey for n in neighbors}
_assert(n_c2.nodeKey in neighbor_keys,
        "find_neighbors: victim has c2 as incoming neighbor")
_assert(n_malware.nodeKey in neighbor_keys,
        "find_neighbors: victim has malware as outgoing neighbor")
_assert(n_process.nodeKey in neighbor_keys,
        "find_neighbors: victim has process as outgoing neighbor")
_assert(n_isolated.nodeKey not in neighbor_keys,
        "find_neighbors: isolated node not in victim neighbors")

# ---------------------------------------------------------------------------
# 7. Two-hop neighbors
# ---------------------------------------------------------------------------
print("\n=== 7. Two-hop neighbors ===\n")

hood = find_two_hop_neighbors(graph, n_victim.nodeKey,
                              include_incoming=True, include_outgoing=True)
one_hop_keys = {n.nodeKey for n in hood.oneHop}
two_hop_keys = {n.nodeKey for n in hood.twoHop}

_assert(n_c2.nodeKey in one_hop_keys or n_malware.nodeKey in one_hop_keys,
        "find_two_hop_neighbors: c2 or malware in one-hop of victim")
_assert(n_attacker.nodeKey in two_hop_keys or n_domain.nodeKey in two_hop_keys
        or n_evidence.nodeKey in two_hop_keys,
        "find_two_hop_neighbors: attacker/domain/evidence reachable in two hops")
_assert(hood.centerNode.nodeKey == n_victim.nodeKey,
        "find_two_hop_neighbors: centerNode is victim")

# ---------------------------------------------------------------------------
# 8. BFS
# ---------------------------------------------------------------------------
print("\n=== 8. BFS ===\n")

bfs = breadth_first_search(graph, n_attacker.nodeKey, max_depth=5,
                           include_incoming=False, include_outgoing=True)
_assert(bfs.visitedNodeCount >= 1,
        "BFS: visited at least start node")
_assert(bfs.visitedNodeCount > 0 and bfs.visitedEdgeCount >= 0,
        "BFS: returns visitedNodeCount and visitedEdgeCount")
_assert(bfs.maxDepthReached >= 0,
        "BFS: maxDepthReached populated")
_assert(bfs.processingTimeMs >= 0,
        "BFS: processingTimeMs populated")

attacker_bfs_keys = {n.nodeKey for n in bfs.visitedNodes}
_assert(n_c2.nodeKey in attacker_bfs_keys,
        "BFS: attacker can reach c2")
_assert(n_victim.nodeKey in attacker_bfs_keys,
        "BFS: attacker can reach victim via c2")

# ---------------------------------------------------------------------------
# 9. DFS
# ---------------------------------------------------------------------------
print("\n=== 9. DFS ===\n")

dfs = depth_first_search(graph, n_attacker.nodeKey, max_depth=5,
                         include_incoming=False, include_outgoing=True)
dfs_keys = {n.nodeKey for n in dfs.visitedNodes}
_assert(n_c2.nodeKey in dfs_keys,
        "DFS: attacker can reach c2")
_assert(dfs.visitedNodeCount >= 1,
        "DFS: visitedNodeCount populated")
_assert(dfs.visitedEdgeCount >= 0,
        "DFS: visitedEdgeCount populated")

# ---------------------------------------------------------------------------
# 10. Shortest path
# ---------------------------------------------------------------------------
print("\n=== 10. Shortest path ===\n")

sp = shortest_path(graph, n_attacker.nodeKey, n_malware.nodeKey,
                   include_outgoing=True, include_incoming=False)
_assert(sp is not None, "shortest_path: path from attacker to malware exists")
assert sp is not None
_assert(sp.nodes[0].nodeKey == n_attacker.nodeKey,
        "shortest_path: starts at attacker")
_assert(sp.nodes[-1].nodeKey == n_malware.nodeKey,
        "shortest_path: ends at malware")
_assert(sp.pathLength == len(sp.edges),
        "shortest_path: pathLength == len(edges)")
_assert(len(sp.pathFingerprint) == 32,
        "shortest_path: pathFingerprint is 32 chars")
_assert(sp.totalRisk > 0,
        "shortest_path: totalRisk accumulated")

# Same path should always produce same fingerprint (deterministic)
sp2 = shortest_path(graph, n_attacker.nodeKey, n_malware.nodeKey,
                    include_outgoing=True, include_incoming=False)
assert sp2 is not None
_assert(sp.pathFingerprint == sp2.pathFingerprint,
        "shortest_path: deterministic pathFingerprint")

sp_none = shortest_path(graph, n_malware.nodeKey, n_attacker.nodeKey,
                        include_outgoing=True, include_incoming=False)
_assert(sp_none is None,
        "shortest_path: returns None when no directed path")

# ---------------------------------------------------------------------------
# 11. Connected components
# ---------------------------------------------------------------------------
print("\n=== 11. Connected components ===\n")

comps = connected_components(graph)
_assert(len(comps) >= 2,
        "connected_components: isolated node forms its own component")
_assert(comps[0] is not None and len(comps[0]) > 0,
        "connected_components: first component is non-empty")
# The isolated node must appear in some component alone
single_comps = [c for c in comps if len(c) == 1]
iso_keys_in_singles = {c[0].nodeKey for c in single_comps}
_assert(n_isolated.nodeKey in iso_keys_in_singles,
        "connected_components: isolated node is its own component")

# ---------------------------------------------------------------------------
# 12. Isolated nodes
# ---------------------------------------------------------------------------
print("\n=== 12. Isolated nodes ===\n")

iso = isolated_nodes(graph)
iso_keys = {n.nodeKey for n in iso}
_assert(n_isolated.nodeKey in iso_keys,
        "isolated_nodes: orphan-node is isolated")
_assert(n_attacker.nodeKey not in iso_keys,
        "isolated_nodes: attacker is not isolated")

# ---------------------------------------------------------------------------
# 13. Graph metrics
# ---------------------------------------------------------------------------
print("\n=== 13. Graph metrics ===\n")

m = calculate_graph_metrics(graph)
_assert(m.connectedComponents >= 2,
        "metrics: at least 2 connected components (isolated node)")
_assert(m.isolatedNodes >= 1,
        "metrics: at least 1 isolated node")
_assert(0.0 <= m.graphDensity <= 1.0,
        "metrics: graphDensity in [0, 1]")
_assert(m.averageRisk >= 0.0,
        "metrics: averageRisk >= 0")
_assert(m.averageConfidence >= 0.0,
        "metrics: averageConfidence >= 0")
_assert(m.highestDegree >= m.lowestDegree,
        "metrics: highestDegree >= lowestDegree")
_assert(m.averageDegree >= 0.0,
        "metrics: averageDegree >= 0")

# ---------------------------------------------------------------------------
# 14. Highest-risk path
# ---------------------------------------------------------------------------
print("\n=== 14. Highest-risk path ===\n")

hrp = highest_risk_path(graph, n_attacker.nodeKey, n_malware.nodeKey,
                        maximum_depth=6, include_outgoing=True,
                        include_incoming=False)
_assert(hrp is not None, "highest_risk_path: path exists")
assert hrp is not None
_assert(hrp.totalRisk >= 0, "highest_risk_path: totalRisk >= 0")
_assert(len(hrp.pathFingerprint) == 32,
        "highest_risk_path: pathFingerprint is 32 chars")

# Verify it is indeed the max among all paths
all_p = all_paths(graph, n_attacker.nodeKey, n_malware.nodeKey,
                  maximum_depth=6, include_outgoing=True, include_incoming=False)
if all_p:
    max_risk = max(p.totalRisk for p in all_p)
    _assert(hrp.totalRisk == max_risk,
            "highest_risk_path: totalRisk equals max across all_paths")

# ---------------------------------------------------------------------------
# 15. Deterministic pathFingerprint
# ---------------------------------------------------------------------------
print("\n=== 15. Deterministic pathFingerprint ===\n")

# Run shortest_path three times — fingerprint must be identical
fps = set()
for _ in range(3):
    p = shortest_path(graph, n_attacker.nodeKey, n_victim.nodeKey,
                      include_outgoing=True, include_incoming=False)
    if p:
        fps.add(p.pathFingerprint)

_assert(len(fps) == 1, "pathFingerprint: deterministic across 3 runs")

# Two different paths → different fingerprints
p_a2v = shortest_path(graph, n_attacker.nodeKey, n_victim.nodeKey,
                      include_outgoing=True, include_incoming=False)
p_a2m = shortest_path(graph, n_attacker.nodeKey, n_malware.nodeKey,
                      include_outgoing=True, include_incoming=False)
if p_a2v and p_a2m:
    _assert(p_a2v.pathFingerprint != p_a2m.pathFingerprint,
            "pathFingerprint: different paths produce different fingerprints")

# ---------------------------------------------------------------------------
# 16. GraphQueryExplanation + engineVersion via query_graph()
# ---------------------------------------------------------------------------
print("\n=== 16. query_graph() — explanation + engineVersion ===\n")

qr = query_graph(
    graph,
    GraphQuery(
        nodeType=GraphNodeTypeEnum.ASSET,
        minimumRisk=50,
        maximumDepth=4,
        includeIncoming=True,
        includeOutgoing=True,
    ),
)
_assert(qr.engineVersion == ATTACK_GRAPH_QUERY_ENGINE_VERSION,
        "query_graph: engineVersion matches constant")
_assert(len(qr.explanation.querySummary) > 0,
        "query_graph: querySummary populated")
_assert(len(qr.explanation.processingStages) > 0,
        "query_graph: processingStages populated")
_assert(qr.explanation.executionTimeMs >= 0,
        "query_graph: executionTimeMs >= 0")
_assert(qr.processingTimeMs >= 0,
        "query_graph: processingTimeMs >= 0")
_assert(qr.metrics is not None,
        "query_graph: metrics populated")
_assert(qr.searchResult is not None,
        "query_graph: searchResult populated")
_assert("nodeType=ASSET" in qr.explanation.filtersApplied,
        "query_graph: filtersApplied records nodeType filter")

# ---------------------------------------------------------------------------
# 17. filter_nodes / filter_edges
# ---------------------------------------------------------------------------
print("\n=== 17. filter_nodes / filter_edges ===\n")

fn = filter_nodes(graph.nodes, node_type=GraphNodeTypeEnum.IP,
                  minimum_risk=70, minimum_confidence=60)
_assert(all(n.nodeType == GraphNodeTypeEnum.IP and n.riskScore >= 70
            and n.confidence >= 60 for n in fn),
        "filter_nodes: AND semantics respected")

fe = filter_edges(graph.edges, edge_type=GraphEdgeTypeEnum.COMMUNICATES_WITH)
_assert(all(e.edgeType == GraphEdgeTypeEnum.COMMUNICATES_WITH for e in fe),
        "filter_edges: edgeType filter works")

# ---------------------------------------------------------------------------
# 18. search_nodes / search_edges / search_metadata
# ---------------------------------------------------------------------------
print("\n=== 18. search_nodes / search_edges / search_metadata ===\n")

sn = search_nodes(graph, label_contains="evil")
_assert(sn.count > 0, "search_nodes: label_contains finds domain")

se = search_edges(graph, edge_type=GraphEdgeTypeEnum.RESOLVES_TO)
_assert(se.count > 0, "search_edges: finds RESOLVES_TO edges")

sm = search_metadata(graph, "role", "attacker")
_assert(sm.count > 0, "search_metadata: finds attacker node by metadata key+value")

sm2 = search_metadata(graph, "source")
_assert(sm2.count > 0, "search_metadata: finds nodes with 'source' key (any value)")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
if _failures:
    print(f"\n{FAIL} {len(_failures)} assertion(s) FAILED:\n")
    for f in _failures:
        print(f"   - {f}")
    sys.exit(1)
else:
    print(f"\n{PASS} All assertions passed.\n")
    print(f"  Engine version : {ATTACK_GRAPH_QUERY_ENGINE_VERSION}")
    print(f"  Graph nodes    : {len(graph.nodes)}")
    print(f"  Graph edges    : {len(graph.edges)}")
    print(f"  Fingerprint    : {graph.graphFingerprint}")
