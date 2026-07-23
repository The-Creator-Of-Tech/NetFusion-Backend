"""
Tests for ATRE Graph Expansion & Subgraph Reasoning.
"""

from netfusion_ai.reasoning import ContextExpander, GraphReasoner, RiskPropagator, CIILResolvedEntity


def test_context_expander_multihop():
    expander = ContextExpander()
    subgraph = expander.expand(["CVE-2023-34362"], max_depth=2)

    assert "nodes" in subgraph
    assert "edges" in subgraph
    assert len(subgraph["nodes"]) >= 2
    assert len(subgraph["edges"]) >= 1


def test_risk_propagator():
    propagator = RiskPropagator()
    nodes = [
        {"canonical_id": "CVE-1", "node_type": "VULNERABILITY"},
        {"canonical_id": "ASSET-1", "node_type": "ASSET"},
    ]
    edges = [{"source_node_id": "CVE-1", "target_node_id": "ASSET-1", "confidence": 0.9}]

    risks = propagator.calculate_risk(nodes, edges)
    assert risks["CVE-1"] > 0.8
    assert risks["ASSET-1"] > 0.7


def test_graph_reasoner_facade():
    reasoner = GraphReasoner()
    seeds = [CIILResolvedEntity(canonical_id="CVE-2023-34362", entity_type="VULNERABILITY", display_name="CVE-2023-34362")]
    subgraph, evidence, rankings, attack_chain, timeline = reasoner.reason(seeds)

    assert len(evidence) >= 1
    assert len(rankings) >= 1
    assert attack_chain.total_stages == 11
    assert timeline.total_events >= 1
