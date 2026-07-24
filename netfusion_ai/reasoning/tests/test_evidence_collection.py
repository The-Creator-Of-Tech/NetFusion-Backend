"""
Tests for Evidence Collection & Relationship Ranking.
"""

from netfusion_ai.reasoning import (
    CIILResolvedEntity,
    EvidenceCollector,
    RelationshipRanker,
)


def test_evidence_collector():
    collector = EvidenceCollector()
    seeds = [
        CIILResolvedEntity(
            canonical_id="CVE-2023-34362",
            entity_type="VULNERABILITY",
            display_name="CVE-2023-34362",
        )
    ]
    subgraph = {
        "nodes": [
            {"canonical_id": "CVE-2023-34362", "node_type": "VULNERABILITY", "label": "CVE-2023-34362"},
            {"canonical_id": "T1190", "node_type": "ATTACK_PATTERN", "label": "T1190"},
        ],
        "edges": [
            {"source_node_id": "CVE-2023-34362", "target_node_id": "T1190", "edge_type": "EXPLOITS"}
        ],
    }

    evidence = collector.collect_evidence(seeds, subgraph)
    assert len(evidence) >= 2
    types = [ev.source_type for ev in evidence]
    assert "VULNERABILITY" in types or "ATTACK_PATTERN" in types


def test_relationship_ranker():
    ranker = RelationshipRanker()
    edges = [
        {"source_node_id": "N1", "target_node_id": "N2", "confidence": 0.9},
        {"source_node_id": "N3", "target_node_id": "N4", "confidence": 0.4},
    ]

    rankings = ranker.rank_relationships(edges, seed_node_ids=["N1"])
    assert len(rankings) == 2
    assert rankings[0].source_id == "N1"
    assert rankings[0].score > rankings[1].score
