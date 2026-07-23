"""
Tests for ATRE Confidence Engine.
"""

from netfusion_ai.reasoning import ConfidenceEngine, GraphEvidence, RelationshipRanking


def test_confidence_scoring_breakdown():
    engine = ConfidenceEngine()
    evidence = [
        GraphEvidence(evidence_id="ev-1", source_type="VULNERABILITY", node_id="CVE-1", label="CVE-1", description="test"),
        GraphEvidence(evidence_id="ev-2", source_type="IOC", node_id="IP-1", label="192.168.1.1", description="test"),
    ]
    relationships = [
        RelationshipRanking(
            source_id="CVE-1",
            target_id="IP-1",
            edge_type="EXPLOITS",
            relationship_strength=0.9,
            graph_distance=1,
            evidence_count=2,
            score=90.0,
        )
    ]

    breakdown = engine.calculate_confidence(
        evidence=evidence,
        relationships=relationships,
        has_kev=True,
        epss_score=0.85,
        cvss_score=9.8,
        analyst_confirmed=True,
    )

    assert breakdown.overall_score > 0.70
    assert breakdown.kev_factor == 1.0
    assert breakdown.analyst_confirmation_factor == 1.0
    assert breakdown.formula_explanation != ""
