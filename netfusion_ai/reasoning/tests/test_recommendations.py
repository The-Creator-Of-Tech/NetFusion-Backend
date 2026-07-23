"""
Tests for ATRE Recommendation Engine.
"""

from netfusion_ai.reasoning import (
    ATRERecommendationEngine,
    CIILResolvedEntity,
    GraphEvidence,
    RecommendationCategory,
)


def test_recommendation_categories_and_reasoning():
    engine = ATRERecommendationEngine()
    entities = [
        CIILResolvedEntity(
            canonical_id="ASSET:web-01",
            entity_type="ASSET",
            display_name="web-01",
        )
    ]
    evidence = [
        GraphEvidence(
            evidence_id="ev-cve",
            source_type="VULNERABILITY",
            node_id="CVE-2023-34362",
            label="CVE-2023-34362",
            description="MOVEit Transfer Vulnerability",
        )
    ]

    recs = engine.generate_recommendations(entities, evidence)

    assert len(recs) == 8
    categories = set(r.category for r in recs)
    assert RecommendationCategory.IMMEDIATE_ACTIONS in categories
    assert RecommendationCategory.CONTAINMENT in categories
    assert RecommendationCategory.MITIGATION in categories
    assert RecommendationCategory.DETECTION_IMPROVEMENTS in categories

    for r in recs:
        assert r.reasoning != ""
        assert len(r.target_entities) >= 1
