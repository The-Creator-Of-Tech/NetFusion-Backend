"""
Tests for NetFusion RecommendationEngine.
"""

import pytest

from netfusion_ai import RecommendationEngine, ContextBuilder, RecommendationCategory


def test_recommendation_engine_grouping():
    engine = RecommendationEngine()
    cb = ContextBuilder()

    context = cb.build_context(
        investigation={"investigation_id": "INV-REC"},
        evidence=[{"evidence_id": "E1", "name": "malware.exe", "source": "sysmon"}],
    )

    recs = engine.generate_recommendations(context)

    assert RecommendationCategory.CONTAINMENT.value in recs
    assert RecommendationCategory.ERADICATION.value in recs
    assert RecommendationCategory.RECOVERY.value in recs
    assert RecommendationCategory.MONITORING.value in recs
    assert RecommendationCategory.FURTHER_INVESTIGATION.value in recs
    assert RecommendationCategory.HARDENING.value in recs

    containment_item = recs[RecommendationCategory.CONTAINMENT.value][0]
    assert len(containment_item.supporting_evidence) > 0
    assert len(containment_item.action_steps) > 0
