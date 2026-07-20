"""
Tests for NetFusion HypothesisEngine.
"""

import pytest

from netfusion_ai import HypothesisEngine, ContextBuilder


def test_hypothesis_engine_multi_hypothesis():
    engine = HypothesisEngine()
    cb = ContextBuilder()

    context = cb.build_context(
        investigation={"investigation_id": "INV-HYP"},
        evidence=[{"evidence_id": "EV-1", "name": "payload.dll", "source": "sysmon"}],
        timeline=[{"title": "DLL injection detected", "summary": "Unbacked executable code observed"}],
    )

    hypotheses = engine.generate_hypotheses(context, min_hypotheses=2)

    assert len(hypotheses) >= 2
    assert hypotheses[0].title != hypotheses[1].title
    assert hypotheses[0].confidence_score > 0.0
    assert len(hypotheses[0].recommended_validation_steps) > 0
