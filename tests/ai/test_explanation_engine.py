"""
Tests for NetFusion ExplanationEngine transparency generator.
"""

import pytest

from netfusion_ai import ExplanationEngine, ConfidenceEngine, ContextBuilder, EvidenceReference


def test_explanation_engine_structure():
    exp_engine = ExplanationEngine()
    conf_engine = ConfidenceEngine()
    cb = ContextBuilder()

    context = cb.build_context()
    conf_meta = conf_engine.calculate_confidence(context)

    ref = EvidenceReference(evidence_id="E-1", source_type="sysmon", summary="EventID 1 process creation")
    explanation = exp_engine.build_explanation(
        reasoning_summary="Analyzed process telemetry to derive conclusions.",
        evidence_references=[ref],
        confidence_metadata=conf_meta,
    )

    assert explanation.reasoning_summary.startswith("Analyzed process")
    assert len(explanation.evidence_references) == 1
    assert len(explanation.assumptions) > 0
    assert len(explanation.limitations) > 0
    assert len(explanation.unknowns) > 0
