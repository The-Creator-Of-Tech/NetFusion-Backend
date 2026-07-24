"""
Tests for Grounded AI Provider Explanation Integration.
"""

from netfusion_ai.reasoning import (
    ATREService,
    ExplanationEngine,
    GraphEvidence,
    ReasoningRequest,
)


class DummyAIProvider:

    def generate(self, prompt: str, system: str = "") -> str:
        return "Grounded LLM Explanation: Based on graph evidence CVE-2023-34362, the incident involved a MOVEit exploit."


def test_explanation_engine_with_provider():
    provider = DummyAIProvider()
    engine = ExplanationEngine(ai_provider=provider)

    evidence = [
        GraphEvidence(
            evidence_id="ev-1",
            source_type="VULNERABILITY",
            node_id="CVE-2023-34362",
            label="CVE-2023-34362",
            description="MOVEit Transfer zero-day vulnerability",
        )
    ]

    from netfusion_ai.reasoning import (
        AttackChain,
        ConfidenceBreakdown,
        Timeline,
    )

    result = engine.generate_explanation(
        user_question="What happened?",
        question_type="WHAT_HAPPENED",
        evidence=evidence,
        attack_chain=AttackChain(stages=[], total_stages=0, overall_confidence=0.8, summary=""),
        hypotheses=[],
        confidence=ConfidenceBreakdown(overall_score=0.85, formula_explanation="Test"),
        contradictions=[],
        recommendations=[],
        timeline=Timeline(),
    )

    assert "MOVEit exploit" in result.technical_analysis


def test_service_with_custom_provider():
    provider = DummyAIProvider()
    service = ATREService(ai_provider=provider)

    req = ReasoningRequest(user_question="Explain CVE-2023-34362 threat level")
    res = service.query(req)

    assert res.explanation.technical_analysis != ""
    assert service.get_statistics()["ai_provider_connected"] is True
