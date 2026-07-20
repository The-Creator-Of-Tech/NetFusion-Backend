"""
Tests for NetFusion AIAnalysisEngine analytical orchestrator.
"""

import pytest

from netfusion_ai import (
    AIAnalysisEngine,
    AnalysisCategory,
    ContextBuilder,
    ProviderAdapter,
    MockAIProvider,
    AIEventPublisher,
)


def test_analysis_engine_execution():
    pub = AIEventPublisher()
    provider = MockAIProvider(custom_response="Detailed incident summary for SOC analysts.")
    adapter = ProviderAdapter(primary_provider=provider, event_publisher=pub)

    engine = AIAnalysisEngine(provider_adapter=adapter, event_publisher=pub)

    cb = ContextBuilder()
    context = cb.build_context(
        investigation={"investigation_id": "INV-001", "title": "Phishing Incident"},
        timeline=[{"title": "User clicked attachment", "summary": "Suspicious macro payloadExecuted"}],
    )

    result = engine.analyze(category=AnalysisCategory.INCIDENT_SUMMARY, context_container=context)

    assert result.investigation_id == "INV-001"
    assert result.category == AnalysisCategory.INCIDENT_SUMMARY
    assert "incident summary" in result.summary.lower()
    assert result.confidence is not None
    assert result.explanation is not None
    assert len(pub.published_events) >= 3
