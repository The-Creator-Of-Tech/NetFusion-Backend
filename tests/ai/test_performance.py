"""
Performance and Stress Tests for NetFusion AI Assistant.
"""

import time
import pytest

from netfusion_ai import AIAssistant, ContextBuilder, AnalysisCategory, MockAIProvider


def test_performance_bulk_analysis():
    assistant = AIAssistant(provider=MockAIProvider())
    cb = ContextBuilder()

    context = cb.build_context(
        investigation={"investigation_id": "PERF-100", "title": "Large Stress Test Incident"},
        timeline=[{"title": f"Timeline Event {i}", "summary": f"Telemetry entry {i}"} for i in range(100)],
        evidence=[{"evidence_id": f"E-{i}", "name": f"file_{i}.dat"} for i in range(50)],
        iocs=[{"type": "ip", "value": f"10.0.0.{i}"} for i in range(50)],
    )

    start = time.time()
    for _ in range(10):
        result = assistant.analyze_investigation(context, category=AnalysisCategory.INCIDENT_SUMMARY)
        assert result.confidence is not None

    elapsed = time.time() - start
    # 10 full analyses over large context should take under 2 seconds
    assert elapsed < 2.0
