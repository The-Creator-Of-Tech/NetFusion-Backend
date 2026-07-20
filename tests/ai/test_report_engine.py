"""
Tests for NetFusion ReportEngine.
"""

import pytest

from netfusion_ai import (
    ReportEngine,
    ContextBuilder,
    ProviderAdapter,
    MockAIProvider,
    AIEventPublisher,
)


def test_report_engine_generation():
    pub = AIEventPublisher()
    provider = MockAIProvider()
    adapter = ProviderAdapter(primary_provider=provider, event_publisher=pub)
    engine = ReportEngine(provider_adapter=adapter, event_publisher=pub)

    cb = ContextBuilder()
    context = cb.build_context(
        investigation={"investigation_id": "INV-REP", "title": "Data Breach Investigation"},
        timeline=[{"timestamp": "2026-07-20T12:00:00Z", "title": "Data Exfiltration", "summary": "TShark flow 1.0GB"}],
        evidence=[{"evidence_id": "EV-99", "name": "pcap_export.pcap", "source": "tshark"}],
    )

    report = engine.generate_report(context, title="Final Security Incident Report")

    assert report.investigation_id == "INV-REP"
    assert report.title == "Final Security Incident Report"
    assert "EXECUTIVE SUMMARY" in report.executive_summary
    assert "TECHNICAL SUMMARY" in report.technical_summary
    assert "INCIDENT NARRATIVE" in report.incident_narrative
    assert "TIMELINE NARRATIVE" in report.timeline_narrative
    assert "EVIDENCE NARRATIVE" in report.evidence_narrative
    assert len(report.mitre_findings) > 0
    assert len(report.hypotheses) > 0
    assert report.risk_assessment is not None
    assert len(report.recommendations) > 0

    assert any(e.event_type == "AIReportGenerated" for e in pub.published_events)
