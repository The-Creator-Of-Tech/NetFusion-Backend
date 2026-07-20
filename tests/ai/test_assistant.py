"""
Integration tests for AIAssistant main API facade.
"""

import pytest

from netfusion_ai import (
    AIAssistant,
    ContextBuilder,
    AnalysisCategory,
    MockAIProvider,
    RecommendationCategory,
)


def test_ai_assistant_all_api_services():
    assistant = AIAssistant(provider=MockAIProvider())
    cb = ContextBuilder()

    context = cb.build_context(
        investigation={"investigation_id": "INV-FACADE-001", "title": "Comprehensive Test Case"},
        timeline=[
            {"timestamp": "2026-07-20T10:00:00Z", "title": "Nmap Scan", "summary": "Port scan 80, 443"},
            {"timestamp": "2026-07-20T10:05:00Z", "title": "PowerShell Execution", "summary": "sysmon eventid 1"},
        ],
        evidence=[{"evidence_id": "EV-1", "name": "memory.dmp", "source": "sysmon"}],
        iocs=[{"type": "ip", "value": "192.168.1.100", "confidence": "HIGH"}],
        sysmon_events=[{"event_id": 1, "image": "powershell.exe", "command_line": "powershell -enc AAAA"}],
        nmap_scans=[{"host": "192.168.1.100", "open_ports": [80, 443]}],
        tshark_captures=[{"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "protocol": "HTTP"}],
    )

    # 1. Analyze Investigation
    res1 = assistant.analyze_investigation(context, category=AnalysisCategory.INCIDENT_SUMMARY)
    assert res1.investigation_id == "INV-FACADE-001"
    assert res1.confidence.overall_score > 0.0

    # 2. Generate Summary
    res2 = assistant.generate_summary(context, summary_type=AnalysisCategory.EXECUTIVE_BRIEF)
    assert res2.category == AnalysisCategory.EXECUTIVE_BRIEF

    # 3. Generate Report
    report = assistant.generate_report(context, title="End-to-End Report")
    assert report.title == "End-to-End Report"
    assert len(report.mitre_findings) > 0

    # 4. Generate Recommendations
    recs = assistant.generate_recommendations(context)
    assert RecommendationCategory.CONTAINMENT.value in recs

    # 5. Analyze IOC
    res_ioc = assistant.analyze_ioc(context, ioc_value="192.168.1.100")
    assert res_ioc.category == AnalysisCategory.IOC_CORRELATION

    # 6. Analyze MITRE
    mitre_inferences = assistant.analyze_mitre(context)
    assert len(mitre_inferences) > 0

    # 7. Analyze Timeline
    res_timeline = assistant.analyze_timeline(context)
    assert res_timeline.category == AnalysisCategory.TIMELINE_ANALYSIS

    # 8. Generate Hypotheses
    hypotheses = assistant.generate_hypotheses(context)
    assert len(hypotheses) >= 2

    # Health check
    health = assistant.health_check()
    assert health.status == "HEALTHY"
