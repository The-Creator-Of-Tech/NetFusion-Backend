"""
Tests for NetFusion ContextBuilder and EvidenceSelector.
"""

import pytest

from netfusion_ai import ContextBuilder, ContextConfig, EvidenceSelector


def test_context_builder_15_sources():
    builder = ContextBuilder(ContextConfig(max_token_budget=8000))

    container = builder.build_context(
        investigation={"investigation_id": "INV-100", "title": "Test Incident", "severity": "HIGH"},
        timeline=[{"event_id": "T1", "timestamp": "2026-07-20T10:00:00Z", "title": "Scan", "summary": "Nmap scan observed"}],
        evidence=[{"evidence_id": "E1", "name": "memory.raw", "source": "sysmon", "file_size_bytes": 1024}],
        canonical_objects=[{"object_type": "IPAddress", "value": "10.0.0.1"}],
        iocs=[{"type": "hash", "value": "a" * 64, "confidence": "HIGH"}],
        threat_intelligence=[{"provider": "virustotal", "positives": 45}],
        sysmon_events=[{"event_id": 1, "image": "cmd.exe", "command_line": "cmd.exe /c whoami"}],
        nmap_scans=[{"host": "10.0.0.1", "open_ports": [80, 443]}],
        tshark_captures=[{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "protocol": "DNS"}],
        tasks=[{"task_id": "TK1", "title": "Isolate Host"}],
        notes=[{"note_id": "N1", "author": "analyst", "content": "Suspicious persistence"}],
        risk_assessment={"overall_score": 8.5, "business_impact": "HIGH"},
        mitre_mappings=[{"technique_id": "T1059", "technique_name": "Command Line"}],
        configuration={"environment": "production"},
    )

    assert container.investigation["title"] == "Test Incident"
    assert len(container.timeline) == 1
    assert len(container.evidence) == 1
    assert len(container.sysmon_events) == 1
    assert container.summary_metadata["sysmon_event_count"] == 1

    md = builder.format_as_markdown(container)
    assert "Test Incident" in md
    assert "Sysmon Events" in md
    assert "10.0.0.1" in md


def test_context_builder_token_budget_truncation():
    builder = ContextBuilder(ContextConfig(max_token_budget=100))  # Low budget forces truncation

    timeline_items = [{"event_id": f"T{i}", "title": f"Event {i}", "summary": "Details " * 50} for i in range(50)]
    container = builder.build_context(timeline=timeline_items)

    assert len(container.timeline) <= 10
