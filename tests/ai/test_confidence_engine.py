"""
Tests for NetFusion ConfidenceEngine.
"""

import pytest

from netfusion_ai import ConfidenceEngine, ContextBuilder, ConfidenceLevel


def test_confidence_engine_scoring():
    engine = ConfidenceEngine()
    cb = ContextBuilder()

    context_rich = cb.build_context(
        timeline=[{"title": f"Event {i}"} for i in range(25)],
        evidence=[{"integrity_status": "verified"} for _ in range(10)],
        sysmon_events=[{"event_id": 1}],
        nmap_scans=[{"host": "10.0.0.1"}],
        threat_intelligence=[{"provider": "virustotal"}],
    )

    conf_rich = engine.calculate_confidence(context_rich)
    assert conf_rich.overall_score >= 0.80
    assert conf_rich.confidence_level in (ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH)

    context_sparse = cb.build_context()
    conf_sparse = engine.calculate_confidence(context_sparse)
    assert conf_sparse.overall_score < 0.60
    assert len(conf_sparse.missing_information) > 0
