"""
Tests for ATRE Timeline Engine.
"""

from netfusion_ai.reasoning import GraphEvidence, TimelineEngine


def test_timeline_builder():
    engine = TimelineEngine()
    evidence = [
        GraphEvidence(
            evidence_id="ev-1",
            source_type="IOC",
            node_id="192.168.1.50",
            label="Suspicious IP",
            description="High risk IP observed",
        )
    ]
    extra = [
        {
            "event_id": "evt-log-1",
            "timestamp": "2026-07-22T10:00:00Z",
            "source": "Logs",
            "title": "Auth Failure",
            "description": "Failed SSH login",
        }
    ]

    timeline = engine.build_timeline(evidence=evidence, extra_events=extra)

    assert timeline.total_events == 2
    assert len(timeline.events) == 2
    sources = [e.source.value for e in timeline.events]
    assert "IOC Sightings" in sources or "Alerts" in sources
    assert "Logs" in sources
