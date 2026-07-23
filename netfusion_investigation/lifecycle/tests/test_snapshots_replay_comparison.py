"""
Tests for SnapshotEngine, ReplayEngine, and ComparisonEngine.
"""

import pytest

from netfusion_investigation.lifecycle.comparison import ComparisonEngine
from netfusion_investigation.lifecycle.models import Investigation, InvestigationLinks, Priority, ReasoningSession, Severity
from netfusion_investigation.lifecycle.replay import ReplayEngine
from netfusion_investigation.lifecycle.snapshots import SnapshotEngine


def test_snapshot_engine():
    se = SnapshotEngine()
    inv = Investigation(
        id="inv-200",
        case_id="CASE-200",
        title="Original Title",
        priority=Priority.LOW,
    )

    s1 = se.create_snapshot(inv, label="V1 State")
    assert s1.version == 1

    inv.title = "Updated Title"
    inv.priority = Priority.CRITICAL
    s2 = se.create_snapshot(inv, label="V2 State")
    assert s2.version == 2

    history = se.get_version_history("inv-200")
    assert len(history) == 2

    restored_v1 = se.restore_snapshot("inv-200", 1)
    assert restored_v1.title == "Original Title"
    assert restored_v1.priority == Priority.LOW

    compared = se.compare_snapshots(s1.id, s2.id)
    assert "title" in compared["modified_fields"]
    assert compared["modified_fields"]["title"]["from"] == "Original Title"
    assert compared["modified_fields"]["title"]["to"] == "Updated Title"

    rolled_back = se.rollback("inv-200", version=1)
    assert rolled_back.title == "Original Title"


def test_replay_engine():
    re = ReplayEngine()
    inv = Investigation(id="inv-300", case_id="CASE-300", title="Replay Spec")

    timeline_events = [{"timestamp": "2026-07-22T10:00:00Z", "title": "Phishing Email Recv"}]
    graph_events = [{"timestamp": "2026-07-22T10:05:00Z", "description": "Host-A linked to C2-IP"}]
    evidence_events = [{"timestamp": "2026-07-22T10:10:00Z", "name": "Malicious Payload.exe"}]
    reasoning_events = [{"timestamp": "2026-07-22T10:15:00Z", "hypothesis": "Ransomware Delivery", "confidence": 0.9}]

    session = re.initialize_replay(
        inv,
        timeline_events=timeline_events,
        graph_events=graph_events,
        evidence_events=evidence_events,
        reasoning_events=reasoning_events,
    )

    assert session.total_steps == 4
    assert session.status == "PAUSED"

    re.play(session.replay_id)
    assert re.get_replay(session.replay_id).status == "PLAYING"

    step2 = re.jump_to_step(session.replay_id, 1)
    assert step2.step_number == 2

    step3 = re.forward(session.replay_id)
    assert step3.step_number == 3

    step2_back = re.backward(session.replay_id)
    assert step2_back.step_number == 2

    current_state = re.get_current_state(session.replay_id)
    assert len(current_state["timeline"]) == 1
    assert len(current_state["evidence"]) == 0  # since at step 2 (index 1)


def test_comparison_engine():
    ce = ComparisonEngine()

    inv1 = Investigation(id="inv-401", case_id="CASE-401", title="Branch A")
    inv2 = Investigation(id="inv-402", case_id="CASE-402", title="Branch B")

    ctx1 = {
        "evidence": [{"id": "ev-1", "name": "Log A"}],
        "confidence": 0.70,
        "risk_score": 60.0,
        "graph_nodes": ["node-1"],
    }
    ctx2 = {
        "evidence": [{"id": "ev-1", "name": "Log A"}, {"id": "ev-2", "name": "Log B"}],
        "confidence": 0.95,
        "risk_score": 85.0,
        "graph_nodes": ["node-1", "node-2"],
    }

    diff = ce.compare_investigations(inv1, inv2, inv1_context=ctx1, inv2_context=ctx2)
    assert len(diff.new_evidence) == 1
    assert diff.new_evidence[0]["id"] == "ev-2"
    assert diff.confidence_delta == 0.25
    assert diff.risk_changes["risk_delta"] == 25.0
    assert "node-2" in diff.changed_graph["added_nodes"]

    # Test Session comparative diff
    sess1 = ReasoningSession(id="s1", investigation_id="inv-1", title="S1", state=ctx1)
    sess2 = ReasoningSession(id="s2", investigation_id="inv-1", title="S2", state=ctx2)
    sess_diff = ce.compare_sessions(sess1, sess2)
    assert sess_diff.confidence_delta == 0.25
