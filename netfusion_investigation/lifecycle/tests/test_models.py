"""
Tests for IL-10 Lifecycle Models and Data Entities.
"""

import pytest
from netfusion_investigation.lifecycle.models import (
    ActivityLogEntry,
    ActivityType,
    Artifact,
    ArtifactType,
    Attachment,
    Bookmark,
    BookmarkType,
    Investigation,
    InvestigationLinks,
    InvestigationSnapshot,
    InvestigationStatus,
    Priority,
    ReasoningSession,
    ReplaySession,
    ReplayStep,
    SessionStatus,
    Severity,
    TraceDifference,
)


def test_investigation_links_serialization():
    links = InvestigationLinks(
        reasoning_session_ids=["sess-1"],
        evidence_ids=["ev-1", "ev-2"],
        ioc_values=["192.168.1.1"],
        cve_ids=["CVE-2026-12345"],
    )
    d = links.to_dict()
    assert d["reasoning_session_ids"] == ["sess-1"]
    assert d["evidence_ids"] == ["ev-1", "ev-2"]
    assert d["ioc_values"] == ["192.168.1.1"]

    restored = InvestigationLinks.from_dict(d)
    assert restored.reasoning_session_ids == ["sess-1"]
    assert restored.cve_ids == ["CVE-2026-12345"]


def test_investigation_model_serialization():
    inv = Investigation(
        id="inv-100",
        case_id="CASE-100",
        title="APT Threat Investigation",
        description="Active C2 session detected",
        priority=Priority.HIGH,
        severity=Severity.CRITICAL,
        status=InvestigationStatus.OPEN,
        owner="analyst_alice",
        team="DFIR",
        labels=["APT", "Ransomware"],
    )
    d = inv.to_dict()
    assert d["id"] == "inv-100"
    assert d["priority"] == "HIGH"
    assert d["severity"] == "CRITICAL"

    restored = Investigation.from_dict(d)
    assert restored.id == "inv-100"
    assert restored.priority == Priority.HIGH
    assert restored.owner == "analyst_alice"


def test_reasoning_session_model():
    sess = ReasoningSession(
        id="sess-1",
        investigation_id="inv-100",
        title="Session 1",
        status=SessionStatus.ACTIVE,
        state={"confidence": 0.85},
    )
    d = sess.to_dict()
    restored = ReasoningSession.from_dict(d)
    assert restored.id == "sess-1"
    assert restored.state["confidence"] == 0.85


def test_artifact_and_attachment_models():
    art = Artifact(
        id="art-1",
        investigation_id="inv-100",
        name="Final Report",
        artifact_type=ArtifactType.REPORT,
        content="Report content",
    )
    d = art.to_dict(include_content=True)
    assert d["content"] == "Report content"

    att = Attachment(
        id="att-1",
        investigation_id="inv-100",
        filename="pcap.cap",
        file_size=1024,
        checksum_sha256="dummyhash",
    )
    assert att.to_dict()["filename"] == "pcap.cap"


def test_snapshot_replay_and_trace_diff_models():
    snap = InvestigationSnapshot(
        id="snap-1",
        investigation_id="inv-100",
        version=1,
        label="Initial State",
    )
    assert snap.to_dict()["version"] == 1

    step = ReplayStep(
        step_id="step-1",
        step_number=1,
        timestamp="2026-07-22T00:00:00Z",
        step_type="TIMELINE",
        description="Alert Triggered",
    )
    r_session = ReplaySession(
        replay_id="rpl-1",
        investigation_id="inv-100",
        steps=[step],
    )
    assert len(r_session.to_dict()["steps"]) == 1

    diff = TraceDifference(
        investigation_id_1="inv-1",
        investigation_id_2="inv-2",
        confidence_delta=0.15,
    )
    assert diff.to_dict()["confidence_delta"] == 0.15
