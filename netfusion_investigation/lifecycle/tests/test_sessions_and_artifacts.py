"""
Tests for SessionManager, ArtifactManager, and AttachmentManager.
"""

import os
import shutil
import tempfile
import pytest

from netfusion_investigation.lifecycle.artifacts import ArtifactManager
from netfusion_investigation.lifecycle.attachments import AttachmentManager
from netfusion_investigation.lifecycle.models import ArtifactType, SessionStatus
from netfusion_investigation.lifecycle.sessions import SessionManager


@pytest.fixture
def temp_storage():
    tmp_dir = tempfile.mkdtemp()
    yield tmp_dir
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_session_lifecycle_and_operations():
    sm = SessionManager()
    s1 = sm.create_session("inv-100", "Reasoning Session Alpha", state={"node_count": 5})
    assert s1.status == SessionStatus.ACTIVE

    sm.pause_session(s1.id)
    assert sm.get_session(s1.id).status == SessionStatus.PAUSED

    sm.resume_session(s1.id)
    assert sm.get_session(s1.id).status == SessionStatus.ACTIVE

    cloned = sm.clone_session(s1.id, new_title="Cloned Session")
    assert cloned.parent_session_id == s1.id
    assert cloned.state["node_count"] == 5

    s2 = sm.create_session("inv-100", "Reasoning Session Beta", state={"new_evidence": ["ev-1"]})
    merged = sm.merge_sessions(s1.id, [s2.id])
    assert "new_evidence" in merged.state

    sm.lock_session(s1.id)
    assert sm.get_session(s1.id).status == SessionStatus.LOCKED
    with pytest.raises(ValueError):
        sm.update_session_state(s1.id, {"test": 1})

    sm.restore_session(s1.id)
    assert sm.get_session(s1.id).status == SessionStatus.ACTIVE

    sm.archive_session(s1.id)
    assert sm.get_session(s1.id).status == SessionStatus.ARCHIVED


def test_artifact_manager(temp_storage):
    am = ArtifactManager(storage_dir=temp_storage)

    art = am.store_artifact(
        investigation_id="inv-100",
        name="Security Summary.md",
        artifact_type=ArtifactType.MARKDOWN,
        content="# Summary\nThreat isolated.",
    )
    assert art.checksum_sha256 != ""
    assert am.verify_artifact(art.id) is True

    fetched = am.get_artifact(art.id)
    assert fetched is not None
    assert fetched.content == "# Summary\nThreat isolated."

    reports = am.list_artifacts("inv-100", artifact_type=ArtifactType.MARKDOWN)
    assert len(reports) == 1

    am.delete_artifact(art.id)
    assert am.get_artifact(art.id) is None


def test_attachment_manager(temp_storage):
    att_mgr = AttachmentManager(storage_dir=temp_storage)
    att = att_mgr.add_attachment(
        investigation_id="inv-100",
        filename="packet_trace.pcap",
        content=b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00",
        content_type="application/vnd.tcpdump.pcap",
    )
    assert att.file_size == 8
    assert att_mgr.verify_checksum(att.id) is True

    data = att_mgr.get_attachment_content(att.id)
    assert data == b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"

    att_mgr.delete_attachment(att.id)
    assert att_mgr.get_attachment(att.id) is None
