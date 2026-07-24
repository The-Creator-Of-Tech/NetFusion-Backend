"""
Tests for InvestigationLifecycleManager facade, InvestigationService, BookmarkManager, ActivityLogger, and EventBus.
"""

import shutil
import tempfile
import pytest

from netfusion_investigation.lifecycle.activity import ActivityLogger
from netfusion_investigation.lifecycle.bookmarks import BookmarkManager
from netfusion_investigation.lifecycle.events import EventBus, InvestigationCreated
from netfusion_investigation.lifecycle.manager import InvestigationLifecycleManager
from netfusion_investigation.lifecycle.models import ArtifactType, BookmarkType, InvestigationStatus, Priority, Severity
from netfusion_investigation.lifecycle.reports import ReportEngine


@pytest.fixture
def temp_storage():
    tmp_dir = tempfile.mkdtemp()
    yield tmp_dir
    shutil.rmtree(tmp_dir, ignore_errors=True)


def test_event_bus_pub_sub():
    eb = EventBus()
    received = []

    def handler(evt):
        received.append(evt)

    eb.subscribe("InvestigationCreated", handler)
    evt = InvestigationCreated(event_id="evt-1", investigation_id="inv-1", payload={"key": "val"})
    eb.publish(evt)

    assert len(received) == 1
    assert received[0].investigation_id == "inv-1"
    assert len(eb.get_history(investigation_id="inv-1")) == 1


def test_bookmark_manager():
    bm = BookmarkManager()
    b = bm.add_bookmark("inv-1", BookmarkType.EVIDENCE, "ev-100", "Critical Memory Dump")
    assert b.title == "Critical Memory Dump"

    b_list = bm.get_bookmarks("inv-1", bookmark_type=BookmarkType.EVIDENCE)
    assert len(b_list) == 1

    bm.remove_bookmark(b.id)
    assert len(bm.get_bookmarks("inv-1")) == 0


def test_report_engine():
    inv = get_dummy_investigation()
    json_rep = ReportEngine.generate_json_report(inv)
    assert "report_type" in json_rep

    md_rep = ReportEngine.generate_markdown_report(inv)
    assert "# Investigation Report:" in md_rep

    html_rep = ReportEngine.generate_html_report(inv)
    assert "<html>" in html_rep


def get_dummy_investigation():
    from netfusion_investigation.lifecycle.models import Investigation
    return Investigation(id="inv-99", case_id="CASE-99", title="Dummy Investigation")


def test_manager_full_flow(temp_storage):
    mgr = InvestigationLifecycleManager(storage_dir=temp_storage)

    # 1. Create Investigation
    inv = mgr.create_investigation(
        case_id="CASE-500",
        title="Enterprise Data Exfiltration",
        description="Suspicious outbound traffic to unknown IP",
        priority=Priority.HIGH,
        severity=Severity.HIGH,
        owner="analyst_charlie",
    )
    assert inv.id is not None

    # 2. Update & Link Entities
    updated = mgr.update_investigation(inv.id, team="Threat Hunting")
    assert updated.team == "Threat Hunting"

    mgr.link_entities(inv.id, ioc_values=["203.0.113.5"], cve_ids=["CVE-2026-9999"])
    inv_fetched = mgr.get_investigation(inv.id)
    assert "203.0.113.5" in inv_fetched.links.ioc_values

    # 3. Create Reasoning Session & Merge
    sess1 = mgr.create_session(inv.id, "Session 1", state={"ip": "203.0.113.5"})
    sess2 = mgr.create_session(inv.id, "Session 2", state={"dns": "exfil-domain.com"})
    merged = mgr.merge_sessions(sess1.id, [sess2.id])
    assert "dns" in merged.state

    # 4. Store Artifact & Add Attachment
    art = mgr.store_artifact(inv.id, "Analyst Notes.md", ArtifactType.MARKDOWN, "# Notes")
    assert art.name == "Analyst Notes.md"

    att = mgr.add_attachment(inv.id, "dump.raw", b"\x00\x01\x02")
    assert att.filename == "dump.raw"

    # 5. Snapshots & Replay
    snap = mgr.create_snapshot(inv.id, label="Pre-mitigation")
    assert snap.version == 1

    rpl_sess = mgr.initialize_replay(inv, timeline_events=[{"timestamp": "2026-07-22T11:00:00Z", "title": "Alert"}])
    assert rpl_sess.total_steps == 1

    # 6. Bookmarks & Activity
    bm = mgr.add_bookmark(inv.id, BookmarkType.REPORT, art.id, "Final Report Bookmark")
    assert bm.id is not None

    acts = mgr.get_activities(inv.id)
    assert len(acts) > 0

    # 7. Search
    found = mgr.search_investigations(ioc="203.0.113.5")
    assert len(found) == 1 and found[0].id == inv.id
