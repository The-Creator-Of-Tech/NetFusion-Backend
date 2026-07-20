"""
Unit tests for NetFusion Workflow domain entities.
"""

import unittest
import time
from netfusion_workflow import (
    Case,
    Investigation,
    Task,
    Evidence,
    TimelineEvent,
    AnalystNote,
    Comment,
    Assignment,
    Tag,
    Attachment,
    Recommendation,
    ReportReference,
    MITREMapping,
    RiskAssessment,
    Approval,
    Bookmark,
    Notification,
    AuditRecord,
    CaseLifecycle,
    Priority,
    Severity,
    TaskStatus,
    ApprovalStatus,
    TagCategory,
    AuditAction,
    EvidenceSource,
    IntegrityStatus,
)


class TestWorkflowDomainObjects(unittest.TestCase):
    def test_case_instantiation_and_dict(self):
        case = Case(
            title="Test Case",
            summary="Case summary text",
            priority=Priority.HIGH,
            severity=Severity.CRITICAL,
            owner="analyst_alice",
        )
        self.assertIsNotNone(case.case_id)
        self.assertEqual(case.status, CaseLifecycle.NEW)
        d = case.to_dict()
        self.assertEqual(d["title"], "Test Case")
        self.assertEqual(d["priority"], "HIGH")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["owner"], "analyst_alice")

    def test_investigation_instantiation_and_dict(self):
        inv = Investigation(
            title="Test Investigation",
            summary="Summary text",
            affected_assets=["10.0.0.1", "server01"],
            affected_users=["user1"],
        )
        self.assertIsNotNone(inv.investigation_id)
        self.assertEqual(inv.status, CaseLifecycle.NEW)
        d = inv.to_dict()
        self.assertEqual(d["title"], "Test Investigation")
        self.assertIn("10.0.0.1", d["affected_assets"])
        self.assertIn("user1", d["affected_users"])

    def test_task_instantiation_and_dict(self):
        task = Task(
            title="Isolate host",
            description="Isolate compromise host from network",
            priority=Priority.CRITICAL,
        )
        self.assertEqual(task.status, TaskStatus.TODO)
        self.assertEqual(task.completion_percentage, 0.0)
        d = task.to_dict()
        self.assertEqual(d["title"], "Isolate host")
        self.assertEqual(d["status"], "TODO")

    def test_evidence_instantiation(self):
        ev = Evidence(
            name="PCAP Artifact",
            source=EvidenceSource.TSHARK,
            description="Packet capture of C2",
        )
        self.assertEqual(ev.integrity_status, IntegrityStatus.UNVERIFIED)
        d = ev.to_dict()
        self.assertEqual(d["name"], "PCAP Artifact")
        self.assertEqual(d["source"], "TSHARK")

    def test_risk_assessment(self):
        risk = RiskAssessment(
            risk_score=85.5,
            confidence=90.0,
            severity=Severity.HIGH,
            affected_systems=["web-server-01"],
        )
        d = risk.to_dict()
        self.assertEqual(d["risk_score"], 85.5)
        self.assertEqual(d["severity"], "HIGH")

    def test_mitre_mapping(self):
        mapping = MITREMapping(
            tactic="Persistence",
            tactic_id="TA0003",
            technique="Create Account",
            technique_id="T1136",
        )
        d = mapping.to_dict()
        self.assertEqual(d["technique_id"], "T1136")

    def test_tag_instantiation(self):
        tag = Tag(name="APT29", category=TagCategory.THREAT_ACTOR)
        d = tag.to_dict()
        self.assertEqual(d["name"], "APT29")
        self.assertEqual(d["category"], "THREAT_ACTOR")


if __name__ == "__main__":
    unittest.main()
