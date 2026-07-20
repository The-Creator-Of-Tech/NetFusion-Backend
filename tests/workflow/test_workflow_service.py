"""
End-to-end integration test suite for WorkflowService API.
"""

import unittest
from netfusion_workflow import (
    WorkflowService,
    CaseLifecycle,
    Priority,
    Severity,
    EvidenceSource,
    TaskStatus,
)


class TestWorkflowServiceIntegration(unittest.TestCase):
    def test_full_investigation_lifecycle_workflow(self):
        service = WorkflowService()

        # 1. Create Case
        case = service.create_case(
            title="Enterprise Ransomware Attack",
            summary="Ransomware outbreak in branch office",
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="soc_lead",
        )
        self.assertEqual(case.status, CaseLifecycle.NEW)

        # 2. Create Investigation
        inv = service.create_investigation(
            title="LockBit Ransomware Host Compromise",
            case_id=case.case_id,
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="soc_lead",
            affected_assets=["192.168.10.50", "SRV-FILE-01"],
            affected_users=["admin_user"],
        )

        # 3. Triage & Progress
        service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="soc_lead")
        service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="soc_lead")

        # 4. Add Tasks
        task1 = service.create_task(
            investigation_id=inv.investigation_id,
            title="Isolate Host SRV-FILE-01",
            assignee="analyst_1",
            priority=Priority.CRITICAL,
        )
        task2 = service.create_task(
            investigation_id=inv.investigation_id,
            title="Collect Ransom Note & Encrypted Files",
            assignee="analyst_2",
            dependencies=[task1.task_id],
        )

        # Complete Task 1 then Task 2
        service.update_task_status(inv.investigation_id, task1.task_id, TaskStatus.COMPLETED, actor="analyst_1")
        service.update_task_status(inv.investigation_id, task2.task_id, TaskStatus.COMPLETED, actor="analyst_2")

        # 5. Add Evidence
        evidence = service.add_evidence(
            investigation_id=inv.investigation_id,
            name="Restore-Files.txt",
            description="Ransom note dropped by LockBit",
            source=EvidenceSource.SYSMON,
            raw_artifact=b"Your files have been encrypted by LockBit...",
            actor="analyst_2",
        )
        self.assertIsNotNone(evidence.hash_sha256)

        # 6. Add Analyst Note
        service.add_note(
            investigation_id=inv.investigation_id,
            title="Ransomware Variant Confirmed",
            content="Confirmed LockBit 3.0 executable running via GPO schedule",
            author="analyst_2",
            ioc_references=["192.168.10.50"],
            mitre_references=["T1486"],
        )

        # 7. Transition to CONTAINMENT -> ERADICATION -> RECOVERY -> VALIDATION -> CLOSED
        service.transition_lifecycle(inv.investigation_id, CaseLifecycle.CONTAINMENT, actor="soc_lead")
        service.transition_lifecycle(inv.investigation_id, CaseLifecycle.ERADICATION, actor="soc_lead")
        service.transition_lifecycle(inv.investigation_id, CaseLifecycle.RECOVERY, actor="soc_lead")
        service.transition_lifecycle(inv.investigation_id, CaseLifecycle.VALIDATION, actor="soc_lead")

        closed_inv = service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="Ransomware outbreak contained, compromised account revoked, servers restored from backup.",
            root_cause="Compromised service account credentials used for RDP entry",
            actor="soc_lead",
        )

        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)
        self.assertIsNotNone(closed_inv.closed_time)

        # 8. Verify Audit Trail & Report Generation
        records = service.audit_logger.get_records()
        self.assertGreater(len(records), 5)

        report_meta = service.generate_report_metadata(inv.investigation_id)
        self.assertEqual(report_meta["executive_summary"]["status"], "CLOSED")


if __name__ == "__main__":
    unittest.main()
