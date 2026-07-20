"""
Unit tests for Analyst Assignments, Reviewer/Manager Roles, Approvals, and Escalation.
"""

import unittest
from netfusion_workflow import (
    Assignment,
    Approval,
    ApprovalStatus,
    WorkflowService,
)


class TestAssignmentsAndApprovals(unittest.TestCase):
    def test_assignment_instantiation(self):
        assignment = Assignment(
            owner="analyst_1",
            assigned_analysts=["analyst_1", "analyst_2"],
            reviewer="tier2_lead",
            manager="soc_manager",
        )
        d = assignment.to_dict()
        self.assertEqual(d["owner"], "analyst_1")
        self.assertEqual(len(d["assigned_analysts"]), 2)
        self.assertEqual(d["reviewer"], "tier2_lead")

    def test_approval_workflow(self):
        approval = Approval(
            requester="analyst_1",
            approver="soc_manager",
            requested_action="Close High Severity Case",
        )
        self.assertEqual(approval.status, ApprovalStatus.PENDING)

        approval.status = ApprovalStatus.APPROVED
        approval.comments.append("Approved after verifying containment.")
        d = approval.to_dict()
        self.assertEqual(d["status"], "APPROVED")
        self.assertEqual(len(d["comments"]), 1)


if __name__ == "__main__":
    unittest.main()
