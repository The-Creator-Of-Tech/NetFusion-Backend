"""
Unit tests for NetFusion Case & Investigation Lifecycle State Machine.
"""

import unittest
from netfusion_workflow import (
    Case,
    Investigation,
    LifecycleEngine,
    CaseLifecycle,
    InvalidLifecycleTransitionError,
)


class TestLifecycleEngine(unittest.TestCase):
    def test_valid_transitions(self):
        inv = Investigation(title="Lifecycle Test")
        self.assertEqual(inv.status, CaseLifecycle.NEW)

        # NEW -> TRIAGED
        audit1 = LifecycleEngine.transition(inv, CaseLifecycle.TRIAGED, actor="analyst_1", reason="Initial triage")
        self.assertEqual(inv.status, CaseLifecycle.TRIAGED)
        self.assertEqual(audit1.changes["old_status"], "NEW")
        self.assertEqual(audit1.changes["new_status"], "TRIAGED")

        # TRIAGED -> IN_PROGRESS
        LifecycleEngine.transition(inv, CaseLifecycle.IN_PROGRESS, actor="analyst_1")
        self.assertEqual(inv.status, CaseLifecycle.IN_PROGRESS)

        # IN_PROGRESS -> CONTAINMENT
        LifecycleEngine.transition(inv, CaseLifecycle.CONTAINMENT, actor="analyst_1")
        self.assertEqual(inv.status, CaseLifecycle.CONTAINMENT)

        # CONTAINMENT -> ERADICATION
        LifecycleEngine.transition(inv, CaseLifecycle.ERADICATION, actor="analyst_1")
        self.assertEqual(inv.status, CaseLifecycle.ERADICATION)

        # ERADICATION -> RECOVERY
        LifecycleEngine.transition(inv, CaseLifecycle.RECOVERY, actor="analyst_1")
        self.assertEqual(inv.status, CaseLifecycle.RECOVERY)

        # RECOVERY -> VALIDATION
        LifecycleEngine.transition(inv, CaseLifecycle.VALIDATION, actor="analyst_1")
        self.assertEqual(inv.status, CaseLifecycle.VALIDATION)

        # VALIDATION -> CLOSED
        inv.root_cause = "Phishing email"
        inv.final_verdict = "Incident contained and mitigated"
        LifecycleEngine.transition(inv, CaseLifecycle.CLOSED, actor="analyst_1")
        self.assertEqual(inv.status, CaseLifecycle.CLOSED)
        self.assertIsNotNone(inv.closed_time)

    def test_invalid_transition_raises_error(self):
        inv = Investigation(title="Invalid Lifecycle Test")
        inv.status = CaseLifecycle.NEW

        # NEW cannot transition directly to ERADICATION
        with self.assertRaises(InvalidLifecycleTransitionError):
            LifecycleEngine.transition(inv, CaseLifecycle.ERADICATION)

    def test_same_state_transition_allowed(self):
        inv = Investigation(title="Same state test")
        LifecycleEngine.transition(inv, CaseLifecycle.NEW)
        self.assertEqual(inv.status, CaseLifecycle.NEW)

    def test_reopening_closed_investigation(self):
        inv = Investigation(title="Reopen Test", status=CaseLifecycle.CLOSED)
        LifecycleEngine.transition(inv, CaseLifecycle.IN_PROGRESS, actor="analyst_2", reason="New evidence discovered")
        self.assertEqual(inv.status, CaseLifecycle.IN_PROGRESS)


if __name__ == "__main__":
    unittest.main()
