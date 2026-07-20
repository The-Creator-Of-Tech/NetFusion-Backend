"""
Unit tests for Audit Logger recording and retrieval.
"""

import unittest
from netfusion_workflow import AuditLogger, AuditAction


class TestAuditLogger(unittest.TestCase):
    def test_audit_recording_and_filtering(self):
        logger = AuditLogger()

        rec1 = logger.record(
            action=AuditAction.CREATE,
            entity_type="Case",
            entity_id="case-100",
            actor="analyst_1",
            changes={"title": "Ransomware Attack"},
        )
        rec2 = logger.record(
            action=AuditAction.STATUS_CHANGE,
            entity_type="Investigation",
            entity_id="inv-200",
            actor="analyst_2",
            changes={"old_status": "NEW", "new_status": "IN_PROGRESS"},
        )

        all_records = logger.get_records()
        self.assertEqual(len(all_records), 2)

        case_records = logger.get_records(entity_type="Case")
        self.assertEqual(len(case_records), 1)
        self.assertEqual(case_records[0].entity_id, "case-100")

        actor2_records = logger.get_records(actor="analyst_2")
        self.assertEqual(len(actor2_records), 1)
        self.assertEqual(actor2_records[0].action, AuditAction.STATUS_CHANGE)


if __name__ == "__main__":
    unittest.main()
