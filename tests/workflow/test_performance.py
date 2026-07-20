"""
Performance test suite for NetFusion Workflow module under load (1,000+ items scale).
"""

import unittest
import time
from netfusion_workflow import WorkflowService, Priority, Severity, EvidenceSource


class TestWorkflowPerformance(unittest.TestCase):
    def test_high_volume_timeline_and_search_performance(self):
        service = WorkflowService()
        inv = service.create_investigation(title="High Volume Load Test")

        # 1. Bulk generate 1,000 timeline events
        start_t = time.time()
        for i in range(1000):
            service.add_timeline_event(
                investigation_id=inv.investigation_id,
                summary=f"Event number {i} - Host scan observed",
                event_type="COLLECTOR_EVENT",
                source="TSHARK" if i % 2 == 0 else "SYSMON",
                severity=Severity.HIGH if i % 10 == 0 else Severity.INFORMATIONAL,
            )
        elapsed_timeline = time.time() - start_t
        self.assertLess(elapsed_timeline, 2.0, "Timeline insertion of 1,000 events took longer than 2s")

        # 2. Test timeline sorting
        start_sort = time.time()
        sorted_events = service.get_timeline(inv.investigation_id, ascending=False)
        elapsed_sort = time.time() - start_sort
        self.assertEqual(len(sorted_events), 1001)  # 1000 + 1 initial creation event
        self.assertLess(elapsed_sort, 0.1, "Sorting 1,000 timeline events took longer than 0.1s")

        # 3. Search query over 1,000 items
        start_search = time.time()
        results = service.search(query="Event number 500")
        elapsed_search = time.time() - start_search
        self.assertEqual(len(results["timeline"]), 1)
        self.assertLess(elapsed_search, 0.2, "Searching 1,000 items took longer than 0.2s")


if __name__ == "__main__":
    unittest.main()
