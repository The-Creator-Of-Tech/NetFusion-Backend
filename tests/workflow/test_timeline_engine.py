"""
Unit tests for TimelineEngine sorting, filtering, grouping, and searching.
"""

import unittest
import time
from netfusion_workflow import TimelineEngine, TimelineEvent, Severity


class TestTimelineEngine(unittest.TestCase):
    def setUp(self):
        self.engine = TimelineEngine()
        now = time.time()

        self.event1 = self.engine.create_event(
            summary="Initial Network Scan",
            event_type="COLLECTOR_EVENT",
            source="NMAP",
            severity=Severity.INFORMATIONAL,
            timestamp=now - 100,
            tags=["recon"],
        )
        self.event2 = self.engine.create_event(
            summary="Exfiltration Alert Detected",
            event_type="AI_FINDING",
            source="AI_ASSISTANT",
            severity=Severity.HIGH,
            timestamp=now - 50,
            tags=["exfil", "alert"],
        )
        self.event3 = self.engine.create_event(
            summary="Host Isolated",
            event_type="STATUS_CHANGE",
            source="WORKFLOW_ENGINE",
            severity=Severity.CRITICAL,
            timestamp=now,
            tags=["containment"],
        )

    def test_sorting(self):
        sorted_asc = self.engine.sort(ascending=True)
        self.assertEqual(sorted_asc[0].summary, "Initial Network Scan")
        self.assertEqual(sorted_asc[-1].summary, "Host Isolated")

        sorted_desc = self.engine.sort(ascending=False)
        self.assertEqual(sorted_desc[0].summary, "Host Isolated")

    def test_filtering(self):
        filtered = self.engine.filter(source="NMAP")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].summary, "Initial Network Scan")

        filtered_sev = self.engine.filter(severity=Severity.CRITICAL)
        self.assertEqual(len(filtered_sev), 1)
        self.assertEqual(filtered_sev[0].summary, "Host Isolated")

    def test_grouping(self):
        groups = self.engine.group_by("source")
        self.assertIn("NMAP", groups)
        self.assertIn("AI_ASSISTANT", groups)
        self.assertEqual(len(groups["NMAP"]), 1)

    def test_search(self):
        results = self.engine.search("Exfiltration")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].summary, "Exfiltration Alert Detected")

        results_tag = self.engine.search("recon")
        self.assertEqual(len(results_tag), 1)


if __name__ == "__main__":
    unittest.main()
