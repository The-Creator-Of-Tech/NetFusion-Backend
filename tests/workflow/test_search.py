"""
Unit tests for SearchEngine cross-entity search and index retrieval.
"""

import unittest
from netfusion_workflow import (
    WorkflowService,
    Priority,
    Severity,
    EvidenceSource,
    Tag,
    TagCategory,
)


class TestSearchEngine(unittest.TestCase):
    def setUp(self):
        self.service = WorkflowService()

        # Create case & investigation
        self.case = self.service.create_case(
            title="APT29 Spearphishing Incident",
            summary="Spearphishing targeting executive team",
            priority=Priority.HIGH,
        )

        self.inv = self.service.create_investigation(
            title="Malicious Document Payload",
            case_id=self.case.case_id,
            summary="Macro payload executed in Word",
            affected_assets=["10.0.8.22"],
            affected_users=["exec_user@corp.com"],
        )

        self.ev = self.service.add_evidence(
            investigation_id=self.inv.investigation_id,
            name="invoice.docm",
            description="Malicious Word document",
            source=EvidenceSource.MANUAL,
            raw_artifact=b"DOCM_PAYLOAD",
            tags=[Tag(name="malware_doc", category=TagCategory.MALWARE)],
        )

        self.note = self.service.add_note(
            investigation_id=self.inv.investigation_id,
            title="Macro Analysis",
            content="Extracted macro calls Powershell payload `http://evil.com/shell.ps1`",
            author="analyst_eve",
            ioc_references=["10.0.8.22", "http://evil.com/shell.ps1"],
            mitre_references=["T1059.001"],
        )

    def test_search_by_query_string(self):
        results = self.service.search(query="Spearphishing")
        self.assertGreater(len(results["cases"]), 0)
        self.assertEqual(results["cases"][0].case_id, self.case.case_id)

    def test_search_by_ioc(self):
        results = self.service.search(query="", ioc="10.0.8.22")
        self.assertGreater(len(results["investigations"]), 0)
        self.assertEqual(results["investigations"][0].investigation_id, self.inv.investigation_id)

    def test_search_by_mitre_id(self):
        results = self.service.search(query="", mitre_id="T1059.001")
        self.assertGreater(len(results["notes"]), 0)
        self.assertEqual(results["notes"][0].note_id, self.note.note_id)


if __name__ == "__main__":
    unittest.main()
