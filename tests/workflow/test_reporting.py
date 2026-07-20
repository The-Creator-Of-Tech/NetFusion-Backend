"""
Unit tests for Reporting preparation engine metadata compilation.
"""

import unittest
from netfusion_workflow import (
    WorkflowService,
    Priority,
    Severity,
    EvidenceSource,
    MITREMapping,
)


class TestReportingEngine(unittest.TestCase):
    def setUp(self):
        self.service = WorkflowService()
        self.inv = self.service.create_investigation(
            title="Data Exfiltration via DNS Tunneling",
            summary="Suspicious high volume TXT query traffic",
            affected_assets=["10.0.1.50"],
            affected_users=["user_alice"],
        )
        self.inv.mitre_mappings.append(
            MITREMapping(
                tactic="Exfiltration",
                tactic_id="TA0010",
                technique="Exfiltration Over Alternative Protocol",
                technique_id="T1048",
            )
        )
        self.service.add_evidence(
            investigation_id=self.inv.investigation_id,
            name="dns_queries.pcap",
            description="DNS traffic capture",
            source=EvidenceSource.TSHARK,
        )

    def test_generate_report_metadata(self):
        metadata = self.service.generate_report_metadata(
            investigation_id=self.inv.investigation_id,
            report_type="EXECUTIVE",
            author="lead_analyst",
        )

        self.assertIn("executive_summary", metadata)
        self.assertIn("technical_summary", metadata)
        self.assertIn("evidence_list", metadata)
        self.assertIn("timeline", metadata)
        self.assertIn("mitre_coverage", metadata)

        exec_sum = metadata["executive_summary"]
        self.assertIn("Data Exfiltration via DNS Tunneling", exec_sum["title"])
        self.assertEqual(exec_sum["author"], "lead_analyst")

        mitre_cov = metadata["mitre_coverage"]
        self.assertEqual(mitre_cov["total_techniques_mapped"], 1)
        self.assertIn("Exfiltration", mitre_cov["tactics"])


if __name__ == "__main__":
    unittest.main()
