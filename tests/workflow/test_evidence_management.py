"""
Unit tests for Evidence Management, checksum calculation, chain of custody, and integrity verification.
"""

import unittest
from netfusion_workflow import (
    EvidenceManager,
    EvidenceSource,
    IntegrityStatus,
    EvidenceIntegrityError,
    WorkflowService,
)


class TestEvidenceManagement(unittest.TestCase):
    def test_checksum_calculation(self):
        data = "Malicious Payload Sample 123"
        hashes = EvidenceManager.calculate_hashes(data)
        self.assertIn("sha256", hashes)
        self.assertIn("md5", hashes)
        self.assertIn("sha1", hashes)
        self.assertEqual(len(hashes["sha256"]), 64)

    def test_evidence_creation_and_integrity_check(self):
        data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        evidence = EvidenceManager.create_evidence(
            name="malware.elf",
            investigation_id="inv-123",
            description="Linux ELF executable",
            source=EvidenceSource.SYSMON,
            raw_artifact=data,
            actor="sysmon_collector",
        )

        self.assertEqual(evidence.integrity_status, IntegrityStatus.VERIFIED)
        self.assertGreater(len(evidence.chain_of_custody), 0)
        self.assertEqual(evidence.chain_of_custody[0].actor, "sysmon_collector")

        # Verify integrity succeeds when unmodified
        res = EvidenceManager.verify_integrity(evidence)
        self.assertTrue(res)

        # Mutate artifact data and verify exception is raised
        evidence.raw_artifact = b"TAMPERED_PAYLOAD"
        with self.assertRaises(EvidenceIntegrityError):
            EvidenceManager.verify_integrity(evidence)
        self.assertEqual(evidence.integrity_status, IntegrityStatus.TAMPERED)

    def test_add_custody_entry(self):
        evidence = EvidenceManager.create_evidence(
            name="memory.dmp",
            investigation_id="inv-456",
            source=EvidenceSource.MANUAL,
        )

        entry = EvidenceManager.add_custody_entry(
            evidence=evidence,
            actor="analyst_charlie",
            action="TRANSFERRED",
            location="FORENSIC_LAB_SAFE",
            notes="Transferred for deep analysis",
        )
        self.assertEqual(len(evidence.chain_of_custody), 2)
        self.assertEqual(entry.actor, "analyst_charlie")
        self.assertEqual(entry.action, "TRANSFERRED")


if __name__ == "__main__":
    unittest.main()
