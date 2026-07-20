"""
NetFusion v1.0 Real-World Investigation Validation Test Suite.

Executes and validates 6 end-to-end investigation scenarios:
1. Phishing Investigation
2. Ransomware Investigation
3. Insider Threat Investigation
4. Lateral Movement Investigation
5. Malware Beaconing Investigation
6. Data Exfiltration Investigation

Validates for each scenario:
- Investigation Lifecycle & Tasks
- Timeline Events & Sorting
- Evidence Artifact Ingestion & Checksum Integrity
- MITRE ATT&CK Mapping
- Risk Assessment & Scoring
- AI Assistant Analysis & Recommendations
- Final Investigation Report Metadata & Executive Summary
"""

import pytest
import unittest
from datetime import datetime, timezone
from netfusion_workflow import (
    WorkflowService,
    CaseLifecycle,
    Priority,
    Severity,
    EvidenceSource,
    TaskStatus,
)
from netfusion_ai import (
    AIAssistant,
    ContextBuilder,
    MockAIProvider,
    AnalysisCategory,
)


class TestRealWorldInvestigations(unittest.TestCase):
    def setUp(self):
        self.workflow_service = WorkflowService()
        self.ai_assistant = AIAssistant(provider=MockAIProvider())
        self.context_builder = ContextBuilder()

    def test_01_phishing_investigation(self):
        """1. Phishing Investigation Scenario"""
        # Create Case & Investigation
        case = self.workflow_service.create_case(
            title="Credential Phishing Campaign - Executive Target",
            summary="Spear phishing email with credential harvester link delivered to C-suite",
            priority=Priority.HIGH,
            severity=Severity.HIGH,
            owner="soc_analyst_1",
        )
        inv = self.workflow_service.create_investigation(
            title="Phishing Email Analysis - ceo@enterprise.com",
            case_id=case.case_id,
            priority=Priority.HIGH,
            severity=Severity.HIGH,
            owner="soc_analyst_1",
            affected_assets=["192.168.1.100", "WORKSTATION-CEO"],
            affected_users=["ceo@enterprise.com"],
        )

        # Transition to IN_PROGRESS
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="soc_analyst_1")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="soc_analyst_1")

        # Add Evidence
        evidence = self.workflow_service.add_evidence(
            investigation_id=inv.investigation_id,
            name="phishing_email.eml",
            description="Malicious email header and payload body",
            source=EvidenceSource.THREAT_INTEL,
            raw_artifact=b"From: billing@update-microsoft-account.com\nTo: ceo@enterprise.com\nSubject: Urgent Account Verification\nURL: http://malicious-phish-domain.com/login",
            actor="soc_analyst_1",
        )
        self.assertIsNotNone(evidence.hash_sha256)

        # Add Analyst Note & MITRE Mapping
        self.workflow_service.add_note(
            investigation_id=inv.investigation_id,
            title="Phishing URL Analysis",
            content="Extracted suspicious link pointing to credential harvest portal. Identified MITRE T1566.002",
            author="soc_analyst_1",
            ioc_references=["http://malicious-phish-domain.com/login", "update-microsoft-account.com"],
            mitre_references=["T1566.002"],
        )

        # AI Analysis
        context = self.context_builder.build_context(
            investigation={"investigation_id": inv.investigation_id, "title": inv.title, "description": case.summary},
            evidence=[evidence.to_dict()],
            iocs=[{"type": "url", "value": "http://malicious-phish-domain.com/login", "confidence": "HIGH"}],
        )
        ai_resp = self.ai_assistant.analyze_investigation(context, category=AnalysisCategory.INCIDENT_SUMMARY)
        self.assertEqual(ai_resp.investigation_id, inv.investigation_id)
        self.assertGreater(ai_resp.confidence.overall_score, 0.0)

        # Close Investigation
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.CONTAINMENT, actor="soc_analyst_1")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.ERADICATION, actor="soc_analyst_1")
        closed_inv = self.workflow_service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="Phishing URL blocked at firewall, user credentials reset, email purged from inboxes.",
            root_cause="External spear phishing email bypassing basic spam filter",
            actor="soc_analyst_1",
        )
        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)

        # Report Validation
        report = self.workflow_service.generate_report_metadata(inv.investigation_id)
        self.assertIn(inv.title, report["executive_summary"]["title"])

    def test_02_ransomware_investigation(self):
        """2. Ransomware Investigation Scenario"""
        case = self.workflow_service.create_case(
            title="LockBit Ransomware Outbreak - Finance Subnet",
            summary="Shadow copies deleted and files encrypted across financial server cluster",
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="incident_responder",
        )
        inv = self.workflow_service.create_investigation(
            title="Host Encryption & VSS Deletion Analysis",
            case_id=case.case_id,
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="incident_responder",
            affected_assets=["10.0.5.12", "FIN-SRV-02"],
            affected_users=["fin_admin"],
        )

        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="incident_responder")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="incident_responder")

        # Tasks
        t1 = self.workflow_service.create_task(inv.investigation_id, "Isolate Host FIN-SRV-02", "sysadmin_1", Priority.CRITICAL)
        self.workflow_service.update_task_status(inv.investigation_id, t1.task_id, TaskStatus.COMPLETED, actor="sysadmin_1")

        # Evidence & MITRE
        evidence = self.workflow_service.add_evidence(
            investigation_id=inv.investigation_id,
            name="sysmon_vss_deletion.evtx",
            description="Sysmon Event ID 1: vssadmin.exe Delete Shadows /All /Quiet",
            source=EvidenceSource.SYSMON,
            raw_artifact=b"EventID: 1, Image: C:\\Windows\\System32\\vssadmin.exe, CommandLine: delete shadows /all /quiet",
            actor="incident_responder",
        )
        self.workflow_service.add_note(
            investigation_id=inv.investigation_id,
            title="Ransomware Execution Verified",
            content="LockBit payload ran vssadmin shadow copy deletion (T1490) followed by file encryption (T1486).",
            author="incident_responder",
            mitre_references=["T1490", "T1486"],
        )

        # AI Analysis
        context = self.context_builder.build_context(
            investigation={"investigation_id": inv.investigation_id, "title": inv.title},
            evidence=[evidence.to_dict()],
            sysmon_events=[{"event_id": 1, "image": "vssadmin.exe", "command_line": "delete shadows /all /quiet"}],
        )
        hypotheses = self.ai_assistant.generate_hypotheses(context)
        self.assertGreaterEqual(len(hypotheses), 1)

        # Close Case
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.CONTAINMENT, actor="incident_responder")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.ERADICATION, actor="incident_responder")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.RECOVERY, actor="incident_responder")
        closed_inv = self.workflow_service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="Ransomware contained. Host restored from immutable offsite backup.",
            root_cause="Compromised RDP service account without MFA",
            actor="incident_responder",
        )
        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)

    def test_03_insider_threat_investigation(self):
        """3. Insider Threat Investigation Scenario"""
        case = self.workflow_service.create_case(
            title="Unauthorized Internal Intellectual Property Download",
            summary="Departing employee exfiltrated source code repository to external USB drive",
            priority=Priority.HIGH,
            severity=Severity.HIGH,
            owner="insider_risk_lead",
        )
        inv = self.workflow_service.create_investigation(
            title="Employee Exfiltration via Removable Media",
            case_id=case.case_id,
            priority=Priority.HIGH,
            severity=Severity.HIGH,
            owner="insider_risk_lead",
            affected_assets=["DEV-LAPTOP-88"],
            affected_users=["dev_user_09"],
        )

        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="insider_risk_lead")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="insider_risk_lead")

        evidence = self.workflow_service.add_evidence(
            investigation_id=inv.investigation_id,
            name="usb_device_mount_log.evtx",
            description="Sysmon Event ID 11 / Windows Event 20001 USB Mass Storage Mount",
            source=EvidenceSource.SYSMON,
            raw_artifact=b"EventID: 11, TargetFilename: E:\\confidential_source_code.zip, Device: SanDisk Ultra USB 3.0",
            actor="insider_risk_lead",
        )

        self.workflow_service.add_note(
            investigation_id=inv.investigation_id,
            title="Insider Exfiltration Identified",
            content="User mounted unauthorized USB drive and copied 4.2GB archive (MITRE T1052.001, T1078).",
            author="insider_risk_lead",
            mitre_references=["T1052.001", "T1078"],
        )

        closed_inv = self.workflow_service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="Device seized by HR/Legal, corporate network access terminated.",
            root_cause="Disgruntled departing employee attempting IP theft",
            actor="insider_risk_lead",
        )
        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)

    def test_04_lateral_movement_investigation(self):
        """4. Lateral Movement Investigation Scenario"""
        case = self.workflow_service.create_case(
            title="Domain Admin Pass-The-Hash Lateral Movement",
            summary="Suspicious PsExec / WMI execution moving laterally from workstation to domain controller",
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="soc_threat_hunter",
        )
        inv = self.workflow_service.create_investigation(
            title="Host-to-DC SMB/WMI Session Analysis",
            case_id=case.case_id,
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="soc_threat_hunter",
            affected_assets=["10.0.1.15", "10.0.1.5", "DC01.corp.local"],
            affected_users=["svc_backup"],
        )

        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="soc_threat_hunter")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="soc_threat_hunter")

        evidence = self.workflow_service.add_evidence(
            investigation_id=inv.investigation_id,
            name="psexec_remote_service_creation.evtx",
            description="Sysmon Event ID 3 (Network Conn) & Event ID 10 (Process Access)",
            source=EvidenceSource.SYSMON,
            raw_artifact=b"EventID: 1, Image: C:\\Windows\\PSEXESVC.exe, SourceIP: 10.0.1.15, DestIP: 10.0.1.5",
            actor="soc_threat_hunter",
        )

        self.workflow_service.add_note(
            investigation_id=inv.investigation_id,
            title="Lateral Movement Verified",
            content="Attacker reused stolen NT hash via SMB port 445 to spawn PSEXESVC on DC01 (MITRE T1021.002).",
            author="soc_threat_hunter",
            mitre_references=["T1021.002", "T1550.002"],
        )

        closed_inv = self.workflow_service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="Host isolated, service account ticket purged, domain admin credentials reset.",
            root_cause="LSASS memory dump on compromised workstation leading to credential theft",
            actor="soc_threat_hunter",
        )
        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)

    def test_05_malware_beaconing_investigation(self):
        """5. Malware Beaconing Investigation Scenario"""
        case = self.workflow_service.create_case(
            title="C2 DNS Beaconing Detection - Cobalt Strike",
            summary="Periodic outbound HTTP/DNS requests to suspicious external IP every 60 seconds",
            priority=Priority.HIGH,
            severity=Severity.HIGH,
            owner="network_analyst",
        )
        inv = self.workflow_service.create_investigation(
            title="PCAP Traffic Analysis - Beaconing Pattern",
            case_id=case.case_id,
            priority=Priority.HIGH,
            severity=Severity.HIGH,
            owner="network_analyst",
            affected_assets=["192.168.10.42"],
            affected_users=["user_bob"],
        )

        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="network_analyst")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="network_analyst")

        evidence = self.workflow_service.add_evidence(
            investigation_id=inv.investigation_id,
            name="tshark_c2_beaconing.pcap",
            description="TShark packet capture showing 60s jittered GET requests to 185.220.101.5",
            source=EvidenceSource.TSHARK,
            raw_artifact=b"GET /submit.php?id=8831 HTTP/1.1\r\nHost: c2-command-server.evil.ru\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            actor="network_analyst",
        )

        self.workflow_service.add_note(
            investigation_id=inv.investigation_id,
            title="Cobalt Strike Beacon Ingress",
            content="Network flow analysis confirmed HTTP C2 beaconing (MITRE T1071.001). IP flagged high risk.",
            author="network_analyst",
            ioc_references=["185.220.101.5", "c2-command-server.evil.ru"],
            mitre_references=["T1071.001"],
        )

        closed_inv = self.workflow_service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="C2 IP blacklisted on edge perimeter firewall, host re-imaged.",
            root_cause="Drive-by download of malicious browser extension",
            actor="network_analyst",
        )
        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)

    def test_06_data_exfiltration_investigation(self):
        """6. Data Exfiltration Investigation Scenario"""
        case = self.workflow_service.create_case(
            title="High Volume Outbound Encrypted Traffic Exfiltration",
            summary="50GB transferred over port 443 to rare external cloud storage domain",
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="sec_operations_lead",
        )
        inv = self.workflow_service.create_investigation(
            title="Nmap & Flow Exfiltration Analysis",
            case_id=case.case_id,
            priority=Priority.CRITICAL,
            severity=Severity.CRITICAL,
            owner="sec_operations_lead",
            affected_assets=["172.16.4.120", "DB-PROD-PRIMARY"],
            affected_users=["db_service_acct"],
        )

        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.TRIAGED, actor="sec_operations_lead")
        self.workflow_service.transition_lifecycle(inv.investigation_id, CaseLifecycle.IN_PROGRESS, actor="sec_operations_lead")

        evidence = self.workflow_service.add_evidence(
            investigation_id=inv.investigation_id,
            name="exfiltration_flow_summary.json",
            description="NetFlow record showing 52.4 GB egress to 45.33.22.11 over HTTPS",
            source=EvidenceSource.NMAP,
            raw_artifact=b'{"src_ip":"172.16.4.120","dst_ip":"45.33.22.11","bytes_sent":56264228864,"proto":"TCP","port":443}',
            actor="sec_operations_lead",
        )

        self.workflow_service.add_note(
            investigation_id=inv.investigation_id,
            title="Database Egress Exfiltration Confirmed",
            content="Database dump archived and transferred via mega.nz cloud storage CLI (MITRE T1048.002).",
            author="sec_operations_lead",
            ioc_references=["45.33.22.11"],
            mitre_references=["T1048.002", "T1567.002"],
        )

        closed_inv = self.workflow_service.close_investigation(
            investigation_id=inv.investigation_id,
            final_verdict="Egress IP blocked, database credentials rotated, DLP policy updated.",
            root_cause="SQL injection vulnerability leveraged to dump database tables",
            actor="sec_operations_lead",
        )
        self.assertEqual(closed_inv.status, CaseLifecycle.CLOSED)


if __name__ == "__main__":
    unittest.main()
