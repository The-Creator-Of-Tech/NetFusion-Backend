"""
NetFusion Nmap Cross-Module Integration Bridge
Translates Nmap host discoveries, open ports, and service fingerprints into Workflow Evidence & Timelines.
"""

from typing import Dict, Any
from netfusion_workflow.enums import EvidenceSource, Severity


class NmapIntegrationBridge:
    """Bridge converting Nmap collector outputs to Workflow domain params."""

    @staticmethod
    def add_host_timeline(workflow_service: Any, investigation_id: str, host_dict: Dict[str, Any]) -> Any:
        ip = host_dict.get("ip", host_dict.get("target", "0.0.0.0"))
        status = host_dict.get("status", "up")
        open_ports = host_dict.get("open_ports", [])

        return workflow_service.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Nmap Discovered Host: {ip}",
            event_type="RECONNAISSANCE",
            source="NMAP",
            severity=Severity.INFORMATIONAL,
            description=f"Host {ip} status is {status}. Discovered {len(open_ports)} open port(s): {open_ports}",
            raw_data=host_dict,
        )

    @staticmethod
    def add_evidence(workflow_service: Any, investigation_id: str, scan_dict: Dict[str, Any]) -> Any:
        target = scan_dict.get("target", scan_dict.get("ip", "network_scan"))
        return workflow_service.add_evidence(
            investigation_id=investigation_id,
            name=f"Nmap Network Discovery: {target}",
            description=str(scan_dict),
            source=EvidenceSource.NMAP,
            raw_artifact=str(scan_dict),
        )
