"""
NetFusion TShark Cross-Module Integration Bridge
Translates TShark network flows, DNS queries, and HTTP requests into Workflow Evidence & Timelines.
"""

from typing import Dict, Any
from netfusion_workflow.enums import EvidenceSource, Severity


class TSharkIntegrationBridge:
    """Bridge converting TShark collector outputs to Workflow domain params."""

    @staticmethod
    def add_flow_timeline(workflow_service: Any, investigation_id: str, flow_dict: Dict[str, Any]) -> Any:
        src = flow_dict.get("source_ip", "0.0.0.0")
        dst = flow_dict.get("destination_ip", "0.0.0.0")
        dport = flow_dict.get("destination_port", 0)
        proto = flow_dict.get("protocol", "TCP")

        return workflow_service.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Network Packet Flow: {src} -> {dst}:{dport} ({proto})",
            event_type="NETWORK_FLOW",
            source="TSHARK",
            severity=Severity.INFORMATIONAL,
            description=f"Observed network traffic flow of {flow_dict.get('bytes_transferred', 0)} bytes",
            raw_data=flow_dict,
        )

    @staticmethod
    def add_dns_timeline(workflow_service: Any, investigation_id: str, dns_dict: Dict[str, Any]) -> Any:
        query = dns_dict.get("query_name", dns_dict.get("query", "unknown.domain"))
        client = dns_dict.get("client_ip", "0.0.0.0")
        sev = Severity.HIGH if ("c2" in query or "malware" in query or "beacon" in query) else Severity.LOW

        return workflow_service.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"DNS Transaction: {query}",
            event_type="DNS_QUERY",
            source="TSHARK",
            severity=sev,
            description=f"Client {client} queried DNS domain {query}",
            raw_data=dns_dict,
        )

    @staticmethod
    def add_evidence(workflow_service: Any, investigation_id: str, packet_dict: Dict[str, Any]) -> Any:
        return workflow_service.add_evidence(
            investigation_id=investigation_id,
            name=f"Network Capture Evidence: {packet_dict.get('protocol', 'PCAP')}",
            description=str(packet_dict),
            source=EvidenceSource.TSHARK,
            raw_artifact=str(packet_dict),
        )
