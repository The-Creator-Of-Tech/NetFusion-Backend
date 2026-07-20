"""
NetFusion Sysmon Cross-Module Integration Bridge
Translates Sysmon canonical events (Processes, Registry, Network, Files) into Workflow Evidence and Timeline events.
"""

import time
from typing import Dict, Any
from netfusion_workflow.enums import EvidenceSource, Severity


class SysmonIntegrationBridge:
    """Bridge converting Sysmon collector outputs to Workflow domain params."""

    @staticmethod
    def add_process_timeline(workflow_service: Any, investigation_id: str, event_dict: Dict[str, Any]) -> Any:
        proc_name = event_dict.get("image", event_dict.get("process_name", "unknown_process"))
        cmd_line = event_dict.get("command_line", "")
        pid = event_dict.get("process_id", 0)

        sev = Severity.INFORMATIONAL
        if "powershell" in cmd_line.lower() or "cmd.exe" in cmd_line.lower():
            sev = Severity.MEDIUM

        return workflow_service.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Sysmon Process Execution: {proc_name}",
            event_type="PROCESS_CREATION",
            source="SYSMON",
            severity=sev,
            description=f"PID {pid} executed command: {cmd_line}",
            raw_data=event_dict,
        )

    @staticmethod
    def add_network_timeline(workflow_service: Any, investigation_id: str, event_dict: Dict[str, Any]) -> Any:
        dest_ip = event_dict.get("destination_ip", "0.0.0.0")
        dest_port = event_dict.get("destination_port", 0)
        src_ip = event_dict.get("source_ip", "0.0.0.0")
        image = event_dict.get("image", "unknown")

        sev = Severity.HIGH if dest_port in (4444, 8080, 1337) else Severity.LOW

        return workflow_service.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Sysmon Network Connection to {dest_ip}:{dest_port}",
            event_type="NETWORK_CONNECTION",
            source="SYSMON",
            severity=sev,
            description=f"Process {image} connected from {src_ip} to {dest_ip}:{dest_port}",
            raw_data=event_dict,
        )

    @staticmethod
    def add_evidence(workflow_service: Any, investigation_id: str, event_dict: Dict[str, Any]) -> Any:
        event_type = event_dict.get("event_type", "Sysmon Event")
        return workflow_service.add_evidence(
            investigation_id=investigation_id,
            name=f"Sysmon Evidence: {event_type}",
            description=str(event_dict),
            source=EvidenceSource.SYSMON,
            raw_artifact=str(event_dict),
        )
