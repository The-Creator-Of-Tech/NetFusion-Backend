"""
Acceptance Scenario 4: Lateral Movement Identified Through Sysmon Process Creation and Network Events
Emits PsExec/WMI process launch, network SMB connections to internal hosts, and credential dumping attempt.
"""

import time
from typing import Dict, Any, List


def get_scenario_4_events() -> List[Dict[str, Any]]:
    """Return raw event telemetry for Scenario 4."""
    now = time.time()
    return [
        {
            "source": "sysmon",
            "event_type": "Process Creation",
            "event_id": 1,
            "image": "C:\\Windows\\System32\\cmd.exe",
            "process_id": 7820,
            "command_line": "cmd.exe /c psexec.exe \\\\10.0.0.50 -u ADMIN -p Password123! cmd.exe",
            "timestamp": now - 400,
        },
        {
            "source": "sysmon",
            "event_type": "Network Connection",
            "event_id": 3,
            "image": "C:\\Windows\\System32\\psexec.exe",
            "source_ip": "10.0.0.12",
            "destination_ip": "10.0.0.50",
            "destination_port": 445,
            "timestamp": now - 380,
        },
        {
            "source": "sysmon",
            "event_type": "Process Creation",
            "event_id": 1,
            "image": "C:\\Windows\\System32\\lsass.exe",
            "process_id": 890,
            "command_line": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 890 C:\\temp\\lsass.dmp full",
            "timestamp": now - 350,
        },
    ]
