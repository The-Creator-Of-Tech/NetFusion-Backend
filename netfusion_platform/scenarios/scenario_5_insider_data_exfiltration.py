"""
Acceptance Scenario 5: Insider Activity Involving File Access, Registry Modification, and Exfiltration
Emits unauthorized sensitive file collection, staging archive creation, registry persistence, and FTP/HTTPS upload.
"""

import time
from typing import Dict, Any, List


def get_scenario_5_events() -> List[Dict[str, Any]]:
    """Return raw event telemetry for Scenario 5."""
    now = time.time()
    return [
        {
            "source": "sysmon",
            "event_type": "File Created",
            "event_id": 11,
            "image": "C:\\Windows\\System32\\7z.exe",
            "target_filename": "C:\\Users\\insider\\AppData\\Local\\Temp\\confidential_financials.zip",
            "timestamp": now - 600,
        },
        {
            "source": "sysmon",
            "event_type": "Registry Modification",
            "event_id": 13,
            "image": "C:\\Windows\\System32\\reg.exe",
            "target_object": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence",
            "timestamp": now - 450,
        },
        {
            "source": "sysmon",
            "event_type": "Network Connection",
            "event_id": 3,
            "image": "C:\\Windows\\System32\\curl.exe",
            "source_ip": "192.168.1.55",
            "destination_ip": "198.51.100.99",
            "destination_port": 21,
            "timestamp": now - 300,
        },
    ]
