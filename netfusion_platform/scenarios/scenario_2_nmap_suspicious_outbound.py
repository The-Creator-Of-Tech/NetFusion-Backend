"""
Acceptance Scenario 2: Unknown Device Discovered by Nmap Followed by Suspicious Outbound Traffic
Emits Nmap host discovery of unauthorized device and unexpected outbound C2 communication.
"""

import time
from typing import Dict, Any, List


def get_scenario_2_events() -> List[Dict[str, Any]]:
    """Return raw event telemetry for Scenario 2."""
    now = time.time()
    return [
        {
            "source": "nmap",
            "target": "192.168.1.188",
            "status": "up",
            "open_ports": [22, 80, 8080],
            "os_family": "Linux",
            "timestamp": now - 600,
        },
        {
            "source": "tshark",
            "source_ip": "192.168.1.188",
            "destination_ip": "198.51.100.44",
            "destination_port": 8080,
            "protocol": "TCP",
            "bytes_transferred": 145000,
            "timestamp": now - 400,
        },
        {
            "source": "threat_intel",
            "ioc": "198.51.100.44",
            "ioc_type": "ip",
            "threat_name": "Rogue Gateway Exfiltration C2",
            "severity": "HIGH",
            "risk_score": 88.0,
            "timestamp": now - 350,
        },
    ]
