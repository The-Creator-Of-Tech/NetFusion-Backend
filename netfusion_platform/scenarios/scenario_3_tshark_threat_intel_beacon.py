"""
Acceptance Scenario 3: Malware Beacon Detected Through TShark and Enriched via Threat Intelligence
Emits periodic DNS queries and HTTP POST beacons captured via TShark and enriched by OpenCTI threat intel.
"""

import time
from typing import Dict, Any, List


def get_scenario_3_events() -> List[Dict[str, Any]]:
    """Return raw event telemetry for Scenario 3."""
    now = time.time()
    return [
        {
            "source": "tshark",
            "client_ip": "10.0.4.15",
            "query_name": "beacon-server.malicious-domain.org",
            "query_type": "A",
            "timestamp": now - 500,
        },
        {
            "source": "tshark",
            "source_ip": "10.0.4.15",
            "destination_ip": "203.0.113.88",
            "destination_port": 443,
            "protocol": "TLS",
            "bytes_transferred": 2048,
            "timestamp": now - 300,
        },
        {
            "source": "threat_intel",
            "ioc": "beacon-server.malicious-domain.org",
            "ioc_type": "domain",
            "threat_name": "Cobalt Strike Beacon C2 Infrastructure",
            "severity": "CRITICAL",
            "risk_score": 98.0,
            "timestamp": now - 280,
        },
    ]
