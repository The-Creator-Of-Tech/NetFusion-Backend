import pytest
from netfusion_collector_sdk.base import CollectorContext
from netfusion_collectors.nmap.mapper import NmapCanonicalMapper
from netfusion_canonical import VulnerabilityDetected, ToolObserved, TechniqueObserved


def test_nse_parsing_and_threat_domain_mapping():
    context = CollectorContext(collector_id="coll-nse", execution_id="exec-nse")
    mapper = NmapCanonicalMapper()

    host_dict = {
        "ip_address": "10.0.1.100",
        "status": "up",
        "reason": "syn-ack",
        "hostnames": [],
        "ports": [
            {
                "port_number": 445,
                "protocol": "tcp",
                "state": "open",
                "reason": "syn-ack",
                "service": {"name": "microsoft-ds"},
                "scripts": [
                    {
                        "id": "smb-vuln-ms17-010",
                        "output": "\n  VULNERABLE:\n  Remote Code Execution vulnerability in Microsoft SMBv1 servers (MS17-010)\n    State: VULNERABLE\n    IDs:  CVE:CVE-2017-0143\n    Risk factor: HIGH\n",
                        "tables": [],
                    }
                ],
            }
        ],
        "os_matches": [],
    }

    objs = mapper.map_host_to_canonical(host_dict, context)

    vuln_objs = [o for o in objs if isinstance(o, VulnerabilityDetected)]
    tool_objs = [o for o in objs if isinstance(o, ToolObserved)]
    tech_objs = [o for o in objs if isinstance(o, TechniqueObserved)]

    assert len(vuln_objs) == 1
    v = vuln_objs[0]
    assert v.vulnerability_id == "CVE-2017-0143"
    assert v.script_id == "smb-vuln-ms17-010"
    assert v.port_number.value == 445

    assert len(tool_objs) == 1
    assert tool_objs[0].tool_name == "Nmap"

    assert len(tech_objs) == 1
    assert tech_objs[0].technique_id == "T1046"
