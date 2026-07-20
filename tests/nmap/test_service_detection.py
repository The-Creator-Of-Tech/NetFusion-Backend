import pytest
from netfusion_collector_sdk.base import CollectorContext
from netfusion_collectors.nmap.mapper import NmapCanonicalMapper
from netfusion_canonical import ServiceFingerprint, ServiceObserved, PortObserved


def test_service_detection_canonical_mapping():
    context = CollectorContext(collector_id="coll-123", execution_id="exec-456")
    mapper = NmapCanonicalMapper()

    host_dict = {
        "ip_address": "10.0.0.15",
        "status": "up",
        "reason": "syn-ack",
        "hostnames": [{"name": "db.corp.internal", "type": "user"}],
        "ports": [
            {
                "port_number": 5432,
                "protocol": "tcp",
                "state": "open",
                "reason": "syn-ack",
                "service": {
                    "name": "postgresql",
                    "product": "PostgreSQL DB",
                    "version": "14.2",
                    "extrainfo": "Ubuntu",
                    "cpe": ["cpe:/a:postgresql:postgresql:14.2"],
                },
                "scripts": [],
            }
        ],
        "os_matches": [],
    }

    objs = mapper.map_host_to_canonical(host_dict, context)

    service_fp_objs = [o for o in objs if isinstance(o, ServiceFingerprint)]
    service_obs_objs = [o for o in objs if isinstance(o, ServiceObserved)]
    port_obs_objs = [o for o in objs if isinstance(o, PortObserved)]

    assert len(port_obs_objs) == 1
    assert port_obs_objs[0].port_number.value == 5432
    assert port_obs_objs[0].service_name == "postgresql"

    assert len(service_obs_objs) == 1
    assert service_obs_objs[0].service_name == "postgresql"
    assert service_obs_objs[0].port.value == 5432

    assert len(service_fp_objs) == 1
    s_fp = service_fp_objs[0]
    assert s_fp.product == "PostgreSQL DB"
    assert s_fp.version == "14.2"
    assert s_fp.collector_id == "coll-123"
