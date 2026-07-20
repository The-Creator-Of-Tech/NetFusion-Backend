import pytest
from netfusion_collector_sdk.base import CollectorContext
from netfusion_collectors.nmap.mapper import NmapCanonicalMapper
from netfusion_canonical import OperatingSystemObserved, HostFingerprint


def test_os_detection_canonical_mapping():
    context = CollectorContext(collector_id="coll-789", execution_id="exec-999")
    mapper = NmapCanonicalMapper()

    host_dict = {
        "ip_address": "172.16.0.10",
        "status": "up",
        "reason": "echo-reply",
        "hostnames": [],
        "ports": [],
        "os_matches": [
            {
                "name": "Microsoft Windows 10 1909",
                "accuracy": 95,
                "vendor": "Microsoft",
                "osfamily": "Windows",
                "osgen": "10",
                "cpe": ["cpe:/o:microsoft:windows_10:1909"],
            }
        ],
    }

    objs = mapper.map_host_to_canonical(host_dict, context)

    os_obs_objs = [o for o in objs if isinstance(o, OperatingSystemObserved)]
    host_fp_objs = [o for o in objs if isinstance(o, HostFingerprint)]

    assert len(host_fp_objs) == 1
    assert len(os_obs_objs) == 1

    os_obs = os_obs_objs[0]
    assert os_obs.os_name == "Microsoft Windows 10 1909"
    assert os_obs.vendor == "Microsoft"
    assert os_obs.os_family == "Windows"
    assert os_obs.accuracy == 95
    assert "cpe:/o:microsoft:windows_10:1909" in os_obs.cpe
