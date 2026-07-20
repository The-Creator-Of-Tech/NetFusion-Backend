import pytest
from unittest.mock import MagicMock
from netfusion_collector_sdk import CollectorContext
from netfusion_collectors.nmap import NmapCollector, NmapConfig, NmapScanType
from .test_xml_parsing import SAMPLE_NMAP_XML


def test_integration_nmap_workflow():
    context = CollectorContext(collector_id="integ-coll", execution_id="integ-exec")
    collector = NmapCollector(context=context)

    config = {
        "targets": ["192.168.1.50"],
        "scan_type": "SYN",
        "ports": "80,443",
        "service_version_detection": True,
        "os_detection": True,
    }

    collector.configure(config)
    collector.runner.execute = MagicMock(return_value=(0, SAMPLE_NMAP_XML, ""))

    collector.on_pre_execute()
    result = collector.execute_collection()
    collector.on_post_execute(result)
    collector.on_cleanup()

    assert result.execution_id == "integ-exec"
    assert result.duration_seconds >= 0.0
    assert len(result.emitted_objects) > 0
