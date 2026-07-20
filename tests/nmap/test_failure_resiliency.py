import pytest
from unittest.mock import MagicMock
from netfusion_collector_sdk import CollectorContext, EventPublisher
from netfusion_collectors.nmap import NmapCollector, NmapConfig


def test_nmap_subprocess_failure():
    context = CollectorContext(collector_id="fail-coll", execution_id="fail-exec")
    collector = NmapCollector(context=context)

    publisher = EventPublisher()
    collector.initialize_runtime(event_publisher=publisher)
    collector.configure({"targets": ["127.0.0.1"]})

    # Mock runner to return exit code 1 and error stderr
    collector.runner.execute = MagicMock(return_value=(1, "", "nmap: invalid target specified"))

    with pytest.raises(RuntimeError) as exc_info:
        collector.execute_collection()

    assert "Nmap subprocess execution failed with exit code 1" in str(exc_info.value)

    # Check FailureEvent published
    event_types = [e.event_type for e in publisher.published_events]
    assert "FailureEvent" in event_types


def test_nmap_invalid_xml_failure():
    context = CollectorContext(collector_id="invalid-xml", execution_id="invalid-xml")
    collector = NmapCollector(context=context)
    collector.configure({"targets": ["127.0.0.1"]})

    collector.runner.execute = MagicMock(return_value=(0, "NOT VALID XML TELEMETRY", ""))

    with pytest.raises(ValueError) as exc_info:
        collector.execute_collection()

    assert "Failed to parse Nmap XML output" in str(exc_info.value)
