import subprocess
import pytest
from unittest.mock import MagicMock
from netfusion_collector_sdk import CollectorContext
from netfusion_collectors.nmap import NmapCollector


def test_nmap_timeout_handling():
    context = CollectorContext(collector_id="timeout-coll", execution_id="timeout-exec")
    collector = NmapCollector(context=context)
    collector.configure({"targets": ["10.0.0.1"], "timeout": 1})

    collector.runner.execute = MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1))

    with pytest.raises(subprocess.TimeoutExpired):
        collector.execute_collection()
