import pytest
from netfusion_collector_sdk import CollectorContext, ExecutionState
from netfusion_collectors.sysmon import SysmonCollector, SysmonConfig


class TestTimeoutCancellation:
    def test_timeout_configuration_enforcement(self):
        config = SysmonConfig(timeout=10)
        assert config.timeout == 10

        collector = SysmonCollector()
        collector.configure({"timeout": 15})
        assert collector.sysmon_config.timeout == 15

    def test_cancellation_hook(self):
        collector = SysmonCollector()
        collector.on_cancellation("User requested stop")
        # Ensure hook runs cleanly without raising
        assert True
