"""
NetFusion 5 Acceptance Investigation Scenarios Package
Automated scenario execution and validation harness.
"""

from netfusion_platform.scenarios.runner import (
    AcceptanceScenarioRunner,
    ScenarioExecutionSummary,
)
from netfusion_platform.scenarios.scenario_1_phishing_powershell import get_scenario_1_events
from netfusion_platform.scenarios.scenario_2_nmap_suspicious_outbound import get_scenario_2_events
from netfusion_platform.scenarios.scenario_3_tshark_threat_intel_beacon import get_scenario_3_events
from netfusion_platform.scenarios.scenario_4_sysmon_lateral_movement import get_scenario_4_events
from netfusion_platform.scenarios.scenario_5_insider_data_exfiltration import get_scenario_5_events

__all__ = [
    "AcceptanceScenarioRunner",
    "ScenarioExecutionSummary",
    "get_scenario_1_events",
    "get_scenario_2_events",
    "get_scenario_3_events",
    "get_scenario_4_events",
    "get_scenario_5_events",
]
