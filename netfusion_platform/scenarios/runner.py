"""
NetFusion Automated Scenario Validation Harness
Executes all 5 production acceptance scenarios and verifies output completeness.
"""

import logging
from typing import Dict, Any, List

from netfusion_platform.pipeline.orchestrator import InvestigationPipelineOrchestrator
from netfusion_platform.reporting.generator import ProductionReportGenerator, InvestigationProductionReport

from netfusion_platform.scenarios.scenario_1_phishing_powershell import get_scenario_1_events
from netfusion_platform.scenarios.scenario_2_nmap_suspicious_outbound import get_scenario_2_events
from netfusion_platform.scenarios.scenario_3_tshark_threat_intel_beacon import get_scenario_3_events
from netfusion_platform.scenarios.scenario_4_sysmon_lateral_movement import get_scenario_4_events
from netfusion_platform.scenarios.scenario_5_insider_data_exfiltration import get_scenario_5_events

logger = logging.getLogger(__name__)


class ScenarioExecutionSummary:
    """Dataclass holding verification results for an executed scenario."""

    def __init__(
        self,
        scenario_id: int,
        title: str,
        timeline_count: int,
        evidence_count: int,
        has_mitre_mapping: bool,
        has_ai_analysis: bool,
        has_recommendations: bool,
        report: InvestigationProductionReport
    ):
        self.scenario_id = scenario_id
        self.title = title
        self.timeline_count = timeline_count
        self.evidence_count = evidence_count
        self.has_mitre_mapping = has_mitre_mapping
        self.has_ai_analysis = has_ai_analysis
        self.has_recommendations = has_recommendations
        self.report = report

    @property
    def is_successful(self) -> bool:
        return (
            self.timeline_count > 0
            and self.evidence_count > 0
            and self.has_ai_analysis
            and self.report is not None
        )


class AcceptanceScenarioRunner:
    """Automated runner for all 5 enterprise investigation acceptance scenarios."""

    def __init__(self):
        self.orchestrator = InvestigationPipelineOrchestrator()

    def run_all_scenarios(self) -> List[ScenarioExecutionSummary]:
        """Execute and validate all 5 realistic cyber investigation scenarios."""
        scenarios = [
            (1, "Scenario 1: Phishing attachment leading to PowerShell execution", get_scenario_1_events()),
            (2, "Scenario 2: Unknown device discovered by Nmap followed by suspicious outbound traffic", get_scenario_2_events()),
            (3, "Scenario 3: Malware beacon detected through TShark and enriched via Threat Intelligence", get_scenario_3_events()),
            (4, "Scenario 4: Lateral movement identified through Sysmon process creation and network events", get_scenario_4_events()),
            (5, "Scenario 5: Insider activity involving file access, registry modification, and exfiltration", get_scenario_5_events()),
        ]

        summaries = []
        for sc_id, title, events in scenarios:
            logger.info("Executing Acceptance Scenario %d: '%s'", sc_id, title)

            pipeline_res = self.orchestrator.run_investigation_pipeline(
                case_title=title,
                raw_events=events,
                scenario_type=f"scenario_{sc_id}"
            )

            case = pipeline_res["case"]
            investigation = pipeline_res["investigation"]
            ai_res = pipeline_res["ai_result"]

            timeline = investigation.timeline
            evidence = investigation.evidence_list

            # Generate Final Production Report
            report = ProductionReportGenerator.generate_report(
                case=case,
                investigation=investigation,
                timeline_events=timeline,
                evidence_items=evidence,
                ai_result=ai_res
            )

            summary = ScenarioExecutionSummary(
                scenario_id=sc_id,
                title=title,
                timeline_count=len(timeline),
                evidence_count=len(evidence),
                has_mitre_mapping=len(report.mitre_attack_matrix) > 0 or hasattr(ai_res, "mitre_inferences"),
                has_ai_analysis=ai_res is not None,
                has_recommendations=len(report.recommendations) > 0,
                report=report
            )

            assert summary.is_successful, f"Scenario {sc_id} failed verification criteria!"
            summaries.append(summary)
            logger.info("Scenario %d passed all quality gates cleanly.", sc_id)

        return summaries
