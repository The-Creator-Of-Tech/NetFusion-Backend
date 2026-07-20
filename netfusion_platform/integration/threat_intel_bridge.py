"""
NetFusion Threat Intelligence Cross-Module Integration Bridge
Translates Threat Intel IOC matches, vulnerabilities, and threat actors into Workflow Evidence & Timelines.
"""

from typing import Dict, Any
from netfusion_workflow.domain import RiskAssessment
from netfusion_workflow.enums import EvidenceSource, Severity, BusinessImpact, Likelihood


class ThreatIntelIntegrationBridge:
    """Bridge converting Threat Intel collector outputs to Workflow domain params."""

    @staticmethod
    def add_match_timeline(workflow_service: Any, investigation_id: str, match_dict: Dict[str, Any]) -> Any:
        ioc = match_dict.get("ioc", match_dict.get("indicator", "unknown_ioc"))
        ioc_type = match_dict.get("ioc_type", "indicator")
        threat_name = match_dict.get("threat_name", match_dict.get("malware_family", "Malicious Indicator"))
        severity_str = str(match_dict.get("severity", "HIGH")).upper()

        sev = Severity.HIGH
        if "CRITICAL" in severity_str:
            sev = Severity.CRITICAL
        elif "MEDIUM" in severity_str:
            sev = Severity.MEDIUM
        elif "LOW" in severity_str:
            sev = Severity.LOW

        return workflow_service.add_timeline_event(
            investigation_id=investigation_id,
            summary=f"Threat Intelligence Match: {ioc} ({threat_name})",
            event_type="THREAT_INTEL_MATCH",
            source="THREAT_INTEL",
            severity=sev,
            description=f"IOC [{ioc_type}] {ioc} matched known threat database. Threat: {threat_name}",
            raw_data=match_dict,
        )

    @staticmethod
    def add_evidence(workflow_service: Any, investigation_id: str, match_dict: Dict[str, Any]) -> Any:
        ioc = match_dict.get("ioc", "Threat Intel Indicator")
        return workflow_service.add_evidence(
            investigation_id=investigation_id,
            name=f"Threat Intel Evidence: {ioc}",
            description=str(match_dict),
            source=EvidenceSource.THREAT_INTEL,
            raw_artifact=str(match_dict),
        )

    @staticmethod
    def to_risk_assessment(match_dict: Dict[str, Any], case_id: str, investigation_id: str) -> RiskAssessment:
        threat_name = match_dict.get("threat_name", "Malicious Activity")
        score = float(match_dict.get("risk_score", match_dict.get("confidence", 85)))

        return RiskAssessment(
            risk_score=score,
            business_impact=BusinessImpact.HIGH if score > 75 else BusinessImpact.MEDIUM,
            likelihood=Likelihood.HIGH if score > 70 else Likelihood.MEDIUM,
            recommendations=[f"Remediate matched threat actor: {threat_name}"],
        )
