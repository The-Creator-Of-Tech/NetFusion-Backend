"""
NetFusion Risk Engine
Calculates multi-dimensional risk outputs:
- Risk Score (0.0 to 10.0 scale)
- Business Impact
- Likelihood
- Confidence
- Priority
- Suggested Response
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.domain import RiskScore
from netfusion_ai.enums import ConfidenceLevel
from netfusion_workflow.enums import Priority, BusinessImpact, Likelihood
from netfusion_ai.context_builder import InvestigationContextContainer


class RiskEngine:
    """Multi-factor security risk evaluation engine."""

    def calculate_risk(
        self,
        context: InvestigationContextContainer,
        extra_severity: Optional[str] = None,
    ) -> RiskScore:
        """Calculates quantitative risk score and qualitative impact assessments."""

        factors: List[str] = []

        # 1. Base Impact score derived from investigation metadata & assets
        inv_sev = (extra_severity or context.investigation.get("severity", "MEDIUM") if context.investigation else "MEDIUM").upper()

        if inv_sev in ("CRITICAL", "HIGH"):
            impact = BusinessImpact.HIGH
            impact_score = 8.5
            factors.append(f"High severity investigation rating ({inv_sev})")
        elif inv_sev == "MEDIUM":
            impact = BusinessImpact.MEDIUM
            impact_score = 5.5
            factors.append("Moderate business operational impact")
        else:
            impact = BusinessImpact.LOW
            impact_score = 3.0
            factors.append("Low severity rating")

        # 2. Likelihood evaluation derived from evidence & IOC presence
        evidence_count = len(context.evidence) + len(context.timeline)
        ioc_count = len(context.iocs)

        if evidence_count > 10 or ioc_count > 5:
            likelihood = Likelihood.CRITICAL
            likelihood_score = 0.9
            factors.append(f"Substantial evidence artifacts ({evidence_count}) and IOCs ({ioc_count}) confirm activity")
        elif evidence_count > 3:
            likelihood = Likelihood.HIGH
            likelihood_score = 0.7
            factors.append("Observed timeline events indicate likely malicious activity")
        else:
            likelihood = Likelihood.MEDIUM
            likelihood_score = 0.4
            factors.append("Limited evidence available to verify full exploitation")

        # 3. Overall Risk Score calculation: Risk = Impact * Likelihood (0.0 - 10.0)
        raw_score = impact_score * likelihood_score
        risk_score = round(max(0.0, min(10.0, raw_score)), 1)

        # 4. Priority Determination
        if risk_score >= 8.0:
            priority = Priority.CRITICAL
            suggested_response = "Immediate emergency response: Isolate compromised hosts and initiate threat eradication."
        elif risk_score >= 6.0:
            priority = Priority.HIGH
            suggested_response = "High priority response: Perform targeted containment and deeper forensic analysis."
        elif risk_score >= 3.5:
            priority = Priority.MEDIUM
            suggested_response = "Medium priority response: Continue investigation and monitor host telemetry."
        else:
            priority = Priority.LOW
            suggested_response = "Low priority response: Document findings and close investigation if benign."

        # Confidence Level
        conf = ConfidenceLevel.HIGH if evidence_count >= 5 else ConfidenceLevel.MEDIUM

        return RiskScore(
            risk_score=risk_score,
            business_impact=impact,
            likelihood=likelihood,
            confidence=conf,
            priority=priority,
            suggested_response=suggested_response,
            contributing_factors=factors,
        )
