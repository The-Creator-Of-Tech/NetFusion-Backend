"""
ATRE Risk Engine — NetFusion IL-9
==================================
Multi-dimensional risk scoring engine with configurable weight profiles.
"""

from typing import Dict, List, Optional
from netfusion_ai.reasoning.models import GraphEvidence, RiskAssessment


class RiskEngine:
    """
    Calculates multi-dimensional security risk scores.
    """

    DEFAULT_WEIGHTS = {
        "asset_risk": 0.15,
        "host_risk": 0.15,
        "investigation_risk": 0.15,
        "campaign_severity": 0.15,
        "threat_actor_confidence": 0.10,
        "attack_likelihood": 0.15,
        "business_impact": 0.15,
    }

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        self.weights = custom_weights or self.DEFAULT_WEIGHTS

    def calculate_risk(
        self,
        evidence: List[GraphEvidence],
        confidence_score: float = 0.8,
        custom_weight_override: Optional[Dict[str, float]] = None,
    ) -> RiskAssessment:
        weights = custom_weight_override or self.weights

        # Determine individual sub-risk scores
        cves = [e for e in evidence if e.source_type == "VULNERABILITY"]
        actors = [e for e in evidence if e.source_type == "THREAT_ACTOR"]
        iocs = [e for e in evidence if e.source_type in ("IOC", "IP_ADDRESS", "FILE_HASH")]
        assets = [e for e in evidence if e.source_type in ("ASSET", "HOST")]

        asset_risk = min(1.0, 0.4 + 0.15 * len(assets)) if assets else 0.65
        host_risk = min(1.0, 0.5 + 0.1 * len(iocs)) if iocs else 0.70
        investigation_risk = round(confidence_score, 2)
        campaign_severity = 0.85 if cves or actors else 0.50
        threat_actor_conf = 0.80 if actors else 0.40
        attack_likelihood = min(1.0, 0.6 + 0.08 * len(evidence))
        business_impact = 0.80  # High business value asset impact default

        # Calculate weighted score
        total_weight = sum(weights.values())
        weighted_total = (
            weights.get("asset_risk", 0.15) * asset_risk
            + weights.get("host_risk", 0.15) * host_risk
            + weights.get("investigation_risk", 0.15) * investigation_risk
            + weights.get("campaign_severity", 0.15) * campaign_severity
            + weights.get("threat_actor_confidence", 0.10) * threat_actor_conf
            + weights.get("attack_likelihood", 0.15) * attack_likelihood
            + weights.get("business_impact", 0.15) * business_impact
        ) / (total_weight if total_weight > 0 else 1.0)

        weighted_total_clamped = round(min(1.0, max(0.0, weighted_total)), 4)

        return RiskAssessment(
            asset_risk=round(asset_risk, 2),
            host_risk=round(host_risk, 2),
            investigation_risk=round(investigation_risk, 2),
            campaign_severity=round(campaign_severity, 2),
            threat_actor_confidence=round(threat_actor_conf, 2),
            attack_likelihood=round(attack_likelihood, 2),
            business_impact=round(business_impact, 2),
            weighted_total_score=weighted_total_clamped,
            weighting_config=weights,
        )
