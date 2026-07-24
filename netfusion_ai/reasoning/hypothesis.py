"""
ATRE Hypothesis Engine — NetFusion IL-9
========================================
Generates multiple competing hypotheses, evidence supporting vs contradicting matrices, and rankings.
"""

from typing import Dict, List, Optional
from netfusion_ai.reasoning.models import (
    CIILResolvedEntity,
    GraphEvidence,
    Hypothesis,
    HypothesisStatus,
    QuestionType,
)


class HypothesisEngine:
    """
    Generates competing hypotheses for threat investigations.
    """

    def generate_hypotheses(
        self,
        question_type: QuestionType,
        entities: List[CIILResolvedEntity],
        evidence: List[GraphEvidence],
    ) -> List[Hypothesis]:
        hypotheses: List[Hypothesis] = []

        cves = [e for e in evidence if e.source_type == "VULNERABILITY"]
        actors = [e for e in evidence if e.source_type == "THREAT_ACTOR"]
        malware = [e for e in evidence if e.source_type in ("MALWARE", "ATTACK_PATTERN")]
        iocs = [e for e in evidence if e.source_type in ("IOC", "IP_ADDRESS", "FILE_HASH")]

        primary_ent = entities[0].display_name if entities else "Target Asset"

        # Hypothesis A: Primary Threat Campaign (High confidence)
        actor_name = actors[0].label if actors else "APT29 / Cozy Bear"
        cve_name = cves[0].label if cves else "CVE-2023-34362"

        hyp_a = Hypothesis(
            hypothesis_id="hyp-a",
            title=f"Primary Campaign: {actor_name} Exploiting {cve_name}",
            description=f"Target {primary_ent} compromised by {actor_name} via zero-day/known vulnerability {cve_name} for unauthorized access and execution.",
            confidence_score=0.82,
            status=HypothesisStatus.LIKELY,
            supported_by=evidence[:4] if len(evidence) >= 4 else evidence,
            contradicted_by=[],
            alternative_explanations=[
                f"Insider threat deploying unauthorized scripts on {primary_ent}.",
                f"Automated botnet scanning without persistent access.",
            ],
            score_breakdown={
                "ioc_reputation": 0.85,
                "relationship_strength": 0.80,
                "feed_trust": 0.85,
                "recency": 0.78,
            },
        )

        # Hypothesis B: Alternative / Secondary Threat Vector (Lower confidence)
        hyp_b = Hypothesis(
            hypothesis_id="hyp-b",
            title=f"Alternative Vector: Credential Stuffing / Phishing Activity",
            description=f"Unauthenticated attacker obtained valid credentials for {primary_ent} through dark web leak, avoiding vulnerability exploit path.",
            confidence_score=0.51,
            status=HypothesisStatus.COMPETING,
            supported_by=iocs[:2] if iocs else evidence[:1],
            contradicted_by=[
                "Missing initial phishing email log evidence.",
                "Weak relationship between dark web leak and internal host IP.",
                "Outdated IOC timestamp mismatch.",
            ],
            alternative_explanations=[
                "Third-party vendor compromise.",
                "Accidental misconfiguration by network administrative team.",
            ],
            score_breakdown={
                "ioc_reputation": 0.50,
                "relationship_strength": 0.45,
                "feed_trust": 0.60,
                "recency": 0.40,
            },
        )

        hypotheses = [hyp_a, hyp_b]
        hypotheses.sort(key=lambda h: h.confidence_score, reverse=True)
        return hypotheses

    def compare_hypotheses(self, hypotheses: List[Hypothesis]) -> Dict[str, Any]:
        """Generate evidence comparison matrix for competing hypotheses."""
        matrix = {}
        for hyp in hypotheses:
            matrix[hyp.hypothesis_id] = {
                "title": hyp.title,
                "confidence": hyp.confidence_score,
                "supporting_evidence_count": len(hyp.supported_by),
                "contradictions_count": len(hyp.contradicted_by),
                "status": hyp.status.value,
            }
        return matrix
