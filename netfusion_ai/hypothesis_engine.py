"""
NetFusion Hypothesis Engine
Generates multiple competing analyst hypotheses:
- Description
- Supporting Evidence
- Contradicting Evidence
- Confidence & Score
- Recommended Validation Steps
MANDATORY RULE: Never output only one hypothesis when uncertainty exists.
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.domain import Hypothesis, EvidenceReference
from netfusion_ai.enums import ConfidenceLevel
from netfusion_ai.context_builder import InvestigationContextContainer


class HypothesisEngine:
    """Multi-hypothesis generation engine for security investigations."""

    def generate_hypotheses(
        self,
        context: InvestigationContextContainer,
        min_hypotheses: int = 2,
    ) -> List[Hypothesis]:
        """Generates multiple competing hypotheses from investigation context."""

        hypotheses: List[Hypothesis] = []

        # Build evidence references from context
        ev_refs = [
            EvidenceReference(
                evidence_id=str(e.get("evidence_id", "EV-001")),
                source_type="evidence",
                summary=f"Artifact {e.get('name', 'Evidence')}",
            )
            for e in context.evidence[:5]
        ]
        if not ev_refs:
            ev_refs.append(
                EvidenceReference(
                    evidence_id="CTX-001",
                    source_type="telemetry",
                    summary="Observed network and process activity",
                )
            )

        # Primary Hypothesis A: External Adversary Exploitation
        h1 = Hypothesis(
            title="Hypothesis A: External Adversary Initial Compromise & Persistence",
            description=(
                "An external threat actor gained initial access via exploitation of an internet-facing "
                "service or spearphishing, subsequently establishing persistence and initiating discovery."
            ),
            supporting_evidence=ev_refs[:2],
            contradicting_evidence=[],
            confidence=ConfidenceLevel.HIGH if len(context.timeline) > 5 else ConfidenceLevel.MEDIUM,
            confidence_score=0.75 if len(context.timeline) > 5 else 0.60,
            recommended_validation_steps=[
                "Perform deep memory inspection on impacted host endpoints.",
                "Review perimeter firewall logs for initial ingress connections.",
                "Validate authentications against Active Directory domain controllers.",
            ],
        )
        hypotheses.append(h1)

        # Competing Hypothesis B: Malicious Insider or Misconfigured Automation
        h2 = Hypothesis(
            title="Hypothesis B: Insider Credential Misuse or Unauthorized Script Execution",
            description=(
                "Activity stems from compromised internal credentials or unauthorized administrative script execution "
                "bypassing standard change management procedures."
            ),
            supporting_evidence=ev_refs[1:3] if len(ev_refs) > 1 else ev_refs,
            contradicting_evidence=[
                EvidenceReference(
                    evidence_id="CONTRA-01",
                    source_type="intel",
                    summary="Observed IOCs correlate with known external APT campaign signatures.",
                )
            ],
            confidence=ConfidenceLevel.MEDIUM,
            confidence_score=0.45,
            recommended_validation_steps=[
                "Interview credential owner and audit recent privilege changes.",
                "Check task scheduler and service creation logs for unauthorized scripts.",
                "Verify MFA challenges for user session logins.",
            ],
        )
        hypotheses.append(h2)

        # Competing Hypothesis C: False Positive / Security Tool Noise
        if min_hypotheses > 2 or len(context.iocs) == 0:
            h3 = Hypothesis(
                title="Hypothesis C: Benign Administrative Activity / Security Tool Misinterpretation",
                description=(
                    "Alerts represent benign automated IT administration, vulnerability scanning, or security software telemetry."
                ),
                supporting_evidence=[],
                contradicting_evidence=ev_refs,
                confidence=ConfidenceLevel.LOW,
                confidence_score=0.25,
                recommended_validation_steps=[
                    "Cross-reference execution timestamps with scheduled maintenance windows.",
                    "Verify file hashes against internal approved software white-list.",
                ],
            )
            hypotheses.append(h3)

        return hypotheses
