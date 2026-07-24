"""
ATRE Planner & Intent Detector — NetFusion IL-9
===============================================
Formulates reasoning execution plan based on question intent and extracted entities.
"""

from typing import List, Optional
from netfusion_ai.reasoning.models import QuestionType, ReasoningPlan, CIILResolvedEntity


class ReasoningPlanner:
    """
    Detects question intent across all 19 supported question types
    and constructs a deterministic ReasoningPlan.
    """

    def detect_intent(self, question: str) -> QuestionType:
        q_lower = question.lower().strip()

        if "what happened" in q_lower or "overview of event" in q_lower:
            return QuestionType.WHAT_HAPPENED
        if "why did it happen" in q_lower or "root cause" in q_lower or "how was it initial" in q_lower:
            return QuestionType.WHY_HAPPENED
        if "what is affected" in q_lower or "impacted systems" in q_lower:
            return QuestionType.WHAT_AFFECTED
        if "assets at risk" in q_lower or "at risk" in q_lower:
            return QuestionType.ASSETS_AT_RISK
        if "evidence support" in q_lower or "supporting evidence" in q_lower or "what evidence" in q_lower:
            return QuestionType.EVIDENCE_SUPPORT
        if "vulnerab" in q_lower or "cve" in q_lower:
            return QuestionType.VULNERABILITIES_INVOLVED
        if "att&ck" in q_lower or "technique" in q_lower or "mitre" in q_lower:
            return QuestionType.ATTACK_TECHNIQUES
        if "campaign" in q_lower:
            return QuestionType.CAMPAIGNS_MATCH
        if "threat actor" in q_lower or "actor" in q_lower or "who is behind" in q_lower:
            return QuestionType.THREAT_ACTOR_LIKELY
        if "malware" in q_lower or "ransomware" in q_lower or "payload" in q_lower:
            return QuestionType.MALWARE_FAMILIES
        if "attack chain" in q_lower or "show chain" in q_lower or "kill chain" in q_lower:
            return QuestionType.SHOW_ATTACK_CHAIN
        if "confidence" in q_lower or "how confident" in q_lower:
            return QuestionType.SHOW_CONFIDENCE
        if "recommend next" in q_lower or "investigation step" in q_lower or "next step" in q_lower:
            return QuestionType.RECOMMEND_INVESTIGATION
        if "containment" in q_lower or "contain" in q_lower:
            return QuestionType.RECOMMEND_CONTAINMENT
        if "remediation" in q_lower or "remediate" in q_lower or "patch" in q_lower:
            return QuestionType.RECOMMEND_REMEDIATION
        if "executive summary" in q_lower or "exec summary" in q_lower:
            return QuestionType.EXEC_SUMMARY
        if "soc report" in q_lower or "soc summary" in q_lower:
            return QuestionType.SOC_REPORT
        if "ir report" in q_lower or "incident response report" in q_lower:
            return QuestionType.IR_REPORT
        if "analyst notes" in q_lower or "notes" in q_lower:
            return QuestionType.ANALYST_NOTES

        return QuestionType.GENERAL_QUERY

    def plan(
        self,
        question: str,
        entities: List[CIILResolvedEntity],
        override_intent: Optional[QuestionType] = None,
    ) -> ReasoningPlan:
        intent = override_intent or self.detect_intent(question)
        extracted_cids = [e.canonical_id for e in entities]

        # Target node types based on intent
        target_types = []
        depth = 2

        if intent in (QuestionType.VULNERABILITIES_INVOLVED, QuestionType.RECOMMEND_REMEDIATION):
            target_types = ["VULNERABILITY", "WEAKNESS"]
        elif intent in (QuestionType.ATTACK_TECHNIQUES, QuestionType.SHOW_ATTACK_CHAIN):
            target_types = ["ATTACK_PATTERN", "WEAKNESS"]
            depth = 3
        elif intent == QuestionType.THREAT_ACTOR_LIKELY:
            target_types = ["THREAT_ACTOR", "CAMPAIGN", "MALWARE"]
            depth = 3
        elif intent == QuestionType.ASSETS_AT_RISK:
            target_types = ["ASSET", "IP_ADDRESS"]
            depth = 2
        else:
            target_types = ["VULNERABILITY", "ATTACK_PATTERN", "WEAKNESS", "THREAT_ACTOR", "CAMPAIGN", "MALWARE", "ASSET", "IOC"]

        return ReasoningPlan(
            question_type=intent,
            primary_intent=intent.value,
            extracted_entities=extracted_cids,
            expansion_depth=depth,
            target_node_types=target_types,
            hypothesis_strategy="competing",
        )
