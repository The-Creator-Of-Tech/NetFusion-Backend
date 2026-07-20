"""
NetFusion AI Analysis Engine
Primary analysis orchestrator generating explainable, non-fabricating analytical outputs:
- Investigation Summary
- Technical Summary
- Evidence Correlation
- Timeline Analysis
- IOC Correlation
- Threat Actor Analysis
- Campaign Analysis
- Malware Assessment
- Root Cause
- Recommendations
- Executive Brief
Publishes AI lifecycle events and attaches structured confidence & explanation metadata.
"""

from typing import Any, Dict, List, Optional, Union

from netfusion_ai.enums import AnalysisCategory, PromptTemplateType, ConfidenceLevel
from netfusion_ai.domain import (
    AnalysisResult,
    Explanation,
    ConfidenceMetadata,
    Hypothesis,
    RecommendationItem,
)
from netfusion_ai.exceptions import ReasoningError
from netfusion_ai.events import (
    AIEventPublisher,
    AIAnalysisStarted,
    AIAnalysisCompleted,
    AIRecommendationGenerated,
    AIHypothesisGenerated,
)
from netfusion_ai.context_builder import ContextBuilder, InvestigationContextContainer
from netfusion_ai.prompt_builder import PromptBuilder
from netfusion_ai.providers.adapter import ProviderAdapter
from netfusion_ai.safety_engine import SafetyEngine
from netfusion_ai.confidence_engine import ConfidenceEngine
from netfusion_ai.explanation_engine import ExplanationEngine
from netfusion_ai.mitre_reasoner import MITREReasoner
from netfusion_ai.hypothesis_engine import HypothesisEngine
from netfusion_ai.risk_engine import RiskEngine
from netfusion_ai.recommendation_engine import RecommendationEngine
from netfusion_ai.evidence_selector import EvidenceSelector


CATEGORY_PROMPT_MAP = {
    AnalysisCategory.INCIDENT_SUMMARY: PromptTemplateType.INCIDENT_SUMMARY,
    AnalysisCategory.TECHNICAL_SUMMARY: PromptTemplateType.TECHNICAL_REPORT,
    AnalysisCategory.EVIDENCE_CORRELATION: PromptTemplateType.INCIDENT_SUMMARY,
    AnalysisCategory.TIMELINE_ANALYSIS: PromptTemplateType.TECHNICAL_REPORT,
    AnalysisCategory.IOC_CORRELATION: PromptTemplateType.IOC_ANALYSIS,
    AnalysisCategory.THREAT_ACTOR_ANALYSIS: PromptTemplateType.THREAT_HUNTING,
    AnalysisCategory.CAMPAIGN_ANALYSIS: PromptTemplateType.THREAT_HUNTING,
    AnalysisCategory.MALWARE_ASSESSMENT: PromptTemplateType.MALWARE_ANALYSIS,
    AnalysisCategory.ROOT_CAUSE: PromptTemplateType.ROOT_CAUSE_ANALYSIS,
    AnalysisCategory.RECOMMENDATIONS: PromptTemplateType.CONTAINMENT_ADVICE,
    AnalysisCategory.EXECUTIVE_BRIEF: PromptTemplateType.EXECUTIVE_REPORT,
}


class AIAnalysisEngine:
    """Primary analytical engine orchestrating AI SOC Copilot operations."""

    def __init__(
        self,
        provider_adapter: ProviderAdapter,
        context_builder: Optional[ContextBuilder] = None,
        prompt_builder: Optional[PromptBuilder] = None,
        event_publisher: Optional[AIEventPublisher] = None,
    ):
        self.provider_adapter = provider_adapter
        self.context_builder = context_builder or ContextBuilder()
        self.prompt_builder = prompt_builder or PromptBuilder()
        self.event_publisher = event_publisher
        self.safety_engine = SafetyEngine()
        self.confidence_engine = ConfidenceEngine()
        self.explanation_engine = ExplanationEngine()
        self.mitre_reasoner = MITREReasoner()
        self.hypothesis_engine = HypothesisEngine()
        self.risk_engine = RiskEngine()
        self.recommendation_engine = RecommendationEngine()
        self.evidence_selector = EvidenceSelector()

    def analyze(
        self,
        category: AnalysisCategory,
        context_container: InvestigationContextContainer,
        user_query: Optional[str] = None,
        preferred_provider: Optional[str] = None,
    ) -> AnalysisResult:
        """Executes targeted AI analysis over investigation context container."""

        inv_id = (context_container.investigation or {}).get("investigation_id", "inv-001")

        if self.event_publisher:
            self.event_publisher.publish(
                AIAnalysisStarted(
                    investigation_id=inv_id,
                    category=category.value if isinstance(category, AnalysisCategory) else str(category),
                    provider_name=preferred_provider or "default",
                )
            )

        # 1. Format Context into Markdown
        context_markdown = self.context_builder.format_as_markdown(context_container)

        # 2. Select Prompt Template
        template_type = CATEGORY_PROMPT_MAP.get(category, PromptTemplateType.INCIDENT_SUMMARY)
        query = user_query or f"Perform analytical breakdown for {category.value}."

        llm_request = self.prompt_builder.build_prompt(
            template_type=template_type,
            context_markdown=context_markdown,
            user_query=query,
        )

        # 3. Generate LLM Output
        llm_response = self.provider_adapter.generate(llm_request, preferred_provider=preferred_provider)

        # 4. Verify Safety & Classify Claims
        facts, inferences, hypotheses_claims, rec_claims = self.safety_engine.verify_and_classify(
            llm_response.content, context_container
        )

        # 5. Calculate Confidence Metadata
        conf_metadata = self.confidence_engine.calculate_confidence(context_container)

        # 6. Generate Hypotheses & Recommendations
        generated_hypotheses = self.hypothesis_engine.generate_hypotheses(context_container)
        grouped_recs = self.recommendation_engine.generate_recommendations(context_container)

        flat_recs: List[RecommendationItem] = []
        for cat_list in grouped_recs.values():
            flat_recs.extend(cat_list)

        # 7. Select Evidence References and Build Explanation
        top_refs = self.evidence_selector.select_key_timeline_events(
            [e for e in context_container.timeline] if context_container.timeline else []
        )
        explanation = self.explanation_engine.build_explanation(
            reasoning_summary=f"Analysis for {category.value} produced based on {len(facts)} verified facts and {len(inferences)} inferences.",
            evidence_references=top_refs,
            confidence_metadata=conf_metadata,
        )

        # 8. Assemble AnalysisResult
        result = AnalysisResult(
            investigation_id=inv_id,
            category=category,
            summary=llm_response.content,
            details={
                "provider_name": llm_response.provider_name,
                "model_name": llm_response.model_name,
                "total_tokens": llm_response.total_tokens,
                "latency_seconds": llm_response.latency_seconds,
            },
            facts=facts,
            inferences=inferences,
            hypotheses=generated_hypotheses,
            recommendations=flat_recs,
            explanation=explanation,
            confidence=conf_metadata,
        )

        # Publish Completion Events
        if self.event_publisher:
            self.event_publisher.publish(
                AIAnalysisCompleted(
                    investigation_id=inv_id,
                    category=category.value if isinstance(category, AnalysisCategory) else str(category),
                    analysis_id=result.analysis_id,
                    confidence_score=conf_metadata.overall_score,
                )
            )
            self.event_publisher.publish(
                AIHypothesisGenerated(
                    investigation_id=inv_id,
                    hypothesis_count=len(generated_hypotheses),
                    top_hypothesis_title=generated_hypotheses[0].title if generated_hypotheses else "",
                )
            )
            self.event_publisher.publish(
                AIRecommendationGenerated(
                    investigation_id=inv_id,
                    recommendation_count=len(flat_recs),
                    categories=list(grouped_recs.keys()),
                )
            )

        return result
