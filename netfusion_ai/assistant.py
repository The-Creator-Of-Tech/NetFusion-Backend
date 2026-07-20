"""
NetFusion AI Investigation Assistant Facade
Main top-level entry point exposing the 8 primary API services:
1. analyze_investigation
2. generate_summary
3. generate_report
4. generate_recommendations
5. analyze_ioc
6. analyze_mitre
7. analyze_timeline
8. generate_hypotheses
"""

from typing import Any, Dict, List, Optional, Union

from netfusion_workflow.domain import Investigation
from netfusion_ai.enums import AnalysisCategory, AIProviderType
from netfusion_ai.domain import (
    AnalysisResult,
    AIReport,
    Hypothesis,
    RecommendationItem,
    MITREInference,
    RiskScore,
)
from netfusion_ai.events import AIEventPublisher
from netfusion_ai.providers.adapter import ProviderAdapter
from netfusion_ai.providers.mock_provider import MockAIProvider
from netfusion_ai.providers.base import BaseAIProvider
from netfusion_ai.context_builder import ContextBuilder, InvestigationContextContainer
from netfusion_ai.prompt_builder import PromptBuilder
from netfusion_ai.analysis_engine import AIAnalysisEngine
from netfusion_ai.mitre_reasoner import MITREReasoner
from netfusion_ai.hypothesis_engine import HypothesisEngine
from netfusion_ai.risk_engine import RiskEngine
from netfusion_ai.recommendation_engine import RecommendationEngine
from netfusion_ai.explanation_engine import ExplanationEngine
from netfusion_ai.confidence_engine import ConfidenceEngine
from netfusion_ai.evidence_selector import EvidenceSelector
from netfusion_ai.memory_manager import MemoryManager
from netfusion_ai.report_engine import ReportEngine
from netfusion_ai.health import AIHealthChecker, AIHealthStatus


class AIAssistant:
    """Enterprise AI Investigation Assistant & SOC Analyst Copilot."""

    def __init__(
        self,
        provider: Optional[BaseAIProvider] = None,
        provider_adapter: Optional[ProviderAdapter] = None,
        event_publisher: Optional[AIEventPublisher] = None,
    ):
        self.event_publisher = event_publisher or AIEventPublisher()

        if provider_adapter:
            self.provider_adapter = provider_adapter
        elif provider:
            self.provider_adapter = ProviderAdapter(primary_provider=provider, event_publisher=self.event_publisher)
        else:
            self.provider_adapter = ProviderAdapter(primary_provider=MockAIProvider(), event_publisher=self.event_publisher)

        # Core Engines
        self.context_builder = ContextBuilder()
        self.prompt_builder = PromptBuilder()
        self.evidence_selector = EvidenceSelector()
        self.confidence_engine = ConfidenceEngine()
        self.explanation_engine = ExplanationEngine()
        self.mitre_reasoner = MITREReasoner()
        self.hypothesis_engine = HypothesisEngine()
        self.risk_engine = RiskEngine()
        self.recommendation_engine = RecommendationEngine()
        self.memory_manager = MemoryManager()
        self.report_engine = ReportEngine(
            provider_adapter=self.provider_adapter,
            context_builder=self.context_builder,
            event_publisher=self.event_publisher,
        )

        # Main Analysis Orchestration Engine
        self.analysis_engine = AIAnalysisEngine(
            provider_adapter=self.provider_adapter,
            context_builder=self.context_builder,
            prompt_builder=self.prompt_builder,
            event_publisher=self.event_publisher,
        )

        # Subsystem Health Checker
        self.health_checker = AIHealthChecker(
            provider_adapter=self.provider_adapter,
            memory_manager=self.memory_manager,
        )

    # =========================================================================
    # 16. API SERVICES
    # =========================================================================

    def analyze_investigation(
        self,
        context_container: InvestigationContextContainer,
        category: AnalysisCategory = AnalysisCategory.INCIDENT_SUMMARY,
        user_query: Optional[str] = None,
    ) -> AnalysisResult:
        """Service 1: Comprehensive Investigation Analysis."""
        inv_id = (context_container.investigation or {}).get("investigation_id", "inv-001")
        self.memory_manager.set_context(inv_id, context_container)

        result = self.analysis_engine.analyze(
            category=category,
            context_container=context_container,
            user_query=user_query,
        )
        self.memory_manager.record_response(inv_id, result)
        return result

    def generate_summary(
        self,
        context_container: InvestigationContextContainer,
        summary_type: AnalysisCategory = AnalysisCategory.INCIDENT_SUMMARY,
    ) -> AnalysisResult:
        """Service 2: Generate Summary (Incident, Technical, Executive)."""
        return self.analyze_investigation(context_container, category=summary_type)

    def generate_report(
        self,
        context_container: InvestigationContextContainer,
        title: Optional[str] = None,
    ) -> AIReport:
        """Service 3: Generate AI-assisted Multi-part Report."""
        inv_id = (context_container.investigation or {}).get("investigation_id", "inv-001")
        self.memory_manager.set_context(inv_id, context_container)
        return self.report_engine.generate_report(context_container, title=title)

    def generate_recommendations(
        self,
        context_container: InvestigationContextContainer,
    ) -> Dict[str, List[RecommendationItem]]:
        """Service 4: Generate Recommendations grouped by remediation category."""
        return self.recommendation_engine.generate_recommendations(context_container)

    def analyze_ioc(
        self,
        context_container: InvestigationContextContainer,
        ioc_value: Optional[str] = None,
    ) -> AnalysisResult:
        """Service 5: Analyze IOCs and correlation strength."""
        query = f"Analyze IOC value: '{ioc_value}'" if ioc_value else "Correlate all investigation IOCs."
        return self.analyze_investigation(context_container, category=AnalysisCategory.IOC_CORRELATION, user_query=query)

    def analyze_mitre(
        self,
        context_container: InvestigationContextContainer,
    ) -> List[MITREInference]:
        """Service 6: Infer MITRE ATT&CK tactics and techniques."""
        return self.mitre_reasoner.infer_mitre_tactics(context_container)

    def analyze_timeline(
        self,
        context_container: InvestigationContextContainer,
    ) -> AnalysisResult:
        """Service 7: Analyze chronological timeline events and attack progression."""
        return self.analyze_investigation(context_container, category=AnalysisCategory.TIMELINE_ANALYSIS)

    def generate_hypotheses(
        self,
        context_container: InvestigationContextContainer,
        min_hypotheses: int = 2,
    ) -> List[Hypothesis]:
        """Service 8: Generate multiple competing analyst hypotheses."""
        return self.hypothesis_engine.generate_hypotheses(context_container, min_hypotheses=min_hypotheses)

    def health_check(self) -> AIHealthStatus:
        """Returns AI subsystem health status."""
        return self.health_checker.check_health()
