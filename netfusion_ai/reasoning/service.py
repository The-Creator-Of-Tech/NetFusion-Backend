"""
ATRE Service Layer — NetFusion IL-9
====================================
Unified high-level facade for domain consumption of the AI Threat Reasoning Engine.
"""

from typing import Any, Dict, List, Optional
from netfusion_ai.reasoning.memory import InvestigationMemoryEngine
from netfusion_ai.reasoning.models import (
    AttackChain,
    ConfidenceBreakdown,
    ExplanationResult,
    Hypothesis,
    ReasoningRequest,
    ReasoningResult,
    Recommendation,
    ReportFormat,
    RiskAssessment,
    Timeline,
)
from netfusion_ai.reasoning.orchestrator import ATREReasoningOrchestrator


class ATREService:
    """
    Primary entry point for NetFusion IL-9 AI Threat Reasoning Engine.
    Wire up once via dependency injection; use across API & platform services.
    """

    def __init__(
        self,
        utkg: Optional[Any] = None,
        identity_service: Optional[Any] = None,
        ai_provider: Optional[Any] = None,
    ):
        self.utkg = utkg
        self.identity_service = identity_service
        self.ai_provider = ai_provider
        self.orchestrator = ATREReasoningOrchestrator(
            utkg=utkg, identity_service=identity_service, ai_provider=ai_provider
        )
        self.trace_engine = self.orchestrator.trace_engine
        self.memory = InvestigationMemoryEngine()
        self._query_history: List[ReasoningResult] = []


    def query(self, request: ReasoningRequest) -> ReasoningResult:
        """Execute full 14-step reasoning pipeline for user question."""
        result = self.orchestrator.execute_reasoning(request)
        self._query_history.append(result)

        # Record to memory
        if request.investigation_id:
            self.memory.store_memory(
                investigation_id=request.investigation_id,
                pattern_type=result.intent.value,
                analyst_confirmations=[h.title for h in result.hypotheses if h.confidence_score > 0.8],
                dismissed_hypotheses=[h.title for h in result.hypotheses if h.status.value == "DISMISSED"],
                tags=[e.canonical_id for e in result.resolved_entities],
            )
        return result

    def generate_hypotheses(self, request: ReasoningRequest) -> List[Hypothesis]:
        """Generate competing hypotheses for question context."""
        result = self.query(request)
        return result.hypotheses

    def explain(self, request: ReasoningRequest) -> ExplanationResult:
        """Generate stakeholder explanation report."""
        result = self.query(request)
        return result.explanation

    def calculate_risk(self, request: ReasoningRequest) -> RiskAssessment:
        """Calculate multi-dimensional risk assessment."""
        result = self.query(request)
        return result.risk_assessment

    def reconstruct_attack_chain(self, request: ReasoningRequest) -> AttackChain:
        """Reconstruct 11-stage ATT&CK tactical attack chain."""
        result = self.query(request)
        return result.attack_chain

    def generate_recommendations(self, request: ReasoningRequest) -> List[Recommendation]:
        """Generate evidence-backed recommendations."""
        result = self.query(request)
        return result.recommendations

    def build_timeline(self, request: ReasoningRequest) -> Timeline:
        """Build chronological investigation timeline."""
        result = self.query(request)
        return result.timeline

    def generate_report(self, request: ReasoningRequest) -> Dict[str, Any]:
        """Generate full formatted investigation report."""
        result = self.query(request)
        return {
            "investigation_id": request.investigation_id,
            "intent": result.intent.value,
            "confidence": result.confidence.overall_score,
            "format": result.explanation.format.value,
            "report_content": result.explanation.formatted_output,
        }

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent reasoning history."""
        items = []
        for res in self._query_history[-limit:]:
            items.append(
                {
                    "investigation_id": res.request.investigation_id,
                    "question": res.request.user_question,
                    "intent": res.intent.value,
                    "confidence": res.confidence.overall_score,
                    "hypotheses_count": len(res.hypotheses),
                    "evidence_count": len(res.evidence),
                }
            )
        return items

    def get_statistics(self) -> Dict[str, Any]:
        """Get ATRE usage & reasoning statistics."""
        return {
            "total_queries_processed": len(self._query_history),
            "average_confidence": (
                sum(r.confidence.overall_score for r in self._query_history) / len(self._query_history)
                if self._query_history
                else 0.0
            ),
            "supported_question_types": 19,
            "utkg_connected": self.utkg is not None,
            "ciil_connected": self.identity_service is not None,
            "ai_provider_connected": self.ai_provider is not None,
        }
