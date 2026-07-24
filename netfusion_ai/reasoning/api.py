"""
ATRE REST API Router — NetFusion IL-9
=====================================
FastAPI router for AI Threat Reasoning Engine (ATRE).
Prefix: /reasoning
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from netfusion_ai.reasoning.models import (
    AttackChain,
    ExplanationResult,
    Hypothesis,
    QuestionType,
    ReasoningRequest,
    ReasoningResult,
    Recommendation,
    RiskAssessment,
    Timeline,
)
from netfusion_ai.reasoning.service import ATREService

router = APIRouter(prefix="/reasoning", tags=["ATRE Reasoning"])

# Singleton service instance with lazy loading
_atre_service_instance: Optional[ATREService] = None


def get_atre_service() -> ATREService:
    global _atre_service_instance
    if _atre_service_instance is None:
        _atre_service_instance = ATREService()
    return _atre_service_instance


def set_atre_service(service: ATREService) -> None:
    global _atre_service_instance
    _atre_service_instance = service


class QueryDTO(BaseModel):
    user_question: str
    question_type: Optional[str] = None
    context_node_ids: List[str] = []
    investigation_id: Optional[str] = None
    time_range: Optional[Dict[str, Any]] = None
    parameters: Dict[str, Any] = {}


@router.post("/query", response_model=Dict[str, Any])
def run_reasoning_query(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Execute full 14-step threat reasoning pipeline."""
    qtype = QuestionType(dto.question_type) if dto.question_type else None
    req = ReasoningRequest(
        user_question=dto.user_question,
        question_type=qtype,
        context_node_ids=dto.context_node_ids,
        investigation_id=dto.investigation_id,
        time_range=dto.time_range,
        parameters=dto.parameters,
    )
    result = service.query(req)
    return {
        "status": "success",
        "investigation_id": dto.investigation_id or result.request.investigation_id,
        "intent": result.intent.value,
        "confidence": result.confidence.overall_score,
        "hypotheses_count": len(result.hypotheses),
        "evidence_count": len(result.evidence),
        "explanation": result.explanation.formatted_output,
        "data": result.model_dump(),
    }


@router.post("/hypothesis")
def generate_hypotheses_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Generate competing hypotheses for question context."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
        investigation_id=dto.investigation_id,
    )
    hyps = service.generate_hypotheses(req)
    return {"status": "success", "count": len(hyps), "hypotheses": [h.model_dump() for h in hyps]}


@router.post("/explain")
def generate_explanation_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Generate stakeholder explanation report."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
        parameters=dto.parameters,
    )
    exp = service.explain(req)
    return {"status": "success", "explanation": exp.model_dump()}


@router.post("/risk")
def calculate_risk_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Calculate multi-dimensional risk assessment."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
    )
    risk = service.calculate_risk(req)
    return {"status": "success", "risk_assessment": risk.model_dump()}


@router.post("/attack-chain")
def attack_chain_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Reconstruct 11-stage ATT&CK tactical attack chain."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
    )
    chain = service.reconstruct_attack_chain(req)
    return {"status": "success", "attack_chain": chain.model_dump()}


@router.post("/recommendations")
def recommendations_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Generate evidence-backed security recommendations."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
    )
    recs = service.generate_recommendations(req)
    return {"status": "success", "count": len(recs), "recommendations": [r.model_dump() for r in recs]}


@router.post("/timeline")
def timeline_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Build chronological investigation timeline."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
    )
    tl = service.build_timeline(req)
    return {"status": "success", "timeline": tl.model_dump()}


@router.post("/report")
def generate_report_endpoint(
    dto: QueryDTO, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Generate full formatted investigation report."""
    req = ReasoningRequest(
        user_question=dto.user_question,
        context_node_ids=dto.context_node_ids,
        parameters=dto.parameters,
    )
    rpt = service.generate_report(req)
    return {"status": "success", "report": rpt}


@router.get("/history")
def get_history_endpoint(
    limit: int = Query(50, ge=1, le=500), service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get recent reasoning history."""
    history = service.get_history(limit=limit)
    return {"status": "success", "count": len(history), "history": history}


@router.get("/statistics")
def get_statistics_endpoint(
    service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get ATRE system statistics."""
    stats = service.get_statistics()
    return {"status": "success", "statistics": stats}


# ============================================================================
# NETFUSION IL-9.1 REASONING TRACE API ENDPOINTS
# ============================================================================

from netfusion_ai.reasoning.reasoning_trace import VisualizationBuilder


@router.get("/trace/{session_id}")
def get_reasoning_trace_endpoint(
    session_id: str, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get complete Reasoning Trace by session ID or investigation ID."""
    trace = service.trace_engine.get_trace(session_id)
    if not trace:
        raise HTTPException(status_code=404, detail=f"Reasoning trace not found for session ID: {session_id}")
    return {"status": "success", "trace": trace.model_dump()}


@router.get("/trace/{session_id}/timeline")
def get_reasoning_trace_timeline_endpoint(
    session_id: str, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get evidence timeline for a reasoning trace session."""
    trace = service.trace_engine.get_trace(session_id)
    if not trace:
        raise HTTPException(status_code=404, detail=f"Reasoning trace not found for session ID: {session_id}")
    timeline_viz = VisualizationBuilder.build_evidence_timeline(trace)
    return {"status": "success", "timeline": timeline_viz}


@router.get("/trace/{session_id}/graph")
def get_reasoning_trace_graph_endpoint(
    session_id: str, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get UTKG graph traversal map for a reasoning trace session."""
    trace = service.trace_engine.get_trace(session_id)
    if not trace:
        raise HTTPException(status_code=404, detail=f"Reasoning trace not found for session ID: {session_id}")
    graph_viz = VisualizationBuilder.build_graph_traversal_map(trace)
    return {"status": "success", "graph_traversal": graph_viz}


@router.get("/trace/{session_id}/confidence")
def get_reasoning_trace_confidence_endpoint(
    session_id: str, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get confidence waterfall calculation trace for a session."""
    trace = service.trace_engine.get_trace(session_id)
    if not trace:
        raise HTTPException(status_code=404, detail=f"Reasoning trace not found for session ID: {session_id}")
    waterfall_viz = VisualizationBuilder.build_confidence_waterfall(trace)
    return {"status": "success", "confidence_waterfall": waterfall_viz}


@router.get("/trace/{session_id}/decisions")
def get_reasoning_trace_decisions_endpoint(
    session_id: str, service: ATREService = Depends(get_atre_service)
) -> Dict[str, Any]:
    """Get recorded decisions and decision tree visualization."""
    trace = service.trace_engine.get_trace(session_id)
    if not trace:
        raise HTTPException(status_code=404, detail=f"Reasoning trace not found for session ID: {session_id}")
    tree_viz = VisualizationBuilder.build_decision_tree(trace)
    return {
        "status": "success",
        "decisions_count": len(trace.decisions),
        "decisions": [d.model_dump() for d in trace.decisions],
        "decision_tree": tree_viz,
    }


@router.get("/trace/{session_id}/export")
def export_reasoning_trace_endpoint(
    session_id: str,
    format: str = Query("json", description="Export format: json, markdown, html, pdf_json"),
    service: ATREService = Depends(get_atre_service),
) -> Dict[str, Any]:
    """Export reasoning trace in JSON, Markdown, HTML, or PDF-ready JSON."""
    try:
        exported_content = service.trace_engine.export_trace(session_id, fmt=format)
        return {
            "status": "success",
            "session_id": session_id,
            "format": format,
            "exported_content": exported_content,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

