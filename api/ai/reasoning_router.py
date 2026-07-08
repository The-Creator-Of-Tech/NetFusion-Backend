"""
AI Reasoning API Router — Phase A4.8.6 (Part A)
==============================================
REST interface for Reasoning engine.

Prefix  : /reasoning
Tag     : Reasoning
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Query

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.ai.reasoning_models import (
    CreateReasoningRequest,
    UpdateReasoningRequest,
    ReasoningStepRequest,
    ReasoningStepResponse,
    ReasoningEvidenceResponse,
    ReasoningResponse,
    ReasoningListResponse,
    ReasoningStatisticsResponse,
    BulkCreateReasoningRequest,
    BulkUpdateReasoningRequest,
    BulkDeleteReasoningRequest,
    BulkOperationResult,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response, validate_pagination

from services.reasoning_service import (
    ReasoningResult,
    ReasoningTrace,
    ReasoningEvidence,
    build_reasoning,
    build_reasoning_trace,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

reasoning_router: APIRouter = APIRouter(
    prefix = "/reasoning",
    tags   = ["Reasoning"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_reasoning
_REASONING_STORE = RepositoryBackedDict("reasoning", "reasoningId", map_reasoning)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _REASONING_STORE.clear()


# ---------------------------------------------------------------------------
# Sort map
# ---------------------------------------------------------------------------
_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt" : "createdAt",
    "updatedAt" : "createdAt",
}


# ---------------------------------------------------------------------------
# Reasoning Step Helpers
# ---------------------------------------------------------------------------

def append_reasoning_step(
    result             : ReasoningResult,
    context_ids        : List[str],
    finding_ids        : List[str],
    alert_ids          : List[str],
    relationship_ids   : List[str],
    timeline_ids       : List[str],
    step_number        : int,
    stage              : Any,  # ReasoningStage enum
    input_summary      : str,
    output_summary     : str,
    confidence         : float,
    evidence_ids       : Optional[List[str]] = None,
    finding_ids_step   : Optional[List[str]] = None,
    alert_ids_step     : Optional[List[str]] = None,
    relationship_ids_s : Optional[List[str]] = None,
    timeline_event_ids : Optional[List[str]] = None,
) -> Tuple[ReasoningResult, ReasoningTrace]:
    """Append a new trace step and rebuild the ReasoningResult."""
    step = build_reasoning_trace(
        step_number        = step_number,
        stage              = stage,
        input_summary      = input_summary,
        output_summary     = output_summary,
        confidence         = confidence,
        evidence_ids       = evidence_ids,
        finding_ids        = finding_ids_step,
        alert_ids          = alert_ids_step,
        relationship_ids   = relationship_ids_s,
        timeline_event_ids = timeline_event_ids,
    )
    new_trace = list(result.reasoningTrace) + [step]
    new_res = build_reasoning(
        context_ids         = context_ids,
        finding_ids         = finding_ids,
        alert_ids           = alert_ids,
        relationship_ids    = relationship_ids,
        timeline_ids        = timeline_ids,
        created_at          = result.createdAt,
        reasoning_trace     = new_trace,
        supporting_evidence = list(result.supportingEvidence),
        decision            = result.decision,
        overall_confidence  = result.overallConfidence,
        overall_risk        = result.overallRisk,
        explanation         = result.decisionExplanation,
    )
    return new_res, step


def update_reasoning_step(
    result             : ReasoningResult,
    context_ids        : List[str],
    finding_ids        : List[str],
    alert_ids          : List[str],
    relationship_ids   : List[str],
    timeline_ids       : List[str],
    step_number        : int,
    stage              : Optional[Any]           = None,  # ReasoningStage enum
    input_summary      : Optional[str]            = None,
    output_summary     : Optional[str]            = None,
    confidence         : Optional[float]          = None,
    evidence_ids       : Optional[List[str]]      = None,
    finding_ids_step   : Optional[List[str]]      = None,
    alert_ids_step     : Optional[List[str]]      = None,
    relationship_ids_s : Optional[List[str]]      = None,
    timeline_event_ids : Optional[List[str]]      = None,
) -> Tuple[ReasoningResult, ReasoningTrace]:
    """Update an existing trace step and rebuild the ReasoningResult."""
    new_trace = []
    found_step = None
    for t in result.reasoningTrace:
        if t.stepNumber == step_number:
            new_stage = stage if stage is not None else t.stage
            new_input = input_summary if input_summary is not None else t.inputSummary
            new_output = output_summary if output_summary is not None else t.outputSummary
            new_conf = confidence if confidence is not None else t.confidence
            new_ev = evidence_ids if evidence_ids is not None else list(t.evidenceIds)
            new_find = finding_ids_step if finding_ids_step is not None else list(t.findingIds)
            new_alert = alert_ids_step if alert_ids_step is not None else list(t.alertIds)
            new_rel = relationship_ids_s if relationship_ids_s is not None else list(t.relationshipIds)
            new_tl = timeline_event_ids if timeline_event_ids is not None else list(t.timelineEventIds)
            
            upd = build_reasoning_trace(
                step_number        = step_number,
                stage              = new_stage,
                input_summary      = new_input,
                output_summary     = new_output,
                confidence         = new_conf,
                evidence_ids       = new_ev,
                finding_ids        = new_find,
                alert_ids          = new_alert,
                relationship_ids   = new_rel,
                timeline_event_ids = new_tl,
            )
            new_trace.append(upd)
            found_step = upd
        else:
            new_trace.append(t)
            
    if found_step is None:
        raise ValueError(f"Reasoning step {step_number} not found.")
        
    new_res = build_reasoning(
        context_ids         = context_ids,
        finding_ids         = finding_ids,
        alert_ids           = alert_ids,
        relationship_ids    = relationship_ids,
        timeline_ids        = timeline_ids,
        created_at          = result.createdAt,
        reasoning_trace     = new_trace,
        supporting_evidence = list(result.supportingEvidence),
        decision            = result.decision,
        overall_confidence  = result.overallConfidence,
        overall_risk        = result.overallRisk,
        explanation         = result.decisionExplanation,
    )
    return new_res, found_step


def delete_reasoning_step(
    result          : ReasoningResult,
    context_ids     : List[str],
    finding_ids     : List[str],
    alert_ids       : List[str],
    relationship_ids: List[str],
    timeline_ids    : List[str],
    step_number     : int,
) -> ReasoningResult:
    """Delete a trace step and rebuild the ReasoningResult."""
    remaining = [t for t in result.reasoningTrace if t.stepNumber != step_number]
    if len(remaining) == len(result.reasoningTrace):
        raise ValueError(f"Reasoning step {step_number} not found.")
        
    new_res = build_reasoning(
        context_ids         = context_ids,
        finding_ids         = finding_ids,
        alert_ids           = alert_ids,
        relationship_ids    = relationship_ids,
        timeline_ids        = timeline_ids,
        created_at          = result.createdAt,
        reasoning_trace     = remaining,
        supporting_evidence = list(result.supportingEvidence),
        decision            = result.decision,
        overall_confidence  = result.overallConfidence,
        overall_risk        = result.overallRisk,
        explanation         = result.decisionExplanation,
    )
    return new_res


def find_reasoning_step(result: ReasoningResult, step_number: int) -> Optional[ReasoningTrace]:
    """Find a step by its step number."""
    for t in result.reasoningTrace:
        if t.stepNumber == step_number:
            return t
    return None


def search_reasoning_steps(result: ReasoningResult, query: str) -> List[ReasoningTrace]:
    """Search steps by query matching input or output summary."""
    q = query.lower().strip()
    return [t for t in result.reasoningTrace if q in t.inputSummary.lower() or q in t.outputSummary.lower()]


def build_reasoning_summary(result: ReasoningResult) -> str:
    """Build a summary covering all reasoning trace steps."""
    if not result.reasoningTrace:
        return "No reasoning trace steps to summarize."
    lines = []
    for t in sorted(result.reasoningTrace, key=lambda x: x.stepNumber):
        lines.append(f"Step {t.stepNumber} ({t.stage.value}): {t.outputSummary[:50]}")
    return "Reasoning Summary: " + " | ".join(lines)


# ---------------------------------------------------------------------------
# Search, Sort, Filter, Paginate Helpers
# ---------------------------------------------------------------------------

def find_reasoning(
    sessions: List[Dict[str, Any]],
    field    : str,
    value    : str,
) -> Optional[Dict[str, Any]]:
    """Find reasoning by a specific field value."""
    target = value.lower().strip()
    for s in sessions:
        res = s["package"]
        v = None
        if field in ("reasoningId", "packageId"): v = res.reasoningId
        elif field == "reasoningKey": v = res.reasoningKey
        elif field == "projectId": v = s.get("projectId")
        elif field == "userId": v = s.get("userId")
        elif field == "status": v = s.get("status")
        elif field == "sessionName": v = s.get("sessionName")
        
        if v is not None and str(v).lower().strip() == target:
            return s
    return None


def sort_reasoning(
    sessions   : List[Dict[str, Any]],
    sort_by    : str = "createdAt",
    sort_order : str = "asc",
) -> List[Dict[str, Any]]:
    """Sort reasoning sessions list."""
    reverse = sort_order.lower() == "desc"
    
    def sort_key(s: Dict[str, Any]):
        res = s["package"]
        if sort_by == "stepCount":
            return (0, len(res.reasoningTrace))
        if sort_by == "confidence":
            return (0, res.overallConfidence)
        if sort_by == "sessionName":
            name = s.get("sessionName") or f"Session {res.reasoningId}"
            return (0, name.lower())
            
        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(res, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())
        
    return sorted(sessions, key=sort_key, reverse=reverse)


def filter_reasoning(
    sessions           : List[Dict[str, Any]],
    status             : Optional[str] = None,
    userId             : Optional[str] = None,
    projectId          : Optional[str] = None,
    investigationId    : Optional[str] = None,
    minimumSteps       : Optional[int] = None,
    maximumSteps       : Optional[int] = None,
    minimumConfidence  : Optional[float] = None,
    maximumConfidence  : Optional[float] = None,
    createdAfter       : Optional[str] = None,
    createdBefore      : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter reasoning sessions list."""
    result = []
    for s in sessions:
        res = s["package"]
        c_status = s.get("status") or "ACTIVE"
        if status is not None and c_status.lower().strip() != status.lower().strip():
            continue
            
        user_id = s.get("userId") or "system"
        if userId is not None and user_id.lower().strip() != userId.lower().strip():
            continue
            
        proj_id = s.get("projectId") or "default-project"
        if projectId is not None and proj_id.lower().strip() != projectId.lower().strip():
            continue
            
        inv_id = s.get("investigationId") or ""
        if investigationId is not None and inv_id.lower().strip() != investigationId.lower().strip():
            continue
            
        step_count = len(res.reasoningTrace)
        if minimumSteps is not None and step_count < minimumSteps:
            continue
        if maximumSteps is not None and step_count > maximumSteps:
            continue
            
        conf = res.overallConfidence
        if minimumConfidence is not None and conf < minimumConfidence:
            continue
        if maximumConfidence is not None and conf > maximumConfidence:
            continue
            
        if createdAfter is not None and res.createdAt <= createdAfter:
            continue
        if createdBefore is not None and res.createdAt >= createdBefore:
            continue
            
        result.append(s)
    return result


def paginate_reasoning(
    sessions  : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate reasoning sessions list."""
    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(sessions)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = sessions[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def search_reasoning_sessions(query: str) -> List[Dict[str, Any]]:
    """Search reasoning sessions matching query string."""
    q_lower = query.lower().strip()
    matched = []
    for s in _REASONING_STORE.values():
        res = s["package"]
        texts = [
            res.reasoningId,
            res.reasoningKey,
            res.reasoningFingerprint,
            res.decision,
            res.decisionExplanation.summary,
            res.engineVersion,
            s.get("projectId") or "default-project",
            s.get("userId") or "system",
            s.get("status") or "ACTIVE",
            s.get("sessionName") or "",
        ]
        # Include lists from reasoning key
        texts.extend(s.get("contextIds") or [])
        texts.extend(s.get("findingIds") or [])
        texts.extend(s.get("alertIds") or [])
        texts.extend(s.get("relationshipIds") or [])
        texts.extend(s.get("timelineIds") or [])
        
        for t in res.reasoningTrace:
            texts.append(t.inputSummary)
            texts.append(t.outputSummary)
            texts.append(t.stage.value)
            
        for e in res.supportingEvidence:
            texts.append(e.evidenceId)
            texts.append(e.reason)
            texts.append(e.sourceType)
            
        if any(q_lower in str(t).lower() for t in texts):
            matched.append(s)
    return matched


def _step_to_response(t: ReasoningTrace) -> ReasoningStepResponse:
    """Map a service ReasoningTrace step to the API ReasoningStepResponse model."""
    return ReasoningStepResponse(
        stepNumber       = t.stepNumber,
        stage            = t.stage.value,
        inputSummary     = t.inputSummary,
        outputSummary    = t.outputSummary,
        confidence       = t.confidence,
        evidenceIds      = list(t.evidenceIds),
        findingIds       = list(t.findingIds),
        alertIds         = list(t.alertIds),
        relationshipIds  = list(t.relationshipIds),
        timelineEventIds = list(t.timelineEventIds),
    )


def _evidence_to_response(e: ReasoningEvidence) -> ReasoningEvidenceResponse:
    """Map a service ReasoningEvidence item to the API ReasoningEvidenceResponse model."""
    return ReasoningEvidenceResponse(
        evidenceId = e.evidenceId,
        weight     = e.weight,
        reason     = e.reason,
        sourceType = e.sourceType,
        confidence = e.confidence,
    )


def _reasoning_to_response(session_dict: Dict[str, Any]) -> ReasoningResponse:
    """Map a stored reasoning session state dict to the API ReasoningResponse model."""
    res = session_dict["package"]
    return ReasoningResponse(
        reasoningId          = res.reasoningId,
        reasoningKey         = res.reasoningKey,
        reasoningFingerprint = res.reasoningFingerprint,
        overallConfidence    = res.overallConfidence,
        overallRisk          = res.overallRisk,
        decision             = res.decision,
        reasoningTrace       = [_step_to_response(t) for t in res.reasoningTrace],
        supportingEvidence   = [_evidence_to_response(e) for e in res.supportingEvidence],
        decisionExplanation  = {
            "summary"               : res.decisionExplanation.summary,
            "strengths"             : list(res.decisionExplanation.strengths),
            "weaknesses"            : list(res.decisionExplanation.weaknesses),
            "assumptions"           : list(res.decisionExplanation.assumptions),
            "confidenceExplanation" : res.decisionExplanation.confidenceExplanation,
            "recommendedNextSteps"  : list(res.decisionExplanation.recommendedNextSteps),
        },
        metadata             = {
            "processingTimeMs"  : res.metadata.processingTimeMs,
            "reasoningDepth"    : res.metadata.reasoningDepth,
            "contextCount"      : res.metadata.contextCount,
            "findingCount"      : res.metadata.findingCount,
            "alertCount"        : res.metadata.alertCount,
            "relationshipCount" : res.metadata.relationshipCount,
            "timelineCount"     : res.metadata.timelineCount,
            "evidenceCount"     : res.metadata.evidenceCount,
            "modelsUsed"        : list(res.metadata.modelsUsed),
        },
        engineVersion        = res.engineVersion,
        createdAt            = res.createdAt,
        projectId            = session_dict.get("projectId") or "default-project",
        userId               = session_dict.get("userId") or "system",
        status               = session_dict.get("status") or "ACTIVE",
        sessionName          = session_dict.get("sessionName") or f"Session {res.reasoningId}",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@reasoning_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List reasoning sessions",
)
def list_reasonings() -> APIResponse:
    try:
        sessions = sorted(_REASONING_STORE.values(), key=lambda s: s["package"].reasoningId)
        payload = ReasoningListResponse(
            reasonings = [_reasoning_to_response(s) for s in sessions],
            total      = len(sessions),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(sessions)} reasoning session(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Reasoning statistics",
)
def get_reasoning_statistics() -> APIResponse:
    try:
        sessions = list(_REASONING_STORE.values())
        total = len(sessions)
        active = sum(1 for s in sessions if (s.get("status") or "ACTIVE") == "ACTIVE")
        completed = sum(1 for s in sessions if s.get("status") == "COMPLETED")
        
        total_steps = sum(len(s["package"].reasoningTrace) for s in sessions)
        avg_steps = round(total_steps / total, 4) if total > 0 else 0.0
        
        conf_sum = sum(s["package"].overallConfidence for s in sessions)
        avg_conf = round(conf_sum / total, 4) if total > 0 else 0.0

        total_reasoning_size = sum(
            len(s["package"].decision) + sum(len(t.inputSummary) + len(t.outputSummary) for t in s["package"].reasoningTrace)
            for s in sessions
        )
        avg_reasoning_size = round(total_reasoning_size / total, 4) if total > 0 else 0.0

        status_counts = {}
        for s in sessions:
            st = s.get("status") or "ACTIVE"
            status_counts[st] = status_counts.get(st, 0) + 1
        
        stats = ReasoningStatisticsResponse(
            totalReasoningSessions     = total,
            activeReasoningSessions    = active,
            completedReasoningSessions = completed,
            averageSteps               = avg_steps,
            averageConfidence          = avg_conf,
            averageReasoningSize       = avg_reasoning_size,
            statusCounts               = dict(sorted(status_counts.items())),
        )
        return build_success_response(
            data    = stats.model_dump(),
            message = "Reasoning statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.get(
    "/{reasoningId}",
    response_model      = APIResponse,
    summary             = "Get reasoning session by ID",
)
def get_reasoning(reasoningId: str) -> APIResponse:
    try:
        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )
        return build_success_response(
            data    = _reasoning_to_response(session_dict).model_dump(),
            message = "Reasoning session retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create reasoning session",
    status_code         = 201,
)
def create_reasoning(body: CreateReasoningRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        try:
            res = build_reasoning(
                context_ids        = body.contextIds,
                finding_ids        = body.findingIds,
                alert_ids          = body.alertIds,
                relationship_ids   = body.relationshipIds,
                timeline_ids       = body.timelineIds,
                created_at         = body.createdAt,
                decision           = body.decision if body.decision is not None else "",
                overall_confidence = body.overallConfidence if body.overallConfidence is not None else 0.0,
                overall_risk       = body.overallRisk if body.overallRisk is not None else 0.0,
            )
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        if res.reasoningId in _REASONING_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Reasoning session '{res.reasoningId}' already exists.")
            )

        session_dict = {
            "package"         : res,
            "projectId"       : body.projectId or "default-project",
            "userId"          : body.userId or "system",
            "status"          : body.status or "ACTIVE",
            "sessionName"     : body.sessionName or f"Session {res.reasoningId}",
            "contextIds"      : body.contextIds,
            "findingIds"      : body.findingIds,
            "alertIds"        : body.alertIds,
            "relationshipIds" : body.relationshipIds,
            "timelineIds"     : body.timelineIds,
        }
        _REASONING_STORE[res.reasoningId] = session_dict
        
        return build_success_response(
            data    = _reasoning_to_response(session_dict).model_dump(),
            message = "Reasoning session created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.put(
    "/{reasoningId}",
    response_model      = APIResponse,
    summary             = "Update reasoning session",
)
def update_reasoning(reasoningId: str, body: UpdateReasoningRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("At least one update field must be supplied.")
            )

        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )

        res = session_dict["package"]
        
        new_decision = body.decision if body.decision is not None else res.decision
        new_conf     = body.overallConfidence if body.overallConfidence is not None else res.overallConfidence
        new_risk     = body.overallRisk if body.overallRisk is not None else res.overallRisk

        try:
            new_res = build_reasoning(
                context_ids         = session_dict["contextIds"],
                finding_ids         = session_dict["findingIds"],
                alert_ids           = session_dict["alertIds"],
                relationship_ids    = session_dict["relationshipIds"],
                timeline_ids        = session_dict["timelineIds"],
                created_at          = res.createdAt,
                reasoning_trace     = list(res.reasoningTrace),
                supporting_evidence = list(res.supportingEvidence),
                decision            = new_decision,
                overall_confidence  = new_conf,
                overall_risk        = new_risk,
                explanation         = res.decisionExplanation,
            )
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        session_dict["package"] = new_res
        if body.projectId is not None:
            session_dict["projectId"] = body.projectId
        if body.userId is not None:
            session_dict["userId"] = body.userId
        if body.status is not None:
            session_dict["status"] = body.status
        if body.sessionName is not None:
            session_dict["sessionName"] = body.sessionName

        _REASONING_STORE[reasoningId] = session_dict

        return build_success_response(
            data    = _reasoning_to_response(session_dict).model_dump(),
            message = "Reasoning session updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.delete(
    "/{reasoningId}",
    response_model      = APIResponse,
    summary             = "Delete reasoning session",
)
def delete_reasoning(reasoningId: str) -> APIResponse:
    try:
        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )
        _REASONING_STORE.pop(reasoningId)
        return build_success_response(
            data    = None,
            message = "Reasoning session deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.post(
    "/{reasoningId}/steps",
    response_model      = APIResponse,
    summary             = "Append reasoning step",
)
def append_reasoning_step(reasoningId: str, body: ReasoningStepRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )

        res = session_dict["package"]
        
        from services.reasoning_service import ReasoningStage
        try:
            stage_enum = ReasoningStage(body.stage.upper().strip())
            step = build_reasoning_trace(
                step_number        = body.stepNumber,
                stage              = stage_enum,
                input_summary      = body.inputSummary,
                output_summary     = body.outputSummary,
                confidence         = body.confidence,
                evidence_ids       = body.evidenceIds,
                finding_ids        = body.findingIds,
                alert_ids          = body.alertIds,
                relationship_ids   = body.relationshipIds,
                timeline_event_ids = body.timelineEventIds,
            )
            
            new_trace = list(res.reasoningTrace) + [step]
            
            new_res = build_reasoning(
                context_ids         = session_dict["contextIds"],
                finding_ids         = session_dict["findingIds"],
                alert_ids           = session_dict["alertIds"],
                relationship_ids    = session_dict["relationshipIds"],
                timeline_ids        = session_dict["timelineIds"],
                created_at          = res.createdAt,
                reasoning_trace     = new_trace,
                supporting_evidence = list(res.supportingEvidence),
                decision            = res.decision,
                overall_confidence  = res.overallConfidence,
                overall_risk        = res.overallRisk,
                explanation         = res.decisionExplanation,
            )
            
            session_dict["package"] = new_res
            _REASONING_STORE[reasoningId] = session_dict
            
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = _step_to_response(step).model_dump(),
            message = "Reasoning step appended successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.get(
    "/{reasoningId}/steps",
    response_model      = APIResponse,
    summary             = "Get reasoning steps",
)
def list_reasoning_steps(reasoningId: str) -> APIResponse:
    try:
        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )

        res = session_dict["package"]
        steps = [_step_to_response(t) for t in res.reasoningTrace]
        return build_success_response(
            data    = [s.model_dump() for s in steps],
            message = f"{len(steps)} step(s) retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Routes
# ---------------------------------------------------------------------------

@reasoning_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search reasoning sessions",
)
def search_reasonings_endpoint(
    q                  : str = Query(..., min_length=1, description="Search string."),
    sortBy             : Optional[str] = "createdAt",
    sortOrder          : Optional[str] = "asc",
    page               : Optional[int] = 1,
    pageSize           : Optional[int] = 20,
    status             : Optional[str] = None,
    userId             : Optional[str] = None,
    projectId          : Optional[str] = None,
    investigationId    : Optional[str] = None,
    minimumSteps       : Optional[int] = None,
    maximumSteps       : Optional[int] = None,
    minimumConfidence  : Optional[float] = None,
    maximumConfidence  : Optional[float] = None,
    createdAfter       : Optional[str] = None,
    createdBefore      : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"createdAt", "updatedAt", "sessionName", "stepCount", "confidence"}
        errs = []
        if sortBy and sortBy not in allowed_sort:
            errs.append(f"sortBy must be one of: {sorted(allowed_sort)}.")
        if sortOrder and sortOrder not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        p = page or 1
        ps = pageSize or 20
        try:
            validate_pagination(p, ps)
        except APIErrorValidation as val_err:
            return exception_to_api_response(val_err)

        matched = search_reasoning_sessions(q)

        matched = filter_reasoning(
            matched,
            status=status,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumSteps=minimumSteps,
            maximumSteps=maximumSteps,
            minimumConfidence=minimumConfidence,
            maximumConfidence=maximumConfidence,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_sessions = sort_reasoning(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_reasoning(sorted_sessions, p, ps)

        payload = {
            "reasonings" : [_reasoning_to_response(w) for w in page_slice],
            "total"      : pag.totalItems,
            "page"       : pag.page,
            "pageSize"   : pag.pageSize,
            "totalPages" : pag.totalPages,
            "query"      : q,
            "sortBy"     : sortBy or "createdAt",
            "sortOrder"  : sortOrder or "asc",
        }
        return build_success_response(
            data    = payload,
            message = f"{pag.totalItems} reasoning session(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create reasoning sessions",
    status_code    = 201,
)
def bulk_create_reasoning_route(
    body: BulkCreateReasoningRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.reasonings:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"reasoningId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                res = build_reasoning(
                    context_ids        = item.contextIds,
                    finding_ids        = item.findingIds,
                    alert_ids          = item.alertIds,
                    relationship_ids   = item.relationshipIds,
                    timeline_ids       = item.timelineIds,
                    created_at         = item.createdAt,
                    decision           = item.decision if item.decision is not None else "",
                    overall_confidence = item.overallConfidence if item.overallConfidence is not None else 0.0,
                    overall_risk       = item.overallRisk if item.overallRisk is not None else 0.0,
                )

                if res.reasoningId in _REASONING_STORE:
                    failed.append({"reasoningId": res.reasoningId, "reason": f"Reasoning session '{res.reasoningId}' already exists."})
                    continue

                session_dict = {
                    "package"         : res,
                    "projectId"       : item.projectId or "default-project",
                    "userId"          : item.userId or "system",
                    "status"          : item.status or "ACTIVE",
                    "sessionName"     : item.sessionName or f"Session {res.reasoningId}",
                    "contextIds"      : item.contextIds,
                    "findingIds"      : item.findingIds,
                    "alertIds"        : item.alertIds,
                    "relationshipIds" : item.relationshipIds,
                    "timelineIds"     : item.timelineIds,
                }
                _REASONING_STORE[res.reasoningId] = session_dict
                succeeded.append(res.reasoningId)
            except Exception as e:
                failed.append({"reasoningId": "", "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.reasonings),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update reasoning sessions",
)
def bulk_update_reasoning_route(
    body: BulkUpdateReasoningRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.items:
            rid = item.reasoningId
            session_dict = _REASONING_STORE.get(rid)
            if session_dict is None:
                failed.append({"reasoningId": rid, "reason": f"Reasoning session '{rid}' not found."})
                continue

            try:
                res = session_dict["package"]
                upd = item.update
                
                new_decision = upd.decision if upd.decision is not None else res.decision
                new_conf     = upd.overallConfidence if upd.overallConfidence is not None else res.overallConfidence
                new_risk     = upd.overallRisk if upd.overallRisk is not None else res.overallRisk

                new_res = build_reasoning(
                    context_ids         = session_dict["contextIds"],
                    finding_ids         = session_dict["findingIds"],
                    alert_ids           = session_dict["alertIds"],
                    relationship_ids    = session_dict["relationshipIds"],
                    timeline_ids        = session_dict["timelineIds"],
                    created_at          = res.createdAt,
                    reasoning_trace     = list(res.reasoningTrace),
                    supporting_evidence = list(res.supportingEvidence),
                    decision            = new_decision,
                    overall_confidence  = new_conf,
                    overall_risk        = new_risk,
                    explanation         = res.decisionExplanation,
                )

                proj_id = upd.projectId if upd.projectId is not None else session_dict.get("projectId") or "default-project"
                user_id = upd.userId if upd.userId is not None else session_dict.get("userId") or "system"
                status_val = upd.status if upd.status is not None else session_dict.get("status") or "ACTIVE"
                name_val = upd.sessionName if upd.sessionName is not None else session_dict.get("sessionName") or f"Session {res.reasoningId}"

                session_dict["package"] = new_res
                session_dict["projectId"] = proj_id
                session_dict["userId"] = user_id
                session_dict["status"] = status_val
                session_dict["sessionName"] = name_val

                _REASONING_STORE[rid] = session_dict
                succeeded.append(rid)
            except Exception as e:
                failed.append({"reasoningId": rid, "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.items),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk update completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete reasoning sessions",
)
def bulk_delete_reasoning_route(
    body: BulkDeleteReasoningRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for rid in body.reasoningIds:
            if rid not in _REASONING_STORE:
                failed.append({"reasoningId": rid, "reason": f"Reasoning session '{rid}' not found."})
                continue

            try:
                _REASONING_STORE.pop(rid)
                succeeded.append(rid)
            except Exception as e:
                failed.append({"reasoningId": rid, "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.reasoningIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.put(
    "/{reasoningId}/steps/{stepId}",
    response_model      = APIResponse,
    summary             = "Update reasoning step",
)
def update_reasoning_step_route(
    reasoningId : str,
    stepId      : str,
    body        : ReasoningStepRequest,
) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )
            
        try:
            step_num = int(stepId)
        except ValueError:
            return exception_to_api_response(
                APIErrorValidation("stepId must be a valid integer step number.")
            )

        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )

        res = session_dict["package"]
        
        from services.reasoning_service import ReasoningStage
        try:
            stage_enum = ReasoningStage(body.stage.upper().strip())
            new_res, updated_step = update_reasoning_step(
                result             = res,
                context_ids        = session_dict["contextIds"],
                finding_ids        = session_dict["findingIds"],
                alert_ids          = session_dict["alertIds"],
                relationship_ids   = session_dict["relationshipIds"],
                timeline_ids       = session_dict["timelineIds"],
                step_number        = step_num,
                stage              = stage_enum,
                input_summary      = body.inputSummary,
                output_summary     = body.outputSummary,
                confidence         = body.confidence,
                evidence_ids       = body.evidenceIds,
                finding_ids_step   = body.findingIds,
                alert_ids_step     = body.alertIds,
                relationship_ids_s = body.relationshipIds,
                timeline_event_ids = body.timelineEventIds,
            )
            session_dict["package"] = new_res
            _REASONING_STORE[reasoningId] = session_dict
        except Exception as e:
            if "not found" in str(e):
                return exception_to_api_response(APIErrorNotFound(str(e)))
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = _step_to_response(updated_step).model_dump(),
            message = "Reasoning step updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.delete(
    "/{reasoningId}/steps/{stepId}",
    response_model      = APIResponse,
    summary             = "Delete reasoning step",
)
def delete_reasoning_step_route(
    reasoningId : str,
    stepId      : str,
) -> APIResponse:
    try:
        try:
            step_num = int(stepId)
        except ValueError:
            return exception_to_api_response(
                APIErrorValidation("stepId must be a valid integer step number.")
            )

        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )

        res = session_dict["package"]
        try:
            new_res = delete_reasoning_step(
                result           = res,
                context_ids      = session_dict["contextIds"],
                finding_ids      = session_dict["findingIds"],
                alert_ids        = session_dict["alertIds"],
                relationship_ids = session_dict["relationshipIds"],
                timeline_ids     = session_dict["timelineIds"],
                step_number      = step_num,
            )
            session_dict["package"] = new_res
            _REASONING_STORE[reasoningId] = session_dict
        except Exception as e:
            if "not found" in str(e):
                return exception_to_api_response(APIErrorNotFound(str(e)))
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = None,
            message = "Reasoning step deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@reasoning_router.get(
    "/{reasoningId}/summary",
    response_model      = APIResponse,
    summary             = "Get reasoning session summary",
)
def get_reasoning_summary_route(reasoningId: str) -> APIResponse:
    try:
        session_dict = _REASONING_STORE.get(reasoningId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Reasoning session '{reasoningId}' not found.")
            )

        res = session_dict["package"]
        summary_text = build_reasoning_summary(res)
        return build_success_response(
            data    = {"summary": summary_text},
            message = "Reasoning summary generated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
