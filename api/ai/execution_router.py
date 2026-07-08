"""
AI Execution API Router — Phase A4.8.7 (Part A)
==============================================
REST interface for AI Execution engine.

Prefix  : /execution
Tag     : AI Execution
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
from api.ai.execution_models import (
    CreateExecutionRequest,
    UpdateExecutionRequest,
    ExecutionResponse,
    ExecutionListResponse,
    ExecutionStatisticsResponse,
    BulkCreateExecutionsRequest,
    BulkUpdateExecutionsRequest,
    BulkDeleteExecutionsRequest,
    BulkOperationResult,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response, validate_pagination

from services.ai_execution_service import (
    AIExecutionRequest,
    AIExecutionResponse,
    AIExecutionMetadata,
    AIExecutionResult,
    build_execution_request,
    build_execution_metadata,
    build_execution_result,
    execute_request,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

execution_router: APIRouter = APIRouter(
    prefix = "/execution",
    tags   = ["AI Execution"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_execution
_EXECUTION_STORE = RepositoryBackedDict("execution", "executionId", map_execution)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _EXECUTION_STORE.clear()


# ---------------------------------------------------------------------------
# Sort map
# ---------------------------------------------------------------------------
_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt" : "createdAt",
    "updatedAt" : "createdAt",
}


# ---------------------------------------------------------------------------
# Execution Utility Helpers
# ---------------------------------------------------------------------------

def retry_execution(
    result      : AIExecutionResult,
    max_attempts: int = 3,
) -> AIExecutionResult:
    """Retry an execution session using ai_execution_service."""
    from services.ai_execution_service import execute_with_retry
    from datetime import datetime
    now_str = datetime.utcnow().isoformat() + "Z"
    return execute_with_retry(
        request      = result.request,
        created_at   = now_str,
        max_attempts = max_attempts,
    )


def cancel_execution(result: AIExecutionResult) -> AIExecutionResult:
    """Cancel a registered execution result package."""
    from services.ai_execution_service import build_execution_metadata, build_execution_result
    meta = build_execution_metadata(
        execution_id       = result.request.executionId,
        provider           = result.request.provider,
        model              = result.request.model,
        strategy           = result.request.strategy,
        attempt_number     = result.metadata.attemptNumber,
        total_attempts     = result.metadata.totalAttempts,
        processing_time_ms = result.metadata.processingTimeMs,
        success            = False,
        error              = "Execution cancelled by user.",
        warnings           = list(result.metadata.warnings) + ["cancelled"],
    )
    return build_execution_result(result.request, None, meta)


def build_execution_summary(result: AIExecutionResult) -> str:
    """Build a deterministic summary of the execution run."""
    req = result.request
    meta = result.metadata
    status_str = "SUCCESS" if meta.success else "FAILED"
    summary = f"Execution Summary: ID={req.executionId} | Provider={req.provider} | Model={req.model} | Status={status_str}"
    if result.response is not None:
        summary += f" | Tokens={result.response.totalTokens} | Latency={result.response.latencyMs}ms | Output={result.response.content[:40]}"
    elif meta.error:
        summary += f" | Error={meta.error[:50]}"
    return summary


def calculate_execution_usage(result: AIExecutionResult) -> Dict[str, Any]:
    """Calculate token and cost usage of execution."""
    if result.response is None:
        return {
            "promptTokens"     : 0,
            "completionTokens" : 0,
            "totalTokens"      : 0,
            "estimatedCost"    : 0.0,
            "latencyMs"        : 0,
        }
    resp = result.response
    return {
        "promptTokens"     : resp.promptTokens,
        "completionTokens" : resp.completionTokens,
        "totalTokens"      : resp.totalTokens,
        "estimatedCost"    : resp.estimatedCost,
        "latencyMs"        : resp.latencyMs,
    }


def get_execution_status_helper(result: AIExecutionResult) -> str:
    """Get the string status from the result metadata success/error flags."""
    if result.metadata.success:
        return "COMPLETED"
    if result.metadata.error == "Pending execution.":
        return "PENDING"
    if result.metadata.error == "Execution cancelled by user.":
        return "CANCELLED"
    return "FAILED"


# ---------------------------------------------------------------------------
# Search, Sort, Filter, Paginate Helpers
# ---------------------------------------------------------------------------

def find_execution(
    sessions: List[Dict[str, Any]],
    field   : str,
    value   : str,
) -> Optional[Dict[str, Any]]:
    """Find execution by a specific field value."""
    target = value.lower().strip()
    for s in sessions:
        res = s["package"]
        v = None
        if field in ("executionId", "packageId"): v = res.request.executionId
        elif field == "executionKey": v = res.request.executionKey
        elif field == "projectId": v = s.get("projectId")
        elif field == "userId": v = s.get("userId")
        elif field == "status": v = s.get("status")
        
        if v is not None and str(v).lower().strip() == target:
            return s
    return None


def sort_executions(
    sessions   : List[Dict[str, Any]],
    sort_by    : str = "createdAt",
    sort_order : str = "asc",
) -> List[Dict[str, Any]]:
    """Sort executions list."""
    reverse = sort_order.lower() == "desc"
    
    def sort_key(s: Dict[str, Any]):
        res = s["package"]
        if sort_by == "totalTokens":
            tokens = res.response.totalTokens if res.response is not None else 0
            return (0, tokens)
        if sort_by == "processingTimeMs":
            return (0, res.metadata.processingTimeMs)
        if sort_by == "status":
            st = s.get("status") or "PENDING"
            return (0, st.lower())
        if sort_by == "executionName":
            name = s.get("executionName") or f"Execution {res.request.executionId}"
            return (0, name.lower())
            
        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(res.request, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())
        
    return sorted(sessions, key=sort_key, reverse=reverse)


def filter_executions(
    sessions        : List[Dict[str, Any]],
    status          : Optional[str] = None,
    provider        : Optional[str] = None,
    model           : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    minimumLatency  : Optional[int] = None,
    maximumLatency  : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter executions list."""
    result = []
    for s in sessions:
        res = s["package"]
        req = res.request
        meta = res.metadata
        
        c_status = s.get("status") or "PENDING"
        if status is not None and c_status.lower().strip() != status.lower().strip():
            continue
            
        if provider is not None and meta.provider.lower().strip() != provider.lower().strip():
            continue
            
        if model is not None and meta.model.lower().strip() != model.lower().strip():
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
            
        tokens = res.response.totalTokens if res.response is not None else 0
        if minimumTokens is not None and tokens < minimumTokens:
            continue
        if maximumTokens is not None and tokens > maximumTokens:
            continue
            
        latency = res.response.latencyMs if res.response is not None else 0
        if minimumLatency is not None and latency < minimumLatency:
            continue
        if maximumLatency is not None and latency > maximumLatency:
            continue
            
        if createdAfter is not None and req.createdAt <= createdAfter:
            continue
        if createdBefore is not None and req.createdAt >= createdBefore:
            continue
            
        result.append(s)
    return result


def paginate_executions(
    sessions  : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate executions list."""
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


def search_executions(query: str) -> List[Dict[str, Any]]:
    """Search executions matching query string."""
    q_lower = query.lower().strip()
    matched = []
    for s in _EXECUTION_STORE.values():
        res = s["package"]
        req = res.request
        texts = [
            req.executionId,
            req.executionKey,
            req.executionFingerprint,
            req.provider,
            req.model,
            req.systemPrompt,
            req.userPrompt,
            req.requestId,
            req.sessionId,
            req.strategy,
            s.get("projectId") or "default-project",
            s.get("userId") or "system",
            s.get("status") or "PENDING",
            s.get("executionName") or "",
        ]
        if res.response is not None:
            texts.extend([
                res.response.responseId,
                res.response.responseKey,
                res.response.responseFingerprint,
                res.response.content,
                res.response.finishReason,
            ])
        if any(q_lower in str(t).lower() for t in texts):
            matched.append(s)
    return matched


def _execution_to_response(session_dict: Dict[str, Any]) -> ExecutionResponse:
    """Map a stored execution run state dict to the API ExecutionResponse model."""
    res = session_dict["package"]
    resp_data = None
    if res.response is not None:
        resp_data = {
            "responseId"          : res.response.responseId,
            "responseKey"         : res.response.responseKey,
            "responseFingerprint" : res.response.responseFingerprint,
            "executionId"         : res.response.executionId,
            "provider"            : res.response.provider,
            "model"               : res.response.model,
            "content"             : res.response.content,
            "finishReason"        : res.response.finishReason,
            "promptTokens"        : res.response.promptTokens,
            "completionTokens"    : res.response.completionTokens,
            "totalTokens"         : res.response.totalTokens,
            "estimatedCost"       : res.response.estimatedCost,
            "latencyMs"           : res.response.latencyMs,
            "createdAt"           : res.response.createdAt,
            "engineVersion"       : res.response.engineVersion,
        }
    return ExecutionResponse(
        executionId          = res.request.executionId,
        executionKey         = res.request.executionKey,
        executionFingerprint = res.request.executionFingerprint,
        provider             = res.request.provider,
        model                = res.request.model,
        systemPrompt         = res.request.systemPrompt,
        userPrompt           = res.request.userPrompt,
        temperature          = res.request.temperature,
        maxTokens            = res.request.maxTokens,
        stream               = res.request.stream,
        requestId            = res.request.requestId,
        sessionId            = res.request.sessionId,
        strategy             = res.request.strategy,
        createdAt            = res.request.createdAt,
        engineVersion        = res.request.engineVersion,
        projectId            = session_dict.get("projectId") or "default-project",
        userId               = session_dict.get("userId") or "system",
        status               = session_dict.get("status") or "ACTIVE",
        response             = resp_data,
        metadata             = {
            "executionId"      : res.metadata.executionId,
            "provider"         : res.metadata.provider,
            "model"            : res.metadata.model,
            "strategy"         : res.metadata.strategy,
            "attemptNumber"    : res.metadata.attemptNumber,
            "totalAttempts"    : res.metadata.totalAttempts,
            "processingTimeMs" : res.metadata.processingTimeMs,
            "success"          : res.metadata.success,
            "error"            : res.metadata.error,
            "warnings"         : list(res.metadata.warnings),
            "engineVersion"    : res.metadata.engineVersion,
        },
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@execution_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List executions",
)
def list_executions() -> APIResponse:
    try:
        sessions = sorted(_EXECUTION_STORE.values(), key=lambda s: s["package"].request.executionId)
        payload = ExecutionListResponse(
            executions = [_execution_to_response(s) for s in sessions],
            total      = len(sessions),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(sessions)} execution(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "AI execution statistics",
)
def get_execution_statistics() -> APIResponse:
    try:
        sessions = list(_EXECUTION_STORE.values())
        total = len(sessions)
        pending = sum(1 for s in sessions if s.get("status") == "PENDING")
        running = sum(1 for s in sessions if s.get("status") == "RUNNING")
        completed = sum(1 for s in sessions if s.get("status") == "COMPLETED")
        failed = sum(1 for s in sessions if s.get("status") == "FAILED")
        
        executed = [s["package"] for s in sessions if s.get("status") in ("COMPLETED", "FAILED")]
        avg_time = round(sum(e.metadata.processingTimeMs for e in executed) / len(executed), 4) if executed else 0.0
        
        successful = [s["package"] for s in sessions if s.get("status") == "COMPLETED" and s["package"].response is not None]
        avg_tokens = round(sum(s.response.totalTokens for s in successful) / len(successful), 4) if successful else 0.0

        total_execution_size = sum(
            len(s["package"].request.systemPrompt) + len(s["package"].request.userPrompt) +
            (len(s["package"].response.content) if s["package"].response is not None else 0)
            for s in sessions
        )
        avg_execution_size = round(total_execution_size / total, 4) if total > 0 else 0.0

        status_counts = {}
        provider_counts = {}
        for s in sessions:
            st = s.get("status") or "PENDING"
            status_counts[st] = status_counts.get(st, 0) + 1
            prov = s["package"].metadata.provider or "unknown"
            provider_counts[prov] = provider_counts.get(prov, 0) + 1

        stats = ExecutionStatisticsResponse(
            totalExecutions      = total,
            pendingExecutions    = pending,
            runningExecutions    = running,
            completedExecutions  = completed,
            failedExecutions     = failed,
            averageExecutionTime = avg_time,
            averageTokens        = avg_tokens,
            averageExecutionSize = avg_execution_size,
            statusCounts         = dict(sorted(status_counts.items())),
            providerCounts       = dict(sorted(provider_counts.items())),
        )
        return build_success_response(
            data    = stats.model_dump(),
            message = "AI execution statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.get(
    "/{executionId}",
    response_model      = APIResponse,
    summary             = "Get execution by ID",
)
def get_execution(executionId: str) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )
        return build_success_response(
            data    = _execution_to_response(session_dict).model_dump(),
            message = "Execution retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Register execution shell",
    status_code         = 201,
)
def create_execution(body: CreateExecutionRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        try:
            req = build_execution_request(
                provider      = body.provider,
                model         = body.model,
                system_prompt = body.systemPrompt,
                user_prompt   = body.userPrompt,
                created_at    = body.createdAt,
                temperature   = body.temperature if body.temperature is not None else 0.0,
                max_tokens    = body.maxTokens if body.maxTokens is not None else 1024,
                stream        = body.stream if body.stream is not None else False,
                request_id    = body.requestId or "",
                session_id    = body.sessionId or "",
                strategy      = body.strategy or "priority",
                validate      = True,
            )
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        if req.executionId in _EXECUTION_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Execution '{req.executionId}' already exists.")
            )

        meta = build_execution_metadata(
            execution_id       = req.executionId,
            provider           = req.provider,
            model              = req.model,
            strategy           = req.strategy,
            attempt_number     = 0,
            total_attempts     = 0,
            processing_time_ms = 0,
            success            = False,
            error              = "Pending execution.",
        )
        res = build_execution_result(req, None, meta)

        session_dict = {
            "package"   : res,
            "projectId" : body.projectId or "default-project",
            "userId"    : body.userId or "system",
            "status"    : "PENDING",
        }
        _EXECUTION_STORE[req.executionId] = session_dict
        
        return build_success_response(
            data    = _execution_to_response(session_dict).model_dump(),
            message = "Execution registered successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.put(
    "/{executionId}",
    response_model      = APIResponse,
    summary             = "Update execution details",
)
def update_execution(executionId: str, body: UpdateExecutionRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("At least one update field must be supplied.")
            )

        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )

        if body.projectId is not None:
            session_dict["projectId"] = body.projectId
        if body.userId is not None:
            session_dict["userId"] = body.userId
        if body.status is not None:
            session_dict["status"] = body.status

        _EXECUTION_STORE[executionId] = session_dict

        return build_success_response(
            data    = _execution_to_response(session_dict).model_dump(),
            message = "Execution updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.delete(
    "/{executionId}",
    response_model      = APIResponse,
    summary             = "Delete execution record",
)
def delete_execution(executionId: str) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )
        _EXECUTION_STORE.pop(executionId)
        return build_success_response(
            data    = None,
            message = "Execution deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.post(
    "/{executionId}/execute",
    response_model      = APIResponse,
    summary             = "Execute registered execution",
)
def run_registered_execution(executionId: str) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )

        res = session_dict["package"]
        req = res.request

        session_dict["status"] = "RUNNING"
        
        from datetime import datetime
        now_str = datetime.utcnow().isoformat() + "Z"

        try:
            result = execute_request(req, created_at=now_str)
            session_dict["package"] = result
            session_dict["status"]  = "COMPLETED" if result.metadata.success else "FAILED"
        except Exception as e:
            session_dict["status"]  = "FAILED"
            return exception_to_api_response(APIErrorValidation(str(e)))

        _EXECUTION_STORE[executionId] = session_dict

        return build_success_response(
            data    = _execution_to_response(session_dict).model_dump(),
            message = "Execution run completed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.get(
    "/{executionId}/status",
    response_model      = APIResponse,
    summary             = "Get execution status",
)
def get_execution_status(executionId: str) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )

        status_str = session_dict.get("status") or "PENDING"
        res = session_dict["package"]
        payload = {
            "executionId"      : executionId,
            "status"           : status_str,
            "success"          : res.metadata.success,
            "error"            : res.metadata.error,
            "processingTimeMs" : res.metadata.processingTimeMs,
        }
        return build_success_response(
            data    = payload,
            message = f"Execution status: {status_str}.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Routes
# ---------------------------------------------------------------------------

@execution_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search executions",
)
def search_executions_endpoint(
    q               : str = Query(..., min_length=1, description="Search string."),
    sortBy          : Optional[str] = "createdAt",
    sortOrder       : Optional[str] = "asc",
    page            : Optional[int] = 1,
    pageSize        : Optional[int] = 20,
    status          : Optional[str] = None,
    provider        : Optional[str] = None,
    model           : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    minimumLatency  : Optional[int] = None,
    maximumLatency  : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"createdAt", "updatedAt", "executionName", "status", "processingTimeMs", "totalTokens"}
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

        matched = search_executions(q)

        matched = filter_executions(
            matched,
            status=status,
            provider=provider,
            model=model,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            minimumLatency=minimumLatency,
            maximumLatency=maximumLatency,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_list = sort_executions(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_executions(sorted_list, p, ps)

        payload = {
            "executions" : [_execution_to_response(w) for w in page_slice],
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
            message = f"{pag.totalItems} execution(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create executions",
    status_code    = 201,
)
def bulk_create_executions_route(
    body: BulkCreateExecutionsRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.executions:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"executionId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                req = build_execution_request(
                    provider      = item.provider,
                    model         = item.model,
                    system_prompt = item.systemPrompt,
                    user_prompt   = item.userPrompt,
                    created_at    = item.createdAt,
                    temperature   = item.temperature if item.temperature is not None else 0.0,
                    max_tokens    = item.maxTokens if item.maxTokens is not None else 1024,
                    stream        = item.stream if item.stream is not None else False,
                    request_id    = item.requestId or "",
                    session_id    = item.sessionId or "",
                    strategy      = item.strategy or "priority",
                    validate      = True,
                )

                if req.executionId in _EXECUTION_STORE:
                    failed.append({"executionId": req.executionId, "reason": f"Execution '{req.executionId}' already exists."})
                    continue

                meta = build_execution_metadata(
                    execution_id       = req.executionId,
                    provider           = req.provider,
                    model              = req.model,
                    strategy           = req.strategy,
                    attempt_number     = 0,
                    total_attempts     = 0,
                    processing_time_ms = 0,
                    success            = False,
                    error              = "Pending execution.",
                )
                res = build_execution_result(req, None, meta)

                session_dict = {
                    "package"   : res,
                    "projectId" : item.projectId or "default-project",
                    "userId"    : item.userId or "system",
                    "status"    : "PENDING",
                }
                _EXECUTION_STORE[req.executionId] = session_dict
                succeeded.append(req.executionId)
            except Exception as e:
                failed.append({"executionId": "", "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.executions),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk create completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update executions",
)
def bulk_update_executions_route(
    body: BulkUpdateExecutionsRequest,
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
            eid = item.executionId
            session_dict = _EXECUTION_STORE.get(eid)
            if session_dict is None:
                failed.append({"executionId": eid, "reason": f"Execution '{eid}' not found."})
                continue

            try:
                upd = item.update
                if upd.projectId is not None:
                    session_dict["projectId"] = upd.projectId
                if upd.userId is not None:
                    session_dict["userId"] = upd.userId
                if upd.status is not None:
                    session_dict["status"] = upd.status

                _EXECUTION_STORE[eid] = session_dict
                succeeded.append(eid)
            except Exception as e:
                failed.append({"executionId": eid, "reason": str(e)})

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


@execution_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete executions",
)
def bulk_delete_executions_route(
    body: BulkDeleteExecutionsRequest,
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for eid in body.executionIds:
            if eid not in _EXECUTION_STORE:
                failed.append({"executionId": eid, "reason": f"Execution '{eid}' not found."})
                continue

            try:
                _EXECUTION_STORE.pop(eid)
                succeeded.append(eid)
            except Exception as e:
                failed.append({"executionId": eid, "reason": str(e)})

        payload = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.executionIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"Bulk delete completed: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.post(
    "/{executionId}/retry",
    response_model      = APIResponse,
    summary             = "Retry execution run",
)
def retry_execution_route(
    executionId  : str,
    maxAttempts  : Optional[int] = Query(3, ge=1, le=10),
) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )

        res = session_dict["package"]
        session_dict["status"] = "RUNNING"
        
        try:
            result = retry_execution(res, max_attempts=maxAttempts)
            session_dict["package"] = result
            session_dict["status"]  = "COMPLETED" if result.metadata.success else "FAILED"
        except Exception as e:
            session_dict["status"]  = "FAILED"
            return exception_to_api_response(APIErrorValidation(str(e)))

        _EXECUTION_STORE[executionId] = session_dict

        return build_success_response(
            data    = _execution_to_response(session_dict).model_dump(),
            message = "Execution retry run completed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.post(
    "/{executionId}/cancel",
    response_model      = APIResponse,
    summary             = "Cancel execution run",
)
def cancel_execution_route(executionId: str) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )

        res = session_dict["package"]
        current_status = session_dict.get("status") or "PENDING"
        if current_status not in ("PENDING", "RUNNING"):
            return exception_to_api_response(
                APIErrorValidation(f"Cannot cancel execution in '{current_status}' status.")
            )

        cancelled_res = cancel_execution(res)
        session_dict["package"] = cancelled_res
        session_dict["status"]  = "CANCELLED"
        _EXECUTION_STORE[executionId] = session_dict

        return build_success_response(
            data    = _execution_to_response(session_dict).model_dump(),
            message = "Execution cancelled successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@execution_router.get(
    "/{executionId}/summary",
    response_model      = APIResponse,
    summary             = "Get execution summary",
)
def get_execution_summary_route(executionId: str) -> APIResponse:
    try:
        session_dict = _EXECUTION_STORE.get(executionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Execution '{executionId}' not found.")
            )

        res = session_dict["package"]
        summary_text = build_execution_summary(res)
        return build_success_response(
            data    = {"summary": summary_text},
            message = "Execution summary generated.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
