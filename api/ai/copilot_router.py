"""
AI Copilot API Router — Phase A4.8.1 (Part B)
==============================================
REST interface for the AI Copilot Engine.

Prefix  : /copilot
Tag     : AI Copilot
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Body, Query

from api.errors import (
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.ai.copilot_models import (
    CreateCopilotSessionRequest,
    UpdateCopilotSessionRequest,
    CopilotChatRequest,
    CopilotChatResponse,
    CopilotSessionResponse,
    CopilotSessionListResponse,
    CopilotStatisticsResponse,
    CopilotSearchResponse,
    BulkCreateCopilotSessionsRequest,
    BulkUpdateCopilotSessionsRequest,
    BulkDeleteCopilotSessionsRequest,
    BulkOperationResult,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response

from services.copilot_orchestrator_service import (
    build_copilot_request,
    build_copilot_response,
    build_copilot_session,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

copilot_router: APIRouter = APIRouter(
    prefix = "/copilot",
    tags   = ["AI Copilot"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_copilot_session
_COPILOT_STORE = RepositoryBackedDict("sessionMemory", "sessionId", map_copilot_session)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _COPILOT_STORE.clear()


def _all_sessions() -> List[Dict[str, Any]]:
    """Return all sessions as a deterministically-ordered list (by sessionId ASC)."""
    return sorted(_COPILOT_STORE.values(), key=lambda s: s.get("sessionId", ""))


def _session_to_response(session: Dict[str, Any]) -> CopilotSessionResponse:
    """Convert a raw session dict to a CopilotSessionResponse model."""
    return CopilotSessionResponse(
        sessionId   = session["sessionId"],
        sessionKey  = session["sessionKey"],
        request     = session["request"],
        response    = session["response"],
        metadata    = session["metadata"],
        createdAt   = session["createdAt"],
        status      = session.get("status", "active"),
        turns       = session.get("turns", 1),
        userId      = session.get("userId", "system"),
        projectId   = session.get("projectId", "default-project"),
        sessionName = session.get("sessionName") or "",
        contextSize = session.get("contextSize", 0),
        updatedAt   = session.get("updatedAt") or "",
    )


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------

def find_session(
    sessions: List[Dict[str, Any]],
    field   : str,
    value   : str,
) -> Optional[Dict[str, Any]]:
    """Return the first session whose field matches value (case-insensitive)."""
    target = value.lower().strip()
    for s in sessions:
        v = s.get(field)
        if v is not None and str(v).lower().strip() == target:
            return s
    return None


_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt"   : "createdAt",
    "updatedAt"   : "updatedAt",
    "sessionName" : "sessionName",
    "status"      : "status",
    "totalTurns"  : "turns",
}


def sort_sessions(
    sessions  : List[Dict[str, Any]],
    sort_by   : str = "createdAt",
    sort_order: str = "asc",
) -> List[Dict[str, Any]]:
    """Return a new list of session dicts sorted by the specified field."""
    reverse = sort_order.lower() == "desc"

    def sort_key(s: Dict[str, Any]):
        if sort_by == "totalTokens":
            meta = s.get("metadata")
            val = (meta.promptTokenEstimate + meta.responseTokenEstimate) if meta else 0
            return (0, val)

        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = s.get(field)
        if v is None:
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        return (0, str(v).lower())

    return sorted(sessions, key=sort_key, reverse=reverse)


def filter_sessions(
    sessions        : List[Dict[str, Any]],
    status          : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumTurns    : Optional[int] = None,
    maximumTurns    : Optional[int] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter session dicts by criteria."""
    result = []
    for s in sessions:
        if status is not None and (s.get("status") or "").lower() != status.lower().strip():
            continue
        if userId is not None and (s.get("userId") or "").lower() != userId.lower().strip():
            continue
        if projectId is not None and (s.get("projectId") or "").lower() != projectId.lower().strip():
            continue

        req = s.get("request")
        invest_id = ""
        if req:
            if hasattr(req, "investigationId"):
                invest_id = req.investigationId
            elif isinstance(req, dict):
                invest_id = req.get("investigationId") or ""
        if investigationId is not None and invest_id.lower().strip() != investigationId.lower().strip():
            continue

        turns = s.get("turns", 1)
        if minimumTurns is not None and turns < minimumTurns:
            continue
        if maximumTurns is not None and turns > maximumTurns:
            continue

        meta = s.get("metadata")
        tokens = 0
        if meta:
            if hasattr(meta, "promptTokenEstimate"):
                tokens = meta.promptTokenEstimate + meta.responseTokenEstimate
            elif isinstance(meta, dict):
                tokens = (meta.get("promptTokenEstimate") or 0) + (meta.get("responseTokenEstimate") or 0)

        if minimumTokens is not None and tokens < minimumTokens:
            continue
        if maximumTokens is not None and tokens > maximumTokens:
            continue

        created_at = s.get("createdAt") or ""
        if createdAfter is not None and created_at <= createdAfter:
            continue
        if createdBefore is not None and created_at >= createdBefore:
            continue

        result.append(s)
    return result


def paginate_sessions(
    sessions : List[Dict[str, Any]],
    page     : int,
    page_size: int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Slice sessions list to requested page and return metadata."""
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


# ---------------------------------------------------------------------------
# Chat helpers
# ---------------------------------------------------------------------------

def append_chat_message(
    messages  : List[Any],
    role      : str,
    content   : str,
    seq       : int,
    created_at: str,
) -> List[Any]:
    """Append a message to the history list."""
    from services.conversation_manager_service import build_message, ConversationRole
    conv_id = "temp-conv"
    if messages:
        conv_id = messages[0].conversationId
    msg = build_message(
        conversation_id = conv_id,
        role            = ConversationRole(role.upper().strip()),
        content         = content,
        sequence_number = seq,
        created_at      = created_at,
    )
    return messages + [msg]


def get_chat_history(session_dict: Dict[str, Any]) -> List[Any]:
    """Retrieve message history."""
    return session_dict.get("messages") or []


def clear_chat_history(session_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Return updated session dict with cleared history."""
    updated = dict(session_dict)
    updated["messages"] = []
    updated["turns"] = 0
    return updated


def build_chat_summary(messages: List[Any]) -> str:
    """Generate deterministic summary text of the messages."""
    if not messages:
        return "No messages to summarize."
    lines = []
    for m in messages:
        role_str = m.role.value if hasattr(m.role, "value") else str(m.role)
        lines.append(f"{role_str}: {m.content[:50]}")
    return "Summary of conversation: " + " | ".join(lines)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@copilot_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List Copilot sessions",
)
def list_copilot_sessions() -> APIResponse:
    try:
        sessions = _all_sessions()
        payload = CopilotSessionListResponse(
            sessions = [_session_to_response(s) for s in sessions],
            total    = len(sessions),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(sessions)} session(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Copilot statistics",
)
def get_copilot_statistics() -> APIResponse:
    try:
        sessions = _all_sessions()
        total = len(sessions)
        active = sum(1 for s in sessions if s.get("status") == "active")
        completed = sum(1 for s in sessions if s.get("status") == "completed")
        turns_sum = sum(s.get("turns", 1) for s in sessions)
        tokens_sum = sum(
            s["metadata"].promptTokenEstimate + s["metadata"].responseTokenEstimate
            for s in sessions
        )
        ctx_sum = sum(s.get("contextSize", 0) for s in sessions)

        average_turns  = round(turns_sum / total, 4) if total > 0 else 0.0
        average_tokens = round(tokens_sum / total, 4) if total > 0 else 0.0
        average_ctx    = round(ctx_sum / total, 4) if total > 0 else 0.0

        status_counts = {}
        for s in sessions:
            st = s.get("status") or "active"
            status_counts[st] = status_counts.get(st, 0) + 1

        stats = CopilotStatisticsResponse(
            totalSessions      = total,
            activeSessions     = active,
            completedSessions  = completed,
            averageTurns       = average_turns,
            averageTokens      = average_tokens,
            averageContextSize = average_ctx,
            statusCounts       = dict(sorted(status_counts.items())),
        )
        return build_success_response(
            data    = stats.model_dump(),
            message = "Copilot statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search Copilot sessions",
)
def search_copilot_sessions(
    q              : str = Query(..., min_length=1, description="Search string."),
    sortBy         : Optional[str] = "createdAt",
    sortOrder      : Optional[str] = "asc",
    page           : Optional[int] = 1,
    pageSize       : Optional[int] = 20,
    status         : Optional[str] = None,
    userId         : Optional[str] = None,
    projectId      : Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumTurns   : Optional[int] = None,
    maximumTurns   : Optional[int] = None,
    minimumTokens  : Optional[int] = None,
    maximumTokens  : Optional[int] = None,
    createdAfter   : Optional[str] = None,
    createdBefore  : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"createdAt", "updatedAt", "sessionName", "status", "totalTurns", "totalTokens"}
        errs = []
        if sortBy and sortBy not in allowed_sort:
            errs.append(f"sortBy must be one of: {sorted(allowed_sort)}.")
        if sortOrder and sortOrder not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        q_lower = q.lower().strip()
        matched = []
        for s in _all_sessions():
            texts = [
                s["sessionId"],
                s["sessionKey"],
                s.get("userId") or "",
                s.get("projectId") or "",
                s.get("sessionName") or "",
                s["request"].systemPrompt,
                s["request"].userPrompt,
                s["response"].content,
                s["request"].contextId,
                s["request"].reasoningId,
                s["request"].promptPackageId,
                s["request"].narrativeId,
                s["request"].investigationId,
            ]
            if any(q_lower in str(t).lower() for t in texts):
                matched.append(s)

        matched = filter_sessions(
            matched,
            status=status,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumTurns=minimumTurns,
            maximumTurns=maximumTurns,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_sess = sort_sessions(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_sessions(sorted_sess, page or 1, pageSize or 20)

        payload = CopilotSearchResponse(
            sessions   = [_session_to_response(s) for s in page_slice],
            total      = pag.totalItems,
            page       = pag.page,
            pageSize   = pag.pageSize,
            totalPages = pag.totalPages,
            query      = q,
            sortBy     = sortBy or "createdAt",
            sortOrder  = sortOrder or "asc",
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{pag.totalItems} session(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.get(
    "/{sessionId}",
    response_model      = APIResponse,
    summary             = "Get Copilot session by ID",
)
def get_copilot_session(sessionId: str) -> APIResponse:
    try:
        session = _COPILOT_STORE.get(sessionId)
        if session is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Copilot session '{sessionId}' not found.")
            )
        return build_success_response(
            data    = _session_to_response(session).model_dump(),
            message = "Copilot session retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create Copilot session",
)
def create_copilot_session(body: CreateCopilotSessionRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        req = build_copilot_request(
            context_id         = body.contextId,
            reasoning_id       = body.reasoningId,
            prompt_package_id  = body.promptPackageId,
            narrative_id       = body.narrativeId,
            investigation_id   = body.investigationId,
            provider           = body.provider,
            model              = body.model,
            system_prompt      = body.systemPrompt,
            user_prompt        = body.userPrompt,
            created_at         = body.createdAt,
            temperature        = body.temperature or 0.0,
            max_tokens         = body.maxTokens or 1024,
            processing_time_ms = body.processingTimeMs or 0,
            warnings           = body.warnings,
        )

        resp = build_copilot_response(
            request_id         = req.requestId,
            provider           = body.provider,
            model              = body.model,
            content            = body.responseContent,
            created_at         = body.responseCreatedAt,
            confidence         = body.confidence or 0.0,
            citations          = body.citations,
            processing_time_ms = body.processingTimeMs or 0,
            warnings           = body.warnings,
        )

        session = build_copilot_session(
            request            = req,
            response           = resp,
            created_at         = body.createdAt,
            processing_time_ms = body.processingTimeMs or 0,
            warnings           = body.warnings,
        )

        if session.sessionId in _COPILOT_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Copilot session '{session.sessionId}' already exists.")
            )

        session_dict = {
            "sessionId"  : session.sessionId,
            "sessionKey" : session.sessionKey,
            "request"    : req,
            "response"   : resp,
            "metadata"   : session.metadata,
            "createdAt"  : session.createdAt,
            "status"     : body.status or "active",
            "turns"      : body.turns or 1,
            "userId"     : body.userId or "system",
            "projectId"  : body.projectId or "default-project",
            "sessionName": body.sessionName or f"Session {session.sessionId[:8]}",
            "contextSize": body.contextSize or (req.metadata.promptTokenEstimate),
            "updatedAt"  : body.updatedAt or body.createdAt,
            "messages"   : [],
        }
        _COPILOT_STORE[session.sessionId] = session_dict

        return build_success_response(
            data    = _session_to_response(session_dict).model_dump(),
            message = "Copilot session created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.put(
    "/{sessionId}",
    response_model      = APIResponse,
    summary             = "Update Copilot session",
)
def update_copilot_session(sessionId: str, body: UpdateCopilotSessionRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("Update request must contain at least one field.")
            )

        session_dict = _COPILOT_STORE.get(sessionId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Copilot session '{sessionId}' not found.")
            )

        if body.status is not None:
            session_dict["status"] = body.status
        if body.turns is not None:
            session_dict["turns"] = body.turns
        if body.userId is not None:
            session_dict["userId"] = body.userId
        if body.projectId is not None:
            session_dict["projectId"] = body.projectId
        if body.sessionName is not None:
            session_dict["sessionName"] = body.sessionName
        if body.contextSize is not None:
            session_dict["contextSize"] = body.contextSize
        if body.updatedAt is not None:
            session_dict["updatedAt"] = body.updatedAt

        if (body.responseContent is not None or
            body.responseConfidence is not None or
            body.responseCitations is not None or
            body.warnings is not None):

            req = session_dict["request"]
            old_resp = session_dict["response"]

            new_content = body.responseContent if body.responseContent is not None else old_resp.content
            new_confidence = body.responseConfidence if body.responseConfidence is not None else old_resp.confidence
            new_citations = body.responseCitations if body.responseCitations is not None else list(old_resp.citations)
            new_warnings = body.warnings if body.warnings is not None else (session_dict.get("warnings") or [])

            new_resp = build_copilot_response(
                request_id         = req.requestId,
                provider           = req.provider,
                model              = req.model,
                content            = new_content,
                created_at         = old_resp.createdAt,
                confidence         = new_confidence,
                citations          = new_citations,
                processing_time_ms = old_resp.metadata.processingTimeMs,
                warnings           = new_warnings,
            )

            new_session = build_copilot_session(
                request            = req,
                response           = new_resp,
                created_at         = session_dict["createdAt"],
                processing_time_ms = session_dict["metadata"].processingTimeMs,
                warnings           = new_warnings,
            )

            session_dict["response"]   = new_resp
            session_dict["metadata"]   = new_session.metadata
            session_dict["sessionKey"] = new_session.sessionKey

        _COPILOT_STORE[sessionId] = session_dict

        return build_success_response(
            data    = _session_to_response(session_dict).model_dump(),
            message = "Copilot session updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.delete(
    "/{sessionId}",
    response_model      = APIResponse,
    summary             = "Delete Copilot session",
)
def delete_copilot_session(sessionId: str) -> APIResponse:
    try:
        session = _COPILOT_STORE.get(sessionId)
        if session is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Copilot session '{sessionId}' not found.")
            )
        _COPILOT_STORE.pop(sessionId)
        return build_success_response(
            data    = None,
            message = "Copilot session deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.post(
    "/chat",
    response_model      = APIResponse,
    summary             = "Copilot chat loop",
)
def copilot_chat(body: CopilotChatRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        existing_messages = []
        turns = 0
        if body.sessionId:
            session_dict = _COPILOT_STORE.get(body.sessionId)
            if session_dict is None:
                return exception_to_api_response(
                    APIErrorNotFound(f"Copilot session '{body.sessionId}' not found.")
                )
            existing_messages = session_dict.get("messages") or []
            turns = session_dict.get("turns") or 0

        # Step 1: Conversation Manager
        from services.conversation_manager_service import (
            ConversationRole,
            build_message,
            build_conversation,
        )

        n = len(existing_messages)
        user_msg = build_message(
            conversation_id = body.conversationId,
            role            = ConversationRole.USER,
            content         = body.userPrompt,
            sequence_number = n + 1,
            created_at      = body.createdAt,
        )

        resp_content = f"Mock response content for prompt: {body.userPrompt}"
        assistant_msg = build_message(
            conversation_id = body.conversationId,
            role            = ConversationRole.ASSISTANT,
            content         = resp_content,
            sequence_number = n + 2,
            created_at      = body.createdAt,
        )

        messages = existing_messages + [user_msg, assistant_msg]

        conv = build_conversation(
            created_by       = body.userId or "system",
            title            = f"Chat {body.conversationId}",
            created_at       = body.createdAt,
            investigation_id = body.investigationId or "default-investigation",
            messages         = messages,
        )

        # Step 2: Context Window
        from services.context_window_service import (
            conversation_messages_to_context_items,
            build_context_window,
            reasoning_result_to_context_item,
        )

        context_items = conversation_messages_to_context_items(
            messages   = conv.messages,
            created_at = body.createdAt,
        )

        # Step 3: Reasoning Result
        from services.reasoning_service import build_reasoning

        reasoning_res = build_reasoning(
            context_ids        = [],
            finding_ids        = [],
            alert_ids          = [],
            relationship_ids   = [],
            timeline_ids       = [],
            created_at         = body.createdAt,
            decision           = "Mock reasoning decision based on pure orchestration.",
            overall_confidence = 90.0,
        )

        reasoning_ctx = reasoning_result_to_context_item(
            result     = reasoning_res,
            created_at = body.createdAt,
        )
        context_items.append(reasoning_ctx)

        ctx_window = build_context_window(
            created_at       = body.createdAt,
            investigation_id = body.investigationId or "default-investigation",
            conversation_id  = body.conversationId,
            items            = context_items,
        )

        # Step 4: Prompt Assembly
        from services.prompt_assembly_service import build_prompt_package, build_prompt_section

        sections = []
        for item in ctx_window.items:
            sections.append(
                build_prompt_section(
                    title    = item.title,
                    content  = item.content,
                    priority = 50,
                )
            )

        prompt_pkg = build_prompt_package(
            reasoning_id     = reasoning_res.reasoningId,
            context_id       = ctx_window.windowId,
            investigation_id = body.investigationId or "default-investigation",
            system_prompt    = body.systemPrompt or "You are a helpful AI copilot assistant.",
            user_prompt      = body.userPrompt,
            created_at       = body.createdAt,
            sections         = sections,
        )

        # Step 5: Copilot Orchestrator
        req = build_copilot_request(
            context_id        = ctx_window.windowId,
            reasoning_id      = reasoning_res.reasoningId,
            prompt_package_id = prompt_pkg.packageId,
            narrative_id      = body.narrativeId or "default-narrative",
            investigation_id  = body.investigationId or "default-investigation",
            provider          = body.provider,
            model             = body.model,
            system_prompt     = prompt_pkg.systemPrompt,
            user_prompt       = prompt_pkg.userPrompt,
            created_at        = body.createdAt,
            temperature       = body.temperature or 0.0,
            max_tokens        = body.maxTokens or 1024,
        )

        resp = build_copilot_response(
            request_id = req.requestId,
            provider   = body.provider,
            model      = body.model,
            content    = resp_content,
            created_at = body.createdAt,
            confidence = 90.0,
            citations  = ["citation-1"],
        )

        session = build_copilot_session(
            request    = req,
            response   = resp,
            created_at = body.createdAt,
        )

        session_dict = {
            "sessionId"  : session.sessionId,
            "sessionKey" : session.sessionKey,
            "request"    : req,
            "response"   : resp,
            "metadata"   : session.metadata,
            "createdAt"  : session.createdAt,
            "status"     : "completed",
            "turns"      : len(messages) // 2,
            "userId"     : body.userId or "system",
            "projectId"  : body.projectId or "default-project",
            "sessionName": body.sessionName or f"Session {session.sessionId[:8]}",
            "contextSize": prompt_pkg.metadata.budget.usedTokens,
            "updatedAt"  : body.createdAt,
            "messages"   : messages,
        }
        _COPILOT_STORE[session.sessionId] = session_dict

        resp_model = _session_to_response(session_dict)
        payload = CopilotChatResponse(session=resp_model)

        return build_success_response(
            data    = payload.model_dump(),
            message = "Chat response generated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Bulk Routes
# ---------------------------------------------------------------------------

@copilot_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create Copilot sessions",
    status_code    = 201,
)
def bulk_create_sessions(
    body: BulkCreateCopilotSessionsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.sessions:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"sessionId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                req = build_copilot_request(
                    context_id         = item.contextId,
                    reasoning_id       = item.reasoningId,
                    prompt_package_id  = item.promptPackageId,
                    narrative_id       = item.narrativeId,
                    investigation_id   = item.investigationId,
                    provider           = item.provider,
                    model              = item.model,
                    system_prompt      = item.systemPrompt,
                    user_prompt        = item.userPrompt,
                    created_at         = item.createdAt,
                    temperature        = item.temperature or 0.0,
                    max_tokens         = item.maxTokens or 1024,
                    processing_time_ms = item.processingTimeMs or 0,
                    warnings           = item.warnings,
                )

                resp = build_copilot_response(
                    request_id         = req.requestId,
                    provider           = item.provider,
                    model              = item.model,
                    content            = item.responseContent,
                    created_at         = item.responseCreatedAt,
                    confidence         = item.confidence or 0.0,
                    citations          = item.citations,
                    processing_time_ms = item.processingTimeMs or 0,
                    warnings           = item.warnings,
                )

                session = build_copilot_session(
                    request            = req,
                    response           = resp,
                    created_at         = item.createdAt,
                    processing_time_ms = item.processingTimeMs or 0,
                    warnings           = item.warnings,
                )

                if session.sessionId in _COPILOT_STORE:
                    failed.append({"sessionId": session.sessionId, "reason": f"Copilot session '{session.sessionId}' already exists."})
                    continue

                session_dict = {
                    "sessionId"  : session.sessionId,
                    "sessionKey" : session.sessionKey,
                    "request"    : req,
                    "response"   : resp,
                    "metadata"   : session.metadata,
                    "createdAt"  : session.createdAt,
                    "status"     : item.status or "active",
                    "turns"      : item.turns or 1,
                    "userId"     : item.userId or "system",
                    "projectId"  : item.projectId or "default-project",
                    "sessionName": item.sessionName or f"Session {session.sessionId[:8]}",
                    "contextSize": item.contextSize or (req.metadata.promptTokenEstimate),
                    "updatedAt"  : item.updatedAt or item.createdAt,
                    "messages"   : [],
                }
                _COPILOT_STORE[session.sessionId] = session_dict
                succeeded.append(session.sessionId)
            except Exception as e:
                failed.append({"sessionId": "", "reason": str(e)})

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.sessions),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update Copilot sessions",
)
def bulk_update_sessions(
    body: BulkUpdateCopilotSessionsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for item in body.items:
            sid = item.sessionId.strip()
            if not sid:
                failed.append({"sessionId": item.sessionId, "reason": "sessionId must not be empty."})
                continue

            session_dict = _COPILOT_STORE.get(sid)
            if session_dict is None:
                failed.append({"sessionId": sid, "reason": f"Copilot session '{sid}' not found."})
                continue

            upd = item.update
            if upd.status is not None:
                session_dict["status"] = upd.status
            if upd.turns is not None:
                session_dict["turns"] = upd.turns
            if upd.userId is not None:
                session_dict["userId"] = upd.userId
            if upd.projectId is not None:
                session_dict["projectId"] = upd.projectId
            if upd.sessionName is not None:
                session_dict["sessionName"] = upd.sessionName
            if upd.contextSize is not None:
                session_dict["contextSize"] = upd.contextSize
            if upd.updatedAt is not None:
                session_dict["updatedAt"] = upd.updatedAt

            if (upd.responseContent is not None or
                upd.responseConfidence is not None or
                upd.responseCitations is not None or
                upd.warnings is not None):

                req = session_dict["request"]
                old_resp = session_dict["response"]

                new_content = upd.responseContent if upd.responseContent is not None else old_resp.content
                new_confidence = upd.responseConfidence if upd.responseConfidence is not None else old_resp.confidence
                new_citations = upd.responseCitations if upd.responseCitations is not None else list(old_resp.citations)
                new_warnings = upd.warnings if upd.warnings is not None else (session_dict.get("warnings") or [])

                new_resp = build_copilot_response(
                    request_id         = req.requestId,
                    provider           = req.provider,
                    model              = req.model,
                    content            = new_content,
                    created_at         = old_resp.createdAt,
                    confidence         = new_confidence,
                    citations          = new_citations,
                    processing_time_ms = old_resp.metadata.processingTimeMs,
                    warnings           = new_warnings,
                )

                new_session = build_copilot_session(
                    request            = req,
                    response           = new_resp,
                    created_at         = session_dict["createdAt"],
                    processing_time_ms = session_dict["metadata"].processingTimeMs,
                    warnings           = new_warnings,
                )

                session_dict["response"]   = new_resp
                session_dict["metadata"]   = new_session.metadata
                session_dict["sessionKey"] = new_session.sessionKey

            _COPILOT_STORE[sid] = session_dict
            succeeded.append(sid)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.items),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk update: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete Copilot sessions",
)
def bulk_delete_sessions(
    body: BulkDeleteCopilotSessionsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for sid in body.sessionIds:
            sid_stripped = sid.strip() if sid else ""
            if not sid_stripped:
                failed.append({"sessionId": sid, "reason": "sessionId must not be empty."})
                continue

            if sid_stripped not in _COPILOT_STORE:
                failed.append({"sessionId": sid_stripped, "reason": f"Copilot session '{sid_stripped}' not found."})
                continue

            del _COPILOT_STORE[sid_stripped]
            succeeded.append(sid_stripped)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.sessionIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk delete: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# History and Summary endpoints
# ---------------------------------------------------------------------------

@copilot_router.get(
    "/{sessionId}/history",
    response_model = APIResponse,
    summary        = "Get chat history",
)
def get_session_history(sessionId: str) -> APIResponse:
    try:
        session = _COPILOT_STORE.get(sessionId)
        if session is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Copilot session '{sessionId}' not found.")
            )
        history = get_chat_history(session)
        data = [m.model_dump() if hasattr(m, "model_dump") else m for m in history]
        return build_success_response(
            data    = data,
            message = f"Retrieved {len(history)} message(s) of history.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.delete(
    "/{sessionId}/history",
    response_model = APIResponse,
    summary        = "Clear chat history",
)
def clear_session_history(sessionId: str) -> APIResponse:
    try:
        session = _COPILOT_STORE.get(sessionId)
        if session is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Copilot session '{sessionId}' not found.")
            )
        cleared = clear_chat_history(session)
        _COPILOT_STORE[sessionId] = cleared
        return build_success_response(
            data    = None,
            message = "Chat history cleared successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@copilot_router.get(
    "/{sessionId}/summary",
    response_model = APIResponse,
    summary        = "Get chat summary",
)
def get_session_summary(sessionId: str) -> APIResponse:
    try:
        session = _COPILOT_STORE.get(sessionId)
        if session is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Copilot session '{sessionId}' not found.")
            )
        history = get_chat_history(session)
        summary = build_chat_summary(history)
        return build_success_response(
            data    = {"summary": summary},
            message = "Chat summary generated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
