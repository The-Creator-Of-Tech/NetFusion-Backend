"""
AI Session Memory API Router — Phase A4.8.3 (Part B)
====================================================
REST interface for Session Memory.

Prefix  : /memory
Tag     : Session Memory
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
from api.ai.session_memory_models import (
    CreateMemoryRequest,
    UpdateMemoryRequest,
    MemoryEntryRequest,
    MemoryEntryResponse,
    MemorySummaryResponse,
    MemoryResponse,
    MemoryListResponse,
    MemoryStatisticsResponse,
    MemorySearchResponse,
    BulkCreateMemoryRequest,
    BulkUpdateMemoryRequest,
    BulkDeleteMemoryRequest,
    BulkOperationResult,
    UpdateMemoryEntryRequest,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response

from services.session_memory_service import (
    SessionMemory,
    MemoryEntry,
    build_session_memory,
    build_memory_entry,
    MemoryTypeEnum,
    MemoryStateEnum,
    _estimate_tokens,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

session_memory_router: APIRouter = APIRouter(
    prefix = "/memory",
    tags   = ["Session Memory"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
# Dict[sessionId -> Dict representing state]
_MEMORY_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _MEMORY_STORE.clear()


def _all_sessions() -> List[Dict[str, Any]]:
    """Return all session memory states sorted deterministically by sessionId ASC."""
    return sorted(_MEMORY_STORE.values(), key=lambda s: s["session"].sessionId)


def _entry_to_response(e: Any) -> MemoryEntryResponse:
    """Map a service MemoryEntry to the API MemoryEntryResponse model."""
    return MemoryEntryResponse(
        memoryId        = e.memoryId,
        memoryKey       = e.memoryKey,
        conversationId  = e.conversationId,
        investigationId = e.investigationId,
        memoryType      = e.memoryType.value if hasattr(e.memoryType, "value") else str(e.memoryType),
        state           = e.state.value if hasattr(e.state, "value") else str(e.state),
        title           = e.title,
        content         = e.content,
        importanceScore = e.importanceScore,
        confidence      = e.confidence,
        sourceId        = e.sourceId,
        tags            = list(e.tags),
        metadata        = e.metadata,
        createdAt       = e.createdAt,
    )


def _summary_to_response(s: Any) -> MemorySummaryResponse:
    """Map a service MemorySummary to the API MemorySummaryResponse model."""
    return MemorySummaryResponse(
        summaryId        = s.summaryId,
        summaryKey       = s.summaryKey,
        conversationId   = s.conversationId,
        summary          = s.summary,
        coveredMemoryIds = list(s.coveredMemoryIds),
        tokenEstimate    = s.tokenEstimate,
        createdAt        = s.createdAt,
    )


def _session_to_response(session_dict: Dict[str, Any]) -> MemoryResponse:
    """Map a stored session memory state dict to the API MemoryResponse model."""
    sess = session_dict["session"]
    return MemoryResponse(
        sessionId         = sess.sessionId,
        sessionKey        = sess.sessionKey,
        conversationId    = sess.conversationId,
        investigationId   = sess.investigationId,
        memories          = [_entry_to_response(e) for e in sess.memories],
        summaries         = [_summary_to_response(sm) for sm in sess.summaries],
        memoryFingerprint = sess.memoryFingerprint,
        createdAt         = sess.createdAt,
        updatedAt         = sess.updatedAt,
        projectId         = session_dict.get("projectId") or "default-project",
        userId            = session_dict.get("userId") or "system",
        status            = session_dict.get("status") or "ACTIVE",
        contextSize       = session_dict.get("contextSize") or 0,
        sessionName       = session_dict.get("sessionName") or f"Memory Session {sess.conversationId}",
    )


# ---------------------------------------------------------------------------
# Memory Entry Helpers
# ---------------------------------------------------------------------------

def append_memory_entry(
    session          : SessionMemory,
    memory_type      : str,
    state            : str,
    title            : str,
    content          : str,
    importance_score : float,
    confidence       : float,
    created_at       : str,
    source_id        : str                      = "",
    tags             : Optional[List[str]]      = None,
    metadata         : Optional[Dict[str, Any]] = None,
) -> SessionMemory:
    """Append a new memory entry to a SessionMemory and rebuild it."""
    m_type = MemoryTypeEnum(memory_type.upper().strip())
    m_state = MemoryStateEnum(state.upper().strip())
    entry = build_memory_entry(
        conversation_id   = session.conversationId,
        memory_type       = m_type,
        title             = title,
        content           = content,
        created_at        = created_at,
        investigation_id  = session.investigationId,
        state             = m_state,
        importance_score  = importance_score,
        confidence        = confidence,
        source_id         = source_id,
        tags              = tags,
        metadata          = metadata,
    )
    new_memories = list(session.memories) + [entry]
    return build_session_memory(
        conversation_id   = session.conversationId,
        created_at        = session.createdAt,
        updated_at        = created_at,
        investigation_id  = session.investigationId,
        memories          = new_memories,
        summaries         = list(session.summaries),
    )


def update_memory_entry(
    session          : SessionMemory,
    entry_id         : str,
    state            : Optional[str]             = None,
    content          : Optional[str]             = None,
    importance_score : Optional[float]           = None,
    confidence       : Optional[float]           = None,
    tags             : Optional[List[str]]       = None,
    metadata         : Optional[Dict[str, Any]]  = None,
) -> SessionMemory:
    """Update a specific memory entry content / state in the session and rebuild it."""
    new_memories = []
    found = False
    for e in session.memories:
        if e.memoryId == entry_id:
            new_state = MemoryStateEnum(state.upper().strip()) if state is not None else e.state
            new_content = content if content is not None else e.content
            new_imp = importance_score if importance_score is not None else e.importanceScore
            new_conf = confidence if confidence is not None else e.confidence
            new_tags = tags if tags is not None else list(e.tags)
            new_meta = metadata if metadata is not None else e.metadata
            
            upd_entry = build_memory_entry(
                conversation_id   = e.conversationId,
                memory_type       = e.memoryType,
                title             = e.title,
                content           = new_content,
                created_at        = e.createdAt,
                investigation_id  = e.investigationId,
                state             = new_state,
                importance_score  = new_imp,
                confidence        = new_conf,
                source_id         = e.sourceId,
                tags              = new_tags,
                metadata          = new_meta,
            )
            new_memories.append(upd_entry)
            found = True
        else:
            new_memories.append(e)
    if not found:
        raise ValueError(f"Memory entry '{entry_id}' not found.")
    return build_session_memory(
        conversation_id   = session.conversationId,
        created_at        = session.createdAt,
        updated_at        = session.updatedAt,
        investigation_id  = session.investigationId,
        memories          = new_memories,
        summaries         = list(session.summaries),
    )


def delete_memory_entry(
    session: SessionMemory,
    entry_id: str,
) -> SessionMemory:
    """Delete a memory entry from the session and rebuild."""
    remaining = [e for e in session.memories if e.memoryId != entry_id]
    if len(remaining) == len(session.memories):
        raise ValueError(f"Memory entry '{entry_id}' not found.")
    return build_session_memory(
        conversation_id   = session.conversationId,
        created_at        = session.createdAt,
        updated_at        = session.updatedAt,
        investigation_id  = session.investigationId,
        memories          = remaining,
        summaries         = list(session.summaries),
    )


def find_memory_entry(session: SessionMemory, entry_id: str) -> Optional[MemoryEntry]:
    """Find a memory entry by its ID."""
    for e in session.memories:
        if e.memoryId == entry_id:
            return e
    return None


def search_memory_entries(session: SessionMemory, query: str) -> List[MemoryEntry]:
    """Search memory entries by query string."""
    q = query.lower().strip()
    return [e for e in session.memories if q in e.content.lower() or q in e.title.lower()]


def build_memory_summary(entries: List[MemoryEntry]) -> str:
    """Generate summary covering a set of memory entries."""
    if not entries:
        return "No memories to summarize."
    lines = []
    for e in entries:
        lines.append(f"[{e.memoryType.value}] {e.title}: {e.content[:50]}")
    return "Memory Summary: " + " | ".join(lines)


# ---------------------------------------------------------------------------
# Search, Sort, Filter, Paginate Helpers
# ---------------------------------------------------------------------------

def find_memory(
    sessions: List[Dict[str, Any]],
    field   : str,
    value   : str,
) -> Optional[Dict[str, Any]]:
    """Find memory session dict by field exact value."""
    target = value.lower().strip()
    for s in sessions:
        sess = s["session"]
        v = None
        if field == "sessionId": v = sess.sessionId
        elif field == "conversationId": v = sess.conversationId
        elif field == "investigationId": v = sess.investigationId
        elif field == "projectId": v = s.get("projectId")
        elif field == "userId": v = s.get("userId")
        elif field == "status": v = s.get("status")

        if v is not None and str(v).lower().strip() == target:
            return s
    return None


_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt" : "createdAt",
    "updatedAt" : "updatedAt",
}


def sort_memory(
    sessions  : List[Dict[str, Any]],
    sort_by   : str = "createdAt",
    sort_order: str = "asc",
) -> List[Dict[str, Any]]:
    """Sort memory sessions list."""
    reverse = sort_order.lower() == "desc"

    def sort_key(s: Dict[str, Any]):
        sess = s["session"]
        if sort_by == "entryCount":
            return (0, len(sess.memories))
        if sort_by == "tokenCount":
            tokens = sum(_estimate_tokens(e.content) for e in sess.memories) + sum(sm.tokenEstimate for sm in sess.summaries)
            return (0, tokens)
        if sort_by == "sessionName":
            name = s.get("sessionName") or f"Memory Session {sess.conversationId}"
            return (0, name.lower())

        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(sess, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())

    return sorted(sessions, key=sort_key, reverse=reverse)


def filter_memory(
    sessions       : List[Dict[str, Any]],
    status         : Optional[str] = None,
    userId         : Optional[str] = None,
    projectId      : Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumEntries : Optional[int] = None,
    maximumEntries : Optional[int] = None,
    minimumTokens  : Optional[int] = None,
    maximumTokens  : Optional[int] = None,
    createdAfter   : Optional[str] = None,
    createdBefore  : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter memory sessions list."""
    result = []
    for s in sessions:
        sess = s["session"]
        c_status = s.get("status") or "ACTIVE"
        if status is not None and c_status.lower().strip() != status.lower().strip():
            continue

        user_id = s.get("userId") or "system"
        if userId is not None and user_id.lower().strip() != userId.lower().strip():
            continue

        proj_id = s.get("projectId") or "default-project"
        if projectId is not None and proj_id.lower().strip() != projectId.lower().strip():
            continue

        if investigationId is not None and sess.investigationId.lower().strip() != investigationId.lower().strip():
            continue

        entry_count = len(sess.memories)
        if minimumEntries is not None and entry_count < minimumEntries:
            continue
        if maximumEntries is not None and entry_count > maximumEntries:
            continue

        token_count = sum(_estimate_tokens(e.content) for e in sess.memories) + sum(sm.tokenEstimate for sm in sess.summaries)
        if minimumTokens is not None and token_count < minimumTokens:
            continue
        if maximumTokens is not None and token_count > maximumTokens:
            continue

        if createdAfter is not None and sess.createdAt <= createdAfter:
            continue
        if createdBefore is not None and sess.createdAt >= createdBefore:
            continue

        result.append(s)
    return result


def paginate_memory(
    sessions : List[Dict[str, Any]],
    page     : int,
    page_size: int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate memory sessions list."""
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
# Endpoints
# ---------------------------------------------------------------------------

@session_memory_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List memory sessions",
)
def list_memory_sessions() -> APIResponse:
    try:
        sessions = _all_sessions()
        payload = MemoryListResponse(
            memories = [_session_to_response(s) for s in sessions],
            total    = len(sessions),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(sessions)} session memory record(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Session memory statistics",
)
def get_memory_statistics() -> APIResponse:
    try:
        sessions = _all_sessions()
        total_sessions = len(sessions)
        
        all_entries = [e for s in sessions for e in s["session"].memories]
        total_memories = len(all_entries)
        
        active = sum(1 for e in all_entries if e.state == MemoryStateEnum.ACTIVE)
        archived = sum(1 for e in all_entries if e.state == MemoryStateEnum.ARCHIVED)
        
        avg_entries = round(total_memories / total_sessions, 4) if total_sessions > 0 else 0.0
        
        tokens_sum = sum(
            sum(_estimate_tokens(e.content) for e in s["session"].memories) +
            sum(sm.tokenEstimate for sm in s["session"].summaries)
            for s in sessions
        )
        avg_tokens = round(tokens_sum / total_sessions, 4) if total_sessions > 0 else 0.0

        ctx_sum = sum(s.get("contextSize", 0) for s in sessions)
        avg_ctx = round(ctx_sum / total_sessions, 4) if total_sessions > 0 else 0.0

        status_counts = {}
        for s in sessions:
            st = s.get("status") or "ACTIVE"
            status_counts[st] = status_counts.get(st, 0) + 1

        stats = MemoryStatisticsResponse(
            totalMemories      = total_memories,
            activeMemories     = active,
            archivedMemories   = archived,
            averageEntries     = avg_entries,
            averageTokens      = avg_tokens,
            averageContextSize = avg_ctx,
            statusCounts       = dict(sorted(status_counts.items())),
        )
        return build_success_response(
            data    = stats.model_dump(),
            message = "Memory statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search memory sessions",
)
def search_memory_sessions_endpoint(
    q               : str = Query(..., min_length=1, description="Search string."),
    sortBy          : Optional[str] = "createdAt",
    sortOrder       : Optional[str] = "asc",
    page            : Optional[int] = 1,
    pageSize        : Optional[int] = 20,
    status          : Optional[str] = None,
    userId          : Optional[str] = None,
    projectId       : Optional[str] = None,
    investigationId : Optional[str] = None,
    minimumEntries  : Optional[int] = None,
    maximumEntries  : Optional[int] = None,
    minimumTokens   : Optional[int] = None,
    maximumTokens   : Optional[int] = None,
    createdAfter    : Optional[str] = None,
    createdBefore   : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"createdAt", "updatedAt", "sessionName", "entryCount", "tokenCount"}
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
            sess = s["session"]
            texts = [
                sess.sessionId,
                sess.sessionKey,
                sess.conversationId,
                sess.investigationId,
                s.get("projectId") or "default-project",
                s.get("userId") or "system",
                s.get("status") or "ACTIVE",
                s.get("sessionName") or "",
            ]
            for e in sess.memories:
                texts.append(e.content)
                texts.append(e.title)
                texts.append(e.memoryId)
                texts.append(e.memoryKey)
                texts.append(e.memoryType.value)
                texts.append(e.state.value)
                for tag in e.tags:
                    texts.append(tag)
            for sm in sess.summaries:
                texts.append(sm.summary)
                texts.append(sm.summaryId)
                
            if any(q_lower in str(t).lower() for t in texts):
                matched.append(s)

        matched = filter_memory(
            matched,
            status=status,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumEntries=minimumEntries,
            maximumEntries=maximumEntries,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_sess = sort_memory(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_memory(sorted_sess, page or 1, pageSize or 20)

        payload = MemorySearchResponse(
            memories   = [_session_to_response(s) for s in page_slice],
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


@session_memory_router.get(
    "/{memoryId}",
    response_model      = APIResponse,
    summary             = "Get memory session by ID",
)
def get_memory_session(memoryId: str) -> APIResponse:
    try:
        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )
        return build_success_response(
            data    = _session_to_response(session_dict).model_dump(),
            message = "Session memory retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create memory session",
)
def create_memory_session(body: CreateMemoryRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        sess = build_session_memory(
            conversation_id   = body.conversationId,
            created_at        = body.createdAt,
            updated_at        = body.createdAt,
            investigation_id  = body.investigationId or "",
            memories          = [],
            summaries         = [],
        )

        if sess.sessionId in _MEMORY_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Session memory '{sess.sessionId}' already exists.")
            )

        session_dict = {
            "session"     : sess,
            "projectId"   : body.projectId or "default-project",
            "userId"      : body.userId or "system",
            "status"      : body.status or "ACTIVE",
            "contextSize" : body.contextSize or 0,
            "sessionName" : body.sessionName or f"Memory Session {body.conversationId}",
        }
        _MEMORY_STORE[sess.sessionId] = session_dict

        return build_success_response(
            data    = _session_to_response(session_dict).model_dump(),
            message = "Session memory created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.put(
    "/{memoryId}",
    response_model      = APIResponse,
    summary             = "Update memory session",
)
def update_memory_session(memoryId: str, body: UpdateMemoryRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("Update request must contain at least one field.")
            )

        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )

        sess = session_dict["session"]
        new_investigation = body.investigationId if body.investigationId is not None else sess.investigationId
        new_updated_at = body.updatedAt if body.updatedAt is not None else sess.updatedAt

        new_sess = build_session_memory(
            conversation_id   = sess.conversationId,
            created_at        = sess.createdAt,
            updated_at        = new_updated_at,
            investigation_id  = new_investigation,
            memories          = list(sess.memories),
            summaries         = list(sess.summaries),
        )

        proj_id = body.projectId if body.projectId is not None else session_dict.get("projectId") or "default-project"
        user_id = body.userId if body.userId is not None else session_dict.get("userId") or "system"
        status_val = body.status if body.status is not None else session_dict.get("status") or "ACTIVE"
        ctx_sz = body.contextSize if body.contextSize is not None else session_dict.get("contextSize") or 0
        name_val = body.sessionName if body.sessionName is not None else session_dict.get("sessionName") or f"Memory Session {sess.conversationId}"

        session_dict["session"] = new_sess
        session_dict["projectId"] = proj_id
        session_dict["userId"] = user_id
        session_dict["status"] = status_val
        session_dict["contextSize"] = ctx_sz
        session_dict["sessionName"] = name_val

        _MEMORY_STORE[memoryId] = session_dict

        return build_success_response(
            data    = _session_to_response(session_dict).model_dump(),
            message = "Session memory updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.delete(
    "/{memoryId}",
    response_model      = APIResponse,
    summary             = "Delete memory session",
)
def delete_memory_session(memoryId: str) -> APIResponse:
    try:
        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )
        _MEMORY_STORE.pop(memoryId)
        return build_success_response(
            data    = None,
            message = "Session memory deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.post(
    "/{memoryId}/entries",
    response_model      = APIResponse,
    summary             = "Append memory entry",
)
def append_memory_entry_route(memoryId: str, body: MemoryEntryRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )

        try:
            new_sess = append_memory_entry(
                session_dict["session"], body.memoryType, body.state, body.title, body.content,
                body.importanceScore, body.confidence, body.createdAt, body.sourceId or "",
                body.tags, body.metadata
            )
            session_dict["session"] = new_sess
            _MEMORY_STORE[memoryId] = session_dict
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        entry = new_sess.memories[-1]
        return build_success_response(
            data    = _entry_to_response(entry).model_dump(),
            message = "Memory entry appended successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.get(
    "/{memoryId}/entries",
    response_model      = APIResponse,
    summary             = "Get memory entries",
)
def list_memory_entries(memoryId: str) -> APIResponse:
    try:
        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )

        sess = session_dict["session"]
        resp_entries = [_entry_to_response(e) for e in sess.memories]
        return build_success_response(
            data    = [e.model_dump() for e in resp_entries],
            message = f"{len(resp_entries)} memory entry/entries retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Bulk Routes
# ---------------------------------------------------------------------------

@session_memory_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create memory sessions",
    status_code    = 201,
)
def bulk_create_memory(
    body: BulkCreateMemoryRequest = Body(...),
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
                failed.append({"memoryId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                sess = build_session_memory(
                    conversation_id   = item.conversationId,
                    created_at        = item.createdAt,
                    updated_at        = item.createdAt,
                    investigation_id  = item.investigationId or "",
                    memories          = [],
                    summaries         = [],
                )

                if sess.sessionId in _MEMORY_STORE:
                    failed.append({"memoryId": sess.sessionId, "reason": f"Session memory '{sess.sessionId}' already exists."})
                    continue

                session_dict = {
                    "session"     : sess,
                    "projectId"   : item.projectId or "default-project",
                    "userId"      : item.userId or "system",
                    "status"      : item.status or "ACTIVE",
                    "contextSize" : item.contextSize or 0,
                    "sessionName" : item.sessionName or f"Memory Session {item.conversationId}",
                }
                _MEMORY_STORE[sess.sessionId] = session_dict
                succeeded.append(sess.sessionId)
            except Exception as e:
                failed.append({"memoryId": "", "reason": str(e)})

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


@session_memory_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update memory sessions",
)
def bulk_update_memory(
    body: BulkUpdateMemoryRequest = Body(...),
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
            mid = item.memoryId.strip()
            if not mid:
                failed.append({"memoryId": item.memoryId, "reason": "memoryId must not be empty."})
                continue

            session_dict = _MEMORY_STORE.get(mid)
            if session_dict is None:
                failed.append({"memoryId": mid, "reason": f"Session memory '{mid}' not found."})
                continue

            sess = session_dict["session"]
            upd = item.update
            try:
                new_investigation = upd.investigationId if upd.investigationId is not None else sess.investigationId
                new_updated_at = upd.updatedAt if upd.updatedAt is not None else sess.updatedAt

                new_sess = build_session_memory(
                    conversation_id   = sess.conversationId,
                    created_at        = sess.createdAt,
                    updated_at        = new_updated_at,
                    investigation_id  = new_investigation,
                    memories          = list(sess.memories),
                    summaries         = list(sess.summaries),
                )

                proj_id = upd.projectId if upd.projectId is not None else session_dict.get("projectId") or "default-project"
                user_id = upd.userId if upd.userId is not None else session_dict.get("userId") or "system"
                status_val = upd.status if upd.status is not None else session_dict.get("status") or "ACTIVE"
                ctx_sz = upd.contextSize if upd.contextSize is not None else session_dict.get("contextSize") or 0
                name_val = upd.sessionName if upd.sessionName is not None else session_dict.get("sessionName") or f"Memory Session {sess.conversationId}"

                session_dict["session"] = new_sess
                session_dict["projectId"] = proj_id
                session_dict["userId"] = user_id
                session_dict["status"] = status_val
                session_dict["contextSize"] = ctx_sz
                session_dict["sessionName"] = name_val

                _MEMORY_STORE[mid] = session_dict
                succeeded.append(mid)
            except Exception as e:
                failed.append({"memoryId": mid, "reason": str(e)})

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


@session_memory_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete memory sessions",
)
def bulk_delete_memory(
    body: BulkDeleteMemoryRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for mid in body.memoryIds:
            mid_stripped = mid.strip() if mid else ""
            if not mid_stripped:
                failed.append({"memoryId": mid, "reason": "memoryId must not be empty."})
                continue

            if mid_stripped not in _MEMORY_STORE:
                failed.append({"memoryId": mid_stripped, "reason": f"Session memory '{mid_stripped}' not found."})
                continue

            del _MEMORY_STORE[mid_stripped]
            succeeded.append(mid_stripped)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.memoryIds),
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
# Memory Entry update / delete & summary routes
# ---------------------------------------------------------------------------

@session_memory_router.put(
    "/{memoryId}/entries/{entryId}",
    response_model = APIResponse,
    summary        = "Update memory entry content",
)
def update_session_memory_entry(
    memoryId : str,
    entryId  : str,
    body     : UpdateMemoryEntryRequest,
) -> APIResponse:
    try:
        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )

        sess = session_dict["session"]
        orig_entry = find_memory_entry(sess, entryId)
        if orig_entry is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Memory entry '{entryId}' not found.")
            )

        target_created_at = orig_entry.createdAt

        try:
            new_sess = update_memory_entry(
                sess, entryId,
                state            = body.state,
                content          = body.content,
                importance_score = body.importanceScore,
                confidence       = body.confidence,
                tags             = body.tags,
                metadata         = body.metadata,
            )
            session_dict["session"] = new_sess
            _MEMORY_STORE[memoryId] = session_dict
        except ValueError as e:
            return exception_to_api_response(APIErrorNotFound(str(e)))

        updated_entry = None
        for e in new_sess.memories:
            if e.createdAt == target_created_at:
                updated_entry = e
                break

        if updated_entry is None:
            return exception_to_api_response(
                APIErrorInternal("Failed to locate updated memory entry.")
            )

        return build_success_response(
            data    = _entry_to_response(updated_entry).model_dump(),
            message = "Memory entry updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.delete(
    "/{memoryId}/entries/{entryId}",
    response_model = APIResponse,
    summary        = "Delete memory entry",
)
def delete_session_memory_entry(memoryId: str, entryId: str) -> APIResponse:
    try:
        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )

        sess = session_dict["session"]
        try:
            new_sess = delete_memory_entry(sess, entryId)
            session_dict["session"] = new_sess
            _MEMORY_STORE[memoryId] = session_dict
        except ValueError as e:
            return exception_to_api_response(APIErrorNotFound(str(e)))

        return build_success_response(
            data    = None,
            message = "Memory entry deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@session_memory_router.get(
    "/{memoryId}/summary",
    response_model = APIResponse,
    summary        = "Get memory session summary",
)
def get_memory_session_summary(memoryId: str) -> APIResponse:
    try:
        session_dict = _MEMORY_STORE.get(memoryId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Session memory '{memoryId}' not found.")
            )

        sess = session_dict["session"]
        summary = build_memory_summary(list(sess.memories))
        return build_success_response(
            data    = {"summary": summary},
            message = "Session memory summary generated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
