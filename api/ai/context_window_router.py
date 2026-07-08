"""
AI Context Window API Router — Phase A4.8.4 (Part B)
===================================================
REST interface for Context Window.

Prefix  : /context
Tag     : Context Window
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
from api.ai.context_window_models import (
    CreateContextWindowRequest,
    UpdateContextWindowRequest,
    ContextWindowEntryRequest,
    ContextWindowEntryResponse,
    ContextWindowResponse,
    ContextWindowListResponse,
    ContextWindowStatisticsResponse,
    ContextWindowSearchResponse,
    BulkCreateContextWindowsRequest,
    BulkUpdateContextWindowsRequest,
    BulkDeleteContextWindowsRequest,
    BulkOperationResult,
    UpdateContextWindowEntryRequest,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response

from services.context_window_service import (
    ContextWindow,
    ContextItem,
    build_context_window,
    build_context_item,
    ContextSourceEnum,
    ContextPriorityEnum,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

context_window_router: APIRouter = APIRouter(
    prefix = "/context",
    tags   = ["Context Window"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_context_window
_CONTEXT_STORE = RepositoryBackedDict("contextWindow", "contextId", map_context_window)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _CONTEXT_STORE.clear()


def _all_windows() -> List[Dict[str, Any]]:
    """Return all context window states sorted deterministically by windowId ASC."""
    return sorted(_CONTEXT_STORE.values(), key=lambda s: s["window"].windowId)


def _entry_to_response(e: Any) -> ContextWindowEntryResponse:
    """Map a service ContextItem to the API ContextWindowEntryResponse model."""
    return ContextWindowEntryResponse(
        contextItemId   = e.contextItemId,
        contextItemKey  = e.contextItemKey,
        source          = e.source.value if hasattr(e.source, "value") else str(e.source),
        priority        = e.priority.value if hasattr(e.priority, "value") else str(e.priority),
        title           = e.title,
        content         = e.content,
        referenceId     = e.referenceId,
        tokenEstimate   = e.tokenEstimate,
        importanceScore = e.importanceScore,
        confidence      = e.confidence,
        metadata        = e.metadata,
        createdAt       = e.createdAt,
    )


def _window_to_response(session_dict: Dict[str, Any]) -> ContextWindowResponse:
    """Map a stored context window state dict to the API ContextWindowResponse model."""
    win = session_dict["window"]
    return ContextWindowResponse(
        windowId            = win.windowId,
        windowKey           = win.windowKey,
        investigationId     = win.investigationId,
        conversationId      = win.conversationId,
        items               = [_entry_to_response(e) for e in win.items],
        totalTokenEstimate  = win.totalTokenEstimate,
        contextFingerprint  = win.contextFingerprint,
        createdAt           = win.createdAt,
        projectId           = session_dict.get("projectId") or "default-project",
        userId              = session_dict.get("userId") or "system",
        status              = session_dict.get("status") or "ACTIVE",
        contextSize         = session_dict.get("contextSize") or 0,
        windowName          = session_dict.get("windowName") or f"Context Window {win.conversationId}",
    )


# ---------------------------------------------------------------------------
# Context Entry Helpers
# ---------------------------------------------------------------------------

def append_context_entry(
    window           : ContextWindow,
    source           : str,
    priority         : str,
    title            : str,
    content          : str,
    importance_score : float,
    confidence       : float,
    created_at       : str,
    reference_id     : str                      = "",
    metadata         : Optional[Dict[str, Any]] = None,
) -> ContextWindow:
    """Append a new context entry to a ContextWindow and rebuild it."""
    c_source = ContextSourceEnum(source.upper().strip())
    c_priority = ContextPriorityEnum(priority.upper().strip())
    entry = build_context_item(
        source           = c_source,
        priority         = c_priority,
        title            = title,
        content          = content,
        created_at       = created_at,
        reference_id     = reference_id,
        importance_score = importance_score,
        confidence       = confidence,
        metadata         = metadata,
    )
    new_items = list(window.items) + [entry]
    return build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = new_items,
    )


def update_context_entry(
    window           : ContextWindow,
    entry_id         : str,
    priority         : Optional[str]             = None,
    content          : Optional[str]             = None,
    importance_score : Optional[float]           = None,
    confidence       : Optional[float]           = None,
    metadata         : Optional[Dict[str, Any]]  = None,
) -> ContextWindow:
    """Update a specific context item content / state in the window and rebuild it."""
    new_items = []
    found = False
    for item in window.items:
        if item.contextItemId == entry_id:
            new_priority = ContextPriorityEnum(priority.upper().strip()) if priority is not None else item.priority
            new_content = content if content is not None else item.content
            new_imp = importance_score if importance_score is not None else item.importanceScore
            new_conf = confidence if confidence is not None else item.confidence
            new_meta = metadata if metadata is not None else item.metadata
            
            upd_item = build_context_item(
                source           = item.source,
                priority         = new_priority,
                title            = item.title,
                content          = new_content,
                created_at       = item.createdAt,
                reference_id     = item.referenceId,
                importance_score = new_imp,
                confidence       = new_conf,
                metadata         = new_meta,
            )
            new_items.append(upd_item)
            found = True
        else:
            new_items.append(item)
    if not found:
        raise ValueError(f"Context item '{entry_id}' not found.")
    return build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = new_items,
    )


def delete_context_entry(
    window   : ContextWindow,
    entry_id : str,
) -> ContextWindow:
    """Delete a context entry from the window and rebuild."""
    remaining = [i for i in window.items if i.contextItemId != entry_id]
    if len(remaining) == len(window.items):
        raise ValueError(f"Context item '{entry_id}' not found.")
    return build_context_window(
        created_at       = window.createdAt,
        investigation_id = window.investigationId,
        conversation_id  = window.conversationId,
        items            = remaining,
    )


def find_context_entry(window: ContextWindow, entry_id: str) -> Optional[ContextItem]:
    """Find a context entry by its ID."""
    for i in window.items:
        if i.contextItemId == entry_id:
            return i
    return None


def search_context_entries(window: ContextWindow, query: str) -> List[ContextItem]:
    """Search context entries by query string."""
    q = query.lower().strip()
    return [i for i in window.items if q in i.content.lower() or q in i.title.lower()]


def build_context_summary(entries: List[ContextItem]) -> str:
    """Generate summary covering a set of context entries."""
    if not entries:
        return "No context items to summarize."
    lines = []
    for e in entries:
        lines.append(f"[{e.source.value}] {e.title}: {e.content[:50]}")
    return "Context Summary: " + " | ".join(lines)


# ---------------------------------------------------------------------------
# Search, Sort, Filter, Paginate Helpers
# ---------------------------------------------------------------------------

def find_context_window(
    windows: List[Dict[str, Any]],
    field  : str,
    value  : str,
) -> Optional[Dict[str, Any]]:
    """Find context window dict by field exact value."""
    target = value.lower().strip()
    for w in windows:
        win = w["window"]
        v = None
        if field == "windowId": v = win.windowId
        elif field == "conversationId": v = win.conversationId
        elif field == "investigationId": v = win.investigationId
        elif field == "projectId": v = w.get("projectId")
        elif field == "userId": v = w.get("userId")
        elif field == "status": v = w.get("status")

        if v is not None and str(v).lower().strip() == target:
            return w
    return None


_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt" : "createdAt",
    "updatedAt" : "createdAt",
}


def sort_context_windows(
    windows    : List[Dict[str, Any]],
    sort_by    : str = "createdAt",
    sort_order : str = "asc",
) -> List[Dict[str, Any]]:
    """Sort context windows list."""
    reverse = sort_order.lower() == "desc"

    def sort_key(w: Dict[str, Any]):
        win = w["window"]
        if sort_by == "entryCount":
            return (0, len(win.items))
        if sort_by == "tokenCount":
            return (0, win.totalTokenEstimate)
        if sort_by == "windowName":
            name = w.get("windowName") or f"Context Window {win.conversationId}"
            return (0, name.lower())

        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(win, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())

    return sorted(windows, key=sort_key, reverse=reverse)


def filter_context_windows(
    windows         : List[Dict[str, Any]],
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
) -> List[Dict[str, Any]]:
    """Filter context windows list."""
    result = []
    for w in windows:
        win = w["window"]
        c_status = w.get("status") or "ACTIVE"
        if status is not None and c_status.lower().strip() != status.lower().strip():
            continue

        user_id = w.get("userId") or "system"
        if userId is not None and user_id.lower().strip() != userId.lower().strip():
            continue

        proj_id = w.get("projectId") or "default-project"
        if projectId is not None and proj_id.lower().strip() != projectId.lower().strip():
            continue

        if investigationId is not None and win.investigationId.lower().strip() != investigationId.lower().strip():
            continue

        entry_count = len(win.items)
        if minimumEntries is not None and entry_count < minimumEntries:
            continue
        if maximumEntries is not None and entry_count > maximumEntries:
            continue

        token_count = win.totalTokenEstimate
        if minimumTokens is not None and token_count < minimumTokens:
            continue
        if maximumTokens is not None and token_count > maximumTokens:
            continue

        if createdAfter is not None and win.createdAt <= createdAfter:
            continue
        if createdBefore is not None and win.createdAt >= createdBefore:
            continue

        result.append(w)
    return result


def paginate_context_windows(
    windows   : List[Dict[str, Any]],
    page      : int,
    page_size : int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate context windows list."""
    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(windows)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = windows[start:end]
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

@context_window_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List context windows",
)
def list_context_windows() -> APIResponse:
    try:
        windows = _all_windows()
        payload = ContextWindowListResponse(
            windows = [_window_to_response(w) for w in windows],
            total   = len(windows),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(windows)} context window(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Context window statistics",
)
def get_context_statistics() -> APIResponse:
    try:
        windows = _all_windows()
        total_contexts = len(windows)
        
        all_items = [i for w in windows for i in w["window"].items]
        total_items = len(all_items)
        
        active = sum(1 for w in windows if w.get("status") == "ACTIVE")
        archived = sum(1 for w in windows if w.get("status") == "ARCHIVED")
        
        avg_entries = round(total_items / total_contexts, 4) if total_contexts > 0 else 0.0
        
        tokens_sum = sum(w["window"].totalTokenEstimate for w in windows)
        avg_tokens = round(tokens_sum / total_contexts, 4) if total_contexts > 0 else 0.0

        ctx_sum = sum(w.get("contextSize", 0) for w in windows)
        avg_ctx = round(ctx_sum / total_contexts, 4) if total_contexts > 0 else 0.0

        status_counts = {}
        for w in windows:
            st = w.get("status") or "ACTIVE"
            status_counts[st] = status_counts.get(st, 0) + 1

        stats = ContextWindowStatisticsResponse(
            totalContexts      = total_contexts,
            activeContexts     = active,
            archivedContexts   = archived,
            averageEntries     = avg_entries,
            averageTokens      = avg_tokens,
            averageContextSize = avg_ctx,
            statusCounts       = dict(sorted(status_counts.items())),
        )
        return build_success_response(
            data    = stats.model_dump(),
            message = "Context window statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search context windows",
)
def search_context_windows_endpoint(
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
        allowed_sort = {"createdAt", "updatedAt", "windowName", "entryCount", "tokenCount"}
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
        for w in _all_windows():
            win = w["window"]
            texts = [
                win.windowId,
                win.windowKey,
                win.investigationId,
                win.conversationId,
                w.get("projectId") or "default-project",
                w.get("userId") or "system",
                w.get("status") or "ACTIVE",
                w.get("windowName") or "",
            ]
            for i in win.items:
                texts.append(i.content)
                texts.append(i.title)
                texts.append(i.contextItemId)
                texts.append(i.contextItemKey)
                texts.append(i.source.value)
                texts.append(i.priority.value)
                
            if any(q_lower in str(t).lower() for t in texts):
                matched.append(w)

        matched = filter_context_windows(
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

        sorted_sess = sort_context_windows(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_context_windows(sorted_sess, page or 1, pageSize or 20)

        payload = ContextWindowSearchResponse(
            memories   = [_window_to_response(w) for w in page_slice],
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
            message = f"{pag.totalItems} window(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.get(
    "/{contextId}",
    response_model      = APIResponse,
    summary             = "Get context window by ID",
)
def get_context_window(contextId: str) -> APIResponse:
    try:
        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )
        return build_success_response(
            data    = _window_to_response(session_dict).model_dump(),
            message = "Context window retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create context window",
)
def create_context_window(body: CreateContextWindowRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        win = build_context_window(
            created_at       = body.createdAt,
            investigation_id = body.investigationId or "",
            conversation_id  = body.conversationId or "",
            items            = [],
        )

        if win.windowId in _CONTEXT_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Context window '{win.windowId}' already exists.")
            )

        session_dict = {
            "window"      : win,
            "projectId"   : body.projectId or "default-project",
            "userId"      : body.userId or "system",
            "status"      : body.status or "ACTIVE",
            "contextSize" : body.contextSize or 0,
            "windowName"  : body.windowName or f"Context Window {body.conversationId}",
        }
        _CONTEXT_STORE[win.windowId] = session_dict

        return build_success_response(
            data    = _window_to_response(session_dict).model_dump(),
            message = "Context window created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.put(
    "/{contextId}",
    response_model      = APIResponse,
    summary             = "Update context window",
)
def update_context_window(contextId: str, body: UpdateContextWindowRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("Update request must contain at least one field.")
            )

        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )

        win = session_dict["window"]
        new_investigation = body.investigationId if body.investigationId is not None else win.investigationId
        new_conversation = body.conversationId if body.conversationId is not None else win.conversationId

        new_win = build_context_window(
            created_at       = win.createdAt,
            investigation_id = new_investigation,
            conversation_id  = new_conversation,
            items            = list(win.items),
        )

        proj_id = body.projectId if body.projectId is not None else session_dict.get("projectId") or "default-project"
        user_id = body.userId if body.userId is not None else session_dict.get("userId") or "system"
        status_val = body.status if body.status is not None else session_dict.get("status") or "ACTIVE"
        ctx_sz = body.contextSize if body.contextSize is not None else session_dict.get("contextSize") or 0
        name_val = body.windowName if body.windowName is not None else session_dict.get("windowName") or f"Context Window {win.conversationId}"

        session_dict["window"] = new_win
        session_dict["projectId"] = proj_id
        session_dict["userId"] = user_id
        session_dict["status"] = status_val
        session_dict["contextSize"] = ctx_sz
        session_dict["windowName"] = name_val

        _CONTEXT_STORE[contextId] = session_dict

        return build_success_response(
            data    = _window_to_response(session_dict).model_dump(),
            message = "Context window updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.delete(
    "/{contextId}",
    response_model      = APIResponse,
    summary             = "Delete context window",
)
def delete_context_window(contextId: str) -> APIResponse:
    try:
        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )
        _CONTEXT_STORE.pop(contextId)
        return build_success_response(
            data    = None,
            message = "Context window deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.post(
    "/{contextId}/entries",
    response_model      = APIResponse,
    summary             = "Append context entry",
)
def append_context_item_route(contextId: str, body: ContextWindowEntryRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )

        try:
            c_source = ContextSourceEnum(body.source.upper().strip())
            c_priority = ContextPriorityEnum(body.priority.upper().strip())
            entry = build_context_item(
                source           = c_source,
                priority         = c_priority,
                title            = body.title,
                content          = body.content,
                created_at       = body.createdAt,
                reference_id     = body.referenceId,
                importance_score = body.importanceScore,
                confidence       = body.confidence,
                metadata         = body.metadata,
            )
            
            new_win = append_context_entry(
                session_dict["window"], body.source, body.priority, body.title, body.content,
                body.importanceScore, body.confidence, body.createdAt, body.referenceId,
                body.metadata
            )
            session_dict["window"] = new_win
            _CONTEXT_STORE[contextId] = session_dict
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        return build_success_response(
            data    = _entry_to_response(entry).model_dump(),
            message = "Context item appended successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.get(
    "/{contextId}/entries",
    response_model      = APIResponse,
    summary             = "Get context entries",
)
def list_context_items(contextId: str) -> APIResponse:
    try:
        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )

        win = session_dict["window"]
        resp_entries = [_entry_to_response(e) for e in win.items]
        return build_success_response(
            data    = [e.model_dump() for e in resp_entries],
            message = f"{len(resp_entries)} context item(s) retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Bulk Routes
# ---------------------------------------------------------------------------

@context_window_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create context windows",
    status_code    = 201,
)
def bulk_create_context_windows(
    body: BulkCreateContextWindowsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.windows:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"windowId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                win = build_context_window(
                    created_at       = item.createdAt,
                    investigation_id = item.investigationId or "",
                    conversation_id  = item.conversationId or "",
                    items            = [],
                )

                if win.windowId in _CONTEXT_STORE:
                    failed.append({"windowId": win.windowId, "reason": f"Context window '{win.windowId}' already exists."})
                    continue

                session_dict = {
                    "window"      : win,
                    "projectId"   : item.projectId or "default-project",
                    "userId"      : item.userId or "system",
                    "status"      : item.status or "ACTIVE",
                    "contextSize" : item.contextSize or 0,
                    "windowName"  : item.windowName or f"Context Window {item.conversationId}",
                }
                _CONTEXT_STORE[win.windowId] = session_dict
                succeeded.append(win.windowId)
            except Exception as e:
                failed.append({"windowId": "", "reason": str(e)})

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.windows),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update context windows",
)
def bulk_update_context_windows(
    body: BulkUpdateContextWindowsRequest = Body(...),
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
            wid = item.windowId.strip()
            if not wid:
                failed.append({"windowId": item.windowId, "reason": "windowId must not be empty."})
                continue

            session_dict = _CONTEXT_STORE.get(wid)
            if session_dict is None:
                failed.append({"windowId": wid, "reason": f"Context window '{wid}' not found."})
                continue

            win = session_dict["window"]
            upd = item.update
            try:
                new_investigation = upd.investigationId if upd.investigationId is not None else win.investigationId
                new_conversation = upd.conversationId if upd.conversationId is not None else win.conversationId

                new_win = build_context_window(
                    created_at       = win.createdAt,
                    investigation_id = new_investigation,
                    conversation_id  = new_conversation,
                    items            = list(win.items),
                )

                proj_id = upd.projectId if upd.projectId is not None else session_dict.get("projectId") or "default-project"
                user_id = upd.userId if upd.userId is not None else session_dict.get("userId") or "system"
                status_val = upd.status if upd.status is not None else session_dict.get("status") or "ACTIVE"
                ctx_sz = upd.contextSize if upd.contextSize is not None else session_dict.get("contextSize") or 0
                name_val = upd.windowName if upd.windowName is not None else session_dict.get("windowName") or f"Context Window {win.conversationId}"

                session_dict["window"] = new_win
                session_dict["projectId"] = proj_id
                session_dict["userId"] = user_id
                session_dict["status"] = status_val
                session_dict["contextSize"] = ctx_sz
                session_dict["windowName"] = name_val

                _CONTEXT_STORE[wid] = session_dict
                succeeded.append(wid)
            except Exception as e:
                failed.append({"windowId": wid, "reason": str(e)})

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


@context_window_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete context windows",
)
def bulk_delete_context_windows(
    body: BulkDeleteContextWindowsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for wid in body.windowIds:
            wid_stripped = wid.strip() if wid else ""
            if not wid_stripped:
                failed.append({"windowId": wid, "reason": "windowId must not be empty."})
                continue

            if wid_stripped not in _CONTEXT_STORE:
                failed.append({"windowId": wid_stripped, "reason": f"Context window '{wid_stripped}' not found."})
                continue

            del _CONTEXT_STORE[wid_stripped]
            succeeded.append(wid_stripped)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.windowIds),
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
# Context Item update / delete & summary routes
# ---------------------------------------------------------------------------

@context_window_router.put(
    "/{contextId}/entries/{entryId}",
    response_model = APIResponse,
    summary        = "Update context entry content",
)
def update_context_window_entry(
    contextId : str,
    entryId   : str,
    body      : UpdateContextWindowEntryRequest,
) -> APIResponse:
    try:
        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )

        win = session_dict["window"]
        orig_entry = find_context_entry(win, entryId)
        if orig_entry is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context item '{entryId}' not found.")
            )

        target_created_at = orig_entry.createdAt

        try:
            new_win = update_context_entry(
                win, entryId,
                priority         = body.priority,
                content          = body.content,
                importance_score = body.importanceScore,
                confidence       = body.confidence,
                metadata         = body.metadata,
            )
            session_dict["window"] = new_win
            _CONTEXT_STORE[contextId] = session_dict
        except ValueError as e:
            return exception_to_api_response(APIErrorNotFound(str(e)))

        updated_entry = None
        for e in new_win.items:
            if e.createdAt == target_created_at:
                updated_entry = e
                break

        if updated_entry is None:
            return exception_to_api_response(
                APIErrorInternal("Failed to locate updated context item.")
            )

        return build_success_response(
            data    = _entry_to_response(updated_entry).model_dump(),
            message = "Context item updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.delete(
    "/{contextId}/entries/{entryId}",
    response_model = APIResponse,
    summary        = "Delete context entry",
)
def delete_context_window_entry(contextId: str, entryId: str) -> APIResponse:
    try:
        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )

        win = session_dict["window"]
        try:
            new_win = delete_context_entry(win, entryId)
            session_dict["window"] = new_win
            _CONTEXT_STORE[contextId] = session_dict
        except ValueError as e:
            return exception_to_api_response(APIErrorNotFound(str(e)))

        return build_success_response(
            data    = None,
            message = "Context item deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@context_window_router.get(
    "/{contextId}/summary",
    response_model = APIResponse,
    summary        = "Get context window summary",
)
def get_context_window_summary(contextId: str) -> APIResponse:
    try:
        session_dict = _CONTEXT_STORE.get(contextId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Context window '{contextId}' not found.")
            )

        win = session_dict["window"]
        summary = build_context_summary(list(win.items))
        return build_success_response(
            data    = {"summary": summary},
            message = "Context window summary generated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
