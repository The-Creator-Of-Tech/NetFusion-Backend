"""
AI Conversation API Router — Phase A4.8.2 (Part B)
===================================================
REST interface for Conversation Management.

Prefix  : /conversations
Tag     : Conversation
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
from api.ai.conversation_models import (
    CreateConversationRequest,
    UpdateConversationRequest,
    ConversationMessageRequest,
    ConversationMessageResponse,
    ConversationMetadataResponse,
    ConversationThreadResponse,
    ConversationResponse,
    ConversationListResponse,
    ConversationStatisticsResponse,
    ConversationSearchResponse,
    BulkCreateConversationsRequest,
    BulkUpdateConversationsRequest,
    BulkDeleteConversationsRequest,
    BulkOperationResult,
    UpdateMessageRequest,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response

from services.conversation_manager_service import (
    Conversation,
    ConversationMessage,
    build_conversation,
    build_message,
    build_statistics,
    ConversationState,
    ConversationRole,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

conversation_router: APIRouter = APIRouter(
    prefix = "/conversations",
    tags   = ["Conversation"],
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
# Dict[conversationId -> Dict representing session state]
_CONVERSATION_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _CONVERSATION_STORE.clear()


def _all_conversations() -> List[Dict[str, Any]]:
    """Return all conversation states sorted deterministically by conversationId ASC."""
    return sorted(_CONVERSATION_STORE.values(), key=lambda s: s["conversation"].conversationId)


def _conversation_to_response(session_dict: Dict[str, Any]) -> ConversationResponse:
    """Map a stored conversation state dict to the API ConversationResponse model."""
    conv = session_dict["conversation"]
    messages = [
        ConversationMessageResponse(
            messageId       = m.messageId,
            messageKey      = m.messageKey,
            conversationId  = m.conversationId,
            parentMessageId = m.parentMessageId,
            role            = m.role.value if hasattr(m.role, "value") else str(m.role),
            content         = m.content,
            sequenceNumber  = m.sequenceNumber,
            tokenEstimate   = m.tokenEstimate,
            metadata        = m.metadata,
            createdAt       = m.createdAt,
        )
        for m in conv.messages
    ]
    threads = [
        ConversationThreadResponse(
            threadId      = t.threadId,
            threadKey     = t.threadKey,
            rootMessageId = t.rootMessageId,
            messageIds    = list(t.messageIds),
            depth         = t.depth,
            createdAt     = t.createdAt,
        )
        for t in conv.threads
    ]
    metadata = ConversationMetadataResponse(
        title         = conv.metadata.title,
        summary       = conv.metadata.summary,
        totalMessages = conv.metadata.totalMessages,
        totalTokens   = conv.metadata.totalTokens,
        lastMessageAt = conv.metadata.lastMessageAt,
        createdBy     = conv.metadata.createdBy,
        tags          = list(conv.metadata.tags),
        engineVersion = conv.metadata.engineVersion,
    )
    return ConversationResponse(
        conversationId          = conv.conversationId,
        conversationKey         = conv.conversationKey,
        investigationId         = conv.investigationId,
        state                   = conv.state.value if hasattr(conv.state, "value") else str(conv.state),
        messages                = messages,
        threads                 = threads,
        metadata                = metadata,
        conversationFingerprint = conv.conversationFingerprint,
        createdAt               = conv.createdAt,
        updatedAt               = conv.updatedAt,
        projectId               = session_dict.get("projectId") or "default-project",
        userId                  = session_dict.get("userId") or conv.metadata.createdBy,
        contextSize             = session_dict.get("contextSize") or 0,
    )


# ---------------------------------------------------------------------------
# Message Helpers
# ---------------------------------------------------------------------------

def append_message(
    conversation     : Conversation,
    role             : str,
    content          : str,
    seq              : int,
    created_at       : str,
    parent_message_id: str = "",
    metadata         : Optional[Dict[str, Any]] = None,
) -> Conversation:
    """Append a new message to a Conversation and rebuild it."""
    role_enum = ConversationRole(role.upper().strip())
    msg = build_message(
        conversation_id   = conversation.conversationId,
        role              = role_enum,
        content           = content,
        sequence_number   = seq,
        created_at        = created_at,
        parent_message_id = parent_message_id,
        metadata          = metadata,
    )
    new_messages = list(conversation.messages) + [msg]
    new_conv = build_conversation(
        created_by       = conversation.metadata.createdBy,
        title            = conversation.metadata.title,
        created_at       = conversation.createdAt,
        investigation_id = conversation.investigationId,
        state            = conversation.state,
        messages         = new_messages,
        threads          = list(conversation.threads),
        summary          = conversation.metadata.summary,
        tags             = list(conversation.metadata.tags),
    )
    return new_conv


def update_message(
    conversation: Conversation,
    message_id  : str,
    content     : str,
) -> Conversation:
    """Update a specific message content in the conversation and rebuild it."""
    new_messages = []
    found = False
    for m in conversation.messages:
        if m.messageId == message_id:
            msg = build_message(
                conversation_id   = m.conversationId,
                role              = m.role,
                content           = content,
                sequence_number   = m.sequenceNumber,
                created_at        = m.createdAt,
                parent_message_id = m.parentMessageId,
                metadata          = m.metadata,
            )
            new_messages.append(msg)
            found = True
        else:
            new_messages.append(m)
    if not found:
        raise ValueError(f"Message '{message_id}' not found.")
    new_conv = build_conversation(
        created_by       = conversation.metadata.createdBy,
        title            = conversation.metadata.title,
        created_at       = conversation.createdAt,
        investigation_id = conversation.investigationId,
        state            = conversation.state,
        messages         = new_messages,
        threads          = list(conversation.threads),
        summary          = conversation.metadata.summary,
        tags             = list(conversation.metadata.tags),
    )
    return new_conv


def delete_message(
    conversation: Conversation,
    message_id  : str,
) -> Conversation:
    """Delete a specific message, re-sequence the remainder, and rebuild."""
    remaining = [m for m in conversation.messages if m.messageId != message_id]
    if len(remaining) == len(conversation.messages):
        raise ValueError(f"Message '{message_id}' not found.")

    new_messages = []
    for idx, m in enumerate(remaining):
        msg = build_message(
            conversation_id   = m.conversationId,
            role              = m.role,
            content           = m.content,
            sequence_number   = idx + 1,
            created_at        = m.createdAt,
            parent_message_id = m.parentMessageId,
            metadata          = m.metadata,
        )
        new_messages.append(msg)

    new_conv = build_conversation(
        created_by       = conversation.metadata.createdBy,
        title            = conversation.metadata.title,
        created_at       = conversation.createdAt,
        investigation_id = conversation.investigationId,
        state            = conversation.state,
        messages         = new_messages,
        threads          = list(conversation.threads),
        summary          = conversation.metadata.summary,
        tags             = list(conversation.metadata.tags),
    )
    return new_conv


def find_message(conversation: Conversation, message_id: str) -> Optional[ConversationMessage]:
    """Find a message by its ID."""
    for m in conversation.messages:
        if m.messageId == message_id:
            return m
    return None


def search_messages(conversation: Conversation, query: str) -> List[ConversationMessage]:
    """Search messages containing query string (case-insensitive)."""
    q = query.lower().strip()
    return [m for m in conversation.messages if q in m.content.lower()]


def build_conversation_summary(messages: List[ConversationMessage]) -> str:
    """Generate a summary string deterministically."""
    if not messages:
        return "No messages to summarize."
    lines = []
    for m in messages:
        lines.append(f"{m.role.value}: {m.content[:50]}")
    return "Conversation Summary: " + " | ".join(lines)


# ---------------------------------------------------------------------------
# Search, Sort, Filter, Paginate Helpers
# ---------------------------------------------------------------------------

def find_conversation(
    sessions: List[Dict[str, Any]],
    field   : str,
    value   : str,
) -> Optional[Dict[str, Any]]:
    """Find conversation by field exact value."""
    target = value.lower().strip()
    for s in sessions:
        conv = s["conversation"]
        v = None
        if field == "conversationId": v = conv.conversationId
        elif field == "title": v = conv.metadata.title
        elif field == "createdBy": v = conv.metadata.createdBy
        elif field == "state": v = conv.state.value if hasattr(conv.state, "value") else str(conv.state)
        elif field == "investigationId": v = conv.investigationId
        elif field == "projectId": v = s.get("projectId")
        elif field == "userId": v = s.get("userId")

        if v is not None and str(v).lower().strip() == target:
            return s
    return None


_SORT_KEY_MAP: Dict[str, str] = {
    "createdAt" : "createdAt",
    "updatedAt" : "updatedAt",
}


def sort_conversations(
    sessions  : List[Dict[str, Any]],
    sort_by   : str = "createdAt",
    sort_order: str = "asc",
) -> List[Dict[str, Any]]:
    """Sort conversations list by field."""
    reverse = sort_order.lower() == "desc"

    def sort_key(s: Dict[str, Any]):
        conv = s["conversation"]
        if sort_by == "messageCount":
            return (0, len(conv.messages))
        if sort_by == "tokenCount":
            return (0, conv.metadata.totalTokens)
        if sort_by == "title":
            return (0, conv.metadata.title.lower())
        if sort_by == "status":
            st = conv.state.value if hasattr(conv.state, "value") else str(conv.state)
            return (0, st.lower())

        field = _SORT_KEY_MAP.get(sort_by, "createdAt")
        v = getattr(conv, field, None)
        if v is None:
            return (1, "") if not reverse else (0, "")
        return (0, str(v).lower())

    return sorted(sessions, key=sort_key, reverse=reverse)


def filter_conversations(
    sessions       : List[Dict[str, Any]],
    status         : Optional[str] = None,
    userId         : Optional[str] = None,
    projectId      : Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumMessages: Optional[int] = None,
    maximumMessages: Optional[int] = None,
    minimumTokens  : Optional[int] = None,
    maximumTokens  : Optional[int] = None,
    createdAfter   : Optional[str] = None,
    createdBefore  : Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter conversations list by criteria."""
    result = []
    for s in sessions:
        conv = s["conversation"]
        c_state = conv.state.value if hasattr(conv.state, "value") else str(conv.state)
        if status is not None and c_state.lower().strip() != status.lower().strip():
            continue

        created_by = conv.metadata.createdBy
        user_val = s.get("userId") or created_by
        if userId is not None and user_val.lower().strip() != userId.lower().strip():
            continue

        proj_val = s.get("projectId") or "default-project"
        if projectId is not None and proj_val.lower().strip() != projectId.lower().strip():
            continue

        if investigationId is not None and conv.investigationId.lower().strip() != investigationId.lower().strip():
            continue

        msg_count = len(conv.messages)
        if minimumMessages is not None and msg_count < minimumMessages:
            continue
        if maximumMessages is not None and msg_count > maximumMessages:
            continue

        token_count = conv.metadata.totalTokens
        if minimumTokens is not None and token_count < minimumTokens:
            continue
        if maximumTokens is not None and token_count > maximumTokens:
            continue

        if createdAfter is not None and conv.createdAt <= createdAfter:
            continue
        if createdBefore is not None and conv.createdAt >= createdBefore:
            continue

        result.append(s)
    return result


def paginate_conversations(
    sessions : List[Dict[str, Any]],
    page     : int,
    page_size: int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """Paginate conversations list."""
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

@conversation_router.get(
    "",
    response_model      = APIResponse,
    summary             = "List conversations",
)
def list_conversations() -> APIResponse:
    try:
        conversations = _all_conversations()
        payload = ConversationListResponse(
            conversations = [_conversation_to_response(c) for c in conversations],
            total         = len(conversations),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(conversations)} conversation(s) found.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.get(
    "/statistics",
    response_model      = APIResponse,
    summary             = "Conversation statistics",
)
def get_conversation_statistics() -> APIResponse:
    try:
        sessions = list(_CONVERSATION_STORE.values())
        conversations = [s["conversation"] for s in sessions]
        stats = build_statistics(conversations)

        ctx_sum = sum(s.get("contextSize", 0) for s in sessions)
        average_ctx = round(ctx_sum / stats.totalConversations, 4) if stats.totalConversations > 0 else 0.0

        status_counts = {}
        for c in conversations:
            c_state = c.state.value if hasattr(c.state, "value") else str(c.state)
            status_counts[c_state] = status_counts.get(c_state, 0) + 1

        payload = ConversationStatisticsResponse(
            totalConversations    = stats.totalConversations,
            activeConversations   = stats.activeConversations,
            archivedConversations = stats.archivedConversations,
            averageMessages       = stats.averageMessages,
            averageTokens         = stats.averageTokens,
            averageContextSize    = average_ctx,
            statusCounts          = dict(sorted(status_counts.items())),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = "Conversation statistics retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.get(
    "/search",
    response_model      = APIResponse,
    summary             = "Search conversations",
)
def search_conversations_endpoint(
    q              : str = Query(..., min_length=1, description="Search string."),
    sortBy         : Optional[str] = "createdAt",
    sortOrder      : Optional[str] = "asc",
    page           : Optional[int] = 1,
    pageSize       : Optional[int] = 20,
    status         : Optional[str] = None,
    userId         : Optional[str] = None,
    projectId      : Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumMessages: Optional[int] = None,
    maximumMessages: Optional[int] = None,
    minimumTokens  : Optional[int] = None,
    maximumTokens  : Optional[int] = None,
    createdAfter   : Optional[str] = None,
    createdBefore  : Optional[str] = None,
) -> APIResponse:
    try:
        allowed_sort = {"createdAt", "updatedAt", "title", "status", "messageCount", "tokenCount"}
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
        for s in _all_conversations():
            c = s["conversation"]
            c_state = c.state.value if hasattr(c.state, "value") else str(c.state)
            texts = [
                c.conversationId,
                c.conversationKey,
                c.investigationId,
                c_state,
                c.metadata.title,
                c.metadata.summary,
                c.metadata.createdBy,
                s.get("projectId") or "default-project",
            ]
            for m in c.messages:
                texts.append(m.content)
                texts.append(m.messageId)
                texts.append(m.role.value if hasattr(m.role, "value") else str(m.role))
            for tag in c.metadata.tags:
                texts.append(tag)

            if any(q_lower in str(t).lower() for t in texts):
                matched.append(s)

        matched = filter_conversations(
            matched,
            status=status,
            userId=userId,
            projectId=projectId,
            investigationId=investigationId,
            minimumMessages=minimumMessages,
            maximumMessages=maximumMessages,
            minimumTokens=minimumTokens,
            maximumTokens=maximumTokens,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_conv = sort_conversations(
            matched,
            sort_by=sortBy,
            sort_order=sortOrder,
        )

        page_slice, pag = paginate_conversations(sorted_conv, page or 1, pageSize or 20)

        payload = ConversationSearchResponse(
            conversations = [_conversation_to_response(c) for c in page_slice],
            total         = pag.totalItems,
            page          = pag.page,
            pageSize      = pag.pageSize,
            totalPages    = pag.totalPages,
            query         = q,
            sortBy         = sortBy or "createdAt",
            sortOrder     = sortOrder or "asc",
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{pag.totalItems} conversation(s) matched '{q}'.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.get(
    "/{conversationId}",
    response_model      = APIResponse,
    summary             = "Get conversation by ID",
)
def get_conversation(conversationId: str) -> APIResponse:
    try:
        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )
        return build_success_response(
            data    = _conversation_to_response(session_dict).model_dump(),
            message = "Conversation retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.post(
    "",
    response_model      = APIResponse,
    summary             = "Create conversation",
)
def create_conversation(body: CreateConversationRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        state_enum = ConversationState.ACTIVE
        if body.state:
            try:
                state_enum = ConversationState(body.state.upper().strip())
            except Exception:
                return exception_to_api_response(
                    APIErrorValidation(f"Invalid conversation state: '{body.state}'.")
                )

        conv = build_conversation(
            created_by       = body.createdBy,
            title            = body.title,
            created_at       = body.createdAt,
            investigation_id = body.investigationId or "",
            state            = state_enum,
            messages         = [],
            threads          = [],
            summary          = body.summary or "",
            tags             = body.tags,
        )

        if conv.conversationId in _CONVERSATION_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Conversation '{conv.conversationId}' already exists.")
            )

        session_dict = {
            "conversation": conv,
            "projectId"   : body.projectId or "default-project",
            "userId"      : body.userId or body.createdBy,
            "contextSize" : body.contextSize or 0,
        }
        _CONVERSATION_STORE[conv.conversationId] = session_dict

        return build_success_response(
            data    = _conversation_to_response(session_dict).model_dump(),
            message = "Conversation created successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.put(
    "/{conversationId}",
    response_model      = APIResponse,
    summary             = "Update conversation",
)
def update_conversation(conversationId: str, body: UpdateConversationRequest) -> APIResponse:
    try:
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation("Update request must contain at least one field.")
            )

        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )

        conv = session_dict["conversation"]
        new_title = body.title if body.title is not None else conv.metadata.title
        new_summary = body.summary if body.summary is not None else conv.metadata.summary
        new_tags = body.tags if body.tags is not None else list(conv.metadata.tags)

        state_enum = conv.state
        if body.state is not None:
            try:
                state_enum = ConversationState(body.state.upper().strip())
            except Exception:
                return exception_to_api_response(
                    APIErrorValidation(f"Invalid conversation state: '{body.state}'.")
                )

        new_conv = build_conversation(
            created_by       = conv.metadata.createdBy,
            title            = new_title,
            created_at       = conv.createdAt,
            investigation_id = conv.investigationId,
            state            = state_enum,
            messages         = list(conv.messages),
            threads          = list(conv.threads),
            summary          = new_summary,
            tags             = new_tags,
        )

        proj_id = body.projectId if body.projectId is not None else session_dict.get("projectId") or "default-project"
        user_id = body.userId if body.userId is not None else session_dict.get("userId") or conv.metadata.createdBy
        ctx_sz = body.contextSize if body.contextSize is not None else session_dict.get("contextSize") or 0

        session_dict["conversation"] = new_conv
        session_dict["projectId"] = proj_id
        session_dict["userId"] = user_id
        session_dict["contextSize"] = ctx_sz

        _CONVERSATION_STORE[conversationId] = session_dict

        return build_success_response(
            data    = _conversation_to_response(session_dict).model_dump(),
            message = "Conversation updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.delete(
    "/{conversationId}",
    response_model      = APIResponse,
    summary             = "Delete conversation",
)
def delete_conversation(conversationId: str) -> APIResponse:
    try:
        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )
        _CONVERSATION_STORE.pop(conversationId)
        return build_success_response(
            data    = None,
            message = "Conversation deleted successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.post(
    "/{conversationId}/messages",
    response_model      = APIResponse,
    summary             = "Append message to conversation",
)
def append_conversation_message(conversationId: str, body: ConversationMessageRequest) -> APIResponse:
    try:
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Request validation failed.", details=errors)
            )

        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )

        try:
            new_conv = append_message(
                session_dict["conversation"], body.role, body.content, len(session_dict["conversation"].messages) + 1,
                body.createdAt, body.parentMessageId or "", body.metadata
            )
            session_dict["conversation"] = new_conv
            _CONVERSATION_STORE[conversationId] = session_dict
        except Exception as e:
            return exception_to_api_response(APIErrorValidation(str(e)))

        msg = new_conv.messages[-1]
        resp_msg = ConversationMessageResponse(
            messageId       = msg.messageId,
            messageKey      = msg.messageKey,
            conversationId  = msg.conversationId,
            parentMessageId = msg.parentMessageId,
            role            = msg.role.value if hasattr(msg.role, "value") else str(msg.role),
            content         = msg.content,
            sequenceNumber  = msg.sequenceNumber,
            tokenEstimate   = msg.tokenEstimate,
            metadata        = msg.metadata,
            createdAt       = msg.createdAt,
        )

        return build_success_response(
            data    = resp_msg.model_dump(),
            message = "Message appended successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.get(
    "/{conversationId}/messages",
    response_model      = APIResponse,
    summary             = "Get conversation messages",
)
def list_conversation_messages(conversationId: str) -> APIResponse:
    try:
        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )

        conv = session_dict["conversation"]
        resp_messages = [
            ConversationMessageResponse(
                messageId       = m.messageId,
                messageKey      = m.messageKey,
                conversationId  = m.conversationId,
                parentMessageId = m.parentMessageId,
                role            = m.role.value if hasattr(m.role, "value") else str(m.role),
                content         = m.content,
                sequenceNumber  = m.sequenceNumber,
                tokenEstimate   = m.tokenEstimate,
                metadata        = m.metadata,
                createdAt       = m.createdAt,
            )
            for m in conv.messages
        ]

        return build_success_response(
            data    = [m.model_dump() for m in resp_messages],
            message = f"{len(resp_messages)} message(s) retrieved.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# Part B Bulk Routes
# ---------------------------------------------------------------------------

@conversation_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create conversations",
    status_code    = 201,
)
def bulk_create_conversations(
    body: BulkCreateConversationsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.conversations:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"conversationId": "", "reason": "; ".join(item_errors)})
                continue

            try:
                state_enum = ConversationState.ACTIVE
                if item.state:
                    try:
                        state_enum = ConversationState(item.state.upper().strip())
                    except Exception:
                        failed.append({"conversationId": "", "reason": f"Invalid state: '{item.state}'"})
                        continue

                conv = build_conversation(
                    created_by       = item.createdBy,
                    title            = item.title,
                    created_at       = item.createdAt,
                    investigation_id = item.investigationId or "",
                    state            = state_enum,
                    messages         = [],
                    threads          = [],
                    summary          = item.summary or "",
                    tags             = item.tags,
                )

                if conv.conversationId in _CONVERSATION_STORE:
                    failed.append({"conversationId": conv.conversationId, "reason": f"Conversation '{conv.conversationId}' already exists."})
                    continue

                session_dict = {
                    "conversation": conv,
                    "projectId"   : item.projectId or "default-project",
                    "userId"      : item.userId or item.createdBy,
                    "contextSize" : item.contextSize or 0,
                }
                _CONVERSATION_STORE[conv.conversationId] = session_dict
                succeeded.append(conv.conversationId)
            except Exception as e:
                failed.append({"conversationId": "", "reason": str(e)})

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.conversations),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update conversations",
)
def bulk_update_conversations(
    body: BulkUpdateConversationsRequest = Body(...),
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
            cid = item.conversationId.strip()
            if not cid:
                failed.append({"conversationId": item.conversationId, "reason": "conversationId must not be empty."})
                continue

            session_dict = _CONVERSATION_STORE.get(cid)
            if session_dict is None:
                failed.append({"conversationId": cid, "reason": f"Conversation '{cid}' not found."})
                continue

            conv = session_dict["conversation"]
            upd = item.update
            try:
                new_title = upd.title if upd.title is not None else conv.metadata.title
                new_summary = upd.summary if upd.summary is not None else conv.metadata.summary
                new_tags = upd.tags if upd.tags is not None else list(conv.metadata.tags)

                state_enum = conv.state
                if upd.state is not None:
                    try:
                        state_enum = ConversationState(upd.state.upper().strip())
                    except Exception:
                        failed.append({"conversationId": cid, "reason": f"Invalid state: '{upd.state}'"})
                        continue

                new_conv = build_conversation(
                    created_by       = conv.metadata.createdBy,
                    title            = new_title,
                    created_at       = conv.createdAt,
                    investigation_id = conv.investigationId,
                    state            = state_enum,
                    messages         = list(conv.messages),
                    threads          = list(conv.threads),
                    summary          = new_summary,
                    tags             = new_tags,
                )

                proj_id = upd.projectId if upd.projectId is not None else session_dict.get("projectId") or "default-project"
                user_id = upd.userId if upd.userId is not None else session_dict.get("userId") or conv.metadata.createdBy
                ctx_sz = upd.contextSize if upd.contextSize is not None else session_dict.get("contextSize") or 0

                session_dict["conversation"] = new_conv
                session_dict["projectId"] = proj_id
                session_dict["userId"] = user_id
                session_dict["contextSize"] = ctx_sz

                _CONVERSATION_STORE[cid] = session_dict
                succeeded.append(cid)
            except Exception as e:
                failed.append({"conversationId": cid, "reason": str(e)})

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


@conversation_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete conversations",
)
def bulk_delete_conversations(
    body: BulkDeleteConversationsRequest = Body(...),
) -> APIResponse:
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for cid in body.conversationIds:
            cid_stripped = cid.strip() if cid else ""
            if not cid_stripped:
                failed.append({"conversationId": cid, "reason": "conversationId must not be empty."})
                continue

            if cid_stripped not in _CONVERSATION_STORE:
                failed.append({"conversationId": cid_stripped, "reason": f"Conversation '{cid_stripped}' not found."})
                continue

            del _CONVERSATION_STORE[cid_stripped]
            succeeded.append(cid_stripped)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.conversationIds),
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
# Message update / delete & summary routes
# ---------------------------------------------------------------------------

@conversation_router.put(
    "/{conversationId}/messages/{messageId}",
    response_model = APIResponse,
    summary        = "Update conversation message content",
)
def update_conversation_message(
    conversationId: str,
    messageId     : str,
    body          : UpdateMessageRequest,
) -> APIResponse:
    try:
        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )

        conv = session_dict["conversation"]
        orig_msg = find_message(conv, messageId)
        if orig_msg is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Message '{messageId}' not found.")
            )
        seq_num = orig_msg.sequenceNumber

        try:
            new_conv = update_message(conv, messageId, body.content)
            session_dict["conversation"] = new_conv
            _CONVERSATION_STORE[conversationId] = session_dict
        except ValueError as e:
            return exception_to_api_response(APIErrorNotFound(str(e)))

        msg = None
        for m in new_conv.messages:
            if m.sequenceNumber == seq_num:
                msg = m
                break

        if msg is None:
            return exception_to_api_response(
                APIErrorInternal("Failed to find the updated message.")
            )

        resp_msg = ConversationMessageResponse(
            messageId       = msg.messageId,
            messageKey      = msg.messageKey,
            conversationId  = msg.conversationId,
            parentMessageId = msg.parentMessageId,
            role            = msg.role.value if hasattr(msg.role, "value") else str(msg.role),
            content         = msg.content,
            sequenceNumber  = msg.sequenceNumber,
            tokenEstimate   = msg.tokenEstimate,
            metadata        = msg.metadata,
            createdAt       = msg.createdAt,
        )
        return build_success_response(
            data    = resp_msg.model_dump(),
            message = "Message updated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.delete(
    "/{conversationId}/messages/{messageId}",
    response_model = APIResponse,
    summary        = "Delete conversation message",
)
def delete_conversation_message(conversationId: str, messageId: str) -> APIResponse:
    try:
        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )

        try:
            new_conv = delete_message(session_dict["conversation"], messageId)
            session_dict["conversation"] = new_conv
            _CONVERSATION_STORE[conversationId] = session_dict
        except ValueError as e:
            return exception_to_api_response(APIErrorNotFound(str(e)))

        return build_success_response(
            data    = None,
            message = "Message deleted and conversation re-sequenced successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))


@conversation_router.get(
    "/{conversationId}/summary",
    response_model = APIResponse,
    summary        = "Get conversation summary",
)
def get_conversation_summary_endpoint(conversationId: str) -> APIResponse:
    try:
        session_dict = _CONVERSATION_STORE.get(conversationId)
        if session_dict is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Conversation '{conversationId}' not found.")
            )

        summary = build_conversation_summary(list(session_dict["conversation"].messages))
        return build_success_response(
            data    = {"summary": summary},
            message = "Conversation summary generated successfully.",
        )
    except Exception as exc:
        return exception_to_api_response(APIErrorInternal(str(exc)))
