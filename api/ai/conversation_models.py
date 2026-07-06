"""
Conversation API Models — Phase A4.8.2 (Part B)
================================================
Immutable Pydantic models for Conversation request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (non-empty strings,
  field presence).
- No UUID or timestamp generation inside models.
- No randomness.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateConversationRequest(BaseModel):
    """
    Request body for POST /api/v2/conversations.
    """
    createdBy      : str
    title          : str
    createdAt      : str
    investigationId: Optional[str]        = ""
    state          : Optional[str]        = "ACTIVE"
    summary        : Optional[str]        = ""
    tags           : Optional[List[str]]  = None
    projectId      : Optional[str]        = "default-project"
    userId         : Optional[str]        = None
    contextSize    : Optional[int]        = Field(default=0, ge=0)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.createdBy or not self.createdBy.strip():
            errors.append("createdBy must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateConversationRequest(BaseModel):
    """
    Request body for PUT /api/v2/conversations/{conversationId}.
    """
    title       : Optional[str]        = None
    state       : Optional[str]        = None
    summary     : Optional[str]        = None
    tags        : Optional[List[str]]  = None
    projectId   : Optional[str]        = None
    userId      : Optional[str]        = None
    contextSize : Optional[int]        = Field(default=None, ge=0)

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class ConversationMessageRequest(BaseModel):
    """
    Request body for POST /api/v2/conversations/{conversationId}/messages.
    """
    role            : str
    content         : str
    createdAt       : str
    parentMessageId : Optional[str]             = ""
    metadata        : Optional[Dict[str, Any]]  = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.role or not self.role.strip():
            errors.append("role must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateMessageRequest(BaseModel):
    """
    Request body for updating a single message content.
    """
    content : str

    class Config:
        frozen = True



# ===========================================================================
# Response Models
# ===========================================================================

class ConversationMessageResponse(BaseModel):
    """
    Payload for a single conversation message response.
    """
    messageId       : str
    messageKey      : str
    conversationId  : str
    parentMessageId : str
    role            : str
    content         : str
    sequenceNumber  : int
    tokenEstimate   : int
    metadata        : Dict[str, Any] = Field(default_factory=dict)
    createdAt       : str

    class Config:
        frozen = True


class ConversationMetadataResponse(BaseModel):
    """
    Payload for conversation aggregates and provenance metadata.
    """
    title         : str
    summary       : str
    totalMessages : int
    totalTokens   : int
    lastMessageAt : str
    createdBy     : str
    tags          : List[str]
    engineVersion : str

    class Config:
        frozen = True


class ConversationThreadResponse(BaseModel):
    """
    Payload for a thread structure.
    """
    threadId      : str
    threadKey     : str
    rootMessageId : str
    messageIds    : List[str]
    depth         : int
    createdAt     : str

    class Config:
        frozen = True


class ConversationResponse(BaseModel):
    """
    Payload for a full conversation response.
    """
    conversationId          : str
    conversationKey         : str
    investigationId         : str
    state                   : str
    messages                : List[ConversationMessageResponse]
    threads                 : List[ConversationThreadResponse]
    metadata                : ConversationMetadataResponse
    conversationFingerprint : str
    createdAt               : str
    updatedAt               : str
    projectId               : str = "default-project"
    userId                  : str = "system"
    contextSize             : int = 0

    class Config:
        frozen = True


class ConversationListResponse(BaseModel):
    """
    Payload for GET /api/v2/conversations.
    """
    conversations : List[ConversationResponse]
    total         : int

    class Config:
        frozen = True


class ConversationStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/conversations/statistics.
    """
    totalConversations    : int
    activeConversations   : int
    archivedConversations : int
    averageMessages       : float
    averageTokens         : float
    averageContextSize    : float
    statusCounts          : Dict[str, int]

    class Config:
        frozen = True


class ConversationSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/conversations/search.
    """
    conversations : List[ConversationResponse]
    total         : int
    page          : int
    pageSize      : int
    totalPages    : int
    query         : str
    sortBy        : str
    sortOrder     : str

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateConversationsRequest(BaseModel):
    """
    Request body for bulk creation.
    """
    conversations : List[CreateConversationRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.conversations:
            errors.append("conversations list must not be empty.")
        for i, c in enumerate(self.conversations):
            sub = c.validate_request()
            for e in sub:
                errors.append(f"conversations[{i}]: {e}")
        return errors


class BulkUpdateConversationsRequest(BaseModel):
    """
    Request body for bulk updates.
    """
    class BulkUpdateItem(BaseModel):
        conversationId : str
        update         : UpdateConversationRequest

        class Config:
            frozen = True

    items : List[BulkUpdateItem] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.items:
            errors.append("items list must not be empty.")
        for i, item in enumerate(self.items):
            if not item.conversationId or not item.conversationId.strip():
                errors.append(f"items[{i}]: conversationId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteConversationsRequest(BaseModel):
    """
    Request body for bulk deletions.
    """
    conversationIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.conversationIds:
            errors.append("conversationIds list must not be empty.")
        for i, cid in enumerate(self.conversationIds):
            if not cid or not cid.strip():
                errors.append(f"conversationIds[{i}]: conversationId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result wrapper for bulk operations.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
