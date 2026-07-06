"""
AI Copilot API Models — Phase A4.8.1 (Part B)
==============================================
Immutable Pydantic models for AI Copilot request and response contracts.

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

from services.copilot_orchestrator_service import (
    CopilotMetadata,
    CopilotRequest,
    CopilotResponse,
)


# ===========================================================================
# Request Models
# ===========================================================================

class CreateCopilotSessionRequest(BaseModel):
    """
    Request body for POST /api/v2/copilot.
    """
    contextId         : str
    reasoningId       : str
    promptPackageId   : str
    narrativeId       : str
    investigationId   : str
    provider          : str
    model             : str
    systemPrompt      : str
    userPrompt        : str
    createdAt         : str
    responseContent   : str
    responseCreatedAt : str
    temperature       : Optional[float]            = Field(default=0.0, ge=0.0, le=2.0)
    maxTokens         : Optional[int]              = Field(default=1024, ge=1)
    confidence        : Optional[float]            = Field(default=0.0, ge=0.0, le=100.0)
    citations         : Optional[List[str]]        = None
    processingTimeMs  : Optional[int]              = Field(default=0, ge=0)
    warnings          : Optional[List[str]]        = None
    status            : Optional[str]              = "active"
    turns             : Optional[int]              = Field(default=1, ge=1)
    userId            : Optional[str]              = "system"
    projectId         : Optional[str]              = "default-project"
    sessionName       : Optional[str]              = None
    contextSize       : Optional[int]              = Field(default=0, ge=0)
    updatedAt         : Optional[str]              = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation error strings. Empty means valid."""
        errors: List[str] = []
        if not self.contextId or not self.contextId.strip():
            errors.append("contextId must not be empty.")
        if not self.reasoningId or not self.reasoningId.strip():
            errors.append("reasoningId must not be empty.")
        if not self.promptPackageId or not self.promptPackageId.strip():
            errors.append("promptPackageId must not be empty.")
        if not self.narrativeId or not self.narrativeId.strip():
            errors.append("narrativeId must not be empty.")
        if not self.investigationId or not self.investigationId.strip():
            errors.append("investigationId must not be empty.")
        if not self.provider or not self.provider.strip():
            errors.append("provider must not be empty.")
        if not self.model or not self.model.strip():
            errors.append("model must not be empty.")
        if not self.systemPrompt or not self.systemPrompt.strip():
            errors.append("systemPrompt must not be empty.")
        if not self.userPrompt or not self.userPrompt.strip():
            errors.append("userPrompt must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if not self.responseContent or not self.responseContent.strip():
            errors.append("responseContent must not be empty.")
        if not self.responseCreatedAt or not self.responseCreatedAt.strip():
            errors.append("responseCreatedAt must not be empty.")
        return errors


class UpdateCopilotSessionRequest(BaseModel):
    """
    Request body for PUT /api/v2/copilot/{sessionId}.
    All fields are optional — supply only what should change.
    At least one field must be provided.
    """
    status            : Optional[str]              = None
    turns             : Optional[int]              = Field(default=None, ge=1)
    responseContent   : Optional[str]              = None
    responseConfidence: Optional[float]            = Field(default=None, ge=0.0, le=100.0)
    responseCitations : Optional[List[str]]        = None
    warnings          : Optional[List[str]]        = None
    metadata          : Optional[Dict[str, Any]]   = None
    userId            : Optional[str]              = None
    projectId         : Optional[str]              = None
    sessionName       : Optional[str]              = None
    contextSize       : Optional[int]              = Field(default=None, ge=0)
    updatedAt         : Optional[str]              = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class CopilotChatRequest(BaseModel):
    """
    Request body for POST /api/v2/copilot/chat.
    """
    conversationId    : str
    userPrompt        : str
    systemPrompt      : Optional[str]              = ""
    provider          : str
    model             : str
    createdAt         : str
    sessionId         : Optional[str]              = ""
    temperature       : Optional[float]            = Field(default=0.0, ge=0.0, le=2.0)
    maxTokens         : Optional[int]              = Field(default=1024, ge=1)
    contextId         : Optional[str]              = ""
    reasoningId       : Optional[str]              = ""
    promptPackageId   : Optional[str]              = ""
    narrativeId       : Optional[str]              = ""
    investigationId   : Optional[str]              = ""
    userId            : Optional[str]              = "system"
    projectId         : Optional[str]              = "default-project"
    sessionName       : Optional[str]              = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation error strings. Empty means valid."""
        errors: List[str] = []
        if not self.conversationId or not self.conversationId.strip():
            errors.append("conversationId must not be empty.")
        if not self.userPrompt or not self.userPrompt.strip():
            errors.append("userPrompt must not be empty.")
        if not self.provider or not self.provider.strip():
            errors.append("provider must not be empty.")
        if not self.model or not self.model.strip():
            errors.append("model must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class CopilotSessionResponse(BaseModel):
    """
    Single session payload.
    """
    sessionId   : str
    sessionKey  : str
    request     : CopilotRequest
    response    : CopilotResponse
    metadata    : CopilotMetadata
    createdAt   : str
    status      : str = "active"
    turns       : int = 1
    userId      : str = "system"
    projectId   : str = "default-project"
    sessionName : str = ""
    contextSize : int = 0
    updatedAt   : str = ""

    class Config:
        frozen = True


class CopilotChatResponse(BaseModel):
    """
    Payload returned by POST /api/v2/copilot/chat.
    """
    session    : CopilotSessionResponse

    class Config:
        frozen = True


class CopilotSessionListResponse(BaseModel):
    """
    Payload for GET /api/v2/copilot (list).
    """
    sessions : List[CopilotSessionResponse]
    total    : int

    class Config:
        frozen = True


class CopilotStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/copilot/statistics.
    """
    totalSessions      : int
    activeSessions     : int
    completedSessions  : int
    averageTurns       : float
    averageTokens      : float
    averageContextSize : float
    statusCounts       : Dict[str, int]

    class Config:
        frozen = True


class CopilotSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/copilot/search.
    """
    sessions   : List[CopilotSessionResponse]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int
    query      : str
    sortBy     : str
    sortOrder  : str

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateCopilotSessionsRequest(BaseModel):
    """
    Request body for POST /api/v2/copilot/bulk/create.
    """
    sessions : List[CreateCopilotSessionRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.sessions:
            errors.append("sessions list must not be empty.")
        for i, s in enumerate(self.sessions):
            sub = s.validate_request()
            for e in sub:
                errors.append(f"sessions[{i}]: {e}")
        return errors


class BulkUpdateCopilotSessionsRequest(BaseModel):
    """
    Request body for PUT /api/v2/copilot/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        sessionId : str
        update    : UpdateCopilotSessionRequest

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
            if not item.sessionId or not item.sessionId.strip():
                errors.append(f"items[{i}]: sessionId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteCopilotSessionsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/copilot/bulk/delete.
    """
    sessionIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.sessionIds:
            errors.append("sessionIds list must not be empty.")
        for i, sid in enumerate(self.sessionIds):
            if not sid or not sid.strip():
                errors.append(f"sessionIds[{i}]: sessionId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Summary of bulk operation results.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
