"""
Prompt Assembly API Models — Phase A4.8.5 (Part A)
=================================================
Immutable Pydantic models for Prompt Assembly request and response contracts.

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

class CreatePromptRequest(BaseModel):
    """
    Request body for POST /api/v2/prompts.
    """
    reasoningId      : str
    contextId        : str
    investigationId  : str
    systemPrompt     : str
    userPrompt       : str
    createdAt        : str
    maxTokens        : Optional[int]        = Field(default=8192, ge=0)
    reservedTokens   : Optional[int]        = Field(default=1024, ge=0)
    processingTimeMs : Optional[int]        = Field(default=0, ge=0)
    projectId        : Optional[str]        = "default-project"
    userId           : Optional[str]        = "system"
    status           : Optional[str]        = "ACTIVE"
    promptName       : Optional[str]        = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.reasoningId or not self.reasoningId.strip():
            errors.append("reasoningId must not be empty.")
        if not self.contextId or not self.contextId.strip():
            errors.append("contextId must not be empty.")
        if not self.investigationId or not self.investigationId.strip():
            errors.append("investigationId must not be empty.")
        if self.systemPrompt is None:
            errors.append("systemPrompt must not be None.")
        if not self.userPrompt or not self.userPrompt.strip():
            errors.append("userPrompt must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdatePromptRequest(BaseModel):
    """
    Request body for PUT /api/v2/prompts/{promptId}.
    """
    reasoningId      : Optional[str]        = None
    contextId        : Optional[str]        = None
    investigationId  : Optional[str]        = None
    systemPrompt     : Optional[str]        = None
    userPrompt       : Optional[str]        = None
    maxTokens        : Optional[int]        = Field(default=None, ge=0)
    reservedTokens   : Optional[int]        = Field(default=None, ge=0)
    processingTimeMs : Optional[int]        = Field(default=None, ge=0)
    projectId        : Optional[str]        = None
    userId           : Optional[str]        = None
    status           : Optional[str]        = None
    promptName       : Optional[str]        = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class PromptSectionRequest(BaseModel):
    """
    Request body for POST /api/v2/prompts/{promptId}/sections.
    """
    title    : str
    content  : str
    priority : Optional[int]                  = 50
    metadata : Optional[Dict[str, Any]]       = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if self.content is None:
            errors.append("content must not be None.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class PromptSectionResponse(BaseModel):
    """
    Payload for a single prompt section.
    """
    sectionId     : str
    title         : str
    priority      : int
    content       : str
    tokenEstimate : int
    metadata      : Dict[str, Any] = Field(default_factory=dict)

    class Config:
        frozen = True


class PromptResponse(BaseModel):
    """
    Payload for a full PromptPackage object response.
    """
    packageId          : str
    packageKey         : str
    packageFingerprint : str
    systemPrompt       : str
    userPrompt         : str
    sections           : List[PromptSectionResponse]
    reasoningId        : str
    contextId          : str
    investigationId    : str
    metadata           : Dict[str, Any]
    createdAt          : str
    projectId          : str = "default-project"
    userId             : str = "system"
    status             : str = "ACTIVE"
    promptName         : str = ""

    class Config:
        frozen = True


class PromptListResponse(BaseModel):
    """
    Payload for GET /api/v2/prompts.
    """
    prompts : List[PromptResponse]
    total   : int

    class Config:
        frozen = True


class PromptStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/prompts/statistics.
    """
    totalPrompts       : int
    activePrompts      : int
    archivedPrompts    : int
    averageSections    : float
    averageTokens      : float
    averagePromptSize  : float
    statusCounts       : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreatePromptsRequest(BaseModel):
    """
    Request body for bulk creation of prompt packages.
    """
    prompts : List[CreatePromptRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.prompts:
            errors.append("prompts list must not be empty.")
        for i, p in enumerate(self.prompts):
            sub = p.validate_request()
            for e in sub:
                errors.append(f"prompts[{i}]: {e}")
        return errors


class BulkUpdatePromptsRequest(BaseModel):
    """
    Request body for bulk updates of prompt packages.
    """
    class BulkUpdateItem(BaseModel):
        promptId : str
        update   : UpdatePromptRequest

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
            if not item.promptId or not item.promptId.strip():
                errors.append(f"items[{i}]: promptId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeletePromptsRequest(BaseModel):
    """
    Request body for bulk deletions.
    """
    promptIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.promptIds:
            errors.append("promptIds list must not be empty.")
        for i, pid in enumerate(self.promptIds):
            if not pid or not pid.strip():
                errors.append(f"promptIds[{i}]: promptId must not be empty.")
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
