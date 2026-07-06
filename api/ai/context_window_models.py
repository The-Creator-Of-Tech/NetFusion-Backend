"""
Context Window API Models — Phase A4.8.4 (Part A)
=================================================
Immutable Pydantic models for Context Window request and response contracts.

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

class CreateContextWindowRequest(BaseModel):
    """
    Request body for POST /api/v2/context.
    """
    createdAt       : str
    investigationId : Optional[str]        = ""
    conversationId  : Optional[str]        = ""
    projectId       : Optional[str]        = "default-project"
    userId          : Optional[str]        = "system"
    status          : Optional[str]        = "ACTIVE"
    contextSize     : Optional[int]        = Field(default=0, ge=0)
    windowName      : Optional[str]        = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateContextWindowRequest(BaseModel):
    """
    Request body for PUT /api/v2/context/{contextId}.
    """
    investigationId : Optional[str]        = None
    conversationId  : Optional[str]        = None
    projectId       : Optional[str]        = None
    userId          : Optional[str]        = None
    status          : Optional[str]        = None
    contextSize     : Optional[int]        = Field(default=None, ge=0)
    windowName      : Optional[str]        = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class ContextWindowEntryRequest(BaseModel):
    """
    Request body for POST /api/v2/context/{contextId}/entries.
    """
    source          : str
    priority        : str
    title           : str
    content         : str
    referenceId     : str
    importanceScore : float
    confidence      : float
    createdAt       : str
    metadata        : Optional[Dict[str, Any]] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.source or not self.source.strip():
            errors.append("source must not be empty.")
        if not self.priority or not self.priority.strip():
            errors.append("priority must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.referenceId or not self.referenceId.strip():
            errors.append("referenceId must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateContextWindowEntryRequest(BaseModel):
    """
    Request body for PUT /api/v2/context/{contextId}/entries/{entryId}.
    """
    priority        : Optional[str]             = None
    content         : Optional[str]             = None
    importanceScore : Optional[float]           = None
    confidence      : Optional[float]           = None
    metadata        : Optional[Dict[str, Any]]  = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(v is not None for v in self.model_dump().values())


# ===========================================================================
# Response Models
# ===========================================================================

class ContextWindowEntryResponse(BaseModel):
    """
    Payload for a single context window item.
    """
    contextItemId   : str
    contextItemKey  : str
    source          : str
    priority        : str
    title           : str
    content         : str
    referenceId     : str
    tokenEstimate   : int
    importanceScore : float
    confidence      : float
    metadata        : Dict[str, Any] = Field(default_factory=dict)
    createdAt       : str

    class Config:
        frozen = True


class ContextWindowResponse(BaseModel):
    """
    Payload for a full ContextWindow object response.
    """
    windowId            : str
    windowKey           : str
    investigationId     : str
    conversationId      : str
    items               : List[ContextWindowEntryResponse]
    totalTokenEstimate  : int
    contextFingerprint  : str
    createdAt           : str
    projectId           : str = "default-project"
    userId              : str = "system"
    status              : str = "ACTIVE"
    contextSize         : int = 0
    windowName          : str = ""

    class Config:
        frozen = True


class ContextWindowListResponse(BaseModel):
    """
    Payload for GET /api/v2/context.
    """
    windows : List[ContextWindowResponse]
    total   : int

    class Config:
        frozen = True


class ContextWindowStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/context/statistics.
    """
    totalContexts      : int
    activeContexts     : int
    archivedContexts   : int
    averageEntries     : float
    averageTokens      : float
    averageContextSize : float
    statusCounts       : Dict[str, int]

    class Config:
        frozen = True


class ContextWindowSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/context/search.
    """
    memories   : List[ContextWindowResponse]
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

class BulkCreateContextWindowsRequest(BaseModel):
    """
    Request body for bulk creation.
    """
    windows : List[CreateContextWindowRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.windows:
            errors.append("windows list must not be empty.")
        for i, w in enumerate(self.windows):
            sub = w.validate_request()
            for e in sub:
                errors.append(f"windows[{i}]: {e}")
        return errors


class BulkUpdateContextWindowsRequest(BaseModel):
    """
    Request body for bulk updates.
    """
    class BulkUpdateItem(BaseModel):
        windowId : str
        update   : UpdateContextWindowRequest

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
            if not item.windowId or not item.windowId.strip():
                errors.append(f"items[{i}]: windowId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteContextWindowsRequest(BaseModel):
    """
    Request body for bulk deletions.
    ```
    """
    windowIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.windowIds:
            errors.append("windowIds list must not be empty.")
        for i, wid in enumerate(self.windowIds):
            if not wid or not wid.strip():
                errors.append(f"windowIds[{i}]: windowId must not be empty.")
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
