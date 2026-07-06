"""
Session Memory API Models — Phase A4.8.3 (Part B)
=================================================
Immutable Pydantic models for Session Memory request and response contracts.

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

class CreateMemoryRequest(BaseModel):
    """
    Request body for POST /api/v2/memory.
    """
    conversationId  : str
    investigationId : Optional[str]        = ""
    createdAt       : str
    projectId       : Optional[str]        = "default-project"
    userId          : Optional[str]        = "system"
    status          : Optional[str]        = "ACTIVE"
    contextSize     : Optional[int]        = Field(default=0, ge=0)
    sessionName     : Optional[str]        = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.conversationId or not self.conversationId.strip():
            errors.append("conversationId must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateMemoryRequest(BaseModel):
    """
    Request body for PUT /api/v2/memory/{memoryId}.
    """
    investigationId : Optional[str]        = None
    updatedAt       : Optional[str]        = None
    projectId       : Optional[str]        = None
    userId          : Optional[str]        = None
    status          : Optional[str]        = None
    contextSize     : Optional[int]        = Field(default=None, ge=0)
    sessionName     : Optional[str]        = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class MemoryEntryRequest(BaseModel):
    """
    Request body for POST /api/v2/memory/{memoryId}/entries.
    """
    memoryType       : str
    state            : str
    title            : str
    content          : str
    importanceScore  : float
    confidence       : float
    createdAt        : str
    sourceId         : Optional[str]             = ""
    tags             : Optional[List[str]]       = None
    metadata         : Optional[Dict[str, Any]]  = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.memoryType or not self.memoryType.strip():
            errors.append("memoryType must not be empty.")
        if not self.state or not self.state.strip():
            errors.append("state must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateMemoryEntryRequest(BaseModel):
    """
    Request body for PUT /api/v2/memory/{memoryId}/entries/{entryId}.
    """
    state           : Optional[str]             = None
    content         : Optional[str]             = None
    importanceScore : Optional[float]           = None
    confidence      : Optional[float]           = None
    tags            : Optional[List[str]]       = None
    metadata        : Optional[Dict[str, Any]]  = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(v is not None for v in self.model_dump().values())


# ===========================================================================
# Response Models
# ===========================================================================

class MemoryEntryResponse(BaseModel):
    """
    Payload for a single memory entry.
    """
    memoryId        : str
    memoryKey       : str
    conversationId  : str
    investigationId : str
    memoryType      : str
    state           : str
    title           : str
    content         : str
    importanceScore : float
    confidence      : float
    sourceId        : str
    tags            : List[str]
    metadata        : Dict[str, Any] = Field(default_factory=dict)
    createdAt       : str

    class Config:
        frozen = True


class MemorySummaryResponse(BaseModel):
    """
    Payload for a single memory summary.
    """
    summaryId        : str
    summaryKey       : str
    conversationId   : str
    summary          : str
    coveredMemoryIds : List[str]
    tokenEstimate    : int
    createdAt        : str

    class Config:
        frozen = True


class MemoryResponse(BaseModel):
    """
    Payload for a full SessionMemory object response.
    """
    sessionId         : str
    sessionKey        : str
    conversationId    : str
    investigationId   : str
    memories          : List[MemoryEntryResponse]
    summaries         : List[MemorySummaryResponse]
    memoryFingerprint : str
    createdAt         : str
    updatedAt         : str
    projectId         : str = "default-project"
    userId            : str = "system"
    status            : str = "ACTIVE"
    contextSize       : int = 0
    sessionName       : str = ""

    class Config:
        frozen = True


class MemoryListResponse(BaseModel):
    """
    Payload for GET /api/v2/memory.
    """
    memories : List[MemoryResponse]
    total    : int

    class Config:
        frozen = True


class MemoryStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/memory/statistics.
    """
    totalMemories      : int
    activeMemories     : int
    archivedMemories   : int
    averageEntries     : float
    averageTokens      : float
    averageContextSize : float
    statusCounts       : Dict[str, int]

    class Config:
        frozen = True


class MemorySearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/memory/search.
    """
    memories   : List[MemoryResponse]
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

class BulkCreateMemoryRequest(BaseModel):
    """
    Request body for bulk creation.
    """
    sessions : List[CreateMemoryRequest] = Field(..., min_length=1)

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


class BulkUpdateMemoryRequest(BaseModel):
    """
    Request body for bulk updates.
    """
    class BulkUpdateItem(BaseModel):
        memoryId : str
        update   : UpdateMemoryRequest

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
            if not item.memoryId or not item.memoryId.strip():
                errors.append(f"items[{i}]: memoryId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteMemoryRequest(BaseModel):
    """
    Request body for bulk deletions.
    """
    memoryIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.memoryIds:
            errors.append("memoryIds list must not be empty.")
        for i, mid in enumerate(self.memoryIds):
            if not mid or not mid.strip():
                errors.append(f"memoryIds[{i}]: memoryId must not be empty.")
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
