"""
AI Execution API Models — Phase A4.8.7 (Part A)
==============================================
Immutable Pydantic models for AI Execution request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns.
- No UUID or timestamp generation inside models.
- No randomness.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateExecutionRequest(BaseModel):
    """
    Request body for POST /api/v2/execution.
    """
    provider     : str
    model        : str
    systemPrompt : str
    userPrompt   : str
    temperature  : Optional[float]      = Field(default=0.0, ge=0.0, le=2.0)
    maxTokens    : Optional[int]        = Field(default=1024, ge=1)
    stream       : Optional[bool]       = False
    requestId    : Optional[str]        = ""
    sessionId    : Optional[str]        = ""
    strategy     : Optional[str]        = "priority"
    createdAt    : str
    projectId    : Optional[str]        = "default-project"
    userId       : Optional[str]        = "system"
    status       : Optional[str]        = "ACTIVE"

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.provider or not self.provider.strip():
            errors.append("provider must not be empty.")
        if not self.model or not self.model.strip():
            errors.append("model must not be empty.")
        if not self.systemPrompt.strip() and not self.userPrompt.strip():
            errors.append("At least one of systemPrompt or userPrompt must be non-empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateExecutionRequest(BaseModel):
    """
    Request body for PUT /api/v2/execution/{executionId}.
    """
    projectId    : Optional[str]        = None
    userId       : Optional[str]        = None
    status       : Optional[str]        = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


# ===========================================================================
# Response Models
# ===========================================================================

class ExecutionUsageResponse(BaseModel):
    """
    Payload for token usage details.
    """
    promptTokens     : int
    completionTokens : int
    totalTokens      : int
    estimatedCost    : float
    latencyMs        : int

    class Config:
        frozen = True


class ExecutionProviderResponse(BaseModel):
    """
    Payload for selected model and provider.
    """
    provider : str
    model    : str

    class Config:
        frozen = True


class ExecutionResponse(BaseModel):
    """
    Payload for a full AIExecutionResult response.
    """
    executionId          : str
    executionKey         : str
    executionFingerprint : str
    provider             : str
    model                : str
    systemPrompt         : str
    userPrompt           : str
    temperature          : float
    maxTokens            : int
    stream               : bool
    requestId            : str
    sessionId            : str
    strategy             : str
    createdAt            : str
    engineVersion        : str
    projectId            : str
    userId               : str
    status               : str
    response             : Optional[Dict[str, Any]] = None
    metadata             : Dict[str, Any]

    class Config:
        frozen = True


class ExecutionListResponse(BaseModel):
    """
    Payload for GET /api/v2/execution.
    """
    executions : List[ExecutionResponse]
    total      : int

    class Config:
        frozen = True


class ExecutionStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/execution/statistics.
    """
    totalExecutions      : int
    pendingExecutions    : int
    runningExecutions    : int
    completedExecutions  : int
    failedExecutions     : int
    averageExecutionTime : float
    averageTokens        : float
    averageExecutionSize : float
    statusCounts         : Dict[str, int]
    providerCounts       : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateExecutionsRequest(BaseModel):
    """
    Request body for bulk creation of executions.
    """
    executions : List[CreateExecutionRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.executions:
            errors.append("executions list must not be empty.")
        for i, e in enumerate(self.executions):
            sub = e.validate_request()
            for err in sub:
                errors.append(f"executions[{i}]: {err}")
        return errors


class BulkUpdateExecutionsRequest(BaseModel):
    """
    Request body for bulk update of executions.
    """
    class BulkUpdateItem(BaseModel):
        executionId : str
        update      : UpdateExecutionRequest

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
            if not item.executionId or not item.executionId.strip():
                errors.append(f"items[{i}]: executionId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteExecutionsRequest(BaseModel):
    """
    Request body for bulk deletion of executions.
    """
    executionIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.executionIds:
            errors.append("executionIds list must not be empty.")
        for i, eid in enumerate(self.executionIds):
            if not eid or not eid.strip():
                errors.append(f"executionIds[{i}]: executionId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Response body representing result of a bulk operation.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
