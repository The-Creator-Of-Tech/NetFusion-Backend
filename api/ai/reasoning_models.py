"""
Reasoning API Models — Phase A4.8.6 (Part A)
===========================================
Immutable Pydantic models for Reasoning request and response contracts.

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

class CreateReasoningRequest(BaseModel):
    """
    Request body for POST /api/v2/reasoning.
    """
    contextIds         : List[str]
    findingIds         : List[str]
    alertIds           : List[str]
    relationshipIds    : List[str]
    timelineIds        : List[str]
    createdAt          : str
    decision           : Optional[str]        = ""
    overallConfidence  : Optional[float]      = Field(default=0.0, ge=0.0, le=100.0)
    overallRisk        : Optional[float]      = Field(default=0.0, ge=0.0, le=100.0)
    projectId          : Optional[str]        = "default-project"
    userId             : Optional[str]        = "system"
    status             : Optional[str]        = "ACTIVE"
    sessionName        : Optional[str]        = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if self.contextIds is None:
            errors.append("contextIds must not be None.")
        if self.findingIds is None:
            errors.append("findingIds must not be None.")
        if self.alertIds is None:
            errors.append("alertIds must not be None.")
        if self.relationshipIds is None:
            errors.append("relationshipIds must not be None.")
        if self.timelineIds is None:
            errors.append("timelineIds must not be None.")
        return errors


class UpdateReasoningRequest(BaseModel):
    """
    Request body for PUT /api/v2/reasoning/{reasoningId}.
    """
    decision           : Optional[str]        = None
    overallConfidence  : Optional[float]      = Field(default=None, ge=0.0, le=100.0)
    overallRisk        : Optional[float]      = Field(default=None, ge=0.0, le=100.0)
    projectId          : Optional[str]        = None
    userId             : Optional[str]        = None
    status             : Optional[str]        = None
    sessionName        : Optional[str]        = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class ReasoningStepRequest(BaseModel):
    """
    Request body for POST /api/v2/reasoning/{reasoningId}/steps.
    """
    stepNumber       : int
    stage            : str
    inputSummary     : str
    outputSummary    : str
    confidence       : float                  = Field(ge=0.0, le=100.0)
    evidenceIds      : Optional[List[str]]    = None
    findingIds       : Optional[List[str]]    = None
    alertIds         : Optional[List[str]]    = None
    relationshipIds  : Optional[List[str]]    = None
    timelineEventIds : Optional[List[str]]    = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """Return a list of validation errors. Empty means valid."""
        errors: List[str] = []
        if self.stepNumber < 1:
            errors.append("stepNumber must be a positive integer >= 1.")
        if not self.stage or not self.stage.strip():
            errors.append("stage must not be empty.")
        else:
            try:
                from services.reasoning_service import ReasoningStage
                ReasoningStage(self.stage.upper().strip())
            except Exception:
                errors.append(f"stage must be a valid ReasoningStage.")
        if self.inputSummary is None:
            errors.append("inputSummary must not be None.")
        if self.outputSummary is None:
            errors.append("outputSummary must not be None.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class ReasoningEvidenceResponse(BaseModel):
    """
    Payload for a single supporting evidence record within a reasoning result.
    """
    evidenceId : str
    weight     : float
    reason     : str
    sourceType : str
    confidence : float

    class Config:
        frozen = True


class ReasoningStepResponse(BaseModel):
    """
    Payload for a single reasoning trace step.
    """
    stepNumber       : int
    stage            : str
    inputSummary     : str
    outputSummary    : str
    confidence       : float
    evidenceIds      : List[str]
    findingIds       : List[str]
    alertIds         : List[str]
    relationshipIds  : List[str]
    timelineEventIds : List[str]

    class Config:
        frozen = True


class ReasoningResponse(BaseModel):
    """
    Payload for a full ReasoningResult response.
    """
    reasoningId          : str
    reasoningKey         : str
    reasoningFingerprint : str
    overallConfidence    : float
    overallRisk          : float
    decision             : str
    reasoningTrace       : List[ReasoningStepResponse]
    supportingEvidence   : List[ReasoningEvidenceResponse]
    decisionExplanation  : Dict[str, Any]
    metadata             : Dict[str, Any]
    engineVersion        : str
    createdAt            : str
    projectId            : str = "default-project"
    userId               : str = "system"
    status               : str = "ACTIVE"
    sessionName          : str = ""

    class Config:
        frozen = True


class ReasoningListResponse(BaseModel):
    """
    Payload for GET /api/v2/reasoning.
    """
    reasonings : List[ReasoningResponse]
    total      : int

    class Config:
        frozen = True


class ReasoningStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/reasoning/statistics.
    """
    totalReasoningSessions     : int
    activeReasoningSessions    : int
    completedReasoningSessions : int
    averageSteps               : float
    averageConfidence          : float
    averageReasoningSize       : float
    statusCounts               : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateReasoningRequest(BaseModel):
    """
    Request body for bulk creation of reasoning sessions.
    """
    reasonings : List[CreateReasoningRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.reasonings:
            errors.append("reasonings list must not be empty.")
        for i, r in enumerate(self.reasonings):
            sub = r.validate_request()
            for e in sub:
                errors.append(f"reasonings[{i}]: {e}")
        return errors


class BulkUpdateReasoningRequest(BaseModel):
    """
    Request body for bulk update of reasoning sessions.
    """
    class BulkUpdateItem(BaseModel):
        reasoningId : str
        update      : UpdateReasoningRequest

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
            if not item.reasoningId or not item.reasoningId.strip():
                errors.append(f"items[{i}]: reasoningId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteReasoningRequest(BaseModel):
    """
    Request body for bulk deletion of reasoning sessions.
    """
    reasoningIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.reasoningIds:
            errors.append("reasoningIds list must not be empty.")
        for i, rid in enumerate(self.reasoningIds):
            if not rid or not rid.strip():
                errors.append(f"reasoningIds[{i}]: reasoningId must not be empty.")
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
