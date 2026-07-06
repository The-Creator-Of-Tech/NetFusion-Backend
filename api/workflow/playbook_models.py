"""
Playbook API Models — Phase A4.10.1
====================================
Immutable Pydantic models for Playbook request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class PlaybookStepRequest(BaseModel):
    """
    Request model representing a single step to create/update within a playbook.
    """
    stepNumber        : int
    title             : str
    description       : str
    stepType          : str
    expectedOutcome   : str
    relatedTechniques : Optional[List[str]] = Field(default_factory=list)
    relatedCVEs       : Optional[List[str]] = Field(default_factory=list)
    relatedIOCs       : Optional[List[str]] = Field(default_factory=list)
    createdAt         : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not isinstance(self.stepNumber, int) or self.stepNumber < 1:
            errors.append(f"stepNumber={self.stepNumber!r} must be a positive integer (>= 1).")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.stepType or not self.stepType.strip():
            errors.append("stepType must not be empty.")
        else:
            from services.playbook_service import PlaybookStepTypeEnum
            try:
                PlaybookStepTypeEnum(self.stepType.strip().upper())
            except ValueError:
                errors.append(f"stepType must be a PlaybookStepTypeEnum member; got {self.stepType!r}.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class PlaybookStepResponse(BaseModel):
    """
    Response model representing a single step in a playbook.
    """
    stepId            : str
    stepKey           : str
    stepNumber        : int
    title             : str
    description       : str
    stepType          : str
    expectedOutcome   : str
    relatedTechniques : List[str]
    relatedCVEs       : List[str]
    relatedIOCs       : List[str]
    createdAt         : str

    class Config:
        frozen = True


class PlaybookSummaryResponse(BaseModel):
    """
    Response model carrying structured summary details for a playbook.
    """
    playbookId   : str
    playbookName : str
    summaryText  : str
    stepCount    : int
    severity     : str
    status       : str
    enabled      : bool
    priority     : int

    class Config:
        frozen = True


# ===========================================================================
# Request Models
# ===========================================================================

class CreatePlaybookRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/playbooks.
    """
    name                : str
    description         : Optional[str] = ""
    severity            : str
    status              : str
    steps               : Optional[List[PlaybookStepRequest]] = Field(default_factory=list)
    relatedThreatActors : Optional[List[str]] = Field(default_factory=list)
    relatedCampaigns    : Optional[List[str]] = Field(default_factory=list)
    confidence          : float
    createdAt           : str
    enabled             : Optional[bool] = True
    priority            : Optional[int] = 1
    category            : Optional[str] = ""
    author              : Optional[str] = ""
    projectId           : Optional[str] = ""
    investigationId     : Optional[str] = ""
    updatedAt           : Optional[str] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.severity or not self.severity.strip():
            errors.append("severity must not be empty.")
        else:
            from services.playbook_service import PlaybookSeverityEnum
            try:
                PlaybookSeverityEnum(self.severity.strip().upper())
            except ValueError:
                errors.append(f"severity must be a PlaybookSeverityEnum member; got {self.severity!r}.")
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        else:
            from services.playbook_service import PlaybookStatusEnum
            try:
                PlaybookStatusEnum(self.status.strip().upper())
            except ValueError:
                errors.append(f"status must be a PlaybookStatusEnum member; got {self.status!r}.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
            errors.append(f"confidence={self.confidence!r} must be a float in [0.0, 100.0].")

        for i, step in enumerate(self.steps or []):
            sub = step.validate_request()
            for e in sub:
                errors.append(f"steps[{i}]: {e}")
        return errors


class UpdatePlaybookRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/playbooks/{playbookId}.
    """
    name                : Optional[str] = None
    description         : Optional[str] = None
    severity            : Optional[str] = None
    status              : Optional[str] = None
    steps               : Optional[List[PlaybookStepRequest]] = None
    relatedThreatActors : Optional[List[str]] = None
    relatedCampaigns    : Optional[List[str]] = None
    confidence          : Optional[float] = None
    enabled             : Optional[bool] = None
    priority            : Optional[int] = None
    category            : Optional[str] = None
    author              : Optional[str] = None
    projectId           : Optional[str] = None
    investigationId     : Optional[str] = None
    updatedAt           : Optional[str] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(
            v is not None
            for k, v in self.model_dump().items()
        )

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if self.severity is not None:
            if not self.severity.strip():
                errors.append("severity must not be empty.")
            else:
                from services.playbook_service import PlaybookSeverityEnum
                try:
                    PlaybookSeverityEnum(self.severity.strip().upper())
                except ValueError:
                    errors.append(f"severity must be a PlaybookSeverityEnum member; got {self.severity!r}.")
        if self.status is not None:
            if not self.status.strip():
                errors.append("status must not be empty.")
            else:
                from services.playbook_service import PlaybookStatusEnum
                try:
                    PlaybookStatusEnum(self.status.strip().upper())
                except ValueError:
                    errors.append(f"status must be a PlaybookStatusEnum member; got {self.status!r}.")
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
                errors.append(f"confidence={self.confidence!r} must be a float in [0.0, 100.0].")
        if self.steps is not None:
            for i, step in enumerate(self.steps):
                sub = step.validate_request()
                for e in sub:
                    errors.append(f"steps[{i}]: {e}")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class PlaybookResponse(BaseModel):
    """
    Response model carrying playbook details.
    """
    playbookId          : str
    playbookKey         : str
    name                : str
    description         : str
    severity            : str
    status              : str
    steps               : List[PlaybookStepResponse]
    relatedThreatActors : List[str]
    relatedCampaigns    : List[str]
    confidence          : float
    createdAt           : str
    updatedAt           : Optional[str] = None
    enabled             : bool = True
    priority            : int = 1
    category            : str = ""
    author              : str = ""
    projectId           : str = ""
    investigationId     : str = ""

    class Config:
        frozen = True


class PlaybookListResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/playbooks.
    """
    playbooks : List[PlaybookResponse]
    total     : int

    class Config:
        frozen = True


class PlaybookStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/playbooks/statistics.
    """
    totalPlaybooks      : int
    enabledPlaybooks     : int
    disabledPlaybooks    : int
    averageSteps        : float
    averagePriority     : float
    categoryCounts      : Dict[str, int]

    class Config:
        frozen = True


class PlaybookSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/playbooks/search.
    """
    playbooks  : List[PlaybookResponse]
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

class BulkCreatePlaybooksRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/playbooks/bulk/create.
    """
    playbooks : List[CreatePlaybookRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.playbooks:
            errors.append("playbooks list must not be empty.")
        for i, item in enumerate(self.playbooks):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"playbooks[{i}]: {e}")
        return errors


class BulkUpdatePlaybooksRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/playbooks/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        playbookId : str
        update     : UpdatePlaybookRequest

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
            if not item.playbookId or not item.playbookId.strip():
                errors.append(f"items[{i}]: playbookId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeletePlaybooksRequest(BaseModel):
    """
    Request body for DELETE /api/v2/workflow/playbooks/bulk/delete.
    """
    playbookIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.playbookIds:
            errors.append("playbookIds list must not be empty.")
        for i, pid in enumerate(self.playbookIds):
            if not pid or not pid.strip():
                errors.append(f"playbookIds[{i}]: playbookId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
