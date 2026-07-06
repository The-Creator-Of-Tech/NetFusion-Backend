"""
Automation API Models — Phase A4.10.3
======================================
Immutable Pydantic models for Automation request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class AutomationStepRequest(BaseModel):
    """
    Request model representing a step to execute within an automation.
    """
    stepNumber  : int
    name        : str
    description : Optional[str] = ""
    action      : str
    parameters  : Optional[Dict[str, Any]] = Field(default_factory=dict)
    createdAt   : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not isinstance(self.stepNumber, int) or self.stepNumber < 1:
            errors.append(f"stepNumber={self.stepNumber!r} must be a positive integer (>= 1).")
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.action or not self.action.strip():
            errors.append("action must not be empty.")
        else:
            from services.automation_engine_service import AutomationActionEnum
            try:
                AutomationActionEnum(self.action.strip().upper())
            except ValueError:
                errors.append(f"action must be an AutomationActionEnum member; got {self.action!r}.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class AutomationStepResponse(BaseModel):
    """
    Response model representing an automation step.
    """
    stepId      : str
    stepKey     : str
    stepNumber  : int
    name        : str
    description : str
    action      : str
    parameters  : Dict[str, Any]
    createdAt   : str

    class Config:
        frozen = True


class AutomationExecutionResponse(BaseModel):
    """
    Response model carrying automation execution logs.
    """
    executionId  : str
    automationId : str
    status       : str
    startedAt    : str
    completedAt  : str
    stepResults  : List[Dict[str, Any]]

    class Config:
        frozen = True


class AutomationSummaryResponse(BaseModel):
    """
    Response model carrying structured summary details for an automation.
    """
    automationId   : str
    automationName : str
    summaryText    : str
    stepCount      : int
    executionCount : int
    status         : str
    trigger        : str
    enabled        : bool
    priority       : int

    class Config:
        frozen = True


# ===========================================================================
# Request Models
# ===========================================================================

class CreateAutomationRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/automation.
    """
    name            : str
    description     : Optional[str] = ""
    status          : str
    trigger         : str
    steps           : Optional[List[AutomationStepRequest]] = Field(default_factory=list)
    priority        : Optional[int] = 100
    createdAt       : str
    enabled         : Optional[bool] = True
    category        : Optional[str] = ""
    author          : Optional[str] = ""
    projectId       : Optional[str] = ""
    investigationId : Optional[str] = ""
    playbookId      : Optional[str] = ""
    ruleId          : Optional[str] = ""
    updatedAt       : Optional[str] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        else:
            from services.automation_engine_service import AutomationStatusEnum
            try:
                AutomationStatusEnum(self.status.strip().upper())
            except ValueError:
                errors.append(f"status must be an AutomationStatusEnum member; got {self.status!r}.")
        if not self.trigger or not self.trigger.strip():
            errors.append("trigger must not be empty.")
        else:
            from services.automation_engine_service import AutomationTriggerEnum
            try:
                AutomationTriggerEnum(self.trigger.strip().upper())
            except ValueError:
                errors.append(f"trigger must be an AutomationTriggerEnum member; got {self.trigger!r}.")
        if not isinstance(self.priority, int) or self.priority < 1:
            errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")

        for i, s in enumerate(self.steps or []):
            sub = s.validate_request()
            for e in sub:
                errors.append(f"steps[{i}]: {e}")
        return errors


class UpdateAutomationRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/automation/{automationId}.
    """
    name            : Optional[str] = None
    description     : Optional[str] = None
    status          : Optional[str] = None
    trigger         : Optional[str] = None
    steps           : Optional[List[AutomationStepRequest]] = None
    priority        : Optional[int] = None
    enabled         : Optional[bool] = None
    category        : Optional[str] = None
    author          : Optional[str] = None
    projectId       : Optional[str] = None
    investigationId : Optional[str] = None
    playbookId      : Optional[str] = None
    ruleId          : Optional[str] = None
    updatedAt       : Optional[str] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(
            v is not None
            for k, v in self.model_dump().items()
        )

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if self.status is not None:
            if not self.status.strip():
                errors.append("status must not be empty.")
            else:
                from services.automation_engine_service import AutomationStatusEnum
                try:
                    AutomationStatusEnum(self.status.strip().upper())
                except ValueError:
                    errors.append(f"status must be an AutomationStatusEnum member; got {self.status!r}.")
        if self.trigger is not None:
            if not self.trigger.strip():
                errors.append("trigger must not be empty.")
            else:
                from services.automation_engine_service import AutomationTriggerEnum
                try:
                    AutomationTriggerEnum(self.trigger.strip().upper())
                except ValueError:
                    errors.append(f"trigger must be an AutomationTriggerEnum member; got {self.trigger!r}.")
        if self.priority is not None:
            if not isinstance(self.priority, int) or self.priority < 1:
                errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if self.steps is not None:
            for i, s in enumerate(self.steps):
                sub = s.validate_request()
                for e in sub:
                    errors.append(f"steps[{i}]: {e}")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class AutomationResponse(BaseModel):
    """
    Response model carrying automation details.
    """
    automationId    : str
    automationKey   : str
    name            : str
    description     : str
    status          : str
    trigger         : str
    steps           : List[AutomationStepResponse]
    priority        : int
    createdAt       : str
    updatedAt       : Optional[str] = None
    enabled         : bool = True
    category        : str = ""
    author          : str = ""
    projectId       : str = ""
    investigationId : str = ""
    playbookId      : str = ""
    ruleId          : str = ""

    class Config:
        frozen = True


class AutomationListResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/automation.
    """
    automations : List[AutomationResponse]
    total       : int

    class Config:
        frozen = True


class AutomationStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/automation/statistics.
    """
    totalAutomations    : int
    enabledAutomations   : int
    disabledAutomations  : int
    totalExecutions     : int
    averageSteps        : float
    averageExecutions   : float
    averagePriority     : float
    categoryCounts      : Dict[str, int]

    class Config:
        frozen = True


class AutomationSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/automation/search.
    """
    automations : List[AutomationResponse]
    total       : int
    page        : int
    pageSize    : int
    totalPages  : int
    query       : str
    sortBy      : str
    sortOrder   : str

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateAutomationsRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/automation/bulk/create.
    """
    automations : List[CreateAutomationRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.automations:
            errors.append("automations list must not be empty.")
        for i, item in enumerate(self.automations):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"automations[{i}]: {e}")
        return errors


class BulkUpdateAutomationsRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/automation/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        automationId : str
        update       : UpdateAutomationRequest

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
            if not item.automationId or not item.automationId.strip():
                errors.append(f"items[{i}]: automationId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteAutomationsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/workflow/automation/bulk/delete.
    """
    automationIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.automationIds:
            errors.append("automationIds list must not be empty.")
        for i, aid in enumerate(self.automationIds):
            if not aid or not aid.strip():
                errors.append(f"automationIds[{i}]: automationId must not be empty.")
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
