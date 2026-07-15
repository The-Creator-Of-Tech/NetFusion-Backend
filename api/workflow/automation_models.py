"""
Automation API Models — Canonical Schema (Aligned with Prisma)
==============================================================
All fields derived from Prisma Automation / AutomationStep / AutomationExecution.

Prisma canonical types:
  - Automation.status    → AutomationStatus  (DRAFT | ACTIVE | DISABLED | ARCHIVED)
  - Automation.trigger   → AutomationTriggerType
      (FINDING_CREATED | ALERT_CREATED | RULE_MATCHED | PLAYBOOK_SELECTED |
       TIMELINE_EVENT | MANUAL)
  - AutomationStep.action → StepType
      (CREATE_ALERT | CREATE_TIMELINE_EVENT | START_PLAYBOOK |
       UPDATE_FINDING | UPDATE_ALERT | TAG_INVESTIGATION)
  - AutomationExecution.status → AutomationExecutionStatus
      (PENDING | ACTIVE | COMPLETED | FAILED)

API-only derived fields (not Prisma columns, stored in metadata):
  - automationKey, stepKey

Fields present in Prisma but not in requests:
  - createdBy, updatedBy, version, deletedAt, metadata
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

_VALID_STATUS  = {"DRAFT", "ACTIVE", "DISABLED", "ARCHIVED"}
_VALID_TRIGGER = {
    "FINDING_CREATED", "ALERT_CREATED", "RULE_MATCHED",
    "PLAYBOOK_SELECTED", "TIMELINE_EVENT", "MANUAL",
}
# StepType values valid for AutomationStep.action (Prisma StepType enum subset)
_VALID_ACTION  = {
    "CREATE_ALERT", "CREATE_TIMELINE_EVENT", "START_PLAYBOOK",
    "UPDATE_FINDING", "UPDATE_ALERT", "TAG_INVESTIGATION",
}
# AutomationExecution.status (Prisma AutomationExecutionStatus)
_VALID_EXEC_STATUS = {"PENDING", "ACTIVE", "COMPLETED", "FAILED"}


# ===========================================================================
# Step sub-models
# ===========================================================================

class AutomationStepRequest(BaseModel):
    """Maps to Prisma AutomationStep (stepNumber, name, description, action, parameters)."""
    stepNumber  : int
    name        : str
    description : Optional[str]            = ""
    action      : str                       # StepType (automation subset)
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
        elif self.action.strip().upper() not in _VALID_ACTION:
            errors.append(
                f"action must be one of {sorted(_VALID_ACTION)}; got {self.action!r}."
            )
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class AutomationStepResponse(BaseModel):
    """Prisma AutomationStep columns + API-only stepKey."""
    stepId      : str
    stepKey     : str           # Prisma AutomationStep.stepKey column
    stepNumber  : int
    name        : str
    description : str
    action      : str           # StepType
    parameters  : Dict[str, Any]
    createdAt   : str

    class Config:
        frozen = True


# ===========================================================================
# Execution response
# ===========================================================================

class AutomationExecutionResponse(BaseModel):
    """
    Mirrors Prisma AutomationExecution.
    status uses AutomationExecutionStatus values: PENDING | ACTIVE | COMPLETED | FAILED
    """
    executionId  : str
    automationId : str
    status       : str      # AutomationExecutionStatus
    startedAt    : str
    completedAt  : str
    stepResults  : List[Dict[str, Any]]

    class Config:
        frozen = True


# ===========================================================================
# Summary response
# ===========================================================================

class AutomationSummaryResponse(BaseModel):
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
# Create / Update requests
# ===========================================================================

class CreateAutomationRequest(BaseModel):
    """
    POST /api/v2/workflow/automation
    projectId is required in Prisma (non-nullable UUID).
    playbookId / ruleId are optional FK relations in Prisma.
    """
    name            : str
    description     : Optional[str]  = ""
    status          : str            # AutomationStatus
    trigger         : str            # AutomationTriggerType
    projectId       : str            # required — Prisma non-nullable
    investigationId : Optional[str]  = None
    playbookId      : Optional[str]  = None
    ruleId          : Optional[str]  = None
    steps           : Optional[List[AutomationStepRequest]] = Field(default_factory=list)
    priority        : Optional[int]  = 100
    createdAt       : str
    enabled         : Optional[bool] = True
    category        : Optional[str]  = ""
    author          : Optional[str]  = ""
    updatedAt       : Optional[str]  = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.projectId or not self.projectId.strip():
            errors.append("projectId must not be empty.")
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        elif self.status.strip().upper() not in _VALID_STATUS:
            errors.append(
                f"status must be one of {sorted(_VALID_STATUS)}; got {self.status!r}."
            )
        if not self.trigger or not self.trigger.strip():
            errors.append("trigger must not be empty.")
        elif self.trigger.strip().upper() not in _VALID_TRIGGER:
            errors.append(
                f"trigger must be one of {sorted(_VALID_TRIGGER)}; got {self.trigger!r}."
            )
        if not isinstance(self.priority, int) or self.priority < 1:
            errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        for i, s in enumerate(self.steps or []):
            for e in s.validate_request():
                errors.append(f"steps[{i}]: {e}")
        return errors


class UpdateAutomationRequest(BaseModel):
    """PUT /api/v2/workflow/automation/{automationId}"""
    name            : Optional[str]  = None
    description     : Optional[str]  = None
    status          : Optional[str]  = None
    trigger         : Optional[str]  = None
    projectId       : Optional[str]  = None
    investigationId : Optional[str]  = None
    playbookId      : Optional[str]  = None
    ruleId          : Optional[str]  = None
    steps           : Optional[List[AutomationStepRequest]] = None
    priority        : Optional[int]  = None
    enabled         : Optional[bool] = None
    category        : Optional[str]  = None
    author          : Optional[str]  = None
    updatedAt       : Optional[str]  = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(v is not None for v in self.model_dump().values())

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if self.status is not None:
            if not self.status.strip():
                errors.append("status must not be empty.")
            elif self.status.strip().upper() not in _VALID_STATUS:
                errors.append(
                    f"status must be one of {sorted(_VALID_STATUS)}; got {self.status!r}."
                )
        if self.trigger is not None:
            if not self.trigger.strip():
                errors.append("trigger must not be empty.")
            elif self.trigger.strip().upper() not in _VALID_TRIGGER:
                errors.append(
                    f"trigger must be one of {sorted(_VALID_TRIGGER)}; got {self.trigger!r}."
                )
        if self.priority is not None and (not isinstance(self.priority, int) or self.priority < 1):
            errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if self.steps is not None:
            for i, s in enumerate(self.steps):
                for e in s.validate_request():
                    errors.append(f"steps[{i}]: {e}")
        return errors


# ===========================================================================
# Response models
# ===========================================================================

class AutomationResponse(BaseModel):
    """Full Automation response. Mirrors Prisma Automation + steps."""
    automationId    : str
    automationKey   : str           # derived, stored in metadata
    name            : str
    description     : str
    status          : str           # AutomationStatus
    trigger         : str           # AutomationTriggerType
    projectId       : str
    investigationId : str
    playbookId      : str
    ruleId          : str
    steps           : List[AutomationStepResponse]
    priority        : int
    createdAt       : str
    updatedAt       : Optional[str] = None
    enabled         : bool          = True
    category        : str           = ""
    author          : str           = ""

    class Config:
        frozen = True


class AutomationListResponse(BaseModel):
    automations : List[AutomationResponse]
    total       : int

    class Config:
        frozen = True


class AutomationStatisticsResponse(BaseModel):
    totalAutomations   : int
    enabledAutomations : int
    disabledAutomations: int
    totalExecutions    : int
    averageSteps       : float
    averageExecutions  : float
    averagePriority    : float
    categoryCounts     : Dict[str, int]

    class Config:
        frozen = True


class AutomationSearchResponse(BaseModel):
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
# Bulk operation models
# ===========================================================================

class BulkCreateAutomationsRequest(BaseModel):
    automations : List[CreateAutomationRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.automations:
            errors.append("automations list must not be empty.")
        for i, item in enumerate(self.automations):
            for e in item.validate_request():
                errors.append(f"automations[{i}]: {e}")
        return errors


class BulkUpdateAutomationsRequest(BaseModel):
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
            for e in item.update.validate_request():
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteAutomationsRequest(BaseModel):
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
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
