"""
Case Flow API Models — Canonical Schema (Aligned with Prisma)
=============================================================
All fields derived from Prisma CaseFlow / CaseFlowStep / CaseFlowExecution.

Prisma canonical types:
  - CaseFlow.status    → CaseStatus    (OPEN | IN_PROGRESS | ON_HOLD | RESOLVED | CLOSED)
  - CaseFlow.priority  → CasePriority  (LOW | MEDIUM | HIGH | CRITICAL)
  - CaseFlowStep.stepType → StepType (case-flow subset)
      (CREATED | ASSIGNED | INVESTIGATED | RECOVERED | CLOSED |
       MANUAL — also valid for case steps)
  - CaseFlowExecution.status → CaseExecutionStatus
      (PENDING | ACTIVE | COMPLETED | FAILED)

API-only derived fields (not Prisma columns, stored in metadata):
  - caseFlowKey, caseNumber

Note: investigationId is non-nullable in Prisma CaseFlow (required).
      playbookId and automationId are optional FK relations.

Fields present in Prisma but not in requests:
  - createdBy, updatedBy, version, deletedAt, metadata
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

_VALID_STATUS   = {"OPEN", "IN_PROGRESS", "ON_HOLD", "RESOLVED", "CLOSED"}
_VALID_PRIORITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
# StepType values valid for CaseFlowStep (Prisma StepType enum)
_VALID_STEP_TYPE = {
    "CREATED", "ASSIGNED", "INVESTIGATED",
    "CONTAINED", "ERADICATED",            # now in Prisma StepType
    "RECOVERED", "CLOSED",
    # Playbook step types are also in StepType and may be used for case steps
    "MANUAL", "AUTOMATED", "VERIFICATION", "CONTAINMENT", "ERADICATION",
}
# CaseFlowExecution.status
_VALID_EXEC_STATUS = {"PENDING", "ACTIVE", "COMPLETED", "FAILED"}


# ===========================================================================
# Step sub-models
# ===========================================================================

class CaseFlowStepRequest(BaseModel):
    """Maps to Prisma CaseFlowStep (stepNumber, stepKey, stepType, title, description, assignedTo)."""
    stepNumber  : int
    stepType    : str           # StepType (case-flow subset)
    title       : str
    description : Optional[str] = ""
    assignedTo  : Optional[str] = ""
    createdAt   : str

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
        elif self.stepType.strip().upper() not in _VALID_STEP_TYPE:
            errors.append(
                f"stepType must be one of {sorted(_VALID_STEP_TYPE)}; got {self.stepType!r}."
            )
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class CaseFlowStepResponse(BaseModel):
    """Prisma CaseFlowStep columns + API-only derived fields."""
    stepId      : str
    stepKey     : str           # Prisma CaseFlowStep.stepKey column
    stepNumber  : int
    stepType    : str           # StepType
    title       : str
    description : str
    assignedTo  : str
    createdAt   : str

    class Config:
        frozen = True


# ===========================================================================
# Execution response
# ===========================================================================

class CaseFlowExecutionResponse(BaseModel):
    """
    Mirrors Prisma CaseFlowExecution.
    status uses CaseExecutionStatus: PENDING | ACTIVE | COMPLETED | FAILED
    """
    executionId : str
    caseFlowId  : str
    status      : str       # CaseExecutionStatus
    startedAt   : str
    completedAt : str
    stepResults : List[Dict[str, Any]]

    class Config:
        frozen = True


# ===========================================================================
# Summary response
# ===========================================================================

class CaseFlowSummaryResponse(BaseModel):
    caseFlowId     : str
    caseName       : str
    summaryText    : str
    stepCount      : int
    executionCount : int
    status         : str
    priority       : str
    owner          : str
    confidence     : float

    class Config:
        frozen = True


# ===========================================================================
# Create / Update requests
# ===========================================================================

class CreateCaseFlowRequest(BaseModel):
    """
    POST /api/v2/workflow/case-flow

    Both projectId and investigationId are required in Prisma (non-nullable).
    playbookId and automationId are optional FK relations.
    findingIds, alertIds, evidenceIds, playbookIds are String[] columns.
    """
    title           : str
    description     : Optional[str]       = ""
    status          : str                 # CaseStatus
    priority        : str                 # CasePriority
    projectId       : str                 # required — Prisma non-nullable
    investigationId : str                 # required — Prisma non-nullable
    playbookId      : Optional[str]       = None
    automationId    : Optional[str]       = None
    steps           : Optional[List[CaseFlowStepRequest]] = Field(default_factory=list)
    findingIds      : Optional[List[str]] = Field(default_factory=list)
    alertIds        : Optional[List[str]] = Field(default_factory=list)
    evidenceIds     : Optional[List[str]] = Field(default_factory=list)
    playbookIds     : Optional[List[str]] = Field(default_factory=list)
    assignedTo      : Optional[str]       = ""
    owner           : Optional[str]       = ""
    confidence      : Optional[float]     = 100.0
    createdAt       : str
    updatedAt       : Optional[str]       = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.projectId or not self.projectId.strip():
            errors.append("projectId must not be empty.")
        if not self.investigationId or not self.investigationId.strip():
            errors.append("investigationId must not be empty.")
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        elif self.status.strip().upper() not in _VALID_STATUS:
            errors.append(
                f"status must be one of {sorted(_VALID_STATUS)}; got {self.status!r}."
            )
        if not self.priority or not self.priority.strip():
            errors.append("priority must not be empty.")
        elif self.priority.strip().upper() not in _VALID_PRIORITY:
            errors.append(
                f"priority must be one of {sorted(_VALID_PRIORITY)}; got {self.priority!r}."
            )
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
                errors.append(
                    f"confidence={self.confidence!r} must be a float in [0.0, 100.0]."
                )
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        for i, s in enumerate(self.steps or []):
            for e in s.validate_request():
                errors.append(f"steps[{i}]: {e}")
        return errors


class UpdateCaseFlowRequest(BaseModel):
    """PUT /api/v2/workflow/case-flow/{caseFlowId}"""
    title           : Optional[str]       = None
    description     : Optional[str]       = None
    status          : Optional[str]       = None
    priority        : Optional[str]       = None
    projectId       : Optional[str]       = None
    investigationId : Optional[str]       = None
    playbookId      : Optional[str]       = None
    automationId    : Optional[str]       = None
    steps           : Optional[List[CaseFlowStepRequest]] = None
    findingIds      : Optional[List[str]] = None
    alertIds        : Optional[List[str]] = None
    evidenceIds     : Optional[List[str]] = None
    playbookIds     : Optional[List[str]] = None
    assignedTo      : Optional[str]       = None
    owner           : Optional[str]       = None
    confidence      : Optional[float]     = None
    updatedAt       : Optional[str]       = None

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
        if self.priority is not None:
            if not self.priority.strip():
                errors.append("priority must not be empty.")
            elif self.priority.strip().upper() not in _VALID_PRIORITY:
                errors.append(
                    f"priority must be one of {sorted(_VALID_PRIORITY)}; got {self.priority!r}."
                )
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
                errors.append(
                    f"confidence={self.confidence!r} must be a float in [0.0, 100.0]."
                )
        if self.steps is not None:
            for i, s in enumerate(self.steps):
                for e in s.validate_request():
                    errors.append(f"steps[{i}]: {e}")
        return errors


# ===========================================================================
# Response models
# ===========================================================================

class CaseFlowResponse(BaseModel):
    """
    Full CaseFlow response. Mirrors Prisma CaseFlow + steps.
    caseFlowKey / caseNumber are API-only derived fields (stored in metadata).
    """
    caseFlowId      : str
    caseFlowKey     : str           # derived, stored in metadata
    caseNumber      : str           # derived, stored in metadata
    title           : str
    description     : str
    status          : str           # CaseStatus
    priority        : str           # CasePriority
    projectId       : str
    investigationId : str
    playbookId      : str
    automationId    : str
    steps           : List[CaseFlowStepResponse]
    findingIds      : List[str]
    alertIds        : List[str]
    evidenceIds     : List[str]
    playbookIds     : List[str]
    assignedTo      : str
    owner           : str
    confidence      : float
    createdAt       : str
    updatedAt       : Optional[str] = None

    class Config:
        frozen = True


class CaseFlowListResponse(BaseModel):
    caseFlows : List[CaseFlowResponse]
    total     : int

    class Config:
        frozen = True


class CaseFlowStatisticsResponse(BaseModel):
    totalCases        : int
    openCases         : int
    closedCases       : int
    inProgressCases   : int
    totalExecutions   : int
    averageSteps      : float
    averageExecutions : float
    averagePriority   : float
    statusCounts      : Dict[str, int]

    class Config:
        frozen = True


class CaseFlowSearchResponse(BaseModel):
    caseFlows  : List[CaseFlowResponse]
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
# Bulk operation models
# ===========================================================================

class BulkCreateCaseFlowsRequest(BaseModel):
    caseFlows : List[CreateCaseFlowRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.caseFlows:
            errors.append("caseFlows list must not be empty.")
        for i, item in enumerate(self.caseFlows):
            for e in item.validate_request():
                errors.append(f"caseFlows[{i}]: {e}")
        return errors


class BulkUpdateCaseFlowsRequest(BaseModel):
    class BulkUpdateItem(BaseModel):
        caseFlowId : str
        update     : UpdateCaseFlowRequest

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
            if not item.caseFlowId or not item.caseFlowId.strip():
                errors.append(f"items[{i}]: caseFlowId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            for e in item.update.validate_request():
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteCaseFlowsRequest(BaseModel):
    caseFlowIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.caseFlowIds:
            errors.append("caseFlowIds list must not be empty.")
        for i, aid in enumerate(self.caseFlowIds):
            if not aid or not aid.strip():
                errors.append(f"caseFlowIds[{i}]: caseFlowId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
