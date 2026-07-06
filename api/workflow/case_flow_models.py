"""
Case Flow API Models — Phase A4.10.4
====================================
Immutable Pydantic models for Case Flow request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class CaseFlowStepRequest(BaseModel):
    """
    Request model representing a step within a case flow.
    """
    stepNumber  : int
    stepType    : str
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
        else:
            from services.case_flow_service import CaseStepTypeEnum
            try:
                CaseStepTypeEnum(self.stepType.strip().upper())
            except ValueError:
                errors.append(f"stepType must be a CaseStepTypeEnum member; got {self.stepType!r}.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class CaseFlowStepResponse(BaseModel):
    """
    Response model representing a case flow step.
    """
    stepId      : str
    stepKey     : str
    stepNumber  : int
    stepType    : str
    title       : str
    description : str
    assignedTo  : str
    createdAt   : str

    class Config:
        frozen = True


class CaseFlowExecutionResponse(BaseModel):
    """
    Response model carrying case flow execution logs.
    """
    executionId : str
    caseFlowId  : str
    status      : str
    startedAt   : str
    completedAt : str
    stepResults : List[Dict[str, Any]]

    class Config:
        frozen = True


class CaseFlowSummaryResponse(BaseModel):
    """
    Response model carrying structured summary details for a case flow.
    """
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
# Request Models
# ===========================================================================

class CreateCaseFlowRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/case-flow.
    """
    title           : str
    description     : Optional[str] = ""
    status          : str
    priority        : str
    steps           : Optional[List[CaseFlowStepRequest]] = Field(default_factory=list)
    findingIds      : Optional[List[str]] = Field(default_factory=list)
    alertIds        : Optional[List[str]] = Field(default_factory=list)
    evidenceIds     : Optional[List[str]] = Field(default_factory=list)
    playbookIds     : Optional[List[str]] = Field(default_factory=list)
    assignedTo      : Optional[str] = ""
    confidence      : Optional[float] = 100.0
    createdAt       : str
    projectId       : Optional[str] = ""
    investigationId : Optional[str] = ""
    automationId    : Optional[str] = ""
    owner           : Optional[str] = ""
    updatedAt       : Optional[str] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        else:
            from services.case_flow_service import CaseStatusEnum
            try:
                CaseStatusEnum(self.status.strip().upper())
            except ValueError:
                errors.append(f"status must be a CaseStatusEnum member; got {self.status!r}.")
        if not self.priority or not self.priority.strip():
            errors.append("priority must not be empty.")
        else:
            from services.case_flow_service import CasePriorityEnum
            try:
                CasePriorityEnum(self.priority.strip().upper())
            except ValueError:
                errors.append(f"priority must be a CasePriorityEnum member; got {self.priority!r}.")
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
                errors.append(f"confidence={self.confidence!r} must be a float in [0.0, 100.0].")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")

        for i, s in enumerate(self.steps or []):
            sub = s.validate_request()
            for e in sub:
                errors.append(f"steps[{i}]: {e}")
        return errors


class UpdateCaseFlowRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/case-flow/{caseFlowId}.
    """
    title           : Optional[str] = None
    description     : Optional[str] = None
    status          : Optional[str] = None
    priority        : Optional[str] = None
    steps           : Optional[List[CaseFlowStepRequest]] = None
    findingIds      : Optional[List[str]] = None
    alertIds        : Optional[List[str]] = None
    evidenceIds     : Optional[List[str]] = None
    playbookIds     : Optional[List[str]] = None
    assignedTo      : Optional[str] = None
    confidence      : Optional[float] = None
    projectId       : Optional[str] = None
    investigationId : Optional[str] = None
    automationId    : Optional[str] = None
    owner           : Optional[str] = None
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
                from services.case_flow_service import CaseStatusEnum
                try:
                    CaseStatusEnum(self.status.strip().upper())
                except ValueError:
                    errors.append(f"status must be a CaseStatusEnum member; got {self.status!r}.")
        if self.priority is not None:
            if not self.priority.strip():
                errors.append("priority must not be empty.")
            else:
                from services.case_flow_service import CasePriorityEnum
                try:
                    CasePriorityEnum(self.priority.strip().upper())
                except ValueError:
                    errors.append(f"priority must be a CasePriorityEnum member; got {self.priority!r}.")
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
                errors.append(f"confidence={self.confidence!r} must be a float in [0.0, 100.0].")
        if self.steps is not None:
            for i, s in enumerate(self.steps):
                sub = s.validate_request()
                for e in sub:
                    errors.append(f"steps[{i}]: {e}")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class CaseFlowResponse(BaseModel):
    """
    Response model carrying case flow details.
    """
    caseFlowId      : str
    caseFlowKey     : str
    caseNumber      : str
    title           : str
    description     : str
    status          : str
    priority        : str
    steps           : List[CaseFlowStepResponse]
    findingIds      : List[str]
    alertIds        : List[str]
    evidenceIds     : List[str]
    playbookIds     : List[str]
    assignedTo      : str
    confidence      : float
    createdAt       : str
    updatedAt       : Optional[str] = None
    projectId       : str = ""
    investigationId : str = ""
    automationId    : str = ""
    owner           : str = ""

    class Config:
        frozen = True


class CaseFlowListResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/case-flow.
    """
    caseFlows : List[CaseFlowResponse]
    total     : int

    class Config:
        frozen = True


class CaseFlowStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/case-flow/statistics.
    """
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
    """
    Payload for GET /api/v2/workflow/case-flow/search.
    """
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
# Bulk Operation Models
# ===========================================================================

class BulkCreateCaseFlowsRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/case-flow/bulk/create.
    """
    caseFlows : List[CreateCaseFlowRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.caseFlows:
            errors.append("caseFlows list must not be empty.")
        for i, item in enumerate(self.caseFlows):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"caseFlows[{i}]: {e}")
        return errors


class BulkUpdateCaseFlowsRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/case-flow/bulk/update.
    """
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
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteCaseFlowsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/workflow/case-flow/bulk/delete.
    """
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
