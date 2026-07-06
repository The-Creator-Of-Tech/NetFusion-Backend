"""
Rules API Models — Phase A4.10.2
==================================
Immutable Pydantic models for Rules request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class RuleConditionRequest(BaseModel):
    """
    Request model representing a rule condition to evaluate.
    """
    field      : str
    operator   : str
    value      : str
    createdAt  : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.field or not self.field.strip():
            errors.append("field must not be empty.")
        if not self.operator or not self.operator.strip():
            errors.append("operator must not be empty.")
        if not self.value or not self.value.strip():
            errors.append("value must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class RuleConditionResponse(BaseModel):
    """
    Response model representing a rule condition.
    """
    conditionId  : str
    conditionKey : str
    field        : str
    operator     : str
    value        : str
    createdAt    : str

    class Config:
        frozen = True


class RuleActionRequest(BaseModel):
    """
    Request model representing an action triggered by matching a rule.
    """
    actionType : str
    parameters : Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.actionType or not self.actionType.strip():
            errors.append("actionType must not be empty.")
        else:
            from services.rules_engine_service import RuleActionEnum
            try:
                RuleActionEnum(self.actionType.strip().upper())
            except ValueError:
                errors.append(f"actionType must be a RuleActionEnum member; got {self.actionType!r}.")
        return errors


class RuleActionResponse(BaseModel):
    """
    Response model representing a triggered action.
    """
    actionId   : str
    actionType : str
    parameters : Dict[str, Any]

    class Config:
        frozen = True


class RuleSummaryResponse(BaseModel):
    """
    Response model carrying structured summary details for a rule.
    """
    ruleId         : str
    ruleName       : str
    summaryText    : str
    conditionCount : int
    actionCount    : int
    severity       : str
    status         : str
    enabled        : bool
    priority       : int

    class Config:
        frozen = True


# ===========================================================================
# Request Models
# ===========================================================================

class CreateRuleRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/rules.
    """
    name            : str
    description     : Optional[str] = ""
    severity        : str
    status          : str
    conditions      : Optional[List[RuleConditionRequest]] = Field(default_factory=list)
    actions         : Optional[List[RuleActionRequest]] = Field(default_factory=list)
    priority        : Optional[int] = 100
    createdAt       : str
    enabled         : Optional[bool] = True
    category        : Optional[str] = ""
    author          : Optional[str] = ""
    projectId       : Optional[str] = ""
    investigationId : Optional[str] = ""
    updatedAt       : Optional[str] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.severity or not self.severity.strip():
            errors.append("severity must not be empty.")
        else:
            from services.rules_engine_service import RuleSeverityEnum
            try:
                RuleSeverityEnum(self.severity.strip().upper())
            except ValueError:
                errors.append(f"severity must be a RuleSeverityEnum member; got {self.severity!r}.")
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        else:
            from services.rules_engine_service import RuleStatusEnum
            try:
                RuleStatusEnum(self.status.strip().upper())
            except ValueError:
                errors.append(f"status must be a RuleStatusEnum member; got {self.status!r}.")
        if not isinstance(self.priority, int) or self.priority < 1:
            errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")

        for i, c in enumerate(self.conditions or []):
            sub = c.validate_request()
            for e in sub:
                errors.append(f"conditions[{i}]: {e}")
        for i, a in enumerate(self.actions or []):
            sub = a.validate_request()
            for e in sub:
                errors.append(f"actions[{i}]: {e}")
        return errors


class UpdateRuleRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/rules/{ruleId}.
    """
    name            : Optional[str] = None
    description     : Optional[str] = None
    severity        : Optional[str] = None
    status          : Optional[str] = None
    conditions      : Optional[List[RuleConditionRequest]] = None
    actions         : Optional[List[RuleActionRequest]] = None
    priority        : Optional[int] = None
    enabled         : Optional[bool] = None
    category        : Optional[str] = None
    author          : Optional[str] = None
    projectId       : Optional[str] = None
    investigationId : Optional[str] = None
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
        if self.severity is not None:
            if not self.severity.strip():
                errors.append("severity must not be empty.")
            else:
                from services.rules_engine_service import RuleSeverityEnum
                try:
                    RuleSeverityEnum(self.severity.strip().upper())
                except ValueError:
                    errors.append(f"severity must be a RuleSeverityEnum member; got {self.severity!r}.")
        if self.status is not None:
            if not self.status.strip():
                errors.append("status must not be empty.")
            else:
                from services.rules_engine_service import RuleStatusEnum
                try:
                    RuleStatusEnum(self.status.strip().upper())
                except ValueError:
                    errors.append(f"status must be a RuleStatusEnum member; got {self.status!r}.")
        if self.priority is not None:
            if not isinstance(self.priority, int) or self.priority < 1:
                errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if self.conditions is not None:
            for i, c in enumerate(self.conditions):
                sub = c.validate_request()
                for e in sub:
                    errors.append(f"conditions[{i}]: {e}")
        if self.actions is not None:
            for i, a in enumerate(self.actions):
                sub = a.validate_request()
                for e in sub:
                    errors.append(f"actions[{i}]: {e}")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class RuleResponse(BaseModel):
    """
    Response model carrying rule details.
    """
    ruleId          : str
    ruleKey         : str
    name            : str
    description     : str
    severity        : str
    status          : str
    conditions      : List[RuleConditionResponse]
    actions         : List[RuleActionResponse]
    priority        : int
    createdAt       : str
    updatedAt       : Optional[str] = None
    enabled         : bool = True
    category        : str = ""
    author          : str = ""
    projectId       : str = ""
    investigationId : str = ""

    class Config:
        frozen = True


class RuleListResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/rules.
    """
    rules : List[RuleResponse]
    total : int

    class Config:
        frozen = True


class RuleStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/rules/statistics.
    """
    totalRules        : int
    enabledRules      : int
    disabledRules     : int
    averageConditions : float
    averageActions    : float
    averagePriority   : float
    categoryCounts    : Dict[str, int]

    class Config:
        frozen = True


class RuleSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/workflow/rules/search.
    """
    rules      : List[RuleResponse]
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

class BulkCreateRulesRequest(BaseModel):
    """
    Request body for POST /api/v2/workflow/rules/bulk/create.
    """
    rules : List[CreateRuleRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.rules:
            errors.append("rules list must not be empty.")
        for i, item in enumerate(self.rules):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"rules[{i}]: {e}")
        return errors


class BulkUpdateRulesRequest(BaseModel):
    """
    Request body for PUT /api/v2/workflow/rules/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        ruleId : str
        update : UpdateRuleRequest

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
            if not item.ruleId or not item.ruleId.strip():
                errors.append(f"items[{i}]: ruleId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteRulesRequest(BaseModel):
    """
    Request body for DELETE /api/v2/workflow/rules/bulk/delete.
    """
    ruleIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.ruleIds:
            errors.append("ruleIds list must not be empty.")
        for i, rid in enumerate(self.ruleIds):
            if not rid or not rid.strip():
                errors.append(f"ruleIds[{i}]: ruleId must not be empty.")
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
