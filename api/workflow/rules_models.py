"""
Rules API Models — Canonical Schema (Aligned with Prisma)
==========================================================
All fields derived from Prisma Rule / RuleCondition / RuleAction models.

Prisma canonical types:
  - Rule.severity → RuleSeverity  (LOW | MEDIUM | HIGH | CRITICAL)
  - Rule.status   → RuleStatus    (DRAFT | ACTIVE | DISABLED | ARCHIVED)
  - RuleAction.actionType → plain String (no Prisma enum constraint)
  - RuleCondition.operator → plain String

API-only derived fields (not Prisma columns, stored in metadata):
  - ruleKey, conditionKey

Fields present in Prisma but not exposed in requests:
  - createdBy, updatedBy, version, deletedAt, metadata
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

_VALID_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VALID_STATUS   = {"DRAFT", "ACTIVE", "DISABLED", "ARCHIVED"}


# ===========================================================================
# Condition sub-models
# ===========================================================================

class RuleConditionRequest(BaseModel):
    """Maps to Prisma RuleCondition (field, operator, value)."""
    field     : str
    operator  : str
    value     : str
    createdAt : str

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
    Prisma RuleCondition columns + API-only derived fields.
    conditionId  → Prisma id (UUID)
    conditionKey → derived (SHA-256), stored in metadata
    """
    conditionId  : str
    conditionKey : str
    field        : str
    operator     : str
    value        : str
    createdAt    : str

    class Config:
        frozen = True


# ===========================================================================
# Action sub-models
# ===========================================================================

class RuleActionRequest(BaseModel):
    """
    Maps to Prisma RuleAction (actionType String, parameters Json?).
    actionType is a free String in Prisma — no enum constraint at DB level.
    """
    actionType : str
    parameters : Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.actionType or not self.actionType.strip():
            errors.append("actionType must not be empty.")
        return errors


class RuleActionResponse(BaseModel):
    """
    Prisma RuleAction columns + API-only derived actionId alias.
    actionId → Prisma id (UUID)
    """
    actionId   : str
    actionType : str
    parameters : Dict[str, Any]

    class Config:
        frozen = True


# ===========================================================================
# Summary response
# ===========================================================================

class RuleSummaryResponse(BaseModel):
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
# Create / Update requests
# ===========================================================================

class CreateRuleRequest(BaseModel):
    """
    POST /api/v2/workflow/rules
    projectId is required in Prisma (non-nullable UUID).
    """
    name            : str
    description     : Optional[str]                 = ""
    severity        : str                           # RuleSeverity
    status          : str                           # RuleStatus
    projectId       : str                           # required — Prisma non-nullable
    investigationId : Optional[str]                 = None
    conditions      : Optional[List[RuleConditionRequest]] = Field(default_factory=list)
    actions         : Optional[List[RuleActionRequest]]    = Field(default_factory=list)
    priority        : Optional[int]                 = 100
    createdAt       : str
    enabled         : Optional[bool]                = True
    category        : Optional[str]                 = ""
    author          : Optional[str]                 = ""
    updatedAt       : Optional[str]                 = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.projectId or not self.projectId.strip():
            errors.append("projectId must not be empty.")
        if not self.severity or not self.severity.strip():
            errors.append("severity must not be empty.")
        elif self.severity.strip().upper() not in _VALID_SEVERITY:
            errors.append(
                f"severity must be one of {sorted(_VALID_SEVERITY)}; got {self.severity!r}."
            )
        if not self.status or not self.status.strip():
            errors.append("status must not be empty.")
        elif self.status.strip().upper() not in _VALID_STATUS:
            errors.append(
                f"status must be one of {sorted(_VALID_STATUS)}; got {self.status!r}."
            )
        if not isinstance(self.priority, int) or self.priority < 1:
            errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        for i, c in enumerate(self.conditions or []):
            for e in c.validate_request():
                errors.append(f"conditions[{i}]: {e}")
        for i, a in enumerate(self.actions or []):
            for e in a.validate_request():
                errors.append(f"actions[{i}]: {e}")
        return errors


class UpdateRuleRequest(BaseModel):
    """PUT /api/v2/workflow/rules/{ruleId}"""
    name            : Optional[str]                 = None
    description     : Optional[str]                 = None
    severity        : Optional[str]                 = None
    status          : Optional[str]                 = None
    projectId       : Optional[str]                 = None
    investigationId : Optional[str]                 = None
    conditions      : Optional[List[RuleConditionRequest]] = None
    actions         : Optional[List[RuleActionRequest]]    = None
    priority        : Optional[int]                 = None
    enabled         : Optional[bool]                = None
    category        : Optional[str]                 = None
    author          : Optional[str]                 = None
    updatedAt       : Optional[str]                 = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(v is not None for v in self.model_dump().values())

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if self.severity is not None:
            if not self.severity.strip():
                errors.append("severity must not be empty.")
            elif self.severity.strip().upper() not in _VALID_SEVERITY:
                errors.append(
                    f"severity must be one of {sorted(_VALID_SEVERITY)}; got {self.severity!r}."
                )
        if self.status is not None:
            if not self.status.strip():
                errors.append("status must not be empty.")
            elif self.status.strip().upper() not in _VALID_STATUS:
                errors.append(
                    f"status must be one of {sorted(_VALID_STATUS)}; got {self.status!r}."
                )
        if self.priority is not None and (not isinstance(self.priority, int) or self.priority < 1):
            errors.append(f"priority={self.priority!r} must be a positive integer (>= 1).")
        if self.conditions is not None:
            for i, c in enumerate(self.conditions):
                for e in c.validate_request():
                    errors.append(f"conditions[{i}]: {e}")
        if self.actions is not None:
            for i, a in enumerate(self.actions):
                for e in a.validate_request():
                    errors.append(f"actions[{i}]: {e}")
        return errors


# ===========================================================================
# Response models
# ===========================================================================

class RuleResponse(BaseModel):
    """Full Rule response. Mirrors Prisma Rule + conditions + actions."""
    ruleId          : str
    ruleKey         : str           # derived, stored in metadata
    name            : str
    description     : str
    severity        : str           # RuleSeverity
    status          : str           # RuleStatus
    projectId       : str
    investigationId : str
    conditions      : List[RuleConditionResponse]
    actions         : List[RuleActionResponse]
    priority        : int
    createdAt       : str
    updatedAt       : Optional[str] = None
    enabled         : bool          = True
    category        : str           = ""
    author          : str           = ""

    class Config:
        frozen = True


class RuleListResponse(BaseModel):
    rules : List[RuleResponse]
    total : int

    class Config:
        frozen = True


class RuleStatisticsResponse(BaseModel):
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
# Bulk operation models
# ===========================================================================

class BulkCreateRulesRequest(BaseModel):
    rules : List[CreateRuleRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.rules:
            errors.append("rules list must not be empty.")
        for i, item in enumerate(self.rules):
            for e in item.validate_request():
                errors.append(f"rules[{i}]: {e}")
        return errors


class BulkUpdateRulesRequest(BaseModel):
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
            for e in item.update.validate_request():
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteRulesRequest(BaseModel):
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
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
