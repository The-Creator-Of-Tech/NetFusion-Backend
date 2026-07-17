"""
Playbook API Models — Canonical Schema (Aligned with Prisma)
=============================================================
All fields derived from the Prisma Playbook / PlaybookStep models.

Prisma canonical types used here:
  - Playbook.severity  → RuleSeverity  (LOW | MEDIUM | HIGH | CRITICAL)
  - Playbook.status    → PlaybookStatus (DRAFT | ACTIVE | DEPRECATED | ARCHIVED)
  - PlaybookStep.stepType → StepType subset
      (MANUAL | AUTOMATED | VERIFICATION | CONTAINMENT | ERADICATION | RECOVERY)

Fields NOT in Prisma that are API-only (derived / computed, never persisted as columns):
  - playbookKey   — SHA-256 identity key, stored in metadata
  - relatedThreatActors / relatedCampaigns — stored in metadata Json column

Fields present in Prisma but NOT exposed on Create/Update requests
(filled by the service / persistence layer):
  - createdBy, updatedBy, version, deletedAt, metadata
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Valid enum sets (mirror Prisma enums exactly)
# ---------------------------------------------------------------------------

_VALID_SEVERITY  = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_VALID_STATUS    = {"DRAFT", "ACTIVE", "DEPRECATED", "ARCHIVED"}
_VALID_STEP_TYPE = {
    "MANUAL", "AUTOMATED", "VERIFICATION",
    "CONTAINMENT", "ERADICATION", "RECOVERY",
}


# ===========================================================================
# Step sub-models
# ===========================================================================

class PlaybookStepRequest(BaseModel):
    """Request model for a single PlaybookStep."""
    stepNumber        : int
    title             : str
    description       : str           = ""
    stepType          : str           # StepType enum value
    executor          : Optional[str] = None
    expectedOutcome   : str           = ""
    relatedTechniques : Optional[List[str]] = Field(default_factory=list)
    relatedCVEs       : Optional[List[str]] = Field(default_factory=list)
    relatedIOCs       : Optional[List[str]] = Field(default_factory=list)
    createdAt         : str
    config            : Optional[Dict[str, Any]] = None

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


class PlaybookStepResponse(BaseModel):
    """Response model for a single PlaybookStep (mirrors Prisma PlaybookStep)."""
    stepId            : str
    stepKey           : str           # derived, stored in metadata
    stepNumber        : int
    title             : str
    description       : str
    stepType          : str           # StepType
    executor          : Optional[str] = None
    expectedOutcome   : str
    relatedTechniques : List[str]
    relatedCVEs       : List[str]
    relatedIOCs       : List[str]
    createdAt         : str
    config            : Optional[Dict[str, Any]] = None

    class Config:
        frozen = True


# ===========================================================================
# Summary response
# ===========================================================================

class PlaybookSummaryResponse(BaseModel):
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
# Create / Update requests
# ===========================================================================

class CreatePlaybookRequest(BaseModel):
    """
    POST /api/v2/workflow/playbooks

    projectId is required in the Prisma schema (non-nullable UUID).
    investigationId is optional (nullable UUID in Prisma).
    relatedThreatActors / relatedCampaigns are stored in Prisma's metadata Json.
    """
    name                : str                 = ""
    description         : Optional[str]       = ""
    severity            : str                 = ""  # RuleSeverity
    status              : str                 = ""  # PlaybookStatus
    projectId           : Optional[str]       = ""  # required by Prisma — validated in validate_request()
    investigationId     : Optional[str]       = None
    steps               : Optional[List[PlaybookStepRequest]] = Field(default_factory=list)
    relatedThreatActors : Optional[List[str]] = Field(default_factory=list)
    relatedCampaigns    : Optional[List[str]] = Field(default_factory=list)
    confidence          : float               = 100.0
    createdAt           : Optional[str]       = ""
    enabled             : Optional[bool]      = True
    priority            : Optional[int]       = 1
    category            : Optional[str]       = ""
    author              : Optional[str]       = ""
    updatedAt           : Optional[str]       = None

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
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
            errors.append(
                f"confidence={self.confidence!r} must be a float in [0.0, 100.0]."
            )
        for i, step in enumerate(self.steps or []):
            for e in step.validate_request():
                errors.append(f"steps[{i}]: {e}")
        return errors


class UpdatePlaybookRequest(BaseModel):
    """PUT /api/v2/workflow/playbooks/{playbookId}"""
    name                : Optional[str]       = None
    description         : Optional[str]       = None
    severity            : Optional[str]       = None
    status              : Optional[str]       = None
    projectId           : Optional[str]       = None
    investigationId     : Optional[str]       = None
    steps               : Optional[List[PlaybookStepRequest]] = None
    relatedThreatActors : Optional[List[str]] = None
    relatedCampaigns    : Optional[List[str]] = None
    confidence          : Optional[float]     = None
    enabled             : Optional[bool]      = None
    priority            : Optional[int]       = None
    category            : Optional[str]       = None
    author              : Optional[str]       = None
    updatedAt           : Optional[str]       = None

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
        if self.confidence is not None:
            if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 100.0):
                errors.append(
                    f"confidence={self.confidence!r} must be a float in [0.0, 100.0]."
                )
        if self.steps is not None:
            for i, step in enumerate(self.steps):
                for e in step.validate_request():
                    errors.append(f"steps[{i}]: {e}")
        return errors


# ===========================================================================
# Response models
# ===========================================================================

class PlaybookResponse(BaseModel):
    """
    Full Playbook response. Mirrors Prisma Playbook + computed API fields.
    relatedThreatActors / relatedCampaigns are round-tripped via metadata.
    """
    playbookId          : str
    playbookKey         : str           # derived
    name                : str
    description         : str
    severity            : str           # RuleSeverity
    status              : str           # PlaybookStatus
    projectId           : str
    investigationId     : str
    steps               : List[PlaybookStepResponse]
    relatedThreatActors : List[str]     # stored in metadata
    relatedCampaigns    : List[str]     # stored in metadata
    confidence          : float
    createdAt           : str
    updatedAt           : Optional[str] = None
    enabled             : bool          = True
    priority            : int           = 1
    category            : str           = ""
    author              : str           = ""

    class Config:
        frozen = True


class PlaybookListResponse(BaseModel):
    playbooks : List[PlaybookResponse]
    total     : int

    class Config:
        frozen = True


class PlaybookStatisticsResponse(BaseModel):
    totalPlaybooks    : int
    enabledPlaybooks  : int
    disabledPlaybooks : int
    averageSteps      : float
    averagePriority   : float
    categoryCounts    : Dict[str, int]

    class Config:
        frozen = True


class PlaybookSearchResponse(BaseModel):
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
# Bulk operation models
# ===========================================================================

class BulkCreatePlaybooksRequest(BaseModel):
    playbooks : List[CreatePlaybookRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.playbooks:
            errors.append("playbooks list must not be empty.")
        for i, item in enumerate(self.playbooks):
            for e in item.validate_request():
                errors.append(f"playbooks[{i}]: {e}")
        return errors


class BulkUpdatePlaybooksRequest(BaseModel):
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
            for e in item.update.validate_request():
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeletePlaybooksRequest(BaseModel):
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
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
