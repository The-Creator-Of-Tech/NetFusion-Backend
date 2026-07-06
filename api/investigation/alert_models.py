"""
Alert API Models — Phase A4.7.6 (Part A)
=========================================
Immutable Pydantic models for Alert API request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (non-empty strings,
  field presence).  Business-rule validation stays in alert_service.py.
- No UUID generation — alert IDs are derived deterministically by the
  alert engine from content keys.
- No timestamp generation — callers supply timestamps.
- No randomness.
- Response models mirror the shape of Alert from alert_service.py so that
  FastAPI can generate correct OpenAPI schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateAlertRequest(BaseModel):
    """
    Request body for POST /api/v2/alerts.

    Required fields
    ---------------
    projectId        : Owning project identifier.
    findingId        : Source finding that triggered this alert.
    investigationId  : Parent investigation identifier.
    title            : Human-readable alert title.
    createdBy        : Analyst / system identifier.
    createdAt        : ISO-8601 creation timestamp.

    Optional fields
    ---------------
    source           : Alert source (default "FINDING").
    severity         : Alert severity (default "MEDIUM").
    description      : Free-text description.
    confidence       : 0–100 confidence score.
    riskScore        : 0–100 risk score.
    assignedTo       : Assigned analyst identifier.
    assetIds         : Linked asset IDs.
    relationshipIds  : Linked relationship IDs.
    evidenceIds      : Linked evidence IDs.
    graphNodeIds     : Linked graph node IDs.
    timelineEventIds : Linked timeline event IDs.
    findingFingerprint       : Opaque fingerprint from the Finding Engine.
    investigationFingerprint : Opaque fingerprint from the Investigation Engine.
    graphFingerprint         : Opaque fingerprint from the Attack Graph Engine.
    reason                   : Explanation — why this alert was raised.
    findingSummary           : Explanation — summary of the source finding.
    affectedAssets           : Explanation — implicated asset IDs.
    recommendedAction        : Explanation — triage / remediation step.
    escalationReason         : Explanation — why the alert was escalated.
    relatedAlertIds          : Correlation — IDs of correlated alerts.
    relatedFindingIds        : Correlation — IDs of related findings.
    sharedEvidenceIds        : Correlation — evidence IDs shared across alerts.
    sharedAssets             : Correlation — asset IDs shared across alerts.
    correlationScore         : Correlation — 0–100 deterministic score.
    tags                     : Classification tags.
    metadata                 : Arbitrary key-value pairs.
    """
    projectId                : str
    findingId                : str
    investigationId          : str
    title                    : str
    createdBy                : str
    createdAt                : str
    source                   : Optional[str]              = "FINDING"
    severity                 : Optional[str]              = "MEDIUM"
    description              : Optional[str]              = ""
    confidence               : Optional[float]            = Field(default=0.0, ge=0, le=100)
    riskScore                : Optional[float]            = Field(default=0.0, ge=0, le=100)
    assignedTo               : Optional[str]              = None
    assetIds                 : Optional[List[str]]        = None
    relationshipIds          : Optional[List[str]]        = None
    evidenceIds              : Optional[List[str]]        = None
    graphNodeIds             : Optional[List[str]]        = None
    timelineEventIds         : Optional[List[str]]        = None
    findingFingerprint       : Optional[str]              = ""
    investigationFingerprint : Optional[str]              = ""
    graphFingerprint         : Optional[str]              = ""
    reason                   : Optional[str]              = ""
    findingSummary           : Optional[str]              = ""
    affectedAssets           : Optional[List[str]]        = None
    recommendedAction        : Optional[str]              = ""
    escalationReason         : Optional[str]              = ""
    relatedAlertIds          : Optional[List[str]]        = None
    relatedFindingIds        : Optional[List[str]]        = None
    sharedEvidenceIds        : Optional[List[str]]        = None
    sharedAssets             : Optional[List[str]]        = None
    correlationScore         : Optional[float]            = Field(default=0.0, ge=0, le=100)
    tags                     : Optional[List[str]]        = None
    metadata                 : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list means the request is valid.

        API-layer rules only:
        - projectId must be non-empty and non-whitespace.
        - findingId must be non-empty and non-whitespace.
        - investigationId must be non-empty and non-whitespace.
        - title must be non-empty and non-whitespace.
        - createdBy must be non-empty and non-whitespace.
        - createdAt must be non-empty and non-whitespace.
        """
        errors: List[str] = []
        if not self.projectId or not self.projectId.strip():
            errors.append("projectId must not be empty.")
        if not self.findingId or not self.findingId.strip():
            errors.append("findingId must not be empty.")
        if not self.investigationId or not self.investigationId.strip():
            errors.append("investigationId must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.createdBy or not self.createdBy.strip():
            errors.append("createdBy must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateAlertRequest(BaseModel):
    """
    Request body for PUT /api/v2/alerts/{alertId}.

    All fields are optional — supply only what should change.
    At least one field must be provided (validated at the route level).

    Mutable fields only — alertId, alertKey, projectId, findingId,
    investigationId, createdBy, createdAt, and engineVersion are immutable
    and cannot be changed through this endpoint.

    Fields
    ------
    title                    : New alert title.
    description              : New description.
    severity                 : New severity value.
    status                   : New lifecycle status.
    confidence               : New confidence score (0–100).
    riskScore                : New risk score (0–100).
    assignedTo               : Assign / reassign to an analyst.
    assetIds                 : Replace linked asset IDs.
    relationshipIds          : Replace linked relationship IDs.
    evidenceIds              : Replace linked evidence IDs.
    graphNodeIds             : Replace linked graph node IDs.
    timelineEventIds         : Replace linked timeline event IDs.
    findingFingerprint       : Update finding fingerprint.
    investigationFingerprint : Update investigation fingerprint.
    graphFingerprint         : Update graph fingerprint.
    reason                   : Update explanation reason.
    findingSummary           : Update explanation finding summary.
    affectedAssets           : Update explanation affected assets.
    recommendedAction        : Update explanation recommended action.
    escalationReason         : Update explanation escalation reason.
    relatedAlertIds          : Update correlation related alert IDs.
    relatedFindingIds        : Update correlation related finding IDs.
    sharedEvidenceIds        : Update correlation shared evidence IDs.
    sharedAssets             : Update correlation shared assets.
    correlationScore         : Update correlation score (0–100).
    tags                     : Replace classification tags.
    metadata                 : Merge / replace metadata key-value pairs.
    """
    title                    : Optional[str]              = None
    description              : Optional[str]              = None
    severity                 : Optional[str]              = None
    status                   : Optional[str]              = None
    confidence               : Optional[float]            = Field(default=None, ge=0, le=100)
    riskScore                : Optional[float]            = Field(default=None, ge=0, le=100)
    assignedTo               : Optional[str]              = None
    assetIds                 : Optional[List[str]]        = None
    relationshipIds          : Optional[List[str]]        = None
    evidenceIds              : Optional[List[str]]        = None
    graphNodeIds             : Optional[List[str]]        = None
    timelineEventIds         : Optional[List[str]]        = None
    findingFingerprint       : Optional[str]              = None
    investigationFingerprint : Optional[str]              = None
    graphFingerprint         : Optional[str]              = None
    reason                   : Optional[str]              = None
    findingSummary           : Optional[str]              = None
    affectedAssets           : Optional[List[str]]        = None
    recommendedAction        : Optional[str]              = None
    escalationReason         : Optional[str]              = None
    relatedAlertIds          : Optional[List[str]]        = None
    relatedFindingIds        : Optional[List[str]]        = None
    sharedEvidenceIds        : Optional[List[str]]        = None
    sharedAssets             : Optional[List[str]]        = None
    correlationScore         : Optional[float]            = Field(default=None, ge=0, le=100)
    tags                     : Optional[List[str]]        = None
    metadata                 : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class AlertFilterRequest(BaseModel):
    """
    Query-parameter filter model for GET /api/v2/alerts.

    All fields are optional — omitting a field means "no filter on that field".

    Fields
    ------
    severity         : Filter by severity (exact match, case-insensitive).
    status           : Filter by status (exact match, case-insensitive).
    source           : Filter by source (exact match, case-insensitive).
    projectId        : Filter by project ID (exact match).
    findingId        : Filter by source finding ID (exact match).
    investigationId  : Filter by investigation ID (exact match).
    assignedTo       : Filter by assigned analyst (exact match).
    minConfidence    : Keep only alerts with confidence >= minConfidence.
    maxConfidence    : Keep only alerts with confidence <= maxConfidence.
    minRiskScore     : Keep only alerts with riskScore >= minRiskScore.
    maxRiskScore     : Keep only alerts with riskScore <= maxRiskScore.
    """
    severity         : Optional[str]   = None
    status           : Optional[str]   = None
    source           : Optional[str]   = None
    projectId        : Optional[str]   = None
    findingId        : Optional[str]   = None
    investigationId  : Optional[str]   = None
    assignedTo       : Optional[str]   = None
    minConfidence    : Optional[float] = Field(default=None, ge=0, le=100)
    maxConfidence    : Optional[float] = Field(default=None, ge=0, le=100)
    minRiskScore     : Optional[float] = Field(default=None, ge=0, le=100)
    maxRiskScore     : Optional[float] = Field(default=None, ge=0, le=100)

    class Config:
        frozen = True


class AlertSearchRequest(BaseModel):
    """
    Request body / query parameter model for alert search operations.

    Fields
    ------
    query : Free-text search string matched against alertId, title,
            description, projectId, findingId (case-insensitive substring).
            Must be non-empty if provided.
    """
    query : str = Field(..., min_length=1, description="Non-empty search string.")

    class Config:
        frozen = True


# ===========================================================================
# Response Models
# ===========================================================================

class AlertExplanationResponse(BaseModel):
    """
    Serialised form of AlertExplanation embedded in AlertResponse.

    Fields mirror AlertExplanation from alert_service.py.
    """
    reason            : str
    findingSummary    : str
    affectedAssets    : List[str]
    recommendedAction : str
    escalationReason  : str

    class Config:
        frozen = True


class AlertCorrelationResponse(BaseModel):
    """
    Serialised form of AlertCorrelation embedded in AlertResponse.

    Fields mirror AlertCorrelation from alert_service.py.
    """
    correlationId     : str
    relatedAlertIds   : List[str]
    relatedFindingIds : List[str]
    sharedEvidenceIds : List[str]
    sharedAssets      : List[str]
    correlationScore  : float

    class Config:
        frozen = True


class AlertResponse(BaseModel):
    """
    Single alert payload returned by GET /api/v2/alerts/{alertId}
    and POST /api/v2/alerts.

    Mirrors the shape of Alert from alert_service.py so that FastAPI
    can generate a typed OpenAPI schema.

    All fields are Optional because alert dicts from the service layer
    may have absent keys depending on how the alert was built.
    """
    alertId                  : Optional[str]                       = None
    alertKey                 : Optional[str]                       = None
    projectId                : Optional[str]                       = None
    findingId                : Optional[str]                       = None
    investigationId          : Optional[str]                       = None
    title                    : Optional[str]                       = None
    description              : Optional[str]                       = None
    severity                 : Optional[str]                       = None
    status                   : Optional[str]                       = None
    source                   : Optional[str]                       = None
    confidence               : Optional[float]                     = None
    riskScore                : Optional[float]                     = None
    assetIds                 : Optional[List[str]]                 = None
    relationshipIds          : Optional[List[str]]                 = None
    evidenceIds              : Optional[List[str]]                 = None
    graphNodeIds             : Optional[List[str]]                 = None
    timelineEventIds         : Optional[List[str]]                 = None
    findingFingerprint       : Optional[str]                       = None
    investigationFingerprint : Optional[str]                       = None
    graphFingerprint         : Optional[str]                       = None
    alertFingerprint         : Optional[str]                       = None
    tags                     : Optional[List[str]]                 = None
    metadata                 : Optional[Dict[str, Any]]            = None
    createdBy                : Optional[str]                       = None
    assignedTo               : Optional[str]                       = None
    createdAt                : Optional[str]                       = None
    updatedAt                : Optional[str]                       = None
    closedAt                 : Optional[str]                       = None
    acknowledgedAt           : Optional[str]                       = None
    resolvedAt               : Optional[str]                       = None
    explanation              : Optional[AlertExplanationResponse]  = None
    correlation              : Optional[AlertCorrelationResponse]  = None
    engineVersion            : Optional[str]                       = None
    auditTrail               : Optional[List[str]]                 = None

    class Config:
        frozen = True


class AlertListResponse(BaseModel):
    """
    Payload for GET /api/v2/alerts (list).

    Fields
    ------
    alerts : List of AlertResponse objects.
    total  : Total count of matching alerts in the in-memory store.
    """
    alerts : List[AlertResponse]
    total  : int

    class Config:
        frozen = True


class AlertStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/alerts/statistics.

    Fields
    ------
    totalAlerts       : Count of all alerts in the in-memory store.
    severityCounts    : Dict mapping severity → count.
    statusCounts      : Dict mapping status → count.
    typeCounts        : Dict mapping source (type) → count.
    averageConfidence : Mean confidence score across all alerts (0.0 if empty).
    averageRiskScore  : Mean riskScore across all alerts (0.0 if empty).  Part B.
    """
    totalAlerts       : int
    severityCounts    : Dict[str, int]
    statusCounts      : Dict[str, int]
    typeCounts        : Dict[str, int]
    averageConfidence : float
    averageRiskScore  : float = 0.0

    class Config:
        frozen = True


class AlertSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/alerts/search.

    Extends AlertListResponse with pagination and search metadata.
    Reserved for Part B — included here so models file is complete.
    """
    alerts     : List[AlertResponse]
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
# Part B — Bulk Operation Models (NOT IMPLEMENTED IN PART A)
# ===========================================================================

class BulkCreateAlertsRequest(BaseModel):
    """
    Request body for POST /api/v2/alerts/bulk/create.

    Fields
    ------
    alerts : List of CreateAlertRequest items to create.
             Must be non-empty.
    """
    alerts : List[CreateAlertRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.alerts:
            errors.append("alerts list must not be empty.")
        for i, a in enumerate(self.alerts):
            sub = a.validate_request()
            for e in sub:
                errors.append(f"alerts[{i}]: {e}")
        return errors


class BulkUpdateAlertsRequest(BaseModel):
    """
    Request body for PUT /api/v2/alerts/bulk/update.

    Each item pairs an alertId with the fields to update.
    """

    class BulkUpdateItem(BaseModel):
        alertId : str
        update  : UpdateAlertRequest

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
            if not item.alertId or not item.alertId.strip():
                errors.append(f"items[{i}]: alertId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteAlertsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/alerts/bulk/delete.

    Fields
    ------
    alertIds : List of alertId strings to delete.  Must be non-empty.
    """
    alertIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.alertIds:
            errors.append("alertIds list must not be empty.")
        for i, aid in enumerate(self.alertIds):
            if not aid or not aid.strip():
                errors.append(f"alertIds[{i}]: alertId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.

    Fields
    ------
    succeeded    : List of alertIds that were successfully processed.
    failed       : List of dicts with alertId and reason keys.
    total        : Total items submitted.
    successCount : Number of succeeded items.
    failCount    : Number of failed items.
    """
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
