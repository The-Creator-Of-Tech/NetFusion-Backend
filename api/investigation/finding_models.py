"""
Finding API Models — Phase A4.7.5 (Part A)
==========================================
Immutable Pydantic models for Finding API request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (non-empty strings,
  field presence).  Business-rule validation stays in finding_service.py.
- No UUID generation — callers supply findingId values or they're derived.
- No timestamp generation — callers supply timestamps.
- No randomness.
- Response models are plain shaped dicts promoted to typed models so that
  FastAPI can generate correct OpenAPI schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateFindingRequest(BaseModel):
    """
    Request body for POST /api/v2/findings.

    Required fields
    ---------------
    projectId        : Owning project identifier.
    investigationId  : Parent investigation identifier.
    title            : Human-readable finding title.
    createdBy        : Analyst / system identifier.
    createdAt        : ISO-8601 creation timestamp.

    Optional fields
    ---------------
    category         : Finding category (default "OTHER").
    severity         : Finding severity (default "MEDIUM").
    description      : Free-text description.
    confidence       : 0–100 confidence score.
    riskScore        : 0–100 risk score.
    assetIds         : Linked asset IDs.
    relationshipIds  : Linked relationship IDs.
    evidenceIds      : Linked evidence IDs.
    timelineEventIds : Linked timeline event IDs.
    graphNodeIds     : Linked graph node IDs.
    mitreTechniqueIds: Linked MITRE technique IDs.
    graphFingerprint : Attack graph fingerprint.
    timelineFingerprint: Timeline fingerprint.
    investigationFingerprint: Investigation fingerprint.
    reason           : Explanation — why this finding was raised.
    evidenceSummary  : Explanation — supporting evidence summary.
    affectedAssets   : Explanation — implicated asset IDs.
    affectedRelationships: Explanation — implicated relationship IDs.
    recommendedAction: Explanation — remediation step.
    tags             : Classification tags.
    metadata         : Arbitrary key-value pairs.
    """
    projectId        : str
    investigationId  : str
    title            : str
    createdBy        : str
    createdAt        : str
    category         : Optional[str]              = "OTHER"
    severity         : Optional[str]              = "MEDIUM"
    description      : Optional[str]              = ""
    confidence       : Optional[float]            = Field(default=0.0, ge=0, le=100)
    riskScore        : Optional[float]            = Field(default=0.0, ge=0, le=100)
    assetIds         : Optional[List[str]]        = None
    relationshipIds  : Optional[List[str]]        = None
    evidenceIds      : Optional[List[str]]        = None
    timelineEventIds : Optional[List[str]]        = None
    graphNodeIds     : Optional[List[str]]        = None
    mitreTechniqueIds: Optional[List[str]]        = None
    graphFingerprint : Optional[str]              = ""
    timelineFingerprint: Optional[str]            = ""
    investigationFingerprint: Optional[str]       = ""
    reason           : Optional[str]              = ""
    evidenceSummary  : Optional[str]              = ""
    affectedAssets   : Optional[List[str]]        = None
    affectedRelationships: Optional[List[str]]    = None
    recommendedAction: Optional[str]              = ""
    tags             : Optional[List[str]]        = None
    metadata         : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list means the request is valid.

        API-layer rules only:
        - projectId must be non-empty and non-whitespace.
        - investigationId must be non-empty and non-whitespace.
        - title must be non-empty and non-whitespace.
        - createdBy must be non-empty and non-whitespace.
        - createdAt must be non-empty and non-whitespace.
        """
        errors: List[str] = []
        if not self.projectId or not self.projectId.strip():
            errors.append("projectId must not be empty.")
        if not self.investigationId or not self.investigationId.strip():
            errors.append("investigationId must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if not self.createdBy or not self.createdBy.strip():
            errors.append("createdBy must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateFindingRequest(BaseModel):
    """
    Request body for PUT /api/v2/findings/{findingId}.

    All fields are optional — supply only what should change.
    At least one field must be provided (validated at the route level).

    Fields
    ------
    title            : New title.
    description      : New description.
    category         : New category.
    severity         : New severity.
    status           : New status.
    confidence       : New confidence score.
    riskScore        : New risk score.
    assetIds / relationshipIds / evidenceIds / timelineEventIds /
      graphNodeIds / mitreTechniqueIds : Replace linked ID lists.
    graphFingerprint / timelineFingerprint / investigationFingerprint
                     : Update fingerprints.
    reason / evidenceSummary / affectedAssets / affectedRelationships /
      recommendedAction : Update explanation fields.
    tags             : Replace tags list.
    metadata         : Merge / replace metadata key-value pairs.
    """
    title            : Optional[str]              = None
    description      : Optional[str]              = None
    category         : Optional[str]              = None
    severity         : Optional[str]              = None
    status           : Optional[str]              = None
    confidence       : Optional[float]            = Field(default=None, ge=0, le=100)
    riskScore        : Optional[float]            = Field(default=None, ge=0, le=100)
    assetIds         : Optional[List[str]]        = None
    relationshipIds  : Optional[List[str]]        = None
    evidenceIds      : Optional[List[str]]        = None
    timelineEventIds : Optional[List[str]]        = None
    graphNodeIds     : Optional[List[str]]        = None
    mitreTechniqueIds: Optional[List[str]]        = None
    graphFingerprint : Optional[str]              = None
    timelineFingerprint: Optional[str]            = None
    investigationFingerprint: Optional[str]       = None
    reason           : Optional[str]              = None
    evidenceSummary  : Optional[str]              = None
    affectedAssets   : Optional[List[str]]        = None
    affectedRelationships: Optional[List[str]]    = None
    recommendedAction: Optional[str]              = None
    tags             : Optional[List[str]]        = None
    metadata         : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class FindingFilterRequest(BaseModel):
    """
    Query-parameter filter model for GET /api/v2/findings.

    All fields are optional — omitting a field means "no filter on that field".

    Fields
    ------
    status           : Filter by status (exact match).
    severity         : Filter by severity (exact match).
    category         : Filter by category (exact match).
    projectId        : Filter by project ID (exact match).
    investigationId  : Filter by investigation ID (exact match).
    minConfidence    : Keep only findings with confidence >= minConfidence.
    maxConfidence    : Keep only findings with confidence <= maxConfidence.
    minRiskScore     : Keep only findings with riskScore >= minRiskScore.
    maxRiskScore     : Keep only findings with riskScore <= maxRiskScore.
    """
    status           : Optional[str] = None
    severity         : Optional[str] = None
    category         : Optional[str] = None
    projectId        : Optional[str] = None
    investigationId  : Optional[str] = None
    minConfidence    : Optional[float] = Field(default=None, ge=0, le=100)
    maxConfidence    : Optional[float] = Field(default=None, ge=0, le=100)
    minRiskScore     : Optional[float] = Field(default=None, ge=0, le=100)
    maxRiskScore     : Optional[float] = Field(default=None, ge=0, le=100)

    class Config:
        frozen = True


class FindingSearchRequest(BaseModel):
    """
    Request body / query parameter model for finding search operations.

    Fields
    ------
    query : Free-text search string matched against findingId, title, description
            (case-insensitive substring).  Must be non-empty if provided.
    """
    query : str = Field(..., min_length=1, description="Non-empty search string.")

    class Config:
        frozen = True


# ===========================================================================
# Response Models
# ===========================================================================

class FindingExplanationResponse(BaseModel):
    """
    Serialized form of FindingExplanation embedded in FindingResponse.

    Fields
    ------
    reason                : Why this finding was raised.
    evidenceSummary       : What evidence supports this finding.
    affectedAssets        : List of implicated asset IDs.
    affectedRelationships : List of implicated relationship IDs.
    recommendedAction     : Concrete remediation or investigation step.
    """
    reason                : str
    evidenceSummary       : str
    affectedAssets        : List[str]
    affectedRelationships : List[str]
    recommendedAction     : str

    class Config:
        frozen = True


class FindingResponse(BaseModel):
    """
    Single finding payload returned by GET /api/v2/findings/{findingId}
    and POST /api/v2/findings.

    Mirrors the shape of Finding from finding_service.py so that
    FastAPI can generate a typed OpenAPI schema.

    All fields are Optional because finding dicts from the service layer may
    have absent keys depending on how the finding was built.
    """
    findingId                : Optional[str]                        = None
    findingKey               : Optional[str]                        = None
    projectId                : Optional[str]                        = None
    investigationId          : Optional[str]                        = None
    title                    : Optional[str]                        = None
    description              : Optional[str]                        = None
    category                 : Optional[str]                        = None
    severity                 : Optional[str]                        = None
    status                   : Optional[str]                        = None
    confidence               : Optional[float]                      = None
    riskScore                : Optional[float]                      = None
    assetIds                 : Optional[List[str]]                  = None
    relationshipIds          : Optional[List[str]]                  = None
    evidenceIds              : Optional[List[str]]                  = None
    timelineEventIds         : Optional[List[str]]                  = None
    graphNodeIds             : Optional[List[str]]                  = None
    mitreTechniqueIds        : Optional[List[str]]                  = None
    graphFingerprint         : Optional[str]                        = None
    timelineFingerprint      : Optional[str]                        = None
    investigationFingerprint : Optional[str]                        = None
    findingFingerprint       : Optional[str]                        = None
    explanation              : Optional[FindingExplanationResponse] = None
    tags                     : Optional[List[str]]                  = None
    metadata                 : Optional[Dict[str, Any]]             = None
    createdBy                : Optional[str]                        = None
    createdAt                : Optional[str]                        = None
    updatedAt                : Optional[str]                        = None
    closedAt                 : Optional[str]                        = None
    engineVersion            : Optional[str]                        = None
    auditTrail               : Optional[List[str]]                  = None

    class Config:
        frozen = True


class FindingListResponse(BaseModel):
    """
    Payload for GET /api/v2/findings (list).

    Fields
    ------
    findings : List of FindingResponse objects.
    total    : Total count of matching findings in the in-memory store.
    """
    findings : List[FindingResponse]
    total    : int

    class Config:
        frozen = True


class FindingStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/findings/statistics.

    Fields
    ------
    totalFindings    : Count of all findings in the in-memory store.
    severityCounts   : Dict mapping severity → count.
    statusCounts     : Dict mapping status → count.
    categoryCounts   : Dict mapping category → count.
    averageConfidence: Mean confidence across all findings (0.0 if empty).
    averageRiskScore : Mean riskScore across all findings (0.0 if empty).  Part B.
    """
    totalFindings     : int
    severityCounts    : Dict[str, int]
    statusCounts      : Dict[str, int]
    categoryCounts    : Dict[str, int]
    averageConfidence : float
    averageRiskScore  : float = 0.0

    class Config:
        frozen = True


class FindingSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/findings/search.

    Extends FindingListResponse with pagination and search metadata.
    """
    findings   : List[FindingResponse]
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

class BulkCreateFindingsRequest(BaseModel):
    """
    Request body for POST /api/v2/findings/bulk/create.

    Fields
    ------
    findings : List of CreateFindingRequest items to create.
               Must be non-empty.
    """
    findings : List[CreateFindingRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.findings:
            errors.append("findings list must not be empty.")
        for i, f in enumerate(self.findings):
            sub = f.validate_request()
            for e in sub:
                errors.append(f"findings[{i}]: {e}")
        return errors


class BulkUpdateFindingsRequest(BaseModel):
    """
    Request body for PUT /api/v2/findings/bulk/update.

    Each item pairs a findingId with the fields to update.
    """

    class BulkUpdateItem(BaseModel):
        findingId : str
        update    : UpdateFindingRequest

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
            if not item.findingId or not item.findingId.strip():
                errors.append(f"items[{i}]: findingId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteFindingsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/findings/bulk/delete.

    Fields
    ------
    findingIds : List of findingId strings to delete.  Must be non-empty.
    """
    findingIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.findingIds:
            errors.append("findingIds list must not be empty.")
        for i, fid in enumerate(self.findingIds):
            if not fid or not fid.strip():
                errors.append(f"findingIds[{i}]: findingId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.

    Fields
    ------
    succeeded : List of findingIds that were successfully processed.
    failed    : List of (findingId, reason) pairs for items that failed.
    total     : Total items submitted.
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
