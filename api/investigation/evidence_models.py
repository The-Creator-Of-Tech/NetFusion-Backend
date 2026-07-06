"""
Evidence API Models — Phase A4.7.2 (Part A)
=============================================
Immutable Pydantic models for Evidence API request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (field presence, non-empty
  strings).  Business-rule validation stays in evidence_service.py.
- No UUID generation — evidence IDs are derived deterministically by the
  evidence engine from content hashes.
- No timestamp generation — callers supply timestamps.
- No randomness.
- Response models mirror the shape of EvidenceRecord / EvidenceBundle so that
  FastAPI can generate correct OpenAPI schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateEvidenceRequest(BaseModel):
    """
    Request body for POST /api/v2/evidence.

    Required fields
    ---------------
    fieldName  : Logical field name that was observed (e.g. "hostname",
                 "macAddress").  Must be non-empty.
    fieldValue : The observed value.  Must be non-empty.
    sourceType : Source system that produced the observation
                 (e.g. "pcap", "dhcp", "nmap").  Must be non-empty.

    Optional fields
    ---------------
    assetId      : ID of the asset this evidence belongs to.
    sourceId     : Opaque back-reference to the source record (loose FK).
    confidence   : Explicit confidence override (0–100).
    packetNumber : Frame index within the capture file.
    captureId    : CaptureSession.captureId back-reference.
    sessionId    : CaptureSession.id back-reference.
    observedAt   : ISO-8601 UTC datetime string of the original observation.
    protocol     : Network protocol the value was observed in (e.g. "DNS").
    packetInfo   : Raw packet info string (_ws.col.info value).
    rawValue     : Unprocessed original value before normalisation.
    tags         : Analyst-applied labels.
    extra        : Arbitrary key-value pairs for EvidenceMetadata.extra.
    """
    fieldName    : str
    fieldValue   : str
    sourceType   : str
    assetId      : Optional[str]              = None
    sourceId     : Optional[str]              = None
    confidence   : Optional[int]              = Field(default=None, ge=0, le=100)
    packetNumber : Optional[int]              = None
    captureId    : Optional[str]              = None
    sessionId    : Optional[str]              = None
    observedAt   : Optional[str]              = None
    protocol     : Optional[str]              = None
    packetInfo   : Optional[str]              = None
    rawValue     : Optional[str]              = None
    tags         : Optional[List[str]]        = None
    extra        : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list means the request is valid.

        API-layer rules only:
        - fieldName must be non-empty and non-whitespace.
        - fieldValue must be non-empty and non-whitespace.
        - sourceType must be non-empty and non-whitespace.
        - confidence, if provided, is already range-validated by Field(ge=0, le=100).
        """
        errors: List[str] = []
        if not self.fieldName or not self.fieldName.strip():
            errors.append("fieldName must not be empty.")
        if not self.fieldValue or not self.fieldValue.strip():
            errors.append("fieldValue must not be empty.")
        if not self.sourceType or not self.sourceType.strip():
            errors.append("sourceType must not be empty.")
        return errors


class UpdateEvidenceRequest(BaseModel):
    """
    Request body for PUT /api/v2/evidence/{evidenceId}.

    All fields are optional — supply only what should change.
    At least one field must be provided (validated at the route level).

    Fields
    ------
    assetId    : Assign or re-assign the evidence to an asset.
    confidence : Override the confidence score (0–100).
    tags       : Replace the full tags list.
    extra      : Merge / replace extra metadata key-value pairs.
    protocol   : Update the protocol string.
    packetInfo : Update the packet info string.
    rawValue   : Update the raw value string.
    """
    assetId    : Optional[str]            = None
    confidence : Optional[int]            = Field(default=None, ge=0, le=100)
    tags       : Optional[List[str]]      = None
    extra      : Optional[Dict[str, Any]] = None
    protocol   : Optional[str]            = None
    packetInfo : Optional[str]            = None
    rawValue   : Optional[str]            = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class EvidenceFilterRequest(BaseModel):
    """
    Query-parameter filter model for GET /api/v2/evidence.

    All fields are optional — omitting a field means "no filter on that field".

    Fields
    ------
    assetId     : Keep only evidence belonging to this asset.
    sourceType  : Keep only evidence from this source system.
    fieldName   : Keep only evidence for this field name (exact match,
                  case-insensitive after normalisation).
    minConfidence : Keep only evidence with confidence >= minConfidence.
    maxConfidence : Keep only evidence with confidence <= maxConfidence.
    captureId   : Keep only evidence from this capture session.
    """
    assetId       : Optional[str]  = None
    sourceType    : Optional[str]  = None
    fieldName     : Optional[str]  = None
    minConfidence : Optional[int]  = Field(default=None, ge=0, le=100)
    maxConfidence : Optional[int]  = Field(default=None, ge=0, le=100)
    captureId     : Optional[str]  = None

    class Config:
        frozen = True


class EvidenceSearchRequest(BaseModel):
    """
    Request body / query parameter model for evidence search operations.

    Fields
    ------
    query : Free-text search string matched against fieldName, fieldValue,
            sourceType, assetId, and captureId (case-insensitive substring).
            Must be non-empty if provided.
    """
    query : str = Field(..., min_length=1, description="Non-empty search string.")

    class Config:
        frozen = True


# ===========================================================================
# Response Models
# ===========================================================================

class EvidenceSourceResponse(BaseModel):
    """
    Serialised form of EvidenceSource embedded in EvidenceResponse.

    Fields mirror EvidenceSource from evidence_service.py.
    """
    sourceType : str
    sourceId   : Optional[str] = None
    confidence : int

    class Config:
        frozen = True


class EvidenceReferenceResponse(BaseModel):
    """
    Serialised form of EvidenceReference embedded in EvidenceResponse.

    Fields mirror EvidenceReference from evidence_service.py.
    """
    packetNumber : Optional[int]  = None
    captureId    : Optional[str]  = None
    sessionId    : Optional[str]  = None
    observedAt   : Optional[str]  = None

    class Config:
        frozen = True


class EvidenceMetadataResponse(BaseModel):
    """
    Serialised form of EvidenceMetadata embedded in EvidenceResponse.

    Fields mirror EvidenceMetadata from evidence_service.py.
    """
    protocol   : Optional[str]       = None
    packetInfo : Optional[str]       = None
    rawValue   : Optional[str]       = None
    tags       : List[str]           = Field(default_factory=list)
    extra      : Dict[str, Any]      = Field(default_factory=dict)

    class Config:
        frozen = True


class EvidenceResponse(BaseModel):
    """
    Single evidence record payload returned by GET /api/v2/evidence/{evidenceId}
    and POST /api/v2/evidence.

    Mirrors the shape of EvidenceRecord from evidence_service.py so that
    FastAPI can generate a typed OpenAPI schema.

    All fields are Optional because the in-memory store may carry partial
    records during early processing before full resolution.
    """
    evidenceId    : Optional[str]                    = None
    evidenceHash  : Optional[str]                    = None
    fieldName     : Optional[str]                    = None
    fieldValue    : Optional[str]                    = None
    assetId       : Optional[str]                    = None
    source        : Optional[EvidenceSourceResponse] = None
    reference     : Optional[EvidenceReferenceResponse] = None
    confidence    : Optional[int]                    = None
    engineVersion : Optional[str]                    = None
    schemaVersion : Optional[str]                    = None
    observedAt    : Optional[str]                    = None
    createdAt     : Optional[str]                    = None
    metadata      : Optional[EvidenceMetadataResponse] = None

    class Config:
        frozen = True


class EvidenceListResponse(BaseModel):
    """
    Payload for GET /api/v2/evidence (list).

    Fields
    ------
    evidence : List of EvidenceResponse objects.
    total    : Total count of matching evidence records in the in-memory store.
    """
    evidence : List[EvidenceResponse]
    total    : int

    class Config:
        frozen = True


class EvidenceStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/evidence/statistics.

    Fields
    ------
    totalRecords      : Count of all evidence records in the in-memory store.
    uniqueAssets      : Count of distinct assetId values (None excluded).
    uniqueFields      : Count of distinct fieldName values.
    uniqueSources     : Count of distinct sourceType values.
    averageConfidence : Mean confidence score across all records (0.0 if empty).
    sourceCounts      : Dict mapping sourceType → count.
    fieldCounts       : Dict mapping fieldName → count.
    assetCounts       : Dict mapping assetId → count (None key omitted).
    """
    totalRecords      : int
    uniqueAssets      : int
    uniqueFields      : int
    uniqueSources     : int
    averageConfidence : float
    sourceCounts      : Dict[str, int]
    fieldCounts       : Dict[str, int]
    assetCounts       : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Part B — Search, Sort, Filter, Pagination, Bulk Operations
# ===========================================================================

class EvidenceSearchQueryRequest(BaseModel):
    """
    Query parameters for GET /api/v2/evidence/search.

    Fields
    ------
    q             : Free-text search string.  Matched case-insensitively as a
                    substring against fieldName, fieldValue, sourceType,
                    assetId, captureId, and evidenceId.  Required, >= 1 char.
    sortBy        : Field to sort results by.
                    Allowed: "confidence", "sourceType", "fieldName", "created".
                    Default "created".
    sortOrder     : "asc" (default) or "desc".
    page          : 1-based page number (default 1).
    pageSize      : Items per page 1–500 (default 20).
    assetId       : Optional exact-match filter on assetId.
    sourceType    : Optional exact-match filter on sourceType.
    fieldName     : Optional exact-match filter on fieldName (case-insensitive).
    minConfidence : Optional minimum confidence filter (0–100).
    maxConfidence : Optional maximum confidence filter (0–100).
    captureId     : Optional exact-match filter on captureId.
    """
    q             : str            = Field(..., min_length=1, description="Non-empty search string.")
    sortBy        : Optional[str]  = Field(default="created",    description="Sort field: confidence|sourceType|fieldName|created.")
    sortOrder     : Optional[str]  = Field(default="asc",        description="Sort direction: asc|desc.")
    page          : Optional[int]  = Field(default=1,  ge=1,     description="1-based page number.")
    pageSize      : Optional[int]  = Field(default=20, ge=1, le=500, description="Items per page (1–500).")
    assetId       : Optional[str]  = None
    sourceType    : Optional[str]  = None
    fieldName     : Optional[str]  = None
    minConfidence : Optional[int]  = Field(default=None, ge=0, le=100)
    maxConfidence : Optional[int]  = Field(default=None, ge=0, le=100)
    captureId     : Optional[str]  = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        allowed_sort = {"confidence", "sourcetype", "fieldname", "created"}
        if self.sortBy and self.sortBy.lower() not in allowed_sort:
            errors.append(f"sortBy must be one of: confidence, sourceType, fieldName, created.")
        if self.sortOrder and self.sortOrder not in ("asc", "desc"):
            errors.append("sortOrder must be 'asc' or 'desc'.")
        return errors


class BulkCreateEvidenceRequest(BaseModel):
    """
    Request body for POST /api/v2/evidence/bulk/create.

    Fields
    ------
    evidence : List of CreateEvidenceRequest items to create.
               Must be non-empty.
    """
    evidence : List[CreateEvidenceRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.evidence:
            errors.append("evidence list must not be empty.")
        for i, item in enumerate(self.evidence):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"evidence[{i}]: {e}")
        return errors


class BulkUpdateEvidenceItem(BaseModel):
    """
    A single update item used in BulkUpdateEvidenceRequest.

    Fields
    ------
    evidenceId : The ID of the record to update.  Must be non-empty.
    update     : The UpdateEvidenceRequest payload for this record.
    """
    evidenceId : str
    update     : UpdateEvidenceRequest

    class Config:
        frozen = True


class BulkUpdateEvidenceRequest(BaseModel):
    """
    Request body for PUT /api/v2/evidence/bulk/update.

    Fields
    ------
    items : List of (evidenceId, UpdateEvidenceRequest) pairs.
            Must be non-empty.
    """
    items : List[BulkUpdateEvidenceItem] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.items:
            errors.append("items list must not be empty.")
        for i, item in enumerate(self.items):
            if not item.evidenceId or not item.evidenceId.strip():
                errors.append(f"items[{i}]: evidenceId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteEvidenceRequest(BaseModel):
    """
    Request body for DELETE /api/v2/evidence/bulk/delete.

    Fields
    ------
    evidenceIds : List of evidenceId strings to delete.  Must be non-empty.
    """
    evidenceIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.evidenceIds:
            errors.append("evidenceIds list must not be empty.")
        for i, eid in enumerate(self.evidenceIds):
            if not eid or not eid.strip():
                errors.append(f"evidenceIds[{i}]: evidenceId must not be empty.")
        return errors


class BulkEvidenceOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.

    Fields
    ------
    succeeded    : List of evidenceIds that were successfully processed.
    failed       : List of dicts with evidenceId and reason keys.
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


class EvidenceSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/evidence/search.

    Extends EvidenceListResponse with pagination and search metadata.
    """
    evidence   : List[EvidenceResponse]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int
    query      : str
    sortBy     : str
    sortOrder  : str

    class Config:
        frozen = True
