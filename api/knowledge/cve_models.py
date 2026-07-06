"""
CVE Intelligence API Models — Phase A4.9.2
===========================================
Immutable Pydantic models for CVE Intelligence request and response contracts.

Design rules
------------
- All models frozen (frozen=True).
- Request models validate only API-layer concerns.
- Response models are plain typed structures for FastAPI / OpenAPI schema generation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class CVSSResponse(BaseModel):
    """
    Response model carrying CVSS base score details.
    """
    baseScore           : float = Field(..., ge=0.0, le=10.0)
    severity            : str
    vectorString        : Optional[str] = ""
    exploitabilityScore : Optional[float] = 0.0
    impactScore         : Optional[float] = 0.0

    class Config:
        frozen = True


class AffectedProductResponse(BaseModel):
    """
    Response model representing an affected vendor/product combination.
    """
    vendor  : str
    product : str
    version : Optional[str] = ""
    patched : bool = False

    class Config:
        frozen = True


# ===========================================================================
# Request Models
# ===========================================================================

class CreateCVERequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/cve.
    """
    cveId             : str
    description       : Optional[str] = ""
    severity          : str
    cvssScore         : float
    publishedDate     : Optional[str] = ""
    modifiedDate      : Optional[str] = ""
    references        : Optional[List[str]] = Field(default_factory=list)
    affectedPlatforms : Optional[List[str]] = Field(default_factory=list)
    mappedTechniqueIds: Optional[List[str]] = Field(default_factory=list)
    createdAt         : str
    exploited         : Optional[bool] = False
    patched           : Optional[bool] = False
    vendor            : Optional[str] = ""
    product           : Optional[str] = ""
    affectedProducts  : Optional[List[AffectedProductResponse]] = Field(default_factory=list)
    cvssDetails       : Optional[CVSSResponse] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.cveId or not self.cveId.strip():
            errors.append("cveId must not be empty.")
        elif not _CVE_ID_RE.match(self.cveId.strip()):
            errors.append(f"cveId='{self.cveId}' must match CVE-YYYY-NNNN format (e.g. CVE-2021-44228).")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if not self.severity or not self.severity.strip():
            errors.append("severity must not be empty.")
        else:
            from services.cve_intelligence_service import SeverityEnum
            try:
                SeverityEnum(self.severity.strip().upper())
            except ValueError:
                errors.append(f"severity must be a SeverityEnum member; got {self.severity!r}.")
        if not isinstance(self.cvssScore, (int, float)) or not (0.0 <= float(self.cvssScore) <= 10.0):
            errors.append(f"cvssScore={self.cvssScore!r} must be a float in [0.0, 10.0].")
        return errors


class UpdateCVERequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/cve/{cveId}.
    """
    description       : Optional[str] = None
    severity          : Optional[str] = None
    cvssScore         : Optional[float] = None
    publishedDate     : Optional[str] = None
    modifiedDate      : Optional[str] = None
    references        : Optional[List[str]] = None
    affectedPlatforms : Optional[List[str]] = None
    mappedTechniqueIds: Optional[List[str]] = None
    exploited         : Optional[bool] = None
    patched           : Optional[bool] = None
    vendor            : Optional[str] = None
    product           : Optional[str] = None
    affectedProducts  : Optional[List[AffectedProductResponse]] = None
    cvssDetails       : Optional[CVSSResponse] = None

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
                from services.cve_intelligence_service import SeverityEnum
                try:
                    SeverityEnum(self.severity.strip().upper())
                except ValueError:
                    errors.append(f"severity must be a SeverityEnum member; got {self.severity!r}.")
        if self.cvssScore is not None:
            if not isinstance(self.cvssScore, (int, float)) or not (0.0 <= float(self.cvssScore) <= 10.0):
                errors.append(f"cvssScore={self.cvssScore!r} must be a float in [0.0, 10.0].")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class CVEResponse(BaseModel):
    """
    Response model representing a single CVE record.
    """
    recordId          : str
    recordKey         : str
    cveId             : str
    description       : str
    severity          : str
    cvssScore         : float
    publishedDate     : str
    modifiedDate      : str
    references        : List[str]
    affectedPlatforms : List[str]
    mappedTechniques  : List[Any]
    createdAt         : str
    exploited         : bool = False
    patched           : bool = False
    vendor            : str = ""
    product           : str = ""
    affectedProducts  : List[AffectedProductResponse] = Field(default_factory=list)
    cvssDetails       : Optional[CVSSResponse] = None

    class Config:
        frozen = True


class CVEListResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/cve.
    """
    cves  : List[CVEResponse]
    total : int

    class Config:
        frozen = True


class CVEStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/cve/statistics.
    """
    totalCVEs     : int
    exploitedCVEs : int
    patchedCVEs   : int
    averageCVSS   : float
    severityCounts: Dict[str, int]
    vendorCounts  : Dict[str, int]

    class Config:
        frozen = True


class CVESearchResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/cve/search.
    """
    cves       : List[CVEResponse]
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

class BulkCreateCVEsRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/cve/bulk/create.
    """
    cves : List[CreateCVERequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.cves:
            errors.append("cves list must not be empty.")
        for i, c in enumerate(self.cves):
            sub = c.validate_request()
            for e in sub:
                errors.append(f"cves[{i}]: {e}")
        return errors


class BulkUpdateCVEsRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/cve/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        cveId  : str
        update : UpdateCVERequest

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
            if not item.cveId or not item.cveId.strip():
                errors.append(f"items[{i}]: cveId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteCVEsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/knowledge/cve/bulk/delete.
    """
    cveIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.cveIds:
            errors.append("cveIds list must not be empty.")
        for i, cid in enumerate(self.cveIds):
            if not cid or not cid.strip():
                errors.append(f"cveIds[{i}]: cveId must not be empty.")
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
