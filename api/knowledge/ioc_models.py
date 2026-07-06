"""
IOC Intelligence API Models — Phase A4.9.3
===========================================
Immutable Pydantic models for IOC request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class IOCRelationshipResponse(BaseModel):
    """
    Response model representing a relationship between an IOC and another entity.
    """
    sourceIocId  : str
    targetId     : str
    targetType   : str  # "cve", "technique", "threat_actor", "campaign"
    relationType : str  # "exploits", "uses", "attributed_to", "associated_with"
    confidence   : float

    class Config:
        frozen = True


class IOCEnrichmentResponse(BaseModel):
    """
    Response model containing reputational and metadata enrichment for an IOC.
    """
    iocId           : str
    iocType         : str
    value           : str
    reputationScore : int = Field(..., ge=0, le=100)
    malicious       : bool
    categories      : List[str]
    firstSeen       : str
    lastSeen        : str
    provider        : str

    class Config:
        frozen = True


# ===========================================================================
# Request Models
# ===========================================================================

class CreateIOCRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/ioc.
    """
    iocType           : str
    value             : str
    severity          : str
    confidence        : str
    description       : Optional[str] = ""
    source            : Optional[str] = ""
    tags              : Optional[List[str]] = Field(default_factory=list)
    relatedCVEs       : Optional[List[str]] = Field(default_factory=list)
    relatedTechniques : Optional[List[str]] = Field(default_factory=list)
    createdAt         : str
    updatedAt         : Optional[str] = None
    malicious         : Optional[bool] = True
    revoked           : Optional[bool] = False
    threatActor       : Optional[str] = ""
    campaign          : Optional[str] = ""

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.iocType or not self.iocType.strip():
            errors.append("iocType must not be empty.")
        else:
            from services.ioc_intelligence_service import IOCTypeEnum
            try:
                IOCTypeEnum(self.iocType.strip().upper())
            except ValueError:
                errors.append(f"iocType must be an IOCTypeEnum member; got {self.iocType!r}.")

        if not self.value or not self.value.strip():
            errors.append("value must not be empty.")

        if not self.severity or not self.severity.strip():
            errors.append("severity must not be empty.")
        else:
            from services.ioc_intelligence_service import IOCSeverityEnum
            try:
                IOCSeverityEnum(self.severity.strip().upper())
            except ValueError:
                errors.append(f"severity must be an IOCSeverityEnum member; got {self.severity!r}.")

        if not self.confidence or not self.confidence.strip():
            errors.append("confidence must not be empty.")
        else:
            from services.ioc_intelligence_service import IOCConfidenceEnum
            try:
                IOCConfidenceEnum(self.confidence.strip().upper())
            except ValueError:
                errors.append(f"confidence must be an IOCConfidenceEnum member; got {self.confidence!r}.")

        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")

        return errors


class UpdateIOCRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/ioc/{iocId}.
    """
    severity          : Optional[str] = None
    confidence        : Optional[str] = None
    description       : Optional[str] = None
    source            : Optional[str] = None
    tags              : Optional[List[str]] = None
    relatedCVEs       : Optional[List[str]] = None
    relatedTechniques : Optional[List[str]] = None
    updatedAt         : Optional[str] = None
    malicious         : Optional[bool] = None
    revoked           : Optional[bool] = None
    threatActor       : Optional[str] = None
    campaign          : Optional[str] = None

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
                from services.ioc_intelligence_service import IOCSeverityEnum
                try:
                    IOCSeverityEnum(self.severity.strip().upper())
                except ValueError:
                    errors.append(f"severity must be an IOCSeverityEnum member; got {self.severity!r}.")
        if self.confidence is not None:
            if not self.confidence.strip():
                errors.append("confidence must not be empty.")
            else:
                from services.ioc_intelligence_service import IOCConfidenceEnum
                try:
                    IOCConfidenceEnum(self.confidence.strip().upper())
                except ValueError:
                    errors.append(f"confidence must be an IOCConfidenceEnum member; got {self.confidence!r}.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class IOCResponse(BaseModel):
    """
    Response model carrying an individual IOC record.
    """
    iocId             : str
    iocKey            : str
    iocFingerprint    : str
    iocType           : str
    value             : str
    severity          : str
    confidence        : str
    description       : str
    source            : str
    tags              : List[str]
    relatedCVEs       : List[str]
    relatedTechniques : List[str]
    createdAt         : str
    updatedAt         : Optional[str] = None
    malicious         : bool = True
    revoked           : bool = False
    threatActor       : str = ""
    campaign          : str = ""

    class Config:
        frozen = True


class IOCListResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/ioc.
    """
    iocs  : List[IOCResponse]
    total : int

    class Config:
        frozen = True


class IOCStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/ioc/statistics.
    """
    totalIOCs         : int
    maliciousIOCs     : int
    revokedIOCs       : int
    averageConfidence : float
    typeCounts        : Dict[str, int]
    sourceCounts      : Dict[str, int]

    class Config:
        frozen = True


class IOCSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/ioc/search.
    """
    iocs       : List[IOCResponse]
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

class BulkCreateIOCsRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/ioc/bulk/create.
    """
    iocs : List[CreateIOCRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.iocs:
            errors.append("iocs list must not be empty.")
        for i, item in enumerate(self.iocs):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"iocs[{i}]: {e}")
        return errors


class BulkUpdateIOCsRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/ioc/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        iocId  : str
        update : UpdateIOCRequest

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
            if not item.iocId or not item.iocId.strip():
                errors.append(f"items[{i}]: iocId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteIOCsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/knowledge/ioc/bulk/delete.
    """
    iocIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.iocIds:
            errors.append("iocIds list must not be empty.")
        for i, iid in enumerate(self.iocIds):
            if not iid or not iid.strip():
                errors.append(f"iocIds[{i}]: iocId must not be empty.")
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
