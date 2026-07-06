"""
Threat Intelligence API Models — Phase A4.9.4
=============================================
Immutable Pydantic models for Threat Intelligence request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Sub-models & Response structures
# ===========================================================================

class ThreatActorResponse(BaseModel):
    """
    Response model representing details of a Threat Actor.
    """
    actorId           : str
    actorKey          : str
    name              : str
    aliases           : List[str]
    description       : str
    country           : str
    motivation        : str
    confidence        : str
    relatedTechniques : List[str]
    relatedCVEs       : List[str]
    relatedIOCs       : List[str]
    createdAt         : str
    updatedAt         : Optional[str] = None
    severity          : str
    active            : bool = True
    malware           : List[str] = Field(default_factory=list)
    industry          : List[str] = Field(default_factory=list)

    class Config:
        frozen = True


class ThreatCampaignResponse(BaseModel):
    """
    Response model representing a threat campaign.
    """
    campaignId        : str
    campaignKey       : str
    name              : str
    description       : str
    startDate         : str
    endDate           : str
    threatActors      : List[str]
    relatedTechniques : List[str]
    relatedCVEs       : List[str]
    relatedIOCs       : List[str]
    confidence        : str
    createdAt         : str
    active            : bool = True

    class Config:
        frozen = True


class ThreatRelationshipResponse(BaseModel):
    """
    Response model representing relationships between threat entities.
    """
    sourceThreatId : str
    targetId       : str
    targetType     : str  # "cve", "technique", "ioc", "campaign"
    relationType   : str  # "targets", "uses", "associated_with"
    confidence     : float

    class Config:
        frozen = True


# ===========================================================================
# Request Models
# ===========================================================================

class CreateThreatRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/threat.
    """
    threatName        : str
    aliases           : Optional[List[str]] = Field(default_factory=list)
    description       : Optional[str] = ""
    country           : Optional[str] = ""
    motivation        : Optional[str] = ""
    confidence        : str
    severity          : str
    active            : Optional[bool] = True
    malware           : Optional[List[str]] = Field(default_factory=list)
    industry          : Optional[List[str]] = Field(default_factory=list)
    relatedTechniques : Optional[List[str]] = Field(default_factory=list)
    relatedCVEs       : Optional[List[str]] = Field(default_factory=list)
    relatedIOCs       : Optional[List[str]] = Field(default_factory=list)
    createdAt         : str
    updatedAt         : Optional[str] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.threatName or not self.threatName.strip():
            errors.append("threatName must not be empty.")

        if not self.confidence or not self.confidence.strip():
            errors.append("confidence must not be empty.")
        else:
            from services.threat_intelligence_service import ThreatConfidenceEnum
            try:
                ThreatConfidenceEnum(self.confidence.strip().upper())
            except ValueError:
                errors.append(f"confidence must be a ThreatConfidenceEnum member; got {self.confidence!r}.")

        if not self.severity or not self.severity.strip():
            errors.append("severity must not be empty.")
        else:
            from services.threat_intelligence_service import ThreatSeverityEnum
            try:
                ThreatSeverityEnum(self.severity.strip().upper())
            except ValueError:
                errors.append(f"severity must be a ThreatSeverityEnum member; got {self.severity!r}.")

        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")

        return errors


class UpdateThreatRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/threat/{threatId}.
    """
    aliases           : Optional[List[str]] = None
    description       : Optional[str] = None
    country           : Optional[str] = None
    motivation        : Optional[str] = None
    confidence        : Optional[str] = None
    severity          : Optional[str] = None
    active            : Optional[bool] = None
    malware           : Optional[List[str]] = None
    industry          : Optional[List[str]] = None
    relatedTechniques : Optional[List[str]] = None
    relatedCVEs       : Optional[List[str]] = None
    relatedIOCs       : Optional[List[str]] = None
    updatedAt         : Optional[str] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(
            v is not None
            for k, v in self.model_dump().items()
        )

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if self.confidence is not None:
            if not self.confidence.strip():
                errors.append("confidence must not be empty.")
            else:
                from services.threat_intelligence_service import ThreatConfidenceEnum
                try:
                    ThreatConfidenceEnum(self.confidence.strip().upper())
                except ValueError:
                    errors.append(f"confidence must be a ThreatConfidenceEnum member; got {self.confidence!r}.")
        if self.severity is not None:
            if not self.severity.strip():
                errors.append("severity must not be empty.")
            else:
                from services.threat_intelligence_service import ThreatSeverityEnum
                try:
                    ThreatSeverityEnum(self.severity.strip().upper())
                except ValueError:
                    errors.append(f"severity must be a ThreatSeverityEnum member; got {self.severity!r}.")
        return errors


# ===========================================================================
# Response Models
# ===========================================================================

class ThreatResponse(BaseModel):
    """
    Response model carrying an individual threat record (Threat Actor).
    """
    threatId          : str
    threatKey         : str
    threatName        : str
    aliases           : List[str]
    description       : str
    country           : str
    motivation        : str
    confidence        : str
    severity          : str
    active            : bool = True
    malware           : List[str] = Field(default_factory=list)
    industry          : List[str] = Field(default_factory=list)
    relatedTechniques : List[str]
    relatedCVEs       : List[str]
    relatedIOCs       : List[str]
    createdAt         : str
    updatedAt         : Optional[str] = None

    class Config:
        frozen = True


class ThreatListResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/threat.
    """
    threats : List[ThreatResponse]
    total   : int

    class Config:
        frozen = True


class ThreatStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/threat/statistics.
    """
    totalThreats      : int
    activeThreats     : int
    averageConfidence : float
    averageSeverity   : float
    actorCounts       : Dict[str, int]
    campaignCounts    : Dict[str, int]
    countryCounts     : Dict[str, int]

    class Config:
        frozen = True


class ThreatSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/threat/search.
    """
    threats    : List[ThreatResponse]
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

class BulkCreateThreatsRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/threat/bulk/create.
    """
    threats : List[CreateThreatRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.threats:
            errors.append("threats list must not be empty.")
        for i, item in enumerate(self.threats):
            sub = item.validate_request()
            for e in sub:
                errors.append(f"threats[{i}]: {e}")
        return errors


class BulkUpdateThreatsRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/threat/bulk/update.
    """
    class BulkUpdateItem(BaseModel):
        threatId : str
        update   : UpdateThreatRequest

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
            if not item.threatId or not item.threatId.strip():
                errors.append(f"items[{i}]: threatId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
            sub = item.update.validate_request()
            for e in sub:
                errors.append(f"items[{i}]: {e}")
        return errors


class BulkDeleteThreatsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/knowledge/threat/bulk/delete.
    """
    threatIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.threatIds:
            errors.append("threatIds list must not be empty.")
        for i, tid in enumerate(self.threatIds):
            if not tid or not tid.strip():
                errors.append(f"threatIds[{i}]: threatId must not be empty.")
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
