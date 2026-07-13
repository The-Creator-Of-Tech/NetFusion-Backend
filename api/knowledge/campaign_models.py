"""
Threat Campaign API Models — Phase A6.8.2
==========================================
Immutable Pydantic models for Threat Campaign request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class CreateCampaignRequest(BaseModel):
    """
    Request body for POST /api/v2/knowledge/campaign.
    """
    name              : str
    description       : Optional[str] = ""
    startDate         : Optional[str] = ""
    endDate           : Optional[str] = ""
    threatActors      : Optional[List[str]] = Field(default_factory=list)
    relatedTechniques : Optional[List[str]] = Field(default_factory=list)
    relatedCVEs       : Optional[List[str]] = Field(default_factory=list)
    relatedIOCs       : Optional[List[str]] = Field(default_factory=list)
    confidence        : str = "MEDIUM"
    active            : Optional[bool] = True
    createdAt         : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.name or not self.name.strip():
            errors.append("name must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        return errors


class UpdateCampaignRequest(BaseModel):
    """
    Request body for PUT /api/v2/knowledge/campaign/{campaignId}.
    """
    name              : Optional[str] = None
    description       : Optional[str] = None
    startDate         : Optional[str] = None
    endDate           : Optional[str] = None
    threatActors      : Optional[List[str]] = None
    relatedTechniques : Optional[List[str]] = None
    relatedCVEs       : Optional[List[str]] = None
    relatedIOCs       : Optional[List[str]] = None
    confidence        : Optional[str] = None
    active            : Optional[bool] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(v is not None for v in self.model_dump().values())

    def validate_request(self) -> List[str]:
        return []


# ===========================================================================
# Response Models
# ===========================================================================

class CampaignResponse(BaseModel):
    """
    Response model representing a single Threat Campaign record.
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


class CampaignListResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/campaign.
    """
    campaigns : List[CampaignResponse]
    total     : int

    class Config:
        frozen = True


class CampaignSearchResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/campaign/search.
    """
    campaigns  : List[CampaignResponse]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int
    query      : str
    sortBy     : str
    sortOrder  : str

    class Config:
        frozen = True


class CampaignStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/knowledge/campaign/statistics.
    """
    totalCampaigns  : int
    activeCampaigns : int
    actorCounts     : Dict[str, int]
    confidenceCounts: Dict[str, int]

    class Config:
        frozen = True


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
