"""
Investigation API Models
========================
Immutable Pydantic models for Investigation API request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class CreateInvestigationRequest(BaseModel):
    """Request body for POST /api/v2/investigation."""
    projectId   : str
    ownerId     : str
    title       : str
    description : Optional[str]            = None
    priority    : Optional[str]            = "MEDIUM"
    tags        : Optional[List[str]]      = None
    metadata    : Optional[Dict[str, Any]] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.projectId or not self.projectId.strip():
            errors.append("projectId must not be empty.")
        if not self.ownerId or not self.ownerId.strip():
            errors.append("ownerId must not be empty.")
        if not self.title or not self.title.strip():
            errors.append("title must not be empty.")
        if self.priority and self.priority.upper() not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            errors.append("priority must be one of LOW, MEDIUM, HIGH, CRITICAL.")
        return errors


class UpdateInvestigationRequest(BaseModel):
    """Request body for PUT /api/v2/investigation/{investigationId}."""
    title       : Optional[str]            = None
    description : Optional[str]            = None
    priority    : Optional[str]            = None
    tags        : Optional[List[str]]      = None
    metadata    : Optional[Dict[str, Any]] = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if self.title is not None and not self.title.strip():
            errors.append("title must not be empty if provided.")
        if self.priority is not None and self.priority.upper() not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            errors.append("priority must be one of LOW, MEDIUM, HIGH, CRITICAL.")
        return errors


class LinkAssetRequest(BaseModel):
    """Request body for POST /api/v2/investigation/{investigationId}/link-asset."""
    assetId : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.assetId or not self.assetId.strip():
            errors.append("assetId must not be empty.")
        return errors


class LinkFindingRequest(BaseModel):
    """Request body for POST /api/v2/investigation/{investigationId}/link-finding."""
    findingId : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.findingId or not self.findingId.strip():
            errors.append("findingId must not be empty.")
        return errors


class InvestigationResponse(BaseModel):
    """Standard investigation response shape."""
    investigationId : str
    projectId       : str
    ownerId         : str
    title           : str
    description     : Optional[str]            = None
    status          : str
    priority        : str
    tags            : List[str]                = []
    metadata        : Dict[str, Any]           = {}
    createdAt       : str
    updatedAt       : str
    closedAt        : Optional[str]            = None
    assetIds        : List[str]                = []
    findingIds      : List[str]                = []
    timelineEventIds: List[str]                = []
    evidenceIds     : List[str]                = []

    class Config:
        frozen = True


class InvestigationStatisticsResponse(BaseModel):
    """Standard statistics response shape."""
    totalInvestigations : int
    openCount           : int
    closedCount         : int
    criticalCount       : int
    averageRisk         : float
    averageConfidence   : float

    class Config:
        frozen = True
