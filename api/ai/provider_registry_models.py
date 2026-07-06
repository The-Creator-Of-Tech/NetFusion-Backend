"""
AI Provider Registry API Models — Phase A4.8.8
==============================================
Immutable Pydantic models for Provider Registry request and response contracts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ===========================================================================
# Request Models
# ===========================================================================

class ProviderCapabilityRequest(BaseModel):
    """Request payload for model capability flags."""
    streaming        : Optional[bool] = False
    toolCalling      : Optional[bool] = False
    jsonMode         : Optional[bool] = False
    vision           : Optional[bool] = False
    embeddings       : Optional[bool] = False
    maxContextTokens : Optional[int]  = 8192
    maxOutputTokens  : Optional[int]  = 4096

    class Config:
        frozen = True


class ProviderModelRequest(BaseModel):
    """Request payload to register or update a model inside a provider."""
    modelName    : str
    alias        : Optional[str] = None
    capabilities : ProviderCapabilityRequest
    enabled      : Optional[bool] = True
    priority     : Optional[int]  = 50
    createdAt    : str

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.modelName or not self.modelName.strip():
            errors.append("modelName must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if self.capabilities.maxContextTokens is not None and self.capabilities.maxContextTokens < 1:
            errors.append("maxContextTokens must be >= 1.")
        if self.capabilities.maxOutputTokens is not None and self.capabilities.maxOutputTokens < 1:
            errors.append("maxOutputTokens must be >= 1.")
        if (self.capabilities.maxContextTokens is not None and 
            self.capabilities.maxOutputTokens is not None and 
            self.capabilities.maxOutputTokens > self.capabilities.maxContextTokens):
            errors.append("maxOutputTokens must be <= maxContextTokens.")
        if self.priority is not None and not (0 <= self.priority <= 100):
            errors.append("priority must be in [0, 100].")
        return errors


class CreateProviderRequest(BaseModel):
    """Request payload for POST /api/v2/providers."""
    providerName    : str
    displayName     : str
    apiVersion      : str
    endpoint        : str
    supportedModels : List[str] = Field(default_factory=list)
    defaultModel    : str
    createdAt       : str
    enabled         : Optional[bool] = True
    priority        : Optional[int]  = 50
    healthScore     : Optional[float] = 100.0
    providerType    : Optional[str]  = "cloud"

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.providerName or not self.providerName.strip():
            errors.append("providerName must not be empty.")
        if not self.endpoint or not self.endpoint.strip():
            errors.append("endpoint must not be empty.")
        if not self.createdAt or not self.createdAt.strip():
            errors.append("createdAt must not be empty.")
        if self.supportedModels and self.defaultModel:
            if self.defaultModel.strip().lower() not in [m.strip().lower() for m in self.supportedModels]:
                errors.append(f"defaultModel='{self.defaultModel}' not in supportedModels.")
        if self.priority is not None and not (0 <= self.priority <= 100):
            errors.append("priority must be in [0, 100].")
        if self.healthScore is not None and not (0.0 <= self.healthScore <= 100.0):
            errors.append("healthScore must be in [0.0, 100.0].")
        return errors


class UpdateProviderRequest(BaseModel):
    """Request payload for PUT /api/v2/providers/{providerId}."""
    displayName  : Optional[str] = None
    apiVersion   : Optional[str] = None
    endpoint     : Optional[str] = None
    defaultModel : Optional[str] = None
    enabled      : Optional[bool] = None
    priority     : Optional[int] = None
    healthScore  : Optional[float] = None
    providerType : Optional[str] = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        return any(v is not None for v in self.model_dump().values())


# ===========================================================================
# Response Models
# ===========================================================================

class ProviderHealthResponse(BaseModel):
    """Response payload for provider health details."""
    providerId  : str
    healthScore : float
    status      : str
    lastChecked : str

    class Config:
        frozen = True


class ProviderModelResponse(BaseModel):
    """Response payload for one model."""
    modelId       : str
    modelKey      : str
    provider      : str
    modelName     : str
    alias         : Optional[str]
    capabilities  : Dict[str, Any]
    enabled       : bool
    priority      : int
    createdAt     : str
    engineVersion : str

    class Config:
        frozen = True


class ProviderResponse(BaseModel):
    """Response payload for a full provider definition."""
    providerId      : str
    providerKey     : str
    providerName    : str
    displayName     : str
    apiVersion      : str
    endpoint        : str
    supportedModels : List[str]
    defaultModel    : str
    enabled         : bool
    createdAt       : str
    engineVersion   : str
    priority        : int
    healthScore     : float
    providerType    : str
    status          : str
    modelCount      : int
    models          : List[ProviderModelResponse] = Field(default_factory=list)

    class Config:
        frozen = True


class ProviderListResponse(BaseModel):
    """Response payload for list of providers."""
    providers : List[ProviderResponse]
    total     : int

    class Config:
        frozen = True


class ProviderSearchResponse(BaseModel):
    """Response payload for search results."""
    providers  : List[ProviderResponse]
    total      : int
    page       : int
    pageSize   : int
    totalPages : int
    query      : str
    sortBy     : str
    sortOrder  : str

    class Config:
        frozen = True


class ProviderStatisticsResponse(BaseModel):
    """Response payload for provider statistics."""
    totalProviders     : int
    activeProviders    : int
    disabledProviders  : int
    healthyProviders   : int
    degradedProviders  : int
    offlineProviders   : int
    averageHealthScore : float
    averagePriority    : float
    averageModels      : float
    providerTypeCounts : Dict[str, int]
    statusCounts       : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Bulk Operation Models
# ===========================================================================

class BulkCreateProvidersRequest(BaseModel):
    """Request payload for bulk provider creation."""
    providers : List[CreateProviderRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.providers:
            errors.append("providers list must not be empty.")
        for i, p in enumerate(self.providers):
            sub = p.validate_request()
            for err in sub:
                errors.append(f"providers[{i}]: {err}")
        return errors


class BulkUpdateProvidersRequest(BaseModel):
    """Request payload for bulk provider update."""
    class BulkUpdateItem(BaseModel):
        providerId : str
        update     : UpdateProviderRequest

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
            if not item.providerId or not item.providerId.strip():
                errors.append(f"items[{i}]: providerId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteProvidersRequest(BaseModel):
    """Request payload for bulk provider deletion."""
    providerIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.providerIds:
            errors.append("providerIds list must not be empty.")
        for i, pid in enumerate(self.providerIds):
            if not pid or not pid.strip():
                errors.append(f"providerIds[{i}]: providerId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """Response payload for bulk operations."""
    succeeded    : List[str]
    failed       : List[Dict[str, str]]
    total        : int
    successCount : int
    failCount    : int

    class Config:
        frozen = True
