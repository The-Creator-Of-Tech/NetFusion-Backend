"""
Asset API Models — Phase A4.7.2 (Part A + Part B)
===================================================
Immutable Pydantic models for Asset API request and response contracts.

Design rules
------------
- All models frozen (frozen=True) — immutable after construction.
- Request models validate only API-layer concerns (non-empty strings,
  field presence).  Business-rule validation stays in asset_service.py.
- No UUID generation — callers supply assetId values.
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

class CreateAssetRequest(BaseModel):
    """
    Request body for POST /api/v2/assets.

    Required fields
    ---------------
    assetId   : Caller-supplied identifier for the new asset.
                Must be non-empty.  Typically a MAC address or "ip:<addr>".

    Optional fields
    ---------------
    macAddress      : Hardware MAC address string.
    hostname        : Resolved hostname for the asset.
    deviceName      : Human-readable device name.
    vendor          : Hardware vendor string (e.g. "Cisco", "Apple").
    operatingSystem : OS identifier string (e.g. "Windows 11", "Linux").
    currentIp       : Current IP address observed for this asset.
    currentStatus   : Lifecycle status string ("active", "external", etc.).
    notes           : Optional free-text notes list.
    metadata        : Arbitrary caller-supplied key-value pairs.
    """
    assetId         : str
    macAddress      : Optional[str]              = None
    hostname        : Optional[str]              = None
    deviceName      : Optional[str]              = None
    vendor          : Optional[str]              = None
    operatingSystem : Optional[str]              = None
    currentIp       : Optional[str]              = None
    currentStatus   : Optional[str]              = None
    notes           : Optional[List[str]]        = None
    metadata        : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        """
        Return a list of validation error strings.
        Empty list means the request is valid.

        API-layer rules only:
        - assetId must be non-empty and non-whitespace.
        """
        errors: List[str] = []
        if not self.assetId or not self.assetId.strip():
            errors.append("assetId must not be empty.")
        return errors


class UpdateAssetRequest(BaseModel):
    """
    Request body for PUT /api/v2/assets/{assetId}.

    All fields are optional — supply only what should change.
    At least one field must be provided (validated at the route level).

    Fields
    ------
    hostname        : New hostname to set.
    deviceName      : New device name to set.
    vendor          : New vendor string.
    operatingSystem : New OS string.
    currentIp       : New current IP address.
    currentStatus   : New lifecycle status.
    notes           : Replace the full notes list.
    metadata        : Merge / replace metadata key-value pairs.
    """
    hostname        : Optional[str]              = None
    deviceName      : Optional[str]              = None
    vendor          : Optional[str]              = None
    operatingSystem : Optional[str]              = None
    currentIp       : Optional[str]              = None
    currentStatus   : Optional[str]              = None
    notes           : Optional[List[str]]        = None
    metadata        : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True

    def has_any_field(self) -> bool:
        """Return True if at least one field is not None."""
        return any(v is not None for v in self.model_dump().values())


class AssetFilterRequest(BaseModel):
    """
    Query-parameter filter model for GET /api/v2/assets.

    All fields are optional — omitting a field means "no filter on that field".

    Fields
    ------
    vendor          : Keep only assets matching this vendor (case-insensitive).
    operatingSystem : Keep only assets matching this OS string (case-insensitive).
    currentStatus   : Keep only assets with this status string.
    minRiskScore    : Keep only assets with currentRiskScore >= minRiskScore.
    maxRiskScore    : Keep only assets with currentRiskScore <= maxRiskScore.
    hasIp           : If True, keep only assets with a non-empty currentIp.
    hasMac          : If True, keep only assets with a non-empty macAddress.
    """
    vendor          : Optional[str]   = None
    operatingSystem : Optional[str]   = None
    currentStatus   : Optional[str]   = None
    minRiskScore    : Optional[int]   = None
    maxRiskScore    : Optional[int]   = None
    hasIp           : Optional[bool]  = None
    hasMac          : Optional[bool]  = None

    class Config:
        frozen = True


class AssetSearchRequest(BaseModel):
    """
    Request body / query parameter model for asset search operations.

    Fields
    ------
    query  : Free-text search string matched against assetId, macAddress,
             hostname, deviceName, currentIp (case-insensitive substring).
             Must be non-empty if provided.
    """
    query : str = Field(..., min_length=1, description="Non-empty search string.")

    class Config:
        frozen = True


class AssetPaginationRequest(BaseModel):
    """
    Pagination query parameters for list endpoints.

    Fields
    ------
    page     : 1-based page number (default 1, must be >= 1).
    pageSize : Items per page (default 20, must be 1–500).
    """
    page     : int = Field(default=1,  ge=1,          description="1-based page number.")
    pageSize : int = Field(default=20, ge=1,  le=500,  description="Items per page (1–500).")

    class Config:
        frozen = True


# ===========================================================================
# Response Models
# ===========================================================================

class AssetResponse(BaseModel):
    """
    Single asset payload returned by GET /api/v2/assets/{assetId} and
    POST /api/v2/assets.

    Mirrors the dict shape produced by asset_service.py builders so that
    FastAPI can generate a typed OpenAPI schema.

    All fields are Optional because asset dicts from the service layer may
    have absent keys (depending on how the asset was built).
    """
    assetId         : Optional[str]              = None
    macAddress      : Optional[str]              = None
    hostname        : Optional[str]              = None
    deviceName      : Optional[str]              = None
    vendor          : Optional[str]              = None
    operatingSystem : Optional[str]              = None
    currentIp       : Optional[str]              = None
    previousIPs     : Optional[List[str]]        = None
    currentStatus   : Optional[str]              = None
    currentRiskScore: Optional[int]              = None
    packetCount     : Optional[int]              = None
    firstSeen       : Optional[str]              = None
    lastSeen        : Optional[str]              = None
    protocols       : Optional[Dict[str, int]]   = None
    notes           : Optional[List[str]]        = None
    metadata        : Optional[Dict[str, Any]]   = None

    class Config:
        frozen = True


class AssetListResponse(BaseModel):
    """
    Payload for GET /api/v2/assets (list).

    Fields
    ------
    assets : List of AssetResponse objects.
    total  : Total count of matching assets in the in-memory store
             (before any pagination).
    """
    assets : List[AssetResponse]
    total  : int

    class Config:
        frozen = True


class AssetStatisticsResponse(BaseModel):
    """
    Payload for GET /api/v2/assets/statistics.

    Fields
    ------
    totalAssets    : Count of all assets in the in-memory store.
    activeAssets   : Count with currentStatus == "active".
    externalAssets : Count with currentStatus == "external".
    highRiskAssets : Count with currentRiskScore >= 60 (RISK_HOST_SCORE_HIGH).
    mediumRiskAssets: Count with currentRiskScore >= 30 (RISK_HOST_SCORE_MEDIUM).
    averageRiskScore: Mean currentRiskScore across all assets (0.0 if empty).
    vendorCounts   : Dict mapping vendor string → count.
    statusCounts   : Dict mapping currentStatus string → count.
    """
    totalAssets     : int
    activeAssets    : int
    externalAssets  : int
    highRiskAssets  : int
    mediumRiskAssets: int
    averageRiskScore: float
    vendorCounts    : Dict[str, int]
    statusCounts    : Dict[str, int]

    class Config:
        frozen = True


# ===========================================================================
# Part B — Search, Bulk, Extended Statistics
# ===========================================================================

class AssetSearchQueryRequest(BaseModel):
    """
    Query parameters for GET /api/v2/assets/search.

    Fields
    ------
    q           : Free-text search string.  Matched case-insensitively as a
                  substring against assetId, macAddress, hostname, deviceName,
                  currentIp, vendor, and operatingSystem.  Required, >= 1 char.
    sortBy      : Field to sort results by.
                  Allowed: "hostname", "vendor", "ip", "risk", "created"
                  (created sorts by assetId as a stable proxy).  Default "hostname".
    sortOrder   : "asc" (default) or "desc".
    page        : 1-based page number (default 1).
    pageSize    : Items per page 1–500 (default 20).
    """
    q         : str            = Field(..., min_length=1, description="Non-empty search string.")
    sortBy    : Optional[str]  = Field(default="hostname",  description="Sort field: hostname|vendor|ip|risk|created.")
    sortOrder : Optional[str]  = Field(default="asc",       description="Sort direction: asc|desc.")
    page      : Optional[int]  = Field(default=1,  ge=1,    description="1-based page number.")
    pageSize  : Optional[int]  = Field(default=20, ge=1, le=500, description="Items per page.")

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        allowed_sort = {"hostname", "vendor", "ip", "risk", "created"}
        if self.sortBy and self.sortBy not in allowed_sort:
            errors.append(f"sortBy must be one of: {sorted(allowed_sort)}.")
        if self.sortOrder and self.sortOrder not in ("asc", "desc"):
            errors.append("sortOrder must be 'asc' or 'desc'.")
        return errors


class BulkCreateAssetsRequest(BaseModel):
    """
    Request body for POST /api/v2/assets/bulk/create.

    Fields
    ------
    assets : List of CreateAssetRequest items to create.
             Must be non-empty.
    """
    assets : List[CreateAssetRequest] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.assets:
            errors.append("assets list must not be empty.")
        seen: set = set()
        for i, a in enumerate(self.assets):
            sub = a.validate_request()
            for e in sub:
                errors.append(f"assets[{i}]: {e}")
            aid = (a.assetId or "").strip()
            if aid in seen:
                errors.append(f"assets[{i}]: duplicate assetId '{aid}' within request.")
            if aid:
                seen.add(aid)
        return errors


class BulkUpdateAssetsRequest(BaseModel):
    """
    Request body for PUT /api/v2/assets/bulk/update.

    Each item pairs an assetId with the fields to update.
    """

    class BulkUpdateItem(BaseModel):
        assetId : str
        update  : UpdateAssetRequest

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
            if not item.assetId or not item.assetId.strip():
                errors.append(f"items[{i}]: assetId must not be empty.")
            if not item.update.has_any_field():
                errors.append(f"items[{i}]: update must contain at least one field.")
        return errors


class BulkDeleteAssetsRequest(BaseModel):
    """
    Request body for DELETE /api/v2/assets/bulk/delete.

    Fields
    ------
    assetIds : List of assetId strings to delete.  Must be non-empty.
    """
    assetIds : List[str] = Field(..., min_length=1)

    class Config:
        frozen = True

    def validate_request(self) -> List[str]:
        errors: List[str] = []
        if not self.assetIds:
            errors.append("assetIds list must not be empty.")
        for i, aid in enumerate(self.assetIds):
            if not aid or not aid.strip():
                errors.append(f"assetIds[{i}]: assetId must not be empty.")
        return errors


class BulkOperationResult(BaseModel):
    """
    Result summary returned by bulk operation endpoints.

    Fields
    ------
    succeeded : List of assetIds that were successfully processed.
    failed    : List of (assetId, reason) pairs for items that failed.
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


class AssetSearchResponse(BaseModel):
    """
    Payload returned by GET /api/v2/assets/search.

    Extends AssetListResponse with pagination metadata.
    """
    assets      : List[AssetResponse]
    total       : int
    page        : int
    pageSize    : int
    totalPages  : int
    query       : str
    sortBy      : str
    sortOrder   : str

    class Config:
        frozen = True


class AssetStatisticsExtendedResponse(BaseModel):
    """
    Extended statistics payload for GET /api/v2/assets/statistics (Part B).

    Includes all Part A fields plus:
    subnetCounts  : Dict mapping subnet prefix (e.g. "192.168.1") → count.
    onlineAssets  : Count with currentStatus == "active" or "online".
    offlineAssets : Count with currentStatus in ("inactive", "offline", "external").
    averageRisk   : Alias for averageRiskScore (float).
    """
    totalAssets     : int
    activeAssets    : int
    externalAssets  : int
    highRiskAssets  : int
    mediumRiskAssets: int
    averageRiskScore: float
    averageRisk     : float
    vendorCounts    : Dict[str, int]
    statusCounts    : Dict[str, int]
    subnetCounts    : Dict[str, int]
    onlineAssets    : int
    offlineAssets   : int

    class Config:
        frozen = True
