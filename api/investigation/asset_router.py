"""
Asset Router — Phase A4.7.2 (Part A + Part B)
===============================================
REST interface for the Asset Engine.

Prefix  : /api/v2/assets
Tag     : Assets

Endpoints (Part A)
------------------
GET    /api/v2/assets              — list all assets (with optional filter)
GET    /api/v2/assets/statistics   — aggregate statistics (extended in Part B)
GET    /api/v2/assets/{assetId}    — get a single asset by ID
POST   /api/v2/assets              — create an asset
PUT    /api/v2/assets/{assetId}    — update an asset
DELETE /api/v2/assets/{assetId}    — delete an asset

Endpoints (Part B)
------------------
GET    /api/v2/assets/search       — search + sort + filter + paginate
POST   /api/v2/assets/bulk/create  — create multiple assets
PUT    /api/v2/assets/bulk/update  — update multiple assets
DELETE /api/v2/assets/bulk/delete  — delete multiple assets

Pure helpers (Part B)
---------------------
find_asset()      — locate a single asset by field/value
sort_assets()     — deterministic multi-key sort
filter_assets()   — extended filter (subnet, observed, online)
paginate_assets() — slice a list and return a Pagination metadata object

Design rules
------------
- No business logic here.  All logic delegated to asset_service.py.
- Uses only existing asset_service builders / helpers.
- No database.  In-memory placeholder collection (_ASSET_STORE).
- Returns only build_success_response() or build_error_response().
- Exceptions converted via exception_to_api_response().
- Request model validation at the API layer only; service validates business rules.
- No authentication, no middleware, no caching.
- No async, no background jobs.

In-memory store
---------------
_ASSET_STORE is a plain dict keyed by assetId.  It is module-level and
survives for the lifetime of the process.  It will be replaced by a proper
repository in a future phase.  Tests can reset it via _reset_store().
"""

from __future__ import annotations

import math
from typing import Annotated, Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, Query

from api.errors import APIErrorConflict, APIErrorNotFound, APIErrorValidation
from api.investigation.asset_models import (
    AssetFilterRequest,
    AssetListResponse,
    AssetPaginationRequest,
    AssetResponse,
    AssetSearchRequest,
    AssetSearchQueryRequest,
    AssetSearchResponse,
    AssetStatisticsExtendedResponse,
    AssetStatisticsResponse,
    BulkCreateAssetsRequest,
    BulkDeleteAssetsRequest,
    BulkOperationResult,
    BulkUpdateAssetsRequest,
    CreateAssetRequest,
    UpdateAssetRequest,
)
from api.models import APIResponse, Pagination
from api.responses import build_success_response
from api.utils import exception_to_api_response
from core.constants import RISK_HOST_SCORE_HIGH, RISK_HOST_SCORE_MEDIUM
from services.asset_service import (
    find_asset_by_id,
    find_asset_by_ip,
    merge_asset_records,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

asset_router: APIRouter = APIRouter(
    prefix = "/assets",
    tags   = ["Assets"],
)

# ---------------------------------------------------------------------------
# In-memory placeholder store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_asset
_ASSET_STORE = RepositoryBackedDict("asset", "assetId", map_asset)


def _reset_store() -> None:
    """Clear the in-memory store.  Used by tests only."""
    _ASSET_STORE.clear()


def _all_assets() -> List[Dict[str, Any]]:
    """Return all assets as a deterministically-ordered list (by assetId ASC)."""
    return sorted(_ASSET_STORE.values(), key=lambda a: a.get("assetId", ""))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _asset_to_response(asset: Dict[str, Any]) -> AssetResponse:
    """Convert a raw asset dict to an AssetResponse model."""
    return AssetResponse(
        assetId          = asset.get("assetId"),
        macAddress       = asset.get("macAddress"),
        hostname         = asset.get("hostname"),
        deviceName       = asset.get("deviceName"),
        vendor           = asset.get("vendor"),
        operatingSystem  = asset.get("operatingSystem"),
        currentIp        = asset.get("currentIp"),
        previousIPs      = asset.get("previousIPs") or [],
        currentStatus    = asset.get("currentStatus"),
        currentRiskScore = asset.get("currentRiskScore", 0),
        packetCount      = asset.get("packetCount", 0),
        firstSeen        = asset.get("firstSeen"),
        lastSeen         = asset.get("lastSeen"),
        protocols        = asset.get("protocols") or {},
        notes            = asset.get("notes") or [],
        metadata         = asset.get("metadata") or {},
    )


def _apply_filters(
    assets : List[Dict[str, Any]],
    vendor : Optional[str]  = None,
    os     : Optional[str]  = None,
    status : Optional[str]  = None,
    min_rs : Optional[int]  = None,
    max_rs : Optional[int]  = None,
    has_ip : Optional[bool] = None,
    has_mac: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """Apply optional filter criteria to a list of asset dicts."""
    result = []
    for a in assets:
        if vendor is not None and (a.get("vendor") or "").lower() != vendor.lower():
            continue
        if os is not None and (a.get("operatingSystem") or "").lower() != os.lower():
            continue
        if status is not None and a.get("currentStatus") != status:
            continue
        if min_rs is not None and a.get("currentRiskScore", 0) < min_rs:
            continue
        if max_rs is not None and a.get("currentRiskScore", 0) > max_rs:
            continue
        if has_ip is True  and not a.get("currentIp"):
            continue
        if has_ip is False and a.get("currentIp"):
            continue
        if has_mac is True  and not a.get("macAddress"):
            continue
        if has_mac is False and a.get("macAddress"):
            continue
        result.append(a)
    return result


def _compute_statistics(assets: List[Dict[str, Any]]) -> AssetStatisticsExtendedResponse:
    """Compute extended aggregate statistics over a list of asset dicts."""
    total    = len(assets)
    active   = sum(1 for a in assets if a.get("currentStatus") == "active")
    external = sum(1 for a in assets if a.get("currentStatus") == "external")
    high_r   = sum(1 for a in assets if a.get("currentRiskScore", 0) >= RISK_HOST_SCORE_HIGH)
    med_r    = sum(1 for a in assets if
                   RISK_HOST_SCORE_MEDIUM <= a.get("currentRiskScore", 0) < RISK_HOST_SCORE_HIGH)
    avg_rs   = (
        round(sum(a.get("currentRiskScore", 0) for a in assets) / total, 4)
        if total > 0 else 0.0
    )

    # Online = active or online; Offline = inactive, offline, external
    online_statuses  = {"active", "online"}
    offline_statuses = {"inactive", "offline", "external"}
    online_count  = sum(1 for a in assets if (a.get("currentStatus") or "") in online_statuses)
    offline_count = sum(1 for a in assets if (a.get("currentStatus") or "") in offline_statuses)

    vendor_counts: Dict[str, int] = {}
    status_counts: Dict[str, int] = {}
    subnet_counts: Dict[str, int] = {}

    for a in assets:
        v = a.get("vendor") or "Unknown"
        vendor_counts[v] = vendor_counts.get(v, 0) + 1

        s = a.get("currentStatus") or "unknown"
        status_counts[s] = status_counts.get(s, 0) + 1

        ip = a.get("currentIp") or ""
        if ip:
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3])
                subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

    return AssetStatisticsExtendedResponse(
        totalAssets      = total,
        activeAssets     = active,
        externalAssets   = external,
        highRiskAssets   = high_r,
        mediumRiskAssets = med_r,
        averageRiskScore = avg_rs,
        averageRisk      = avg_rs,
        vendorCounts     = dict(sorted(vendor_counts.items())),
        statusCounts     = dict(sorted(status_counts.items())),
        subnetCounts     = dict(sorted(subnet_counts.items())),
        onlineAssets     = online_count,
        offlineAssets    = offline_count,
    )


# ===========================================================================
# Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /assets
# ---------------------------------------------------------------------------

@asset_router.get(
    "",
    response_model       = APIResponse,
    summary              = "List assets",
    description          = (
        "Return all assets in the in-memory store.  "
        "Optional query parameters filter results by vendor, OS, status, "
        "risk score range, IP presence, and MAC presence."
    ),
)
def list_assets(
    vendor          : Annotated[Optional[str],  Query(description="Filter by vendor (case-insensitive exact match.)")] = None,
    operating_system: Annotated[Optional[str],  Query(alias="operatingSystem", description="Filter by OS (case-insensitive exact match.)")] = None,
    current_status  : Annotated[Optional[str],  Query(alias="currentStatus",   description="Filter by currentStatus.")] = None,
    min_risk_score  : Annotated[Optional[int],  Query(alias="minRiskScore",    description="Minimum currentRiskScore (inclusive).")] = None,
    max_risk_score  : Annotated[Optional[int],  Query(alias="maxRiskScore",    description="Maximum currentRiskScore (inclusive).")] = None,
    has_ip          : Annotated[Optional[bool], Query(alias="hasIp",           description="If true, return only assets with a currentIp.")] = None,
    has_mac         : Annotated[Optional[bool], Query(alias="hasMac",          description="If true, return only assets with a macAddress.")] = None,
) -> APIResponse:
    """
    GET /api/v2/assets

    Returns all assets, optionally filtered.  No pagination in this phase.
    """
    try:
        assets = _apply_filters(
            _all_assets(),
            vendor = vendor,
            os     = operating_system,
            status = current_status,
            min_rs = min_risk_score,
            max_rs = max_risk_score,
            has_ip = has_ip,
            has_mac= has_mac,
        )
        payload = AssetListResponse(
            assets = [_asset_to_response(a) for a in assets],
            total  = len(assets),
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{len(assets)} asset(s) found.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /assets/statistics
# ---------------------------------------------------------------------------

@asset_router.get(
    "/statistics",
    response_model       = APIResponse,
    summary              = "Asset statistics",
    description          = "Return aggregate statistics over all assets in the in-memory store.",
)
def get_asset_statistics() -> APIResponse:
    """
    GET /api/v2/assets/statistics

    Returns AssetStatisticsResponse — totals, risk breakdown, vendor counts.
    """
    try:
        stats = _compute_statistics(_all_assets())
        return build_success_response(
            data    = stats.model_dump(),
            message = "Asset statistics retrieved.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# GET /assets/{assetId}
# ---------------------------------------------------------------------------

@asset_router.get(
    "/{assetId}",
    response_model       = APIResponse,
    summary              = "Get asset by ID",
    description          = "Return a single asset by its assetId.",
)
def get_asset(assetId: str) -> APIResponse:
    """
    GET /api/v2/assets/{assetId}

    Looks up by assetId.  Returns 404 if not found.
    """
    try:
        asset = find_asset_by_id(assetId, _all_assets())
        if asset is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Asset '{assetId}' not found.")
            )
        return build_success_response(
            data    = _asset_to_response(asset).model_dump(),
            message = "Asset retrieved.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /assets
# ---------------------------------------------------------------------------

@asset_router.post(
    "",
    response_model       = APIResponse,
    summary              = "Create asset",
    description          = "Create a new asset in the in-memory store.",
    status_code          = 201,
)
def create_asset(
    body: CreateAssetRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/assets

    Validates the request, checks for duplicate assetId, then builds and
    stores a new asset dict using fields from the request body.

    Returns 409 if an asset with the same assetId already exists.
    Returns 422 if request validation fails.
    """
    try:
        # API-layer validation
        errors = body.validate_request()
        if errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid asset request.", details=errors)
            )

        asset_id = body.assetId.strip()

        # Duplicate check
        if asset_id in _ASSET_STORE:
            return exception_to_api_response(
                APIErrorConflict(f"Asset '{asset_id}' already exists.")
            )

        # Build asset dict from request — mirrors the shape used by asset_service
        new_asset: Dict[str, Any] = {
            "assetId"        : asset_id,
            "macAddress"     : body.macAddress,
            "hostname"       : body.hostname,
            "deviceName"     : body.deviceName,
            "vendor"         : body.vendor or "Unknown",
            "operatingSystem": body.operatingSystem or "Unknown",
            "currentIp"      : body.currentIp,
            "previousIPs"    : [body.currentIp] if body.currentIp else [],
            "currentStatus"  : body.currentStatus or "active",
            "currentRiskScore": 0,
            "packetCount"    : 0,
            "firstSeen"      : None,
            "lastSeen"       : None,
            "protocols"      : {},
            "identityEvidence": [],
            "findings"       : [],
            "alerts"         : [],
            "packets"        : [],
            "connections"    : [],
            "timeline"       : [],
            "reports"        : [],
            "notes"          : list(body.notes) if body.notes else [],
            "metadata"       : dict(body.metadata) if body.metadata else {},
        }

        _ASSET_STORE[asset_id] = new_asset

        return build_success_response(
            data    = _asset_to_response(new_asset).model_dump(),
            message = "Asset created.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /assets/{assetId}
# ---------------------------------------------------------------------------

@asset_router.put(
    "/{assetId}",
    response_model       = APIResponse,
    summary              = "Update asset",
    description          = "Update an existing asset in the in-memory store.",
)
def update_asset(
    assetId: str,
    body   : UpdateAssetRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/assets/{assetId}

    At least one field must be provided in the body.
    Only non-None fields overwrite the stored value.
    Returns 404 if the asset does not exist.
    Returns 422 if the body contains no fields.
    """
    try:
        # API-layer: require at least one field
        if not body.has_any_field():
            return exception_to_api_response(
                APIErrorValidation(
                    "Update request must contain at least one field.",
                    details=["All fields in the request body are null."],
                )
            )

        asset = find_asset_by_id(assetId, _all_assets())
        if asset is None:
            return exception_to_api_response(
                APIErrorNotFound(f"Asset '{assetId}' not found.")
            )

        # Apply updates — None fields are skipped
        if body.hostname        is not None: asset["hostname"]         = body.hostname
        if body.deviceName      is not None: asset["deviceName"]       = body.deviceName
        if body.vendor          is not None: asset["vendor"]           = body.vendor
        if body.operatingSystem is not None: asset["operatingSystem"]  = body.operatingSystem
        if body.currentStatus   is not None: asset["currentStatus"]    = body.currentStatus
        if body.notes           is not None: asset["notes"]            = list(body.notes)
        if body.metadata        is not None:
            existing_meta = asset.get("metadata") or {}
            asset["metadata"] = {**existing_meta, **dict(body.metadata)}
        if body.currentIp is not None:
            asset["currentIp"] = body.currentIp
            if body.currentIp not in asset.get("previousIPs", []):
                asset.setdefault("previousIPs", []).append(body.currentIp)

        # Persist back to store
        _ASSET_STORE[assetId] = asset

        return build_success_response(
            data    = _asset_to_response(asset).model_dump(),
            message = "Asset updated.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /assets/{assetId}
# ---------------------------------------------------------------------------

@asset_router.delete(
    "/{assetId}",
    response_model       = APIResponse,
    summary              = "Delete asset",
    description          = "Remove an asset from the in-memory store.",
)
def delete_asset(assetId: str) -> APIResponse:
    """
    DELETE /api/v2/assets/{assetId}

    Returns 404 if the asset does not exist.
    Returns success with data=None on successful deletion.
    """
    try:
        if assetId not in _ASSET_STORE:
            return exception_to_api_response(
                APIErrorNotFound(f"Asset '{assetId}' not found.")
            )

        del _ASSET_STORE[assetId]

        return build_success_response(
            data    = None,
            message = f"Asset '{assetId}' deleted.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))

# ===========================================================================
# Part B — Pure deterministic helpers
# ===========================================================================

# Canonical sort-key map
_SORT_KEY_MAP: Dict[str, str] = {
    "hostname" : "hostname",
    "vendor"   : "vendor",
    "ip"       : "currentIp",
    "risk"     : "currentRiskScore",
    "created"  : "assetId",   # assetId used as stable creation-order proxy
}


def find_asset(
    assets : List[Dict[str, Any]],
    field  : str,
    value  : str,
) -> Optional[Dict[str, Any]]:
    """
    Return the first asset whose ``field`` matches ``value`` (case-insensitive).

    Pure deterministic helper — no side-effects, no I/O.

    Parameters
    ----------
    assets : Ordered list of asset dicts to search.
    field  : Dict key to match against (e.g. "hostname", "currentIp").
    value  : Value to match (case-insensitive string comparison).

    Returns
    -------
    The first matching asset dict, or None if not found.
    """
    target = value.lower()
    for a in assets:
        v = a.get(field)
        if v is not None and str(v).lower() == target:
            return a
    return None


def sort_assets(
    assets    : List[Dict[str, Any]],
    sort_by   : str  = "hostname",
    sort_order: str  = "asc",
) -> List[Dict[str, Any]]:
    """
    Return a new list of asset dicts sorted by the specified field.

    Pure deterministic helper — the input list is never mutated.

    Supported sort_by values
    ------------------------
    "hostname" — sort by hostname (None/missing sorted last)
    "vendor"   — sort by vendor   (None/missing sorted last)
    "ip"       — sort by currentIp (None/missing sorted last; sorts lexicographically)
    "risk"     — sort by currentRiskScore (numeric; None treated as 0)
    "created"  — sort by assetId (stable proxy for insertion order)

    Parameters
    ----------
    assets     : List of asset dicts.
    sort_by    : One of the supported sort keys above.  Unrecognised values
                 fall back to "hostname".
    sort_order : "asc" (default) or "desc".  Any other value treated as "asc".

    Returns
    -------
    New sorted list — input not mutated.
    """
    field = _SORT_KEY_MAP.get(sort_by, "hostname")
    reverse = sort_order.lower() == "desc"

    def sort_key(a: Dict[str, Any]):
        v = a.get(field)
        if v is None:
            # Sort None last for asc, first for desc (invert sentinel)
            return (1, "") if not reverse else (0, "")
        if isinstance(v, (int, float)):
            return (0, v)
        return (0, str(v).lower())

    return sorted(assets, key=sort_key, reverse=reverse)


def filter_assets(
    assets  : List[Dict[str, Any]],
    vendor  : Optional[str]  = None,
    hostname: Optional[str]  = None,
    subnet  : Optional[str]  = None,
    min_risk: Optional[int]  = None,
    max_risk: Optional[int]  = None,
    observed: Optional[bool] = None,
    online  : Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """
    Extended filter helper supporting subnet, observed, and online predicates.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    assets   : Ordered list of asset dicts.
    vendor   : Case-insensitive exact match on vendor.
    hostname : Case-insensitive substring match on hostname.
    subnet   : CIDR-less prefix match on currentIp (e.g. "192.168.1").
               An asset matches if its currentIp starts with "{subnet}.".
    min_risk : Keep assets with currentRiskScore >= min_risk.
    max_risk : Keep assets with currentRiskScore <= max_risk.
    observed : If True, keep only assets with lastSeen set (not None/empty).
               If False, keep only assets where lastSeen is None/empty.
    online   : If True, keep only assets with currentStatus in
               {"active", "online"}.
               If False, keep only assets NOT in that set.

    Returns
    -------
    Filtered list — input not mutated.
    """
    online_statuses = {"active", "online"}
    result = []
    for a in assets:
        if vendor is not None:
            if (a.get("vendor") or "").lower() != vendor.lower():
                continue
        if hostname is not None:
            if hostname.lower() not in (a.get("hostname") or "").lower():
                continue
        if subnet is not None:
            ip = a.get("currentIp") or ""
            prefix = subnet.rstrip(".")
            if not ip.startswith(prefix + "."):
                continue
        if min_risk is not None:
            if a.get("currentRiskScore", 0) < min_risk:
                continue
        if max_risk is not None:
            if a.get("currentRiskScore", 0) > max_risk:
                continue
        if observed is True and not a.get("lastSeen"):
            continue
        if observed is False and a.get("lastSeen"):
            continue
        if online is True and (a.get("currentStatus") or "") not in online_statuses:
            continue
        if online is False and (a.get("currentStatus") or "") in online_statuses:
            continue
        result.append(a)
    return result


def paginate_assets(
    assets   : List[Dict[str, Any]],
    page     : int,
    page_size: int,
) -> Tuple[List[Dict[str, Any]], Pagination]:
    """
    Slice an asset list to the requested page and return metadata.

    Pure deterministic helper — the input list is never mutated.

    Parameters
    ----------
    assets    : Full ordered list of asset dicts (already filtered/sorted).
    page      : 1-based page number (clamped to >= 1).
    page_size : Items per page (clamped to >= 1).

    Returns
    -------
    (page_slice, Pagination) where:
    - page_slice : the sub-list for the requested page.
    - Pagination : metadata model with page, pageSize, totalItems, totalPages.
    """
    safe_page      = max(1, page)
    safe_page_size = max(1, page_size)
    total          = len(assets)
    total_pages    = math.ceil(total / safe_page_size) if total > 0 else 0
    start          = (safe_page - 1) * safe_page_size
    end            = start + safe_page_size
    page_slice     = assets[start:end]
    pagination     = Pagination(
        page       = safe_page,
        pageSize   = safe_page_size,
        totalItems = total,
        totalPages = total_pages,
    )
    return page_slice, pagination


def _search_assets(
    assets: List[Dict[str, Any]],
    query : str,
) -> List[Dict[str, Any]]:
    """
    Return assets where any searchable text field contains *query* as a
    case-insensitive substring.

    Searchable fields: assetId, macAddress, hostname, deviceName,
                       currentIp, vendor, operatingSystem.
    """
    q = query.lower()
    search_fields = (
        "assetId", "macAddress", "hostname",
        "deviceName", "currentIp", "vendor", "operatingSystem",
    )
    result = []
    for a in assets:
        for f in search_fields:
            v = a.get(f) or ""
            if q in str(v).lower():
                result.append(a)
                break
    return result


# ===========================================================================
# Part B — Endpoints
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /assets/search
# ---------------------------------------------------------------------------

@asset_router.get(
    "/search",
    response_model = APIResponse,
    summary        = "Search assets",
    description    = (
        "Full-text search across assetId, macAddress, hostname, deviceName, "
        "currentIp, vendor, and operatingSystem.  Supports sorting, filtering, "
        "and pagination via query parameters."
    ),
)
def search_assets(
    q            : Annotated[str,            Query(min_length=1, description="Search string (>= 1 char).")],
    sort_by      : Annotated[Optional[str],  Query(alias="sortBy",    description="Sort field: hostname|vendor|ip|risk|created.")] = "hostname",
    sort_order   : Annotated[Optional[str],  Query(alias="sortOrder", description="Sort direction: asc|desc.")] = "asc",
    page         : Annotated[Optional[int],  Query(ge=1,             description="1-based page number.")] = 1,
    page_size    : Annotated[Optional[int],  Query(alias="pageSize", ge=1, le=500, description="Items per page.")] = 20,
    vendor_filter: Annotated[Optional[str],  Query(alias="vendor",   description="Exact vendor filter.")] = None,
    hostname_filter: Annotated[Optional[str], Query(alias="hostname", description="Substring hostname filter.")] = None,
    subnet_filter: Annotated[Optional[str],  Query(alias="subnet",   description="Subnet prefix filter (e.g. '192.168.1').")] = None,
    min_risk     : Annotated[Optional[int],  Query(alias="minRisk",  description="Minimum risk score.")] = None,
    max_risk     : Annotated[Optional[int],  Query(alias="maxRisk",  description="Maximum risk score.")] = None,
    observed     : Annotated[Optional[bool], Query(description="If true, only assets with lastSeen set.")] = None,
    online       : Annotated[Optional[bool], Query(description="If true, only active/online assets.")] = None,
) -> APIResponse:
    """
    GET /api/v2/assets/search

    Free-text search + optional filters + sort + pagination.
    """
    try:
        # Validate sort parameters
        allowed_sort = {"hostname", "vendor", "ip", "risk", "created"}
        errs = []
        if sort_by and sort_by not in allowed_sort:
            errs.append(f"sortBy must be one of: {sorted(allowed_sort)}.")
        if sort_order and sort_order not in ("asc", "desc"):
            errs.append("sortOrder must be 'asc' or 'desc'.")
        if errs:
            return exception_to_api_response(
                APIErrorValidation("Invalid search parameters.", details=errs)
            )

        # 1. Search
        matched = _search_assets(_all_assets(), q)

        # 2. Extended filter
        matched = filter_assets(
            matched,
            vendor   = vendor_filter,
            hostname = hostname_filter,
            subnet   = subnet_filter,
            min_risk = min_risk,
            max_risk = max_risk,
            observed = observed,
            online   = online,
        )

        # 3. Sort
        sorted_assets = sort_assets(
            matched,
            sort_by    = sort_by or "hostname",
            sort_order = sort_order or "asc",
        )

        # 4. Paginate
        page_slice, pag = paginate_assets(sorted_assets, page or 1, page_size or 20)

        payload = AssetSearchResponse(
            assets     = [_asset_to_response(a) for a in page_slice],
            total      = pag.totalItems,
            page       = pag.page,
            pageSize   = pag.pageSize,
            totalPages = pag.totalPages,
            query      = q,
            sortBy     = sort_by or "hostname",
            sortOrder  = sort_order or "asc",
        )
        return build_success_response(
            data    = payload.model_dump(),
            message = f"{pag.totalItems} asset(s) matched '{q}'.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# POST /assets/bulk/create
# ---------------------------------------------------------------------------

@asset_router.post(
    "/bulk/create",
    response_model = APIResponse,
    summary        = "Bulk create assets",
    description    = "Create multiple assets in one request.  Partial success is supported.",
    status_code    = 201,
)
def bulk_create_assets(
    body: BulkCreateAssetsRequest = Body(...),
) -> APIResponse:
    """
    POST /api/v2/assets/bulk/create

    Each item is processed independently.  Failures (validation error,
    duplicate assetId) are captured per-item; the operation does not abort
    on first failure.

    Returns BulkOperationResult with succeeded / failed lists.
    """
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk create request.", details=req_errors)
            )

        succeeded: List[str]           = []
        failed   : List[Dict[str, str]] = []

        for item in body.assets:
            item_errors = item.validate_request()
            if item_errors:
                failed.append({"assetId": item.assetId, "reason": "; ".join(item_errors)})
                continue

            asset_id = item.assetId.strip()
            if asset_id in _ASSET_STORE:
                failed.append({"assetId": asset_id, "reason": f"Asset '{asset_id}' already exists."})
                continue

            new_asset: Dict[str, Any] = {
                "assetId"         : asset_id,
                "macAddress"      : item.macAddress,
                "hostname"        : item.hostname,
                "deviceName"      : item.deviceName,
                "vendor"          : item.vendor or "Unknown",
                "operatingSystem" : item.operatingSystem or "Unknown",
                "currentIp"       : item.currentIp,
                "previousIPs"     : [item.currentIp] if item.currentIp else [],
                "currentStatus"   : item.currentStatus or "active",
                "currentRiskScore": 0,
                "packetCount"     : 0,
                "firstSeen"       : None,
                "lastSeen"        : None,
                "protocols"       : {},
                "identityEvidence": [],
                "findings"        : [],
                "alerts"          : [],
                "packets"         : [],
                "connections"     : [],
                "timeline"        : [],
                "reports"         : [],
                "notes"           : list(item.notes) if item.notes else [],
                "metadata"        : dict(item.metadata) if item.metadata else {},
            }
            _ASSET_STORE[asset_id] = new_asset
            succeeded.append(asset_id)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.assets),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk create: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# PUT /assets/bulk/update
# ---------------------------------------------------------------------------

@asset_router.put(
    "/bulk/update",
    response_model = APIResponse,
    summary        = "Bulk update assets",
    description    = "Update multiple assets in one request.  Partial success is supported.",
)
def bulk_update_assets(
    body: BulkUpdateAssetsRequest = Body(...),
) -> APIResponse:
    """
    PUT /api/v2/assets/bulk/update

    Each item is processed independently.  Failures (not found, validation)
    are captured per-item without aborting the batch.

    Returns BulkOperationResult with succeeded / failed lists.
    """
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk update request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for item in body.items:
            asset_id = item.assetId.strip()

            if not asset_id:
                failed.append({"assetId": item.assetId, "reason": "assetId must not be empty."})
                continue

            if not item.update.has_any_field():
                failed.append({"assetId": asset_id, "reason": "Update must contain at least one field."})
                continue

            asset = find_asset_by_id(asset_id, _all_assets())
            if asset is None:
                failed.append({"assetId": asset_id, "reason": f"Asset '{asset_id}' not found."})
                continue

            upd = item.update
            if upd.hostname        is not None: asset["hostname"]        = upd.hostname
            if upd.deviceName      is not None: asset["deviceName"]      = upd.deviceName
            if upd.vendor          is not None: asset["vendor"]          = upd.vendor
            if upd.operatingSystem is not None: asset["operatingSystem"] = upd.operatingSystem
            if upd.currentStatus   is not None: asset["currentStatus"]   = upd.currentStatus
            if upd.notes           is not None: asset["notes"]           = list(upd.notes)
            if upd.metadata        is not None:
                existing_meta = asset.get("metadata") or {}
                asset["metadata"] = {**existing_meta, **dict(upd.metadata)}
            if upd.currentIp is not None:
                asset["currentIp"] = upd.currentIp
                if upd.currentIp not in asset.get("previousIPs", []):
                    asset.setdefault("previousIPs", []).append(upd.currentIp)

            _ASSET_STORE[asset_id] = asset
            succeeded.append(asset_id)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.items),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk update: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))


# ---------------------------------------------------------------------------
# DELETE /assets/bulk/delete
# ---------------------------------------------------------------------------

@asset_router.delete(
    "/bulk/delete",
    response_model = APIResponse,
    summary        = "Bulk delete assets",
    description    = "Delete multiple assets in one request.  Partial success is supported.",
)
def bulk_delete_assets(
    body: BulkDeleteAssetsRequest = Body(...),
) -> APIResponse:
    """
    DELETE /api/v2/assets/bulk/delete

    Each assetId is processed independently.  Missing IDs are captured as
    failures without aborting the batch.

    Returns BulkOperationResult with succeeded / failed lists.
    """
    try:
        req_errors = body.validate_request()
        if req_errors:
            return exception_to_api_response(
                APIErrorValidation("Invalid bulk delete request.", details=req_errors)
            )

        succeeded: List[str]            = []
        failed   : List[Dict[str, str]] = []

        for asset_id in body.assetIds:
            aid = asset_id.strip() if asset_id else ""
            if not aid:
                failed.append({"assetId": asset_id, "reason": "assetId must not be empty."})
                continue
            if aid not in _ASSET_STORE:
                failed.append({"assetId": aid, "reason": f"Asset '{aid}' not found."})
                continue
            del _ASSET_STORE[aid]
            succeeded.append(aid)

        result = BulkOperationResult(
            succeeded    = succeeded,
            failed       = failed,
            total        = len(body.assetIds),
            successCount = len(succeeded),
            failCount    = len(failed),
        )
        return build_success_response(
            data    = result.model_dump(),
            message = f"Bulk delete: {len(succeeded)} succeeded, {len(failed)} failed.",
        )
    except Exception as exc:
        from api.errors import APIErrorInternal
        return exception_to_api_response(APIErrorInternal(str(exc)))
