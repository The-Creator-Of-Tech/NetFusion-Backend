"""
Threat Campaign API Router — Phase A6.8.2
==========================================
REST interface for Threat Campaigns.

Prefix  : /campaign
Tag     : Threat Campaigns
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body

from api.errors import (
    APILayerError,
    APIErrorConflict,
    APIErrorInternal,
    APIErrorNotFound,
    APIErrorValidation,
)
from api.models import APIResponse
from api.responses import build_success_response, build_paginated_response
from api.utils import exception_to_api_response, validate_pagination
from api.knowledge.campaign_models import (
    CreateCampaignRequest,
    UpdateCampaignRequest,
    CampaignResponse,
    CampaignListResponse,
    CampaignSearchResponse,
    CampaignStatisticsResponse,
    BulkOperationResult,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

campaign_router: APIRouter = APIRouter(
    prefix="/campaign",
    tags=["Threat Campaigns"],
)

# ---------------------------------------------------------------------------
# In-Memory Store — shared with threat_router via the same backing dict
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_threat_campaign
from api.knowledge.threat_router import _CAMPAIGN_STORE, _normalize_campaign


def _reset_store() -> None:
    """Clear the store. Used by tests only."""
    _CAMPAIGN_STORE.clear()


def _all_campaigns() -> List[Dict[str, Any]]:
    """Return all campaigns normalized and ordered by name ASC."""
    raw = _CAMPAIGN_STORE.values()
    normalized = [_normalize_campaign(r) for r in raw]
    return sorted(normalized, key=lambda c: c.get("name", ""))


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def find_campaign(campaigns: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a campaign by campaignId, campaignKey, or name (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for c in campaigns:
        if c.get("campaignId", "").lower() == normalized:
            return c
        if c.get("campaignKey", "").lower() == normalized:
            return c
        if c.get("name", "").lower() == normalized:
            return c
    return None


def search_campaigns(campaigns: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text and list fields."""
    if not query or not query.strip():
        return list(campaigns)
    q = query.strip().lower()
    results = []
    for c in campaigns:
        if q in c.get("name", "").lower():
            results.append(c)
            continue
        if q in c.get("description", "").lower():
            results.append(c)
            continue
        if q in c.get("confidence", "").lower():
            results.append(c)
            continue
        if any(q in ta.lower() for ta in c.get("threatActors", [])):
            results.append(c)
            continue
        if any(q in t.lower() for t in c.get("relatedTechniques", [])):
            results.append(c)
            continue
        if any(q in cv.lower() for cv in c.get("relatedCVEs", [])):
            results.append(c)
            continue
        if any(q in ioc.lower() for ioc in c.get("relatedIOCs", [])):
            results.append(c)
            continue
    return results


def sort_campaigns(
    campaigns: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc",
) -> List[Dict[str, Any]]:
    """Sorts campaigns deterministically, falling back to campaignId ASC."""
    valid_fields = {"campaignName", "confidence", "startDate", "createdAt"}
    if sort_by not in valid_fields:
        raise APIErrorValidation(
            message="Invalid sort field.",
            details=[f"Sorting by '{sort_by}' is not supported. Supported fields: {sorted(list(valid_fields))}"]
        )

    order = sort_order.strip().lower()
    if order not in {"asc", "desc"}:
        raise APIErrorValidation(
            message="Invalid sort order.",
            details=[f"Sort order '{sort_order}' must be 'asc' or 'desc'."]
        )

    def get_sort_key(c: Dict[str, Any]) -> Any:
        if sort_by == "campaignName":
            return c.get("name", "")
        elif sort_by == "confidence":
            conf_priority = {"low": 1, "medium": 2, "high": 3, "verified": 4}
            return conf_priority.get(c.get("confidence", "").lower(), -1)
        elif sort_by == "startDate":
            return c.get("startDate", "")
        elif sort_by == "createdAt":
            return c.get("createdAt", "")
        return ""

    reverse = (order == "desc")
    sorted_list = sorted(campaigns, key=lambda x: x.get("campaignId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_campaigns(
    campaigns: List[Dict[str, Any]],
    confidence: Optional[str] = None,
    active: Optional[bool] = None,
    threatActor: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filters campaign records."""
    filtered = list(campaigns)

    if confidence is not None:
        cf_val = confidence.strip().upper()
        filtered = [c for c in filtered if c.get("confidence", "").upper() == cf_val]

    if active is not None:
        filtered = [c for c in filtered if bool(c.get("active", True)) == active]

    if threatActor is not None:
        ta_val = threatActor.strip().lower()
        filtered = [
            c for c in filtered
            if any(ta_val in ta.lower() for ta in c.get("threatActors", []))
        ]

    return filtered


def paginate_campaigns(
    campaigns: List[Dict[str, Any]],
    page: int,
    page_size: int,
) -> Tuple[List[Dict[str, Any]], int]:
    """Paginates the campaign list."""
    total_items = len(campaigns)
    start = (page - 1) * page_size
    end = start + page_size
    return campaigns[start:end], total_items


def calculate_campaign_statistics(campaigns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregate statistics over a list of campaigns."""
    total = len(campaigns)
    active = sum(1 for c in campaigns if c.get("active"))

    actor_counts: Dict[str, int] = {}
    confidence_counts: Dict[str, int] = {}

    for c in campaigns:
        for ta in c.get("threatActors", []):
            actor_counts[ta] = actor_counts.get(ta, 0) + 1
        conf = c.get("confidence", "MEDIUM").upper()
        confidence_counts[conf] = confidence_counts.get(conf, 0) + 1

    return {
        "totalCampaigns":   total,
        "activeCampaigns":  active,
        "actorCounts":      dict(sorted(actor_counts.items())),
        "confidenceCounts": dict(sorted(confidence_counts.items())),
    }


def _to_response_model(c: Dict[str, Any]) -> CampaignResponse:
    """Convert a normalized campaign dict to CampaignResponse.

    Always normalizes first so both legacy metadata-backed records and
    raw Prisma records are handled safely.
    """
    n = _normalize_campaign(c)
    return CampaignResponse(
        campaignId=n["campaignId"],
        campaignKey=n["campaignKey"],
        name=n["name"],
        description=n["description"],
        startDate=n["startDate"],
        endDate=n["endDate"],
        threatActors=list(n["threatActors"]),
        relatedTechniques=list(n["relatedTechniques"]),
        relatedCVEs=list(n["relatedCVEs"]),
        relatedIOCs=list(n["relatedIOCs"]),
        confidence=n["confidence"],
        createdAt=n["createdAt"],
        active=n.get("active", True),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@campaign_router.get(
    "/",
    response_model=APIResponse,
    summary="List threat campaign records",
)
def list_campaigns(
    confidence: Optional[str] = None,
    active: Optional[bool] = None,
    threatActor: Optional[str] = None,
    sortBy: str = "campaignName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_camps = _all_campaigns()

        filtered = filter_campaigns(
            all_camps,
            confidence=confidence,
            active=active,
            threatActor=threatActor,
        )

        sorted_camps = sort_campaigns(filtered, sortBy, sortOrder)
        paginated, total = paginate_campaigns(sorted_camps, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]

        return build_paginated_response(
            items=[r.model_dump() for r in responses],
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Campaign records listed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@campaign_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get campaign statistics",
)
def get_statistics() -> APIResponse:
    try:
        all_camps = _all_campaigns()
        stats = calculate_campaign_statistics(all_camps)
        return build_success_response(
            data=stats,
            message="Statistics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@campaign_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search threat campaign records",
)
def search_campaign_records(
    query: str = "",
    sortBy: str = "campaignName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_camps = _all_campaigns()
        searched = search_campaigns(all_camps, query)
        sorted_camps = sort_campaigns(searched, sortBy, sortOrder)
        paginated, total = paginate_campaigns(sorted_camps, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]
        total_pages = math.ceil(total / pageSize) if total > 0 else 0

        search_data = CampaignSearchResponse(
            campaigns=responses,
            total=total,
            page=page,
            pageSize=pageSize,
            totalPages=total_pages,
            query=query,
            sortBy=sortBy,
            sortOrder=sortOrder,
        )

        return build_success_response(
            data=search_data.model_dump(),
            message="Search completed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@campaign_router.get(
    "/{campaignId}",
    response_model=APIResponse,
    summary="Get campaign by ID",
)
def get_campaign(campaignId: str) -> APIResponse:
    try:
        all_camps = _all_campaigns()
        c = find_campaign(all_camps, campaignId)
        if not c:
            raise APIErrorNotFound(f"Campaign '{campaignId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="Campaign record retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@campaign_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a threat campaign record",
)
def create_campaign(
    request: CreateCampaignRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        import hashlib as _hashlib
        import uuid as _uuid

        _CAMP_NS = _uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")
        camp_key = _hashlib.sha256(request.name.strip().lower().encode("utf-8")).hexdigest()[:32]
        camp_id = str(_uuid.uuid5(_CAMP_NS, camp_key))

        if camp_id in _CAMPAIGN_STORE:
            raise APIErrorConflict(f"Campaign with name '{request.name}' already exists.")

        _CAMPAIGN_STORE[camp_id] = {
            "campaignId":        camp_id,
            "campaignKey":       camp_key,
            "name":              request.name,
            "description":       request.description or "",
            "startDate":         request.startDate or "",
            "endDate":           request.endDate or "",
            "threatActors":      list(request.threatActors or []),
            "relatedTechniques": list(request.relatedTechniques or []),
            "relatedCVEs":       list(request.relatedCVEs or []),
            "relatedIOCs":       list(request.relatedIOCs or []),
            "confidence":        (request.confidence or "MEDIUM").upper(),
            "createdAt":         request.createdAt,
            "active":            bool(request.active),
        }

        return build_success_response(
            data=_to_response_model(_CAMPAIGN_STORE[camp_id]).model_dump(),
            message="Campaign record created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@campaign_router.put(
    "/{campaignId}",
    response_model=APIResponse,
    summary="Update a threat campaign record",
)
def update_campaign(
    campaignId: str,
    request: UpdateCampaignRequest = Body(...)
) -> APIResponse:
    try:
        all_camps = _all_campaigns()
        c = find_campaign(all_camps, campaignId)
        if not c:
            raise APIErrorNotFound(f"Campaign '{campaignId}' not found.")

        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")

        rec_id = c["campaignId"]
        updated = {
            "campaignId":        rec_id,
            "campaignKey":       c["campaignKey"],
            "name":              request.name if request.name is not None else c["name"],
            "description":       request.description if request.description is not None else c["description"],
            "startDate":         request.startDate if request.startDate is not None else c["startDate"],
            "endDate":           request.endDate if request.endDate is not None else c["endDate"],
            "threatActors":      list(request.threatActors if request.threatActors is not None else c["threatActors"]),
            "relatedTechniques": list(request.relatedTechniques if request.relatedTechniques is not None else c["relatedTechniques"]),
            "relatedCVEs":       list(request.relatedCVEs if request.relatedCVEs is not None else c["relatedCVEs"]),
            "relatedIOCs":       list(request.relatedIOCs if request.relatedIOCs is not None else c["relatedIOCs"]),
            "confidence":        (request.confidence if request.confidence is not None else c["confidence"]).upper(),
            "createdAt":         c["createdAt"],
            "active":            bool(request.active if request.active is not None else c.get("active", True)),
        }

        _CAMPAIGN_STORE[rec_id] = updated

        return build_success_response(
            data=_to_response_model(updated).model_dump(),
            message="Campaign record updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@campaign_router.delete(
    "/{campaignId}",
    response_model=APIResponse,
    summary="Delete a threat campaign record",
)
def delete_campaign(campaignId: str) -> APIResponse:
    try:
        all_camps = _all_campaigns()
        c = find_campaign(all_camps, campaignId)
        if not c:
            raise APIErrorNotFound(f"Campaign '{campaignId}' not found.")

        del _CAMPAIGN_STORE[c["campaignId"]]

        return build_success_response(
            data=None,
            message="Campaign record deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))
