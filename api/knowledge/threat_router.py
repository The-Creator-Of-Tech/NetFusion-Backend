"""
Threat Intelligence API Router — Phase A4.9.4
=============================================
REST interface for Threat Intelligence.

Prefix  : /threat
Tag     : Threat Intelligence
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
from api.knowledge.threat_models import (
    CreateThreatRequest,
    UpdateThreatRequest,
    ThreatResponse,
    ThreatListResponse,
    ThreatStatisticsResponse,
    ThreatSearchResponse,
    ThreatRelationshipResponse,
    ThreatCampaignResponse,
    BulkCreateThreatsRequest,
    BulkUpdateThreatsRequest,
    BulkDeleteThreatsRequest,
    BulkOperationResult,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

threat_router: APIRouter = APIRouter(
    prefix="/threat",
    tags=["Threat Intelligence"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_threat_actor, map_threat_campaign
_THREAT_STORE = RepositoryBackedDict("threatActor", "threatId", map_threat_actor)
_CAMPAIGN_STORE = RepositoryBackedDict("threatCampaign", "campaignId", map_threat_campaign)


def _reset_store() -> None:
    """Clear the in-memory stores. Used by tests only."""
    _THREAT_STORE.clear()
    _CAMPAIGN_STORE.clear()


def _normalize_threat(r: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a raw record so it always has the keys _to_response_model() expects.

    Handles two shapes:
    1. Legacy / in-memory record  — already has `threatId`, `threatKey`, `name`, etc.
    2. Normalized Prisma record   — has top-level `id`, `name`, and may lack
                                    `threatId`, `threatKey`, `aliases`, `malware`,
                                    `country`, `relatedTechniques`, etc.
    """
    # Already a fully normalized legacy record
    if r.get("threatId") and r.get("threatKey"):
        return r

    import hashlib as _hashlib
    import uuid as _uuid

    _THREAT_NS = _uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

    # --- Derive threatId / threatKey from the record --------------------------
    name_raw: str = r.get("name") or r.get("actorName") or r.get("id") or "threat_unknown"
    threat_key = _hashlib.sha256(name_raw.strip().lower().encode("utf-8")).hexdigest()[:32]
    threat_id: str = (
        r.get("threatId")
        or r.get("actorId")
        or str(_uuid.uuid5(_THREAT_NS, threat_key))
    )

    def _fmt_date(val: Any) -> str:
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        if hasattr(val, "isoformat"):
            try:
                return val.isoformat()
            except Exception:
                return str(val)
        return str(val)

    # aliases: may be a list of dicts with a `name` field, or plain strings
    raw_aliases = r.get("aliases") or []
    aliases: List[str] = []
    for a in raw_aliases:
        if isinstance(a, dict):
            aliases.append(a.get("name") or a.get("alias") or "")
        elif isinstance(a, str):
            aliases.append(a)
    aliases = [x for x in aliases if x]

    # malware: same pattern
    raw_malware = r.get("malware") or []
    malware: List[str] = []
    for m in raw_malware:
        if isinstance(m, dict):
            malware.append(m.get("name") or m.get("malwareName") or "")
        elif isinstance(m, str):
            malware.append(m)
    malware = [x for x in malware if x]

    return {
        "threatId":          threat_id,
        "threatKey":         r.get("threatKey") or r.get("actorKey") or threat_key,
        "name":              name_raw,
        "aliases":           aliases,
        "description":       r.get("description") or "",
        "country":           r.get("country") or r.get("originCountry") or "",
        "motivation":        r.get("motivation") or "",
        "confidence":        (r.get("confidence") or "MEDIUM").upper(),
        "severity":          (r.get("severity") or r.get("threatLevel") or "MEDIUM").upper(),
        "active":            bool(r.get("active", True)),
        "malware":           malware,
        "industry":          list(r.get("industry") or []),
        "relatedTechniques": list(r.get("relatedTechniques") or []),
        "relatedCVEs":       list(r.get("relatedCVEs") or []),
        "relatedIOCs":       list(r.get("relatedIOCs") or []),
        "createdAt":         _fmt_date(r.get("createdAt")),
        "updatedAt":         _fmt_date(r.get("updatedAt")) or None,
    }


def _normalize_campaign(r: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a raw campaign record so it always has the keys the router expects.

    Handles two shapes:
    1. Legacy / in-memory record  — already has `campaignId`, `campaignKey`, `name`, etc.
    2. Normalized Prisma record   — has top-level `id`, `name`, and may lack
                                    `campaignId`, `campaignKey`, `startDate`, `endDate`,
                                    `threatActors`, `relatedTechniques`, etc.
    """
    # Already a fully normalized legacy record
    if r.get("campaignId") and r.get("campaignKey"):
        return r

    import hashlib as _hashlib
    import uuid as _uuid

    _CAMP_NS = _uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

    name_raw: str = r.get("name") or r.get("campaignName") or r.get("id") or "campaign_unknown"
    camp_key = _hashlib.sha256(name_raw.strip().lower().encode("utf-8")).hexdigest()[:32]
    camp_id: str = (
        r.get("campaignId")
        or str(_uuid.uuid5(_CAMP_NS, camp_key))
    )

    def _fmt_date(val: Any) -> str:
        if val is None:
            return ""
        if isinstance(val, str):
            return val
        if hasattr(val, "isoformat"):
            try:
                return val.isoformat()
            except Exception:
                return str(val)
        return str(val)

    return {
        "campaignId":        camp_id,
        "campaignKey":       r.get("campaignKey") or camp_key,
        "name":              name_raw,
        "description":       r.get("description") or "",
        "startDate":         _fmt_date(r.get("startDate")) or "",
        "endDate":           _fmt_date(r.get("endDate")) or "",
        "threatActors":      list(r.get("threatActors") or []),
        "relatedTechniques": list(r.get("relatedTechniques") or []),
        "relatedCVEs":       list(r.get("relatedCVEs") or []),
        "relatedIOCs":       list(r.get("relatedIOCs") or []),
        "confidence":        (r.get("confidence") or "MEDIUM").upper(),
        "createdAt":         _fmt_date(r.get("createdAt")),
        "active":            bool(r.get("active", True)),
    }


def _all_threats() -> List[Dict[str, Any]]:
    """Return all threat actors normalized and ordered by name ASC."""
    raw = _THREAT_STORE.values()
    normalized = [_normalize_threat(r) for r in raw]
    return sorted(normalized, key=lambda c: c.get("name", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_threat(threats: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a Threat by threatId, threatKey, or threatName (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for c in threats:
        if c.get("threatId", "").lower() == normalized:
            return c
        if c.get("threatKey", "").lower() == normalized:
            return c
        if c.get("name", "").lower() == normalized:
            return c
    return None


def search_threats(threats: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text and list fields."""
    if not query or not query.strip():
        return list(threats)
    q = query.strip().lower()
    results = []
    for c in threats:
        if q in c.get("name", "").lower():
            results.append(c)
            continue
        if q in c.get("description", "").lower():
            results.append(c)
            continue
        if q in c.get("country", "").lower():
            results.append(c)
            continue
        if q in c.get("motivation", "").lower():
            results.append(c)
            continue
        if any(q in alias.lower() for alias in c.get("aliases", [])):
            results.append(c)
            continue
        if any(q in mal.lower() for mal in c.get("malware", [])):
            results.append(c)
            continue
        if any(q in ind.lower() for ind in c.get("industry", [])):
            results.append(c)
            continue
        if any(q in tech.lower() for tech in c.get("relatedTechniques", [])):
            results.append(c)
            continue
        if any(q in cv.lower() for cv in c.get("relatedCVEs", [])):
            results.append(c)
            continue
        if any(q in ioc.lower() for ioc in c.get("relatedIOCs", [])):
            results.append(c)
            continue
    return results


def sort_threats(
    threats: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts threats deterministically, falling back to threatId ASC."""
    valid_fields = {"threatName", "confidence", "severity", "createdAt", "updatedAt"}
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

    confidence_priority = {"low": 1, "medium": 2, "high": 3, "verified": 4}
    severity_priority = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def get_sort_key(c: Dict[str, Any]) -> Any:
        if sort_by == "threatName":
            return c.get("name", "")
        elif sort_by == "confidence":
            val = c.get("confidence", "").strip().lower()
            return confidence_priority.get(val, -1)
        elif sort_by == "severity":
            val = c.get("severity", "").strip().lower()
            return severity_priority.get(val, -1)
        elif sort_by == "createdAt":
            return c.get("createdAt", "")
        elif sort_by == "updatedAt":
            return c.get("updatedAt", "") or ""
        return ""

    reverse = (order == "desc")
    # Stable sort
    sorted_list = sorted(threats, key=lambda x: x.get("threatId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_threats(
    threats: List[Dict[str, Any]],
    actor: Optional[str] = None,
    campaign: Optional[str] = None,
    malware: Optional[str] = None,
    country: Optional[str] = None,
    industry: Optional[str] = None,
    confidence: Optional[str] = None,
    severity: Optional[str] = None,
    active: Optional[bool] = None,
    minimumConfidence: Optional[float] = None,
    maximumConfidence: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Filters threat records."""
    filtered = list(threats)
    conf_weight = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "VERIFIED": 100.0}

    if actor is not None:
        a_val = actor.strip().lower()
        filtered = [c for c in filtered if a_val in c.get("name", "").lower()]

    if campaign is not None:
        c_val = campaign.strip().lower()
        # Find campaign IDs that match c_val (normalize each campaign record first)
        matching_campaigns = {
            _normalize_campaign(camp)["campaignId"]
            for camp in _CAMPAIGN_STORE.values()
            if c_val in (_normalize_campaign(camp).get("name", "")).lower()
        }
        filtered = [
            c for c in filtered
            if any(
                c["threatId"] in _normalize_campaign(camp).get("threatActors", [])
                for camp in _CAMPAIGN_STORE.values()
                if _normalize_campaign(camp)["campaignId"] in matching_campaigns
            )
        ]

    if malware is not None:
        m_val = malware.strip().lower()
        filtered = [
            c for c in filtered
            if any(m_val in mal.lower() for mal in c.get("malware", []))
        ]

    if country is not None:
        ct_val = country.strip().lower()
        filtered = [c for c in filtered if c.get("country", "").lower() == ct_val]

    if industry is not None:
        i_val = industry.strip().lower()
        filtered = [
            c for c in filtered
            if any(i_val in ind.lower() for ind in c.get("industry", []))
        ]

    if confidence is not None:
        cf_val = confidence.strip().upper()
        filtered = [c for c in filtered if c.get("confidence", "").upper() == cf_val]

    if severity is not None:
        s_val = severity.strip().upper()
        filtered = [c for c in filtered if c.get("severity", "").upper() == s_val]

    if active is not None:
        filtered = [c for c in filtered if bool(c.get("active", True)) == active]

    if minimumConfidence is not None:
        filtered = [
            c for c in filtered
            if conf_weight.get(c.get("confidence", "").upper(), 0.0) >= minimumConfidence
        ]

    if maximumConfidence is not None:
        filtered = [
            c for c in filtered
            if conf_weight.get(c.get("confidence", "").upper(), 0.0) <= maximumConfidence
        ]

    return filtered


def paginate_threats(
    threats: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Paginates the threat list."""
    total_items = len(threats)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = threats[start:end]
    return sliced, total_items


def build_threat_summary(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a structured threat summary."""
    name = threat.get("name", "")
    country = threat.get("country", "")
    motivation = threat.get("motivation", "")
    severity = threat.get("severity", "")
    active = threat.get("active", True)

    status = "active" if active else "inactive"
    text = (
        f"Threat Actor '{name}' of origin country '{country}' has {severity} severity. "
        f"The actor is motivated by '{motivation}' and is currently {status}."
    )
    return {
        "threatId": threat.get("threatId", ""),
        "threatName": name,
        "summaryText": text,
        "aliasCount": len(threat.get("aliases", [])),
        "malwareCount": len(threat.get("malware", [])),
        "techniqueCount": len(threat.get("relatedTechniques", [])),
    }


def calculate_threat_statistics(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregate statistics over a list of threats."""
    total = len(threats)
    active = sum(1 for c in threats if c.get("active"))

    conf_weight = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "VERIFIED": 100.0}
    total_conf = sum(conf_weight.get(c.get("confidence", "").upper(), 0.0) for c in threats)
    avg_conf = round(total_conf / total, 4) if total > 0 else 0.0

    sev_weight = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}
    total_sev = sum(sev_weight.get(c.get("severity", "").upper(), 0.0) for c in threats)
    avg_sev = round(total_sev / total, 4) if total > 0 else 0.0

    actor_counts: Dict[str, int] = {}
    country_counts: Dict[str, int] = {}

    for c in threats:
        name = c.get("name", "")
        if name:
            actor_counts[name] = actor_counts.get(name, 0) + 1

        country = c.get("country", "").upper()
        if country:
            country_counts[country] = country_counts.get(country, 0) + 1

    campaign_counts: Dict[str, int] = {}
    for camp_raw in _CAMPAIGN_STORE.values():
        camp = _normalize_campaign(camp_raw)
        camp_name = camp["name"]
        campaign_counts[camp_name] = len(camp.get("threatActors", []))

    return {
        "totalThreats": total,
        "activeThreats": active,
        "averageConfidence": avg_conf,
        "averageSeverity": avg_sev,
        "actorCounts": dict(sorted(actor_counts.items())),
        "campaignCounts": dict(sorted(campaign_counts.items())),
        "countryCounts": dict(sorted(country_counts.items())),
    }


def _to_response_model(c: Dict[str, Any]) -> ThreatResponse:
    """Helper to convert stored dictionary to ThreatResponse model.

    Always normalizes first so both legacy metadata-backed records and
    raw Prisma records are handled safely.
    """
    n = _normalize_threat(c)
    return ThreatResponse(
        threatId=n["threatId"],
        threatKey=n["threatKey"],
        threatName=n["name"],
        aliases=list(n["aliases"]),
        description=n["description"],
        country=n["country"],
        motivation=n["motivation"],
        confidence=n["confidence"],
        severity=n["severity"],
        active=n["active"],
        malware=list(n["malware"]),
        industry=list(n["industry"]),
        relatedTechniques=list(n["relatedTechniques"]),
        relatedCVEs=list(n["relatedCVEs"]),
        relatedIOCs=list(n["relatedIOCs"]),
        createdAt=n["createdAt"],
        updatedAt=n.get("updatedAt"),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@threat_router.get(
    "/",
    response_model=APIResponse,
    summary="List threat actor records",
)
def list_threats(
    actor: Optional[str] = None,
    campaign: Optional[str] = None,
    malware: Optional[str] = None,
    country: Optional[str] = None,
    industry: Optional[str] = None,
    confidence: Optional[str] = None,
    severity: Optional[str] = None,
    active: Optional[bool] = None,
    minimumConfidence: Optional[float] = None,
    maximumConfidence: Optional[float] = None,
    sortBy: str = "threatName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_threats_list = _all_threats()

        filtered = filter_threats(
            all_threats_list,
            actor=actor,
            campaign=campaign,
            malware=malware,
            country=country,
            industry=industry,
            confidence=confidence,
            severity=severity,
            active=active,
            minimumConfidence=minimumConfidence,
            maximumConfidence=maximumConfidence,
        )

        sorted_threats = sort_threats(filtered, sortBy, sortOrder)
        paginated, total = paginate_threats(sorted_threats, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]

        return build_paginated_response(
            items=[r.model_dump() for r in responses],
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Threat records listed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get threat statistics",
)
def get_statistics() -> APIResponse:
    try:
        all_threats_list = _all_threats()
        stats = calculate_threat_statistics(all_threats_list)
        return build_success_response(
            data=stats,
            message="Statistics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search threat actor records",
)
def search_threat_records(
    query: str = "",
    sortBy: str = "threatName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_threats_list = _all_threats()
        searched = search_threats(all_threats_list, query)
        sorted_threats = sort_threats(searched, sortBy, sortOrder)
        paginated, total = paginate_threats(sorted_threats, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]
        total_pages = math.ceil(total / pageSize) if total > 0 else 0

        search_data = ThreatSearchResponse(
            threats=responses,
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


@threat_router.get(
    "/{threatId}",
    response_model=APIResponse,
    summary="Get threat actor by ID",
)
def get_threat(threatId: str) -> APIResponse:
    try:
        all_threats_list = _all_threats()
        c = find_threat(all_threats_list, threatId)
        if not c:
            raise APIErrorNotFound(f"Threat '{threatId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="Threat record retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a threat actor record",
)
def create_threat(
    request: CreateThreatRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.threat_intelligence_service import (
            ThreatConfidenceEnum,
            build_threat_actor,
        )

        try:
            c_enum = ThreatConfidenceEnum(request.confidence.strip().upper())
            actor = build_threat_actor(
                name=request.threatName,
                confidence=c_enum,
                created_at=request.createdAt,
                aliases=request.aliases,
                description=request.description or "",
                country=request.country or "",
                motivation=request.motivation or "",
                related_techniques=request.relatedTechniques,
                related_cves=request.relatedCVEs,
                related_iocs=request.relatedIOCs,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = actor.actorId
        if rec_id in _THREAT_STORE:
            raise APIErrorConflict(f"Threat Actor with ID '{rec_id}' (name '{request.threatName}') already exists.")

        _THREAT_STORE[rec_id] = {
            "threatId": rec_id,
            "threatKey": actor.actorKey,
            "name": actor.name,
            "aliases": list(actor.aliases),
            "description": actor.description,
            "country": actor.country,
            "motivation": actor.motivation,
            "confidence": actor.confidence.value,
            "relatedTechniques": list(actor.relatedTechniques),
            "relatedCVEs": list(actor.relatedCVEs),
            "relatedIOCs": list(actor.relatedIOCs),
            "createdAt": actor.createdAt,
            "updatedAt": request.updatedAt,
            "severity": request.severity.strip().upper(),
            "active": bool(request.active),
            "malware": list(request.malware or []),
            "industry": list(request.industry or []),
        }

        return build_success_response(
            data=_to_response_model(_THREAT_STORE[rec_id]).model_dump(),
            message="Threat record created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.put(
    "/{threatId}",
    response_model=APIResponse,
    summary="Update a threat actor record",
)
def update_threat(
    threatId: str,
    request: UpdateThreatRequest = Body(...)
) -> APIResponse:
    try:
        all_threats_list = _all_threats()
        c = find_threat(all_threats_list, threatId)
        if not c:
            raise APIErrorNotFound(f"Threat '{threatId}' not found.")

        rec_id = c["threatId"]

        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")

        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.threat_intelligence_service import (
            ThreatConfidenceEnum,
            build_threat_actor,
        )

        confidence_str = request.confidence if request.confidence is not None else c.get("confidence")
        aliases = request.aliases if request.aliases is not None else c.get("aliases")
        description = request.description if request.description is not None else c.get("description")
        country = request.country if request.country is not None else c.get("country")
        motivation = request.motivation if request.motivation is not None else c.get("motivation")
        related_techniques = request.relatedTechniques if request.relatedTechniques is not None else c.get("relatedTechniques")
        related_cves = request.relatedCVEs if request.relatedCVEs is not None else c.get("relatedCVEs")
        related_iocs = request.relatedIOCs if request.relatedIOCs is not None else c.get("relatedIOCs")

        try:
            c_enum = ThreatConfidenceEnum(confidence_str.strip().upper())
            actor = build_threat_actor(
                name=c.get("name"),
                confidence=c_enum,
                created_at=c.get("createdAt"),
                aliases=aliases,
                description=description,
                country=country,
                motivation=motivation,
                related_techniques=related_techniques,
                related_cves=related_cves,
                related_iocs=related_iocs,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        severity = request.severity if request.severity is not None else c.get("severity")
        active = request.active if request.active is not None else c.get("active")
        malware = request.malware if request.malware is not None else c.get("malware")
        industry = request.industry if request.industry is not None else c.get("industry")
        updatedAt = request.updatedAt if request.updatedAt is not None else c.get("updatedAt")

        _THREAT_STORE[rec_id] = {
            "threatId": rec_id,
            "threatKey": actor.actorKey,
            "name": actor.name,
            "aliases": list(actor.aliases),
            "description": actor.description,
            "country": actor.country,
            "motivation": actor.motivation,
            "confidence": actor.confidence.value,
            "relatedTechniques": list(actor.relatedTechniques),
            "relatedCVEs": list(actor.relatedCVEs),
            "relatedIOCs": list(actor.relatedIOCs),
            "createdAt": actor.createdAt,
            "updatedAt": updatedAt,
            "severity": severity.strip().upper(),
            "active": bool(active),
            "malware": list(malware),
            "industry": list(industry),
        }

        return build_success_response(
            data=_to_response_model(_THREAT_STORE[rec_id]).model_dump(),
            message="Threat record updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.delete(
    "/{threatId}",
    response_model=APIResponse,
    summary="Delete a threat actor record",
)
def delete_threat(threatId: str) -> APIResponse:
    try:
        all_threats_list = _all_threats()
        c = find_threat(all_threats_list, threatId)
        if not c:
            raise APIErrorNotFound(f"Threat '{threatId}' not found.")

        rec_id = c["threatId"]
        del _THREAT_STORE[rec_id]

        return build_success_response(
            data=None,
            message="Threat record deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.get(
    "/{threatId}/relationships",
    response_model=APIResponse,
    summary="Get relationships for a threat actor",
)
def get_relationships(threatId: str) -> APIResponse:
    try:
        all_threats_list = _all_threats()
        c = find_threat(all_threats_list, threatId)
        if not c:
            raise APIErrorNotFound(f"Threat '{threatId}' not found.")

        n = _normalize_threat(c)
        relationships: List[ThreatRelationshipResponse] = []
        for cve_id in n.get("relatedCVEs", []):
            relationships.append(
                ThreatRelationshipResponse(
                    sourceThreatId=n["threatId"],
                    targetId=cve_id,
                    targetType="cve",
                    relationType="targets",
                    confidence=100.0,
                )
            )

        for tech_id in n.get("relatedTechniques", []):
            relationships.append(
                ThreatRelationshipResponse(
                    sourceThreatId=n["threatId"],
                    targetId=tech_id,
                    targetType="technique",
                    relationType="uses",
                    confidence=100.0,
                )
            )

        for ioc_val in n.get("relatedIOCs", []):
            relationships.append(
                ThreatRelationshipResponse(
                    sourceThreatId=n["threatId"],
                    targetId=ioc_val,
                    targetType="ioc",
                    relationType="associated_with",
                    confidence=100.0,
                )
            )

        for camp_raw in _CAMPAIGN_STORE.values():
            camp = _normalize_campaign(camp_raw)
            if n["threatId"] in camp.get("threatActors", []):
                relationships.append(
                    ThreatRelationshipResponse(
                        sourceThreatId=n["threatId"],
                        targetId=camp["campaignId"],
                        targetType="campaign",
                        relationType="associated_with",
                        confidence=85.0,
                    )
                )

        return build_success_response(
            data=[x.model_dump() for x in relationships],
            message="Threat relationships retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.get(
    "/{threatId}/campaigns",
    response_model=APIResponse,
    summary="Get threat campaigns associated with a threat actor",
)
def get_campaigns(threatId: str) -> APIResponse:
    try:
        all_threats_list = _all_threats()
        c = find_threat(all_threats_list, threatId)
        if not c:
            raise APIErrorNotFound(f"Threat '{threatId}' not found.")

        n = _normalize_threat(c)
        matching_camps: List[ThreatCampaignResponse] = []
        for camp_raw in _CAMPAIGN_STORE.values():
            camp = _normalize_campaign(camp_raw)
            if n["threatId"] in camp.get("threatActors", []):
                matching_camps.append(
                    ThreatCampaignResponse(
                        campaignId=camp["campaignId"],
                        campaignKey=camp["campaignKey"],
                        name=camp["name"],
                        description=camp["description"],
                        startDate=camp["startDate"],
                        endDate=camp["endDate"],
                        threatActors=list(camp["threatActors"]),
                        relatedTechniques=list(camp["relatedTechniques"]),
                        relatedCVEs=list(camp["relatedCVEs"]),
                        relatedIOCs=list(camp["relatedIOCs"]),
                        confidence=camp["confidence"],
                        createdAt=camp["createdAt"],
                        active=camp.get("active", True),
                    )
                )

        return build_success_response(
            data=[x.model_dump() for x in matching_camps],
            message="Associated campaigns retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.get(
    "/{threatId}/summary",
    response_model=APIResponse,
    summary="Get structured summary of a threat actor",
)
def get_threat_summary_route(threatId: str) -> APIResponse:
    try:
        all_threats_list = _all_threats()
        c = find_threat(all_threats_list, threatId)
        if not c:
            raise APIErrorNotFound(f"Threat '{threatId}' not found.")

        summary = build_threat_summary(c)
        return build_success_response(
            data=summary,
            message="Threat summary built successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create threat actor records",
)
def bulk_create_threats(
    request: BulkCreateThreatsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.threat_intelligence_service import (
            ThreatConfidenceEnum,
            build_threat_actor,
        )

        for item in request.threats:
            try:
                c_enum = ThreatConfidenceEnum(item.confidence.strip().upper())
                actor = build_threat_actor(
                    name=item.threatName,
                    confidence=c_enum,
                    created_at=item.createdAt,
                    aliases=item.aliases,
                    description=item.description or "",
                    country=item.country or "",
                    motivation=item.motivation or "",
                    related_techniques=item.relatedTechniques,
                    related_cves=item.relatedCVEs,
                    related_iocs=item.relatedIOCs,
                )

                rec_id = actor.actorId
                if rec_id in _THREAT_STORE or rec_id in succeeded:
                    failed.append({"id": item.threatName, "reason": f"Threat Actor with ID '{rec_id}' already exists."})
                    continue

                _THREAT_STORE[rec_id] = {
                    "threatId": rec_id,
                    "threatKey": actor.actorKey,
                    "name": actor.name,
                    "aliases": list(actor.aliases),
                    "description": actor.description,
                    "country": actor.country,
                    "motivation": actor.motivation,
                    "confidence": actor.confidence.value,
                    "relatedTechniques": list(actor.relatedTechniques),
                    "relatedCVEs": list(actor.relatedCVEs),
                    "relatedIOCs": list(actor.relatedIOCs),
                    "createdAt": actor.createdAt,
                    "updatedAt": item.updatedAt,
                    "severity": item.severity.strip().upper(),
                    "active": bool(item.active),
                    "malware": list(item.malware or []),
                    "industry": list(item.industry or []),
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.threatName, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.threats),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=result.model_dump(),
            message="Bulk create completed.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update threat actor records",
)
def bulk_update_threats(
    request: BulkUpdateThreatsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.threat_intelligence_service import (
            ThreatConfidenceEnum,
            build_threat_actor,
        )

        for item in request.items:
            rec_id = None
            all_threats_list = _all_threats()
            existing = find_threat(all_threats_list, item.threatId)
            if existing:
                rec_id = existing["threatId"]

            if not rec_id:
                failed.append({"id": item.threatId, "reason": f"Threat Actor '{item.threatId}' not found."})
                continue

            try:
                confidence_str = item.update.confidence if item.update.confidence is not None else existing.get("confidence")
                aliases = item.update.aliases if item.update.aliases is not None else existing.get("aliases")
                description = item.update.description if item.update.description is not None else existing.get("description")
                country = item.update.country if item.update.country is not None else existing.get("country")
                motivation = item.update.motivation if item.update.motivation is not None else existing.get("motivation")
                related_techniques = item.update.relatedTechniques if item.update.relatedTechniques is not None else existing.get("relatedTechniques")
                related_cves = item.update.relatedCVEs if item.update.relatedCVEs is not None else existing.get("relatedCVEs")
                related_iocs = item.update.relatedIOCs if item.update.relatedIOCs is not None else existing.get("relatedIOCs")

                c_enum = ThreatConfidenceEnum(confidence_str.strip().upper())
                actor = build_threat_actor(
                    name=existing.get("name"),
                    confidence=c_enum,
                    created_at=existing.get("createdAt"),
                    aliases=aliases,
                    description=description,
                    country=country,
                    motivation=motivation,
                    related_techniques=related_techniques,
                    related_cves=related_cves,
                    related_iocs=related_iocs,
                )

                severity = item.update.severity if item.update.severity is not None else existing.get("severity")
                active = item.update.active if item.update.active is not None else existing.get("active")
                malware = item.update.malware if item.update.malware is not None else existing.get("malware")
                industry = item.update.industry if item.update.industry is not None else existing.get("industry")
                updatedAt = item.update.updatedAt if item.update.updatedAt is not None else existing.get("updatedAt")

                _THREAT_STORE[rec_id] = {
                    "threatId": rec_id,
                    "threatKey": actor.actorKey,
                    "name": actor.name,
                    "aliases": list(actor.aliases),
                    "description": actor.description,
                    "country": actor.country,
                    "motivation": actor.motivation,
                    "confidence": actor.confidence.value,
                    "relatedTechniques": list(actor.relatedTechniques),
                    "relatedCVEs": list(actor.relatedCVEs),
                    "relatedIOCs": list(actor.relatedIOCs),
                    "createdAt": actor.createdAt,
                    "updatedAt": updatedAt,
                    "severity": severity.strip().upper(),
                    "active": bool(active),
                    "malware": list(malware),
                    "industry": list(industry),
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.threatId, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.items),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=result.model_dump(),
            message="Bulk update completed.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@threat_router.delete(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete threat actor records",
)
def bulk_delete_threats(
    request: BulkDeleteThreatsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        all_threats_list = _all_threats()
        for threat_id in request.threatIds:
            existing = find_threat(all_threats_list, threat_id)
            if not existing:
                failed.append({"id": threat_id, "reason": f"Threat Actor '{threat_id}' not found."})
                continue

            try:
                rec_id = existing["threatId"]
                del _THREAT_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": threat_id, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.threatIds),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=result.model_dump(),
            message="Bulk delete completed.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))
