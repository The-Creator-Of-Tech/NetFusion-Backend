"""
IOC Intelligence API Router — Phase A4.9.3
===========================================
REST interface for IOC Intelligence.

Prefix  : /ioc
Tag     : IOC Intelligence
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
from api.knowledge.ioc_models import (
    CreateIOCRequest,
    UpdateIOCRequest,
    IOCResponse,
    IOCListResponse,
    IOCStatisticsResponse,
    IOCSearchResponse,
    IOCRelationshipResponse,
    IOCEnrichmentResponse,
    BulkCreateIOCsRequest,
    BulkUpdateIOCsRequest,
    BulkDeleteIOCsRequest,
    BulkOperationResult,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

ioc_router: APIRouter = APIRouter(
    prefix="/ioc",
    tags=["IOC Intelligence"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
# Dict[iocId -> IOC dict]
_IOC_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _IOC_STORE.clear()


def _all_iocs() -> List[Dict[str, Any]]:
    """Return all IOCs ordered by value ASC."""
    return sorted(_IOC_STORE.values(), key=lambda c: c.get("value", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_ioc(iocs: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds an IOC by iocId, iocKey, or value (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for c in iocs:
        if c.get("iocId", "").lower() == normalized:
            return c
        if c.get("iocKey", "").lower() == normalized:
            return c
        if c.get("value", "").lower() == normalized:
            return c
    return None


def search_iocs(iocs: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text and list fields."""
    if not query or not query.strip():
        return list(iocs)
    q = query.strip().lower()
    results = []
    for c in iocs:
        if q in c.get("value", "").lower():
            results.append(c)
            continue
        if q in c.get("description", "").lower():
            results.append(c)
            continue
        if q in c.get("iocType", "").lower():
            results.append(c)
            continue
        if q in c.get("source", "").lower():
            results.append(c)
            continue
        if q in c.get("threatActor", "").lower():
            results.append(c)
            continue
        if q in c.get("campaign", "").lower():
            results.append(c)
            continue
        if any(q in t.lower() for t in c.get("tags", [])):
            results.append(c)
            continue
        if any(q in cv.lower() for cv in c.get("relatedCVEs", [])):
            results.append(c)
            continue
        if any(q in tech.lower() for tech in c.get("relatedTechniques", [])):
            results.append(c)
            continue
    return results


def sort_iocs(
    iocs: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts IOCs deterministically, falling back to iocId ASC."""
    valid_fields = {"iocType", "iocValue", "confidence", "createdAt", "updatedAt"}
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

    def get_sort_key(c: Dict[str, Any]) -> Any:
        if sort_by == "iocType":
            return c.get("iocType", "")
        elif sort_by == "iocValue":
            return c.get("value", "")
        elif sort_by == "confidence":
            val = c.get("confidence", "").strip().lower()
            return confidence_priority.get(val, -1)
        elif sort_by == "createdAt":
            return c.get("createdAt", "")
        elif sort_by == "updatedAt":
            return c.get("updatedAt", "") or ""
        return ""

    reverse = (order == "desc")
    # Stable sort
    sorted_list = sorted(iocs, key=lambda x: x.get("iocId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_iocs(
    iocs: List[Dict[str, Any]],
    iocType: Optional[str] = None,
    confidence: Optional[str] = None,
    malicious: Optional[bool] = None,
    revoked: Optional[bool] = None,
    source: Optional[str] = None,
    threatActor: Optional[str] = None,
    campaign: Optional[str] = None,
    minimumConfidence: Optional[float] = None,
    maximumConfidence: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Filters IOC records."""
    filtered = list(iocs)
    conf_weight = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "VERIFIED": 100.0}

    if iocType is not None:
        t_val = iocType.strip().upper()
        filtered = [c for c in filtered if c.get("iocType", "").upper() == t_val]

    if confidence is not None:
        c_val = confidence.strip().upper()
        filtered = [c for c in filtered if c.get("confidence", "").upper() == c_val]

    if malicious is not None:
        filtered = [c for c in filtered if bool(c.get("malicious", True)) == malicious]

    if revoked is not None:
        filtered = [c for c in filtered if bool(c.get("revoked", False)) == revoked]

    if source is not None:
        s_val = source.strip().lower()
        filtered = [c for c in filtered if c.get("source", "").lower() == s_val]

    if threatActor is not None:
        ta_val = threatActor.strip().lower()
        filtered = [c for c in filtered if ta_val in c.get("threatActor", "").lower()]

    if campaign is not None:
        cmp_val = campaign.strip().lower()
        filtered = [c for c in filtered if cmp_val in c.get("campaign", "").lower()]

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


def paginate_iocs(
    iocs: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Paginates the IOC list."""
    total_items = len(iocs)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = iocs[start:end]
    return sliced, total_items


def build_ioc_summary(ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a structured IOC summary."""
    value = ioc.get("value", "")
    itype = ioc.get("iocType", "")
    severity = ioc.get("severity", "")
    conf = ioc.get("confidence", "")
    malicious = ioc.get("malicious", True)

    status = "malicious" if malicious else "benign/suspicious"
    text = (
        f"Indicator '{value}' is a {itype} with {severity} severity and {conf} confidence. "
        f"It is currently classified as {status}."
    )
    return {
        "iocId": ioc.get("iocId", ""),
        "iocType": itype,
        "value": value,
        "summaryText": text,
        "tagCount": len(ioc.get("tags", [])),
        "cveCount": len(ioc.get("relatedCVEs", [])),
        "techniqueCount": len(ioc.get("relatedTechniques", [])),
    }


def calculate_ioc_statistics(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregate statistics over a list of IOCs."""
    total = len(iocs)
    malicious = sum(1 for c in iocs if c.get("malicious"))
    revoked = sum(1 for c in iocs if c.get("revoked"))

    conf_weight = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "VERIFIED": 100.0}
    total_conf = sum(conf_weight.get(c.get("confidence", "").upper(), 0.0) for c in iocs)
    avg_conf = round(total_conf / total, 4) if total > 0 else 0.0

    type_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}

    for c in iocs:
        itype = c.get("iocType", "").upper()
        if itype:
            type_counts[itype] = type_counts.get(itype, 0) + 1

        src = c.get("source", "").lower()
        if src:
            source_counts[src] = source_counts.get(src, 0) + 1

    return {
        "totalIOCs": total,
        "maliciousIOCs": malicious,
        "revokedIOCs": revoked,
        "averageConfidence": avg_conf,
        "typeCounts": dict(sorted(type_counts.items())),
        "sourceCounts": dict(sorted(source_counts.items())),
    }


def _to_response_model(c: Dict[str, Any]) -> IOCResponse:
    """Helper to convert stored dictionary to IOCResponse model."""
    return IOCResponse(
        iocId=c["iocId"],
        iocKey=c["iocKey"],
        iocFingerprint=c["iocFingerprint"],
        iocType=c["iocType"],
        value=c["value"],
        severity=c["severity"],
        confidence=c["confidence"],
        description=c["description"],
        source=c["source"],
        tags=list(c["tags"]),
        relatedCVEs=list(c["relatedCVEs"]),
        relatedTechniques=list(c["relatedTechniques"]),
        createdAt=c["createdAt"],
        updatedAt=c.get("updatedAt"),
        malicious=c["malicious"],
        revoked=c["revoked"],
        threatActor=c.get("threatActor", ""),
        campaign=c.get("campaign", ""),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@ioc_router.get(
    "/",
    response_model=APIResponse,
    summary="List IOC records",
)
def list_iocs(
    iocType: Optional[str] = None,
    confidence: Optional[str] = None,
    malicious: Optional[bool] = None,
    revoked: Optional[bool] = None,
    source: Optional[str] = None,
    threatActor: Optional[str] = None,
    campaign: Optional[str] = None,
    minimumConfidence: Optional[float] = None,
    maximumConfidence: Optional[float] = None,
    sortBy: str = "iocValue",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_iocs_list = _all_iocs()

        filtered = filter_iocs(
            all_iocs_list,
            iocType=iocType,
            confidence=confidence,
            malicious=malicious,
            revoked=revoked,
            source=source,
            threatActor=threatActor,
            campaign=campaign,
            minimumConfidence=minimumConfidence,
            maximumConfidence=maximumConfidence,
        )

        sorted_iocs = sort_iocs(filtered, sortBy, sortOrder)
        paginated, total = paginate_iocs(sorted_iocs, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]

        return build_paginated_response(
            items=[r.model_dump() for r in responses],
            page=page,
            page_size=pageSize,
            total_items=total,
            message="IOC records listed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get IOC statistics",
)
def get_statistics() -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        stats = calculate_ioc_statistics(all_iocs_list)
        return build_success_response(
            data=stats,
            message="Statistics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search IOC records",
)
def search_ioc_records(
    query: str = "",
    sortBy: str = "iocValue",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_iocs_list = _all_iocs()
        searched = search_iocs(all_iocs_list, query)
        sorted_iocs = sort_iocs(searched, sortBy, sortOrder)
        paginated, total = paginate_iocs(sorted_iocs, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]
        total_pages = math.ceil(total / pageSize) if total > 0 else 0

        search_data = IOCSearchResponse(
            iocs=responses,
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


@ioc_router.get(
    "/{iocId}",
    response_model=APIResponse,
    summary="Get IOC record by ID",
)
def get_ioc(iocId: str) -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        c = find_ioc(all_iocs_list, iocId)
        if not c:
            raise APIErrorNotFound(f"IOC '{iocId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="IOC record retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.post(
    "/",
    response_model=APIResponse,
    summary="Create an IOC record",
)
def create_ioc(
    request: CreateIOCRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.ioc_intelligence_service import (
            IOCTypeEnum,
            IOCSeverityEnum,
            IOCConfidenceEnum,
            build_ioc_record,
        )

        try:
            t_enum = IOCTypeEnum(request.iocType.strip().upper())
            s_enum = IOCSeverityEnum(request.severity.strip().upper())
            c_enum = IOCConfidenceEnum(request.confidence.strip().upper())

            ioc_rec = build_ioc_record(
                ioc_type=t_enum,
                value=request.value,
                severity=s_enum,
                confidence=c_enum,
                created_at=request.createdAt,
                description=request.description or "",
                source=request.source or "",
                tags=request.tags,
                related_cves=request.relatedCVEs,
                related_techniques=request.relatedTechniques,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = ioc_rec.iocId
        if rec_id in _IOC_STORE:
            raise APIErrorConflict(f"IOC record with ID '{rec_id}' (value '{request.value}') already exists.")

        _IOC_STORE[rec_id] = {
            "iocId": rec_id,
            "iocKey": ioc_rec.iocKey,
            "iocFingerprint": ioc_rec.iocFingerprint,
            "iocType": ioc_rec.iocType.value,
            "value": ioc_rec.value,
            "severity": ioc_rec.severity.value,
            "confidence": ioc_rec.confidence.value,
            "description": ioc_rec.description,
            "source": ioc_rec.source,
            "tags": list(ioc_rec.tags),
            "relatedCVEs": list(ioc_rec.relatedCVEs),
            "relatedTechniques": list(ioc_rec.relatedTechniques),
            "createdAt": ioc_rec.createdAt,
            "updatedAt": request.updatedAt,
            "malicious": bool(request.malicious),
            "revoked": bool(request.revoked),
            "threatActor": request.threatActor or "",
            "campaign": request.campaign or "",
        }

        return build_success_response(
            data=_to_response_model(_IOC_STORE[rec_id]).model_dump(),
            message="IOC record created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.put(
    "/{iocId}",
    response_model=APIResponse,
    summary="Update an IOC record",
)
def update_ioc(
    iocId: str,
    request: UpdateIOCRequest = Body(...)
) -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        c = find_ioc(all_iocs_list, iocId)
        if not c:
            raise APIErrorNotFound(f"IOC '{iocId}' not found.")

        rec_id = c["iocId"]

        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")

        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.ioc_intelligence_service import (
            IOCTypeEnum,
            IOCSeverityEnum,
            IOCConfidenceEnum,
            build_ioc_record,
        )

        severity_str = request.severity if request.severity is not None else c.get("severity")
        confidence_str = request.confidence if request.confidence is not None else c.get("confidence")
        description = request.description if request.description is not None else c.get("description")
        source = request.source if request.source is not None else c.get("source")
        tags = request.tags if request.tags is not None else c.get("tags")
        related_cves = request.relatedCVEs if request.relatedCVEs is not None else c.get("relatedCVEs")
        related_techniques = request.relatedTechniques if request.relatedTechniques is not None else c.get("relatedTechniques")

        try:
            t_enum = IOCTypeEnum(c.get("iocType").strip().upper())
            s_enum = IOCSeverityEnum(severity_str.strip().upper())
            c_enum = IOCConfidenceEnum(confidence_str.strip().upper())

            ioc_rec = build_ioc_record(
                ioc_type=t_enum,
                value=c.get("value"),
                severity=s_enum,
                confidence=c_enum,
                created_at=c.get("createdAt"),
                description=description,
                source=source,
                tags=tags,
                related_cves=related_cves,
                related_techniques=related_techniques,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        malicious = request.malicious if request.malicious is not None else c.get("malicious")
        revoked = request.revoked if request.revoked is not None else c.get("revoked")
        threatActor = request.threatActor if request.threatActor is not None else c.get("threatActor")
        campaign = request.campaign if request.campaign is not None else c.get("campaign")
        updatedAt = request.updatedAt if request.updatedAt is not None else c.get("updatedAt")

        _IOC_STORE[rec_id] = {
            "iocId": rec_id,
            "iocKey": ioc_rec.iocKey,
            "iocFingerprint": ioc_rec.iocFingerprint,
            "iocType": ioc_rec.iocType.value,
            "value": ioc_rec.value,
            "severity": ioc_rec.severity.value,
            "confidence": ioc_rec.confidence.value,
            "description": ioc_rec.description,
            "source": ioc_rec.source,
            "tags": list(ioc_rec.tags),
            "relatedCVEs": list(ioc_rec.relatedCVEs),
            "relatedTechniques": list(ioc_rec.relatedTechniques),
            "createdAt": ioc_rec.createdAt,
            "updatedAt": updatedAt,
            "malicious": bool(malicious),
            "revoked": bool(revoked),
            "threatActor": threatActor or "",
            "campaign": campaign or "",
        }

        return build_success_response(
            data=_to_response_model(_IOC_STORE[rec_id]).model_dump(),
            message="IOC record updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.delete(
    "/{iocId}",
    response_model=APIResponse,
    summary="Delete an IOC record",
)
def delete_ioc(iocId: str) -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        c = find_ioc(all_iocs_list, iocId)
        if not c:
            raise APIErrorNotFound(f"IOC '{iocId}' not found.")

        rec_id = c["iocId"]
        del _IOC_STORE[rec_id]

        return build_success_response(
            data=None,
            message="IOC record deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.get(
    "/{iocId}/relationships",
    response_model=APIResponse,
    summary="Get relationships for an IOC",
)
def get_relationships(iocId: str) -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        c = find_ioc(all_iocs_list, iocId)
        if not c:
            raise APIErrorNotFound(f"IOC '{iocId}' not found.")

        relationships: List[IOCRelationshipResponse] = []
        for cve_id in c.get("relatedCVEs", []):
            relationships.append(
                IOCRelationshipResponse(
                    sourceIocId=c["iocId"],
                    targetId=cve_id,
                    targetType="cve",
                    relationType="exploits",
                    confidence=100.0,
                )
            )

        for tech_id in c.get("relatedTechniques", []):
            relationships.append(
                IOCRelationshipResponse(
                    sourceIocId=c["iocId"],
                    targetId=tech_id,
                    targetType="technique",
                    relationType="uses",
                    confidence=100.0,
                )
            )

        if c.get("threatActor"):
            relationships.append(
                IOCRelationshipResponse(
                    sourceIocId=c["iocId"],
                    targetId=c["threatActor"],
                    targetType="threat_actor",
                    relationType="attributed_to",
                    confidence=75.0,
                )
            )

        if c.get("campaign"):
            relationships.append(
                IOCRelationshipResponse(
                    sourceIocId=c["iocId"],
                    targetId=c["campaign"],
                    targetType="campaign",
                    relationType="associated_with",
                    confidence=80.0,
                )
            )

        return build_success_response(
            data=[x.model_dump() for x in relationships],
            message="IOC relationships retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.get(
    "/{iocId}/enrichment",
    response_model=APIResponse,
    summary="Get enrichment details for an IOC",
)
def get_enrichment(iocId: str) -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        c = find_ioc(all_iocs_list, iocId)
        if not c:
            raise APIErrorNotFound(f"IOC '{iocId}' not found.")

        sev_scores = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
        reputation = sev_scores.get(c.get("severity", "").upper(), 50)

        enrichment = IOCEnrichmentResponse(
            iocId=c["iocId"],
            iocType=c["iocType"],
            value=c["value"],
            reputationScore=reputation,
            malicious=c["malicious"],
            categories=c["tags"],
            firstSeen=c["createdAt"],
            lastSeen=c.get("updatedAt") or c["createdAt"],
            provider="NetFusion Intelligence Engine",
        )

        return build_success_response(
            data=enrichment.model_dump(),
            message="IOC enrichment retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.get(
    "/{iocId}/summary",
    response_model=APIResponse,
    summary="Get structured summary of an IOC",
)
def get_ioc_summary_route(iocId: str) -> APIResponse:
    try:
        all_iocs_list = _all_iocs()
        c = find_ioc(all_iocs_list, iocId)
        if not c:
            raise APIErrorNotFound(f"IOC '{iocId}' not found.")

        summary = build_ioc_summary(c)
        return build_success_response(
            data=summary,
            message="IOC summary built successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@ioc_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create IOC records",
)
def bulk_create_iocs(
    request: BulkCreateIOCsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.ioc_intelligence_service import (
            IOCTypeEnum,
            IOCSeverityEnum,
            IOCConfidenceEnum,
            build_ioc_record,
        )

        for item in request.iocs:
            try:
                t_enum = IOCTypeEnum(item.iocType.strip().upper())
                s_enum = IOCSeverityEnum(item.severity.strip().upper())
                c_enum = IOCConfidenceEnum(item.confidence.strip().upper())

                ioc_rec = build_ioc_record(
                    ioc_type=t_enum,
                    value=item.value,
                    severity=s_enum,
                    confidence=c_enum,
                    created_at=item.createdAt,
                    description=item.description or "",
                    source=item.source or "",
                    tags=item.tags,
                    related_cves=item.relatedCVEs,
                    related_techniques=item.relatedTechniques,
                )

                rec_id = ioc_rec.iocId
                if rec_id in _IOC_STORE or rec_id in succeeded:
                    failed.append({"id": item.value, "reason": f"IOC record with ID '{rec_id}' already exists."})
                    continue

                _IOC_STORE[rec_id] = {
                    "iocId": rec_id,
                    "iocKey": ioc_rec.iocKey,
                    "iocFingerprint": ioc_rec.iocFingerprint,
                    "iocType": ioc_rec.iocType.value,
                    "value": ioc_rec.value,
                    "severity": ioc_rec.severity.value,
                    "confidence": ioc_rec.confidence.value,
                    "description": ioc_rec.description,
                    "source": ioc_rec.source,
                    "tags": list(ioc_rec.tags),
                    "relatedCVEs": list(ioc_rec.relatedCVEs),
                    "relatedTechniques": list(ioc_rec.relatedTechniques),
                    "createdAt": ioc_rec.createdAt,
                    "updatedAt": item.updatedAt,
                    "malicious": bool(item.malicious),
                    "revoked": bool(item.revoked),
                    "threatActor": item.threatActor or "",
                    "campaign": item.campaign or "",
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.value, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.iocs),
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


@ioc_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update IOC records",
)
def bulk_update_iocs(
    request: BulkUpdateIOCsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.ioc_intelligence_service import (
            IOCTypeEnum,
            IOCSeverityEnum,
            IOCConfidenceEnum,
            build_ioc_record,
        )

        for item in request.items:
            rec_id = None
            all_iocs_list = _all_iocs()
            existing = find_ioc(all_iocs_list, item.iocId)
            if existing:
                rec_id = existing["iocId"]

            if not rec_id:
                failed.append({"id": item.iocId, "reason": f"IOC '{item.iocId}' not found."})
                continue

            try:
                severity_str = item.update.severity if item.update.severity is not None else existing.get("severity")
                confidence_str = item.update.confidence if item.update.confidence is not None else existing.get("confidence")
                description = item.update.description if item.update.description is not None else existing.get("description")
                source = item.update.source if item.update.source is not None else existing.get("source")
                tags = item.update.tags if item.update.tags is not None else existing.get("tags")
                related_cves = item.update.relatedCVEs if item.update.relatedCVEs is not None else existing.get("relatedCVEs")
                related_techniques = item.update.relatedTechniques if item.update.relatedTechniques is not None else existing.get("relatedTechniques")

                t_enum = IOCTypeEnum(existing.get("iocType").strip().upper())
                s_enum = IOCSeverityEnum(severity_str.strip().upper())
                c_enum = IOCConfidenceEnum(confidence_str.strip().upper())

                ioc_rec = build_ioc_record(
                    ioc_type=t_enum,
                    value=existing.get("value"),
                    severity=s_enum,
                    confidence=c_enum,
                    created_at=existing.get("createdAt"),
                    description=description,
                    source=source,
                    tags=tags,
                    related_cves=related_cves,
                    related_techniques=related_techniques,
                )

                malicious = item.update.malicious if item.update.malicious is not None else existing.get("malicious")
                revoked = item.update.revoked if item.update.revoked is not None else existing.get("revoked")
                threatActor = item.update.threatActor if item.update.threatActor is not None else existing.get("threatActor")
                campaign = item.update.campaign if item.update.campaign is not None else existing.get("campaign")
                updatedAt = item.update.updatedAt if item.update.updatedAt is not None else existing.get("updatedAt")

                _IOC_STORE[rec_id] = {
                    "iocId": rec_id,
                    "iocKey": ioc_rec.iocKey,
                    "iocFingerprint": ioc_rec.iocFingerprint,
                    "iocType": ioc_rec.iocType.value,
                    "value": ioc_rec.value,
                    "severity": ioc_rec.severity.value,
                    "confidence": ioc_rec.confidence.value,
                    "description": ioc_rec.description,
                    "source": ioc_rec.source,
                    "tags": list(ioc_rec.tags),
                    "relatedCVEs": list(ioc_rec.relatedCVEs),
                    "relatedTechniques": list(ioc_rec.relatedTechniques),
                    "createdAt": ioc_rec.createdAt,
                    "updatedAt": updatedAt,
                    "malicious": bool(malicious),
                    "revoked": bool(revoked),
                    "threatActor": threatActor or "",
                    "campaign": campaign or "",
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.iocId, "reason": str(e)})

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


@ioc_router.delete(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete IOC records",
)
def bulk_delete_iocs(
    request: BulkDeleteIOCsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        all_iocs_list = _all_iocs()
        for ioc_id in request.iocIds:
            existing = find_ioc(all_iocs_list, ioc_id)
            if not existing:
                failed.append({"id": ioc_id, "reason": f"IOC '{ioc_id}' not found."})
                continue

            try:
                rec_id = existing["iocId"]
                del _IOC_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": ioc_id, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.iocIds),
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
