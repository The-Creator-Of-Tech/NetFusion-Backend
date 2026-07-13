"""
CVE Intelligence API Router — Phase A4.9.2
===========================================
REST interface for CVE Intelligence.

Prefix  : /cve
Tag     : CVE Intelligence
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, Query

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
from api.knowledge.cve_models import (
    CreateCVERequest,
    UpdateCVERequest,
    CVEResponse,
    CVEListResponse,
    CVEStatisticsResponse,
    CVESearchResponse,
    CVSSResponse,
    AffectedProductResponse,
    BulkCreateCVEsRequest,
    BulkUpdateCVEsRequest,
    BulkDeleteCVEsRequest,
    BulkOperationResult,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

cve_router: APIRouter = APIRouter(
    prefix="/cve",
    tags=["CVE Intelligence"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_cve
_CVE_STORE = RepositoryBackedDict("cve", "cveId", map_cve)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _CVE_STORE.clear()


def _all_cves() -> List[Dict[str, Any]]:
    """Return all CVEs ordered by cveId ASC."""
    return sorted(_CVE_STORE.values(), key=lambda c: c.get("cveId", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_cve(cves: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a CVE by recordId, recordKey, or cveId (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for c in cves:
        if c.get("cveId", "").lower() == normalized:
            return c
        if c.get("recordId", "").lower() == normalized:
            return c
        if c.get("recordKey", "").lower() == normalized:
            return c
    return None


def search_cves(cves: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text, list, and product fields."""
    if not query or not query.strip():
        return list(cves)
    q = query.strip().lower()
    results = []
    for c in cves:
        if q in c.get("cveId", "").lower():
            results.append(c)
            continue
        if q in c.get("description", "").lower():
            results.append(c)
            continue
        if q in c.get("severity", "").lower():
            results.append(c)
            continue
        if q in c.get("vendor", "").lower():
            results.append(c)
            continue
        if q in c.get("product", "").lower():
            results.append(c)
            continue
        if any(q in plat.lower() for plat in c.get("affectedPlatforms", [])):
            results.append(c)
            continue
        if any(q in ref.lower() for ref in c.get("references", [])):
            results.append(c)
            continue
        if any(q in pr.get("vendor", "").lower() or q in pr.get("product", "").lower() for pr in c.get("affectedProducts", [])):
            results.append(c)
            continue
    return results


def sort_cves(
    cves: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts CVEs deterministically, falling back to cveId ASC."""
    valid_fields = {"cveId", "publishedDate", "severity", "cvssScore", "createdAt"}
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

    severity_priority = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def get_sort_key(c: Dict[str, Any]) -> Any:
        if sort_by == "cveId":
            return c.get("cveId", "")
        elif sort_by == "publishedDate":
            return c.get("publishedDate", "")
        elif sort_by == "severity":
            val = c.get("severity", "").strip().lower()
            return severity_priority.get(val, -1)
        elif sort_by == "cvssScore":
            return c.get("cvssScore", 0.0)
        elif sort_by == "createdAt":
            return c.get("createdAt", "")
        return ""

    reverse = (order == "desc")
    # Stable sort: primary sort with reverse, secondary sort is cveId ASC (always ASC)
    sorted_list = sorted(cves, key=lambda x: x.get("cveId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_cves(
    cves: List[Dict[str, Any]],
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    exploited: Optional[bool] = None,
    patched: Optional[bool] = None,
    minimumCVSS: Optional[float] = None,
    maximumCVSS: Optional[float] = None,
    publishedAfter: Optional[str] = None,
    publishedBefore: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Applies filters to CVEs."""
    filtered = list(cves)

    if severity is not None:
        s_val = severity.strip().upper()
        filtered = [c for c in filtered if c.get("severity", "").upper() == s_val]

    if vendor is not None:
        v_val = vendor.strip().lower()
        filtered = [
            c for c in filtered
            if v_val in c.get("vendor", "").lower() or
               any(v_val in pr.get("vendor", "").lower() for pr in c.get("affectedProducts", []))
        ]

    if product is not None:
        p_val = product.strip().lower()
        filtered = [
            c for c in filtered
            if p_val in c.get("product", "").lower() or
               any(p_val in pr.get("product", "").lower() for pr in c.get("affectedProducts", []))
        ]

    if exploited is not None:
        filtered = [c for c in filtered if bool(c.get("exploited", False)) == exploited]

    if patched is not None:
        filtered = [
            c for c in filtered
            if bool(c.get("patched", False)) == patched or
               any(bool(pr.get("patched", False)) == patched for pr in c.get("affectedProducts", []))
        ]

    if minimumCVSS is not None:
        filtered = [c for c in filtered if c.get("cvssScore", 0.0) >= minimumCVSS]

    if maximumCVSS is not None:
        filtered = [c for c in filtered if c.get("cvssScore", 0.0) <= maximumCVSS]

    if publishedAfter is not None:
        p_after = publishedAfter.strip()
        filtered = [c for c in filtered if c.get("publishedDate", "") >= p_after]

    if publishedBefore is not None:
        p_before = publishedBefore.strip()
        filtered = [c for c in filtered if c.get("publishedDate", "") <= p_before]

    return filtered


def paginate_cves(
    cves: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Paginates the CVE list."""
    total_items = len(cves)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = cves[start:end]
    return sliced, total_items


def build_cve_summary(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a structured CVE summary."""
    cve_id = cve.get("cveId", "")
    severity = cve.get("severity", "")
    cvss = cve.get("cvssScore", 0.0)
    vendor = cve.get("vendor", "")
    product = cve.get("product", "")
    platforms_str = ", ".join(cve.get("affectedPlatforms", []))

    text = (
        f"CVE {cve_id} is a {severity} severity vulnerability with a CVSS score of {cvss}. "
        f"It affects {vendor} {product} on platforms: {platforms_str}."
    )
    return {
        "cveId": cve_id,
        "severity": severity,
        "cvssScore": cvss,
        "summaryText": text,
        "platformCount": len(cve.get("affectedPlatforms", [])),
        "referenceCount": len(cve.get("references", [])),
        "productCount": len(cve.get("affectedProducts", [])),
    }


def calculate_cve_statistics(cves: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregate statistics over a list of CVEs."""
    total = len(cves)
    exploited = sum(1 for c in cves if c.get("exploited"))
    patched = sum(
        1 for c in cves
        if c.get("patched") or any(pr.get("patched") for pr in c.get("affectedProducts", []))
    )

    total_cvss = sum(c.get("cvssScore", 0.0) for c in cves)
    avg_cvss = round(total_cvss / total, 4) if total > 0 else 0.0

    severity_counts: Dict[str, int] = {}
    vendor_counts: Dict[str, int] = {}

    for c in cves:
        sev = c.get("severity", "").upper()
        if sev:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        vendors = set()
        v = c.get("vendor", "").strip()
        if v:
            vendors.add(v)
        for pr in c.get("affectedProducts", []):
            vendor_name = pr.get("vendor", "").strip()
            if vendor_name:
                vendors.add(vendor_name)

        for vendor_name in vendors:
            vendor_counts[vendor_name] = vendor_counts.get(vendor_name, 0) + 1

    return {
        "totalCVEs": total,
        "exploitedCVEs": exploited,
        "patchedCVEs": patched,
        "averageCVSS": avg_cvss,
        "severityCounts": dict(sorted(severity_counts.items())),
        "vendorCounts": dict(sorted(vendor_counts.items())),
    }


def _to_response_model(c: Dict[str, Any]) -> CVEResponse:
    """Helper to convert stored dictionary to CVEResponse model."""
    from api.knowledge.mitre_router import _to_response_model as mitre_to_resp
    
    mapped_techs = []
    for mt in c.get("mappedTechniques", []):
        # mt is an instance of MitreTechnique from mitre_attack_service
        # Let's map it to TechniqueResponse using duck-typing
        from api.knowledge.mitre_models import TechniqueResponse
        mapped_techs.append(
            TechniqueResponse(
                techniqueId=mt.techniqueId,
                techniqueKey=mt.techniqueKey,
                mitreId=mt.mitreId,
                name=mt.name,
                tactic=mt.tactic.value,
                description=mt.description,
                platforms=list(mt.platforms),
                detection=mt.detection,
                mitigations=list(mt.mitigations),
                references=list(mt.references),
                createdAt=mt.createdAt,
                severity="MEDIUM", # default severity for mapped tech
                dataSource="",
                revoked=False,
                deprecated=False,
                tacticCount=1,
            )
        )
        
    products_resp = [
        AffectedProductResponse(
            vendor=p.get("vendor", ""),
            product=p.get("product", ""),
            version=p.get("version", "*"),
            patched=p.get("patched", False),
        )
        for p in c.get("affectedProducts", [])
    ]
    
    cvss_details = None
    if c.get("cvssDetails"):
        cd = c["cvssDetails"]
        cvss_details = CVSSResponse(
            baseScore=cd.get("baseScore", c.get("cvssScore", 0.0)),
            severity=cd.get("severity", c.get("severity", "MEDIUM")),
            vectorString=cd.get("vectorString", ""),
            exploitabilityScore=cd.get("exploitabilityScore", 0.0),
            impactScore=cd.get("impactScore", 0.0),
        )

    # Support records that may be returned either under a `metadata` dict
    # or as top-level fields. Provide safe fallbacks so the API layer does
    # not raise KeyError when the seed/data uses different shapes.
    record_id = c.get("recordId") or c.get("id") or ""
    record_key = c.get("recordKey") or c.get("cveId") or ""

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

    return CVEResponse(
        recordId=record_id,
        recordKey=record_key,
        cveId=c.get("cveId", ""),
        description=c.get("description", ""),
        severity=c.get("severity", ""),
        cvssScore=c.get("cvssScore", 0.0),
        publishedDate=_fmt_date(c.get("publishedDate")),
        modifiedDate=_fmt_date(c.get("modifiedDate")),
        references=list(c.get("references") or []),
        affectedPlatforms=list(c.get("affectedPlatforms") or []),
        mappedTechniques=mapped_techs,
        createdAt=_fmt_date(c.get("createdAt")),
        exploited=bool(c.get("exploited", False)),
        patched=bool(c.get("patched", False)),
        vendor=c.get("vendor", ""),
        product=c.get("product", ""),
        affectedProducts=products_resp,
        cvssDetails=cvss_details,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@cve_router.get(
    "/",
    response_model=APIResponse,
    summary="List CVE records",
)
def list_cves(
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    exploited: Optional[bool] = None,
    patched: Optional[bool] = None,
    minimumCVSS: Optional[float] = None,
    maximumCVSS: Optional[float] = None,
    publishedAfter: Optional[str] = None,
    publishedBefore: Optional[str] = None,
    sortBy: str = "cveId",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_cves_list = _all_cves()

        filtered = filter_cves(
            all_cves_list,
            severity=severity,
            vendor=vendor,
            product=product,
            exploited=exploited,
            patched=patched,
            minimumCVSS=minimumCVSS,
            maximumCVSS=maximumCVSS,
            publishedAfter=publishedAfter,
            publishedBefore=publishedBefore,
        )

        sorted_cves = sort_cves(filtered, sortBy, sortOrder)
        paginated, total = paginate_cves(sorted_cves, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]

        return build_paginated_response(
            items=[r.model_dump() for r in responses],
            page=page,
            page_size=pageSize,
            total_items=total,
            message="CVE records listed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get CVE statistics",
)
def get_statistics() -> APIResponse:
    try:
        all_cves_list = _all_cves()
        stats = calculate_cve_statistics(all_cves_list)
        return build_success_response(
            data=stats,
            message="Statistics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search CVE records",
)
def search_cve_records(
    query: str = "",
    sortBy: str = "cveId",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_cves_list = _all_cves()
        searched = search_cves(all_cves_list, query)
        sorted_cves = sort_cves(searched, sortBy, sortOrder)
        paginated, total = paginate_cves(sorted_cves, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]
        total_pages = math.ceil(total / pageSize) if total > 0 else 0

        search_data = CVESearchResponse(
            cves=responses,
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


@cve_router.get(
    "/{cveId}",
    response_model=APIResponse,
    summary="Get CVE record by ID",
)
def get_cve(cveId: str) -> APIResponse:
    try:
        all_cves_list = _all_cves()
        c = find_cve(all_cves_list, cveId)
        if not c:
            raise APIErrorNotFound(f"CVE '{cveId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="CVE record retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a CVE record",
)
def create_cve(
    request: CreateCVERequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.cve_intelligence_service import SeverityEnum, build_cve_record
        from api.knowledge.mitre_router import _TECHNIQUE_STORE
        from services.mitre_attack_service import build_mitre_technique, TacticEnum

        # Reconstruct MitreTechniques from mappedTechniqueIds
        mapped_techniques = []
        for tid in (request.mappedTechniqueIds or []):
            t_data = _TECHNIQUE_STORE.get(tid)
            if not t_data:
                for stored_t in _TECHNIQUE_STORE.values():
                    if stored_t.get("mitreId", "").lower() == tid.strip().lower() or stored_t.get("techniqueKey", "").lower() == tid.strip().lower():
                        t_data = stored_t
                        break
            if t_data:
                try:
                    t_enum = TacticEnum(t_data["tactic"].upper())
                    mt = build_mitre_technique(
                        mitre_id=t_data["mitreId"],
                        name=t_data["name"],
                        tactic=t_enum,
                        created_at=t_data["createdAt"],
                        description=t_data["description"],
                        platforms=t_data["platforms"],
                        detection=t_data["detection"],
                        mitigations=t_data["mitigations"],
                        references=t_data["references"],
                    )
                    mapped_techniques.append(mt)
                except Exception:
                    pass

        try:
            s_enum = SeverityEnum(request.severity.strip().upper())
            cve_rec = build_cve_record(
                cve_id=request.cveId,
                severity=s_enum,
                cvss_score=request.cvssScore,
                created_at=request.createdAt,
                description=request.description or "",
                published_date=request.publishedDate or "",
                modified_date=request.modifiedDate or "",
                references=request.references,
                affected_platforms=request.affectedPlatforms,
                mapped_techniques=mapped_techniques,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = cve_rec.recordId
        if rec_id in _CVE_STORE:
            raise APIErrorConflict(f"CVE record with ID '{rec_id}' (cveId '{request.cveId}') already exists.")

        # Stored dict
        prods = [
            {
                "vendor": p.vendor,
                "product": p.product,
                "version": p.version or "*",
                "patched": p.patched,
            }
            for p in (request.affectedProducts or [])
        ]
        
        # If products are empty but top-level vendor/product exists, add a default product
        if not prods and (request.vendor or request.product):
            prods.append(
                {
                    "vendor": request.vendor or "",
                    "product": request.product or "",
                    "version": "*",
                    "patched": bool(request.patched),
                }
            )

        cvss_details_dict = None
        if request.cvssDetails:
            cvss_details_dict = {
                "baseScore": request.cvssDetails.baseScore,
                "severity": request.cvssDetails.severity,
                "vectorString": request.cvssDetails.vectorString or "",
                "exploitabilityScore": request.cvssDetails.exploitabilityScore or 0.0,
                "impactScore": request.cvssDetails.impactScore or 0.0,
            }

        _CVE_STORE[rec_id] = {
            "recordId": rec_id,
            "recordKey": cve_rec.recordKey,
            "cveId": cve_rec.cveId,
            "description": cve_rec.description,
            "severity": cve_rec.severity.value,
            "cvssScore": cve_rec.cvssScore,
            "publishedDate": cve_rec.publishedDate,
            "modifiedDate": cve_rec.modifiedDate,
            "references": list(cve_rec.references),
            "affectedPlatforms": list(cve_rec.affectedPlatforms),
            "mappedTechniques": list(cve_rec.mappedTechniques),
            "createdAt": cve_rec.createdAt,
            "exploited": bool(request.exploited),
            "patched": bool(request.patched) or any(pr["patched"] for pr in prods),
            "vendor": request.vendor or (prods[0]["vendor"] if prods else ""),
            "product": request.product or (prods[0]["product"] if prods else ""),
            "affectedProducts": prods,
            "cvssDetails": cvss_details_dict,
        }

        return build_success_response(
            data=_to_response_model(_CVE_STORE[rec_id]).model_dump(),
            message="CVE record created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.put(
    "/{cveId}",
    response_model=APIResponse,
    summary="Update a CVE record",
)
def update_cve(
    cveId: str,
    request: UpdateCVERequest = Body(...)
) -> APIResponse:
    try:
        all_cves_list = _all_cves()
        c = find_cve(all_cves_list, cveId)
        if not c:
            raise APIErrorNotFound(f"CVE '{cveId}' not found.")

        rec_id = c["recordId"]

        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")

        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.cve_intelligence_service import SeverityEnum, build_cve_record
        from api.knowledge.mitre_router import _TECHNIQUE_STORE
        from services.mitre_attack_service import build_mitre_technique, TacticEnum

        description = request.description if request.description is not None else c.get("description")
        severity_str = request.severity if request.severity is not None else c.get("severity")
        cvss_score = request.cvssScore if request.cvssScore is not None else c.get("cvssScore")
        published_date = request.publishedDate if request.publishedDate is not None else c.get("publishedDate")
        modified_date = request.modifiedDate if request.modifiedDate is not None else c.get("modifiedDate")
        references = request.references if request.references is not None else c.get("references")
        affected_platforms = request.affectedPlatforms if request.affectedPlatforms is not None else c.get("affectedPlatforms")

        # Handle mapped techniques
        if request.mappedTechniqueIds is not None:
            mapped_techniques = []
            for tid in request.mappedTechniqueIds:
                t_data = _TECHNIQUE_STORE.get(tid)
                if not t_data:
                    for stored_t in _TECHNIQUE_STORE.values():
                        if stored_t.get("mitreId", "").lower() == tid.strip().lower() or stored_t.get("techniqueKey", "").lower() == tid.strip().lower():
                            t_data = stored_t
                            break
                if t_data:
                    try:
                        t_enum = TacticEnum(t_data["tactic"].upper())
                        mt = build_mitre_technique(
                            mitre_id=t_data["mitreId"],
                            name=t_data["name"],
                            tactic=t_enum,
                            created_at=t_data["createdAt"],
                            description=t_data["description"],
                            platforms=t_data["platforms"],
                            detection=t_data["detection"],
                            mitigations=t_data["mitigations"],
                            references=t_data["references"],
                        )
                        mapped_techniques.append(mt)
                    except Exception:
                        pass
        else:
            mapped_techniques = c.get("mappedTechniques", [])

        try:
            s_enum = SeverityEnum(severity_str.strip().upper())
            cve_rec = build_cve_record(
                cve_id=c.get("cveId"),
                severity=s_enum,
                cvss_score=cvss_score,
                created_at=c.get("createdAt"),
                description=description,
                published_date=published_date,
                modified_date=modified_date,
                references=references,
                affected_platforms=affected_platforms,
                mapped_techniques=mapped_techniques,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        exploited = request.exploited if request.exploited is not None else c.get("exploited")
        patched = request.patched if request.patched is not None else c.get("patched")
        vendor = request.vendor if request.vendor is not None else c.get("vendor")
        product = request.product if request.product is not None else c.get("product")

        if request.affectedProducts is not None:
            prods = [
                {
                    "vendor": p.vendor,
                    "product": p.product,
                    "version": p.version or "*",
                    "patched": p.patched,
                }
                for p in request.affectedProducts
            ]
        else:
            prods = c.get("affectedProducts", [])

        cvss_details_dict = c.get("cvssDetails")
        if request.cvssDetails:
            cvss_details_dict = {
                "baseScore": request.cvssDetails.baseScore,
                "severity": request.cvssDetails.severity,
                "vectorString": request.cvssDetails.vectorString or "",
                "exploitabilityScore": request.cvssDetails.exploitabilityScore or 0.0,
                "impactScore": request.cvssDetails.impactScore or 0.0,
            }

        _CVE_STORE[rec_id] = {
            "recordId": rec_id,
            "recordKey": cve_rec.recordKey,
            "cveId": cve_rec.cveId,
            "description": cve_rec.description,
            "severity": cve_rec.severity.value,
            "cvssScore": cve_rec.cvssScore,
            "publishedDate": cve_rec.publishedDate,
            "modifiedDate": cve_rec.modifiedDate,
            "references": list(cve_rec.references),
            "affectedPlatforms": list(cve_rec.affectedPlatforms),
            "mappedTechniques": list(cve_rec.mappedTechniques),
            "createdAt": cve_rec.createdAt,
            "exploited": bool(exploited),
            "patched": bool(patched) or any(pr["patched"] for pr in prods),
            "vendor": vendor or (prods[0]["vendor"] if prods else ""),
            "product": product or (prods[0]["product"] if prods else ""),
            "affectedProducts": prods,
            "cvssDetails": cvss_details_dict,
        }

        return build_success_response(
            data=_to_response_model(_CVE_STORE[rec_id]).model_dump(),
            message="CVE record updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.delete(
    "/{cveId}",
    response_model=APIResponse,
    summary="Delete a CVE record",
)
def delete_cve(cveId: str) -> APIResponse:
    try:
        all_cves_list = _all_cves()
        c = find_cve(all_cves_list, cveId)
        if not c:
            raise APIErrorNotFound(f"CVE '{cveId}' not found.")

        rec_id = c["recordId"]
        del _CVE_STORE[rec_id]

        return build_success_response(
            data=None,
            message="CVE record deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.get(
    "/{cveId}/cvss",
    response_model=APIResponse,
    summary="Get CVSS details of a CVE",
)
def get_cve_cvss(cveId: str) -> APIResponse:
    try:
        all_cves_list = _all_cves()
        c = find_cve(all_cves_list, cveId)
        if not c:
            raise APIErrorNotFound(f"CVE '{cveId}' not found.")

        cvss_details = c.get("cvssDetails")
        if not cvss_details:
            cvss_details = CVSSResponse(
                baseScore=c.get("cvssScore", 0.0),
                severity=c.get("severity", "MEDIUM"),
                vectorString="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                exploitabilityScore=3.9,
                impactScore=5.9,
            )
        else:
            if isinstance(cvss_details, dict):
                cvss_details = CVSSResponse(**cvss_details)

        return build_success_response(
            data=cvss_details.model_dump(),
            message="CVSS details retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.get(
    "/{cveId}/products",
    response_model=APIResponse,
    summary="Get affected products of a CVE",
)
def get_cve_products(cveId: str) -> APIResponse:
    try:
        all_cves_list = _all_cves()
        c = find_cve(all_cves_list, cveId)
        if not c:
            raise APIErrorNotFound(f"CVE '{cveId}' not found.")

        products = c.get("affectedProducts", [])
        resp_items = []
        for p in products:
            if isinstance(p, dict):
                resp_items.append(AffectedProductResponse(**p))
            else:
                resp_items.append(p)

        if not resp_items and (c.get("vendor") or c.get("product")):
            resp_items.append(
                AffectedProductResponse(
                    vendor=c.get("vendor", ""),
                    product=c.get("product", ""),
                    version="*",
                    patched=c.get("patched", False),
                )
            )

        return build_success_response(
            data=[x.model_dump() for x in resp_items],
            message="Affected products retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.get(
    "/{cveId}/summary",
    response_model=APIResponse,
    summary="Get structured summary of a CVE",
)
def get_cve_summary(cveId: str) -> APIResponse:
    try:
        all_cves_list = _all_cves()
        c = find_cve(all_cves_list, cveId)
        if not c:
            raise APIErrorNotFound(f"CVE '{cveId}' not found.")

        summary = build_cve_summary(c)
        return build_success_response(
            data=summary,
            message="CVE summary built successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@cve_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create CVE records",
)
def bulk_create_cves(
    request: BulkCreateCVEsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.cve_intelligence_service import SeverityEnum, build_cve_record
        from api.knowledge.mitre_router import _TECHNIQUE_STORE
        from services.mitre_attack_service import build_mitre_technique, TacticEnum

        for item in request.cves:
            try:
                mapped_techniques = []
                for tid in (item.mappedTechniqueIds or []):
                    t_data = _TECHNIQUE_STORE.get(tid)
                    if not t_data:
                        for stored_t in _TECHNIQUE_STORE.values():
                            if stored_t.get("mitreId", "").lower() == tid.strip().lower() or stored_t.get("techniqueKey", "").lower() == tid.strip().lower():
                                t_data = stored_t
                                break
                    if t_data:
                        try:
                            t_enum = TacticEnum(t_data["tactic"].upper())
                            mt = build_mitre_technique(
                                mitre_id=t_data["mitreId"],
                                name=t_data["name"],
                                tactic=t_enum,
                                created_at=t_data["createdAt"],
                                description=t_data["description"],
                                platforms=t_data["platforms"],
                                detection=t_data["detection"],
                                mitigations=t_data["mitigations"],
                                references=t_data["references"],
                            )
                            mapped_techniques.append(mt)
                        except Exception:
                            pass

                s_enum = SeverityEnum(item.severity.strip().upper())
                cve_rec = build_cve_record(
                    cve_id=item.cveId,
                    severity=s_enum,
                    cvss_score=item.cvssScore,
                    created_at=item.createdAt,
                    description=item.description or "",
                    published_date=item.publishedDate or "",
                    modified_date=item.modifiedDate or "",
                    references=item.references,
                    affected_platforms=item.affectedPlatforms,
                    mapped_techniques=mapped_techniques,
                )

                rec_id = cve_rec.recordId
                if rec_id in _CVE_STORE or rec_id in succeeded:
                    failed.append({"id": item.cveId, "reason": f"CVE record with ID '{rec_id}' already exists."})
                    continue

                prods = [
                    {
                        "vendor": p.vendor,
                        "product": p.product,
                        "version": p.version or "*",
                        "patched": p.patched,
                    }
                    for p in (item.affectedProducts or [])
                ]
                if not prods and (item.vendor or item.product):
                    prods.append(
                        {
                            "vendor": item.vendor or "",
                            "product": item.product or "",
                            "version": "*",
                            "patched": bool(item.patched),
                        }
                    )

                cvss_details_dict = None
                if item.cvssDetails:
                    cvss_details_dict = {
                        "baseScore": item.cvssDetails.baseScore,
                        "severity": item.cvssDetails.severity,
                        "vectorString": item.cvssDetails.vectorString or "",
                        "exploitabilityScore": item.cvssDetails.exploitabilityScore or 0.0,
                        "impactScore": item.cvssDetails.impactScore or 0.0,
                    }

                _CVE_STORE[rec_id] = {
                    "recordId": rec_id,
                    "recordKey": cve_rec.recordKey,
                    "cveId": cve_rec.cveId,
                    "description": cve_rec.description,
                    "severity": cve_rec.severity.value,
                    "cvssScore": cve_rec.cvssScore,
                    "publishedDate": cve_rec.publishedDate,
                    "modifiedDate": cve_rec.modifiedDate,
                    "references": list(cve_rec.references),
                    "affectedPlatforms": list(cve_rec.affectedPlatforms),
                    "mappedTechniques": list(cve_rec.mappedTechniques),
                    "createdAt": cve_rec.createdAt,
                    "exploited": bool(item.exploited),
                    "patched": bool(item.patched) or any(pr["patched"] for pr in prods),
                    "vendor": item.vendor or (prods[0]["vendor"] if prods else ""),
                    "product": item.product or (prods[0]["product"] if prods else ""),
                    "affectedProducts": prods,
                    "cvssDetails": cvss_details_dict,
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.cveId, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.cves),
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


@cve_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update CVE records",
)
def bulk_update_cves(
    request: BulkUpdateCVEsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.cve_intelligence_service import SeverityEnum, build_cve_record
        from api.knowledge.mitre_router import _TECHNIQUE_STORE
        from services.mitre_attack_service import build_mitre_technique, TacticEnum

        for item in request.items:
            rec_id = None
            # Lookup existing CVE to find rec_id
            all_cves_list = _all_cves()
            existing = find_cve(all_cves_list, item.cveId)
            if existing:
                rec_id = existing["recordId"]

            if not rec_id:
                failed.append({"id": item.cveId, "reason": f"CVE '{item.cveId}' not found."})
                continue

            try:
                description = item.update.description if item.update.description is not None else existing.get("description")
                severity_str = item.update.severity if item.update.severity is not None else existing.get("severity")
                cvss_score = item.update.cvssScore if item.update.cvssScore is not None else existing.get("cvssScore")
                published_date = item.update.publishedDate if item.update.publishedDate is not None else existing.get("publishedDate")
                modified_date = item.update.modifiedDate if item.update.modifiedDate is not None else existing.get("modifiedDate")
                references = item.update.references if item.update.references is not None else existing.get("references")
                affected_platforms = item.update.affectedPlatforms if item.update.affectedPlatforms is not None else existing.get("affectedPlatforms")

                if item.update.mappedTechniqueIds is not None:
                    mapped_techniques = []
                    for tid in item.update.mappedTechniqueIds:
                        t_data = _TECHNIQUE_STORE.get(tid)
                        if not t_data:
                            for stored_t in _TECHNIQUE_STORE.values():
                                if stored_t.get("mitreId", "").lower() == tid.strip().lower() or stored_t.get("techniqueKey", "").lower() == tid.strip().lower():
                                    t_data = stored_t
                                    break
                        if t_data:
                            try:
                                t_enum = TacticEnum(t_data["tactic"].upper())
                                mt = build_mitre_technique(
                                    mitre_id=t_data["mitreId"],
                                    name=t_data["name"],
                                    tactic=t_enum,
                                    created_at=t_data["createdAt"],
                                    description=t_data["description"],
                                    platforms=t_data["platforms"],
                                    detection=t_data["detection"],
                                    mitigations=t_data["mitigations"],
                                    references=t_data["references"],
                                )
                                mapped_techniques.append(mt)
                            except Exception:
                                pass
                else:
                    mapped_techniques = existing.get("mappedTechniques", [])

                s_enum = SeverityEnum(severity_str.strip().upper())
                cve_rec = build_cve_record(
                    cve_id=existing.get("cveId"),
                    severity=s_enum,
                    cvss_score=cvss_score,
                    created_at=existing.get("createdAt"),
                    description=description,
                    published_date=published_date,
                    modified_date=modified_date,
                    references=references,
                    affected_platforms=affected_platforms,
                    mapped_techniques=mapped_techniques,
                )

                exploited = item.update.exploited if item.update.exploited is not None else existing.get("exploited")
                patched = item.update.patched if item.update.patched is not None else existing.get("patched")
                vendor = item.update.vendor if item.update.vendor is not None else existing.get("vendor")
                product = item.update.product if item.update.product is not None else existing.get("product")

                if item.update.affectedProducts is not None:
                    prods = [
                        {
                            "vendor": p.vendor,
                            "product": p.product,
                            "version": p.version or "*",
                            "patched": p.patched,
                        }
                        for p in item.update.affectedProducts
                    ]
                else:
                    prods = existing.get("affectedProducts", [])

                cvss_details_dict = existing.get("cvssDetails")
                if item.update.cvssDetails:
                    cvss_details_dict = {
                        "baseScore": item.update.cvssDetails.baseScore,
                        "severity": item.update.cvssDetails.severity,
                        "vectorString": item.update.cvssDetails.vectorString or "",
                        "exploitabilityScore": item.update.cvssDetails.exploitabilityScore or 0.0,
                        "impactScore": item.update.cvssDetails.impactScore or 0.0,
                    }

                _CVE_STORE[rec_id] = {
                    "recordId": rec_id,
                    "recordKey": cve_rec.recordKey,
                    "cveId": cve_rec.cveId,
                    "description": cve_rec.description,
                    "severity": cve_rec.severity.value,
                    "cvssScore": cve_rec.cvssScore,
                    "publishedDate": cve_rec.publishedDate,
                    "modifiedDate": cve_rec.modifiedDate,
                    "references": list(cve_rec.references),
                    "affectedPlatforms": list(cve_rec.affectedPlatforms),
                    "mappedTechniques": list(cve_rec.mappedTechniques),
                    "createdAt": cve_rec.createdAt,
                    "exploited": bool(exploited),
                    "patched": bool(patched) or any(pr["patched"] for pr in prods),
                    "vendor": vendor or (prods[0]["vendor"] if prods else ""),
                    "product": product or (prods[0]["product"] if prods else ""),
                    "affectedProducts": prods,
                    "cvssDetails": cvss_details_dict,
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.cveId, "reason": str(e)})

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


@cve_router.delete(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete CVE records",
)
def bulk_delete_cves(
    request: BulkDeleteCVEsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        all_cves_list = _all_cves()
        for cve_id in request.cveIds:
            existing = find_cve(all_cves_list, cve_id)
            if not existing:
                failed.append({"id": cve_id, "reason": f"CVE '{cve_id}' not found."})
                continue

            try:
                rec_id = existing["recordId"]
                del _CVE_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": cve_id, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.cveIds),
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
