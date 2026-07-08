"""
MITRE ATT&CK API Router — Phase A4.9.1
======================================
REST interface for MITRE ATT&CK Engine.

Prefix  : /mitre
Tag     : MITRE ATT&CK
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
from api.knowledge.mitre_models import (
    CreateTechniqueRequest,
    UpdateTechniqueRequest,
    TechniqueResponse,
    TechniqueListResponse,
    TechniqueStatisticsResponse,
    TechniqueSearchResponse,
    MitreTacticResponse,
    MitreMitigationResponse,
    BulkCreateTechniquesRequest,
    BulkUpdateTechniquesRequest,
    BulkDeleteTechniquesRequest,
    BulkOperationResult,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

mitre_router: APIRouter = APIRouter(
    prefix="/mitre",
    tags=["MITRE ATT&CK"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
from api.persistence import RepositoryBackedDict, map_mitre_technique
_TECHNIQUE_STORE = RepositoryBackedDict("mitre", "mitreId", map_mitre_technique)


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _TECHNIQUE_STORE.clear()


def _all_techniques() -> List[Dict[str, Any]]:
    """Return all techniques ordered by techniqueId ASC."""
    return sorted(_TECHNIQUE_STORE.values(), key=lambda t: t.get("techniqueId", ""))


# ---------------------------------------------------------------------------
# Tactic Metadata Registry
# ---------------------------------------------------------------------------
_TACTIC_INFO = {
    "RECONNAISSANCE": {
        "tactic": "RECONNAISSANCE",
        "name": "Reconnaissance",
        "shortName": "reconnaissance",
        "description": "The adversary is trying to gather information they can use to plan future operations.",
        "order": 1,
    },
    "RESOURCE_DEVELOPMENT": {
        "tactic": "RESOURCE_DEVELOPMENT",
        "name": "Resource Development",
        "shortName": "resource-development",
        "description": "The adversary is trying to build resources they can use to support operations.",
        "order": 2,
    },
    "INITIAL_ACCESS": {
        "tactic": "INITIAL_ACCESS",
        "name": "Initial Access",
        "shortName": "initial-access",
        "description": "The adversary is trying to get into your network.",
        "order": 3,
    },
    "EXECUTION": {
        "tactic": "EXECUTION",
        "name": "Execution",
        "shortName": "execution",
        "description": "The adversary is trying to run malicious code.",
        "order": 4,
    },
    "PERSISTENCE": {
        "tactic": "PERSISTENCE",
        "name": "Persistence",
        "shortName": "persistence",
        "description": "The adversary is trying to maintain their foothold.",
        "order": 5,
    },
    "PRIVILEGE_ESCALATION": {
        "tactic": "PRIVILEGE_ESCALATION",
        "name": "Privilege Escalation",
        "shortName": "privilege-escalation",
        "description": "The adversary is trying to gain higher-level permissions.",
        "order": 6,
    },
    "DEFENSE_EVASION": {
        "tactic": "DEFENSE_EVASION",
        "name": "Defense Evasion",
        "shortName": "defense-evasion",
        "description": "The adversary is trying to avoid detection.",
        "order": 7,
    },
    "CREDENTIAL_ACCESS": {
        "tactic": "CREDENTIAL_ACCESS",
        "name": "Credential Access",
        "shortName": "credential-access",
        "description": "The adversary is trying to steal passwords and usernames.",
        "order": 8,
    },
    "DISCOVERY": {
        "tactic": "DISCOVERY",
        "name": "Discovery",
        "shortName": "discovery",
        "description": "The adversary is trying to figure out your environment.",
        "order": 9,
    },
    "LATERAL_MOVEMENT": {
        "tactic": "LATERAL_MOVEMENT",
        "name": "Lateral Movement",
        "shortName": "lateral-movement",
        "description": "The adversary is trying to move through your environment.",
        "order": 10,
    },
    "COLLECTION": {
        "tactic": "COLLECTION",
        "name": "Collection",
        "shortName": "collection",
        "description": "The adversary is trying to gather data of interest to their goal.",
        "order": 11,
    },
    "COMMAND_AND_CONTROL": {
        "tactic": "COMMAND_AND_CONTROL",
        "name": "Command and Control",
        "shortName": "command-and-control",
        "description": "The adversary is trying to communicate with controlled systems.",
        "order": 12,
    },
    "EXFILTRATION": {
        "tactic": "EXFILTRATION",
        "name": "Exfiltration",
        "shortName": "exfiltration",
        "description": "The adversary is trying to steal data.",
        "order": 13,
    },
    "IMPACT": {
        "tactic": "IMPACT",
        "name": "Impact",
        "shortName": "impact",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        "order": 14,
    },
}


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_technique(techniques: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a technique by techniqueId, techniqueKey, or mitreId (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for t in techniques:
        if t.get("techniqueId", "").lower() == normalized:
            return t
        if t.get("techniqueKey", "").lower() == normalized:
            return t
        if t.get("mitreId", "").lower() == normalized:
            return t
    return None


def search_techniques(techniques: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across all relevant text and list fields."""
    if not query or not query.strip():
        return list(techniques)
    q = query.strip().lower()
    results = []
    for t in techniques:
        if q in t.get("name", "").lower():
            results.append(t)
            continue
        if q in t.get("description", "").lower():
            results.append(t)
            continue
        if q in t.get("mitreId", "").lower():
            results.append(t)
            continue
        if q in t.get("tactic", "").lower():
            results.append(t)
            continue
        if q in t.get("detection", "").lower():
            results.append(t)
            continue
        if q in t.get("severity", "").lower():
            results.append(t)
            continue
        if q in t.get("dataSource", "").lower():
            results.append(t)
            continue
        if any(q in p.lower() for p in t.get("platforms", [])):
            results.append(t)
            continue
        if any(q in m.lower() for m in t.get("mitigations", [])):
            results.append(t)
            continue
        if any(q in r.lower() for r in t.get("references", [])):
            results.append(t)
            continue
    return results


def sort_techniques(
    techniques: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts techniques deterministically, falling back to techniqueId ASC."""
    valid_fields = {"techniqueId", "techniqueName", "createdAt", "severity", "tacticCount"}
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

    severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def get_sort_key(t: Dict[str, Any]) -> Any:
        if sort_by == "techniqueId":
            return t.get("techniqueId", "")
        elif sort_by == "techniqueName":
            return t.get("name", "")
        elif sort_by == "createdAt":
            return t.get("createdAt", "")
        elif sort_by == "severity":
            val = t.get("severity", "").strip().lower()
            return severity_priority.get(val, -1)
        elif sort_by == "tacticCount":
            return t.get("tacticCount", 1)
        return ""

    reverse = (order == "desc")
    # Stable sort: primary sort with reverse, secondary sort is techniqueId ASC (always ASC)
    sorted_list = sorted(techniques, key=lambda x: x.get("techniqueId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_techniques(
    techniques: List[Dict[str, Any]],
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    data_source: Optional[str] = None,
    detection: Optional[str] = None,
    mitigation: Optional[str] = None,
    revoked: Optional[bool] = None,
    deprecated: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    """Applies filters to techniques."""
    filtered = list(techniques)

    if tactic is not None:
        t_val = tactic.strip().lower()
        filtered = [t for t in filtered if t_val in t.get("tactic", "").lower()]

    if platform is not None:
        p_val = platform.strip().lower()
        filtered = [
            t for t in filtered
            if any(p_val in p.lower() for p in t.get("platforms", []))
        ]

    if data_source is not None:
        ds_val = data_source.strip().lower()
        filtered = [t for t in filtered if ds_val in t.get("dataSource", "").lower()]

    if detection is not None:
        det_val = detection.strip().lower()
        filtered = [t for t in filtered if det_val in t.get("detection", "").lower()]

    if mitigation is not None:
        mit_val = mitigation.strip().lower()
        filtered = [
            t for t in filtered
            if any(mit_val in m.lower() for m in t.get("mitigations", []))
        ]

    if revoked is not None:
        filtered = [t for t in filtered if bool(t.get("revoked", False)) == revoked]

    if deprecated is not None:
        filtered = [t for t in filtered if bool(t.get("deprecated", False)) == deprecated]

    return filtered


def paginate_techniques(
    techniques: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Paginates the technique list."""
    total_items = len(techniques)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = techniques[start:end]
    return sliced, total_items


def build_technique_summary(technique: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a structured technique summary."""
    mitre_id = technique.get("mitreId", "")
    name = technique.get("name", "")
    tactic = technique.get("tactic", "")
    platforms_str = ", ".join(technique.get("platforms", []))
    mitigations_count = len(technique.get("mitigations", []))

    text = (
        f"MITRE ATT&CK Technique {mitre_id} ({name}) "
        f"belongs to tactic {tactic}. Applicable platforms: {platforms_str}. "
        f"It has {mitigations_count} documented mitigations."
    )
    return {
        "mitreId": mitre_id,
        "name": name,
        "tactic": tactic,
        "summaryText": text,
        "platformCount": len(technique.get("platforms", [])),
        "mitigationCount": mitigations_count,
        "referenceCount": len(technique.get("references", [])),
    }


def calculate_technique_statistics(techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregate statistics over a list of techniques."""
    total = len(techniques)
    revoked = sum(1 for t in techniques if t.get("revoked"))
    deprecated = sum(1 for t in techniques if t.get("deprecated"))

    tactic_counts: Dict[str, int] = {}
    platform_counts: Dict[str, int] = {}

    total_tactics = 0
    for t in techniques:
        tactic = t.get("tactic", "")
        if tactic:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            total_tactics += 1

        for p in t.get("platforms", []):
            platform_counts[p] = platform_counts.get(p, 0) + 1

    avg_tactics = round(total_tactics / total, 4) if total > 0 else 0.0

    return {
        "totalTechniques": total,
        "revokedTechniques": revoked,
        "deprecatedTechniques": deprecated,
        "averageTactics": avg_tactics,
        "tacticCounts": dict(sorted(tactic_counts.items())),
        "platformCounts": dict(sorted(platform_counts.items())),
    }


def _to_response_model(t: Dict[str, Any]) -> TechniqueResponse:
    """Helper to convert stored dictionary to TechniqueResponse model."""
    return TechniqueResponse(
        techniqueId=t["techniqueId"],
        techniqueKey=t["techniqueKey"],
        mitreId=t["mitreId"],
        name=t["name"],
        tactic=t["tactic"],
        description=t["description"],
        platforms=list(t["platforms"]),
        detection=t["detection"],
        mitigations=list(t["mitigations"]),
        references=list(t["references"]),
        createdAt=t["createdAt"],
        severity=t["severity"],
        dataSource=t["dataSource"],
        revoked=t["revoked"],
        deprecated=t["deprecated"],
        tacticCount=t.get("tacticCount", 1),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@mitre_router.get(
    "/",
    response_model=APIResponse,
    summary="List MITRE ATT&CK techniques",
)
def list_techniques(
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    dataSource: Optional[str] = None,
    detection: Optional[str] = None,
    mitigation: Optional[str] = None,
    revoked: Optional[bool] = None,
    deprecated: Optional[bool] = None,
    sortBy: str = "techniqueId",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_techs = _all_techniques()

        filtered = filter_techniques(
            all_techs,
            tactic=tactic,
            platform=platform,
            data_source=dataSource,
            detection=detection,
            mitigation=mitigation,
            revoked=revoked,
            deprecated=deprecated,
        )

        sorted_techs = sort_techniques(filtered, sortBy, sortOrder)
        paginated, total = paginate_techniques(sorted_techs, page, pageSize)
        responses = [_to_response_model(t) for t in paginated]

        return build_paginated_response(
            items=[r.model_dump() for r in responses],
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Techniques listed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get MITRE ATT&CK technique statistics",
)
def get_statistics() -> APIResponse:
    try:
        all_techs = _all_techniques()
        stats = calculate_technique_statistics(all_techs)
        return build_success_response(
            data=stats,
            message="Statistics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search MITRE ATT&CK techniques",
)
def search_mitre_techniques(
    query: str = "",
    sortBy: str = "techniqueId",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_techs = _all_techniques()
        searched = search_techniques(all_techs, query)
        sorted_techs = sort_techniques(searched, sortBy, sortOrder)
        paginated, total = paginate_techniques(sorted_techs, page, pageSize)
        responses = [_to_response_model(t) for t in paginated]
        total_pages = math.ceil(total / pageSize) if total > 0 else 0

        search_data = TechniqueSearchResponse(
            techniques=responses,
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


@mitre_router.get(
    "/{techniqueId}",
    response_model=APIResponse,
    summary="Get technique by ID",
)
def get_technique(techniqueId: str) -> APIResponse:
    try:
        all_techs = _all_techniques()
        t = find_technique(all_techs, techniqueId)
        if not t:
            raise APIErrorNotFound(f"Technique '{techniqueId}' not found.")
        return build_success_response(
            data=_to_response_model(t).model_dump(),
            message="Technique retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a MITRE ATT&CK technique",
)
def create_technique(
    request: CreateTechniqueRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.mitre_attack_service import TacticEnum, build_mitre_technique

        try:
            t_enum = TacticEnum(request.tactic.strip().upper())
            mitre_tech = build_mitre_technique(
                mitre_id=request.mitreId,
                name=request.name,
                tactic=t_enum,
                created_at=request.createdAt,
                description=request.description or "",
                platforms=request.platforms,
                detection=request.detection or "",
                mitigations=request.mitigations,
                references=request.references,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        tech_id = mitre_tech.techniqueId
        if tech_id in _TECHNIQUE_STORE:
            raise APIErrorConflict(f"Technique with ID '{tech_id}' (mitreId '{request.mitreId}') already exists.")

        _TECHNIQUE_STORE[tech_id] = {
            "techniqueId": tech_id,
            "techniqueKey": mitre_tech.techniqueKey,
            "mitreId": mitre_tech.mitreId,
            "name": mitre_tech.name,
            "tactic": mitre_tech.tactic.value,
            "description": mitre_tech.description,
            "platforms": list(mitre_tech.platforms),
            "detection": mitre_tech.detection,
            "mitigations": list(mitre_tech.mitigations),
            "references": list(mitre_tech.references),
            "createdAt": mitre_tech.createdAt,
            "severity": request.severity or "MEDIUM",
            "dataSource": request.dataSource or "",
            "revoked": bool(request.revoked),
            "deprecated": bool(request.deprecated),
            "tacticCount": 1,
        }

        return build_success_response(
            data=_to_response_model(_TECHNIQUE_STORE[tech_id]).model_dump(),
            message="Technique created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.put(
    "/{techniqueId}",
    response_model=APIResponse,
    summary="Update a MITRE ATT&CK technique",
)
def update_technique(
    techniqueId: str,
    request: UpdateTechniqueRequest = Body(...)
) -> APIResponse:
    try:
        all_techs = _all_techniques()
        t = find_technique(all_techs, techniqueId)
        if not t:
            raise APIErrorNotFound(f"Technique '{techniqueId}' not found.")

        tech_id = t["techniqueId"]

        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")

        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.mitre_attack_service import TacticEnum, build_mitre_technique

        name = request.name if request.name is not None else t.get("name")
        tactic_str = request.tactic if request.tactic is not None else t.get("tactic")
        description = request.description if request.description is not None else t.get("description")
        platforms = request.platforms if request.platforms is not None else t.get("platforms")
        detection = request.detection if request.detection is not None else t.get("detection")
        mitigations = request.mitigations if request.mitigations is not None else t.get("mitigations")
        references = request.references if request.references is not None else t.get("references")

        try:
            t_enum = TacticEnum(tactic_str.strip().upper())
            mitre_tech = build_mitre_technique(
                mitre_id=t.get("mitreId"),
                name=name,
                tactic=t_enum,
                created_at=t.get("createdAt"),
                description=description,
                platforms=platforms,
                detection=detection,
                mitigations=mitigations,
                references=references,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        severity = request.severity if request.severity is not None else t.get("severity")
        dataSource = request.dataSource if request.dataSource is not None else t.get("dataSource")
        revoked = request.revoked if request.revoked is not None else t.get("revoked")
        deprecated = request.deprecated if request.deprecated is not None else t.get("deprecated")

        _TECHNIQUE_STORE[tech_id] = {
            "techniqueId": tech_id,
            "techniqueKey": mitre_tech.techniqueKey,
            "mitreId": mitre_tech.mitreId,
            "name": mitre_tech.name,
            "tactic": mitre_tech.tactic.value,
            "description": mitre_tech.description,
            "platforms": list(mitre_tech.platforms),
            "detection": mitre_tech.detection,
            "mitigations": list(mitre_tech.mitigations),
            "references": list(mitre_tech.references),
            "createdAt": mitre_tech.createdAt,
            "severity": severity,
            "dataSource": dataSource,
            "revoked": bool(revoked),
            "deprecated": bool(deprecated),
            "tacticCount": 1,
        }

        return build_success_response(
            data=_to_response_model(_TECHNIQUE_STORE[tech_id]).model_dump(),
            message="Technique updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.delete(
    "/{techniqueId}",
    response_model=APIResponse,
    summary="Delete a MITRE ATT&CK technique",
)
def delete_technique(techniqueId: str) -> APIResponse:
    try:
        all_techs = _all_techniques()
        t = find_technique(all_techs, techniqueId)
        if not t:
            raise APIErrorNotFound(f"Technique '{techniqueId}' not found.")

        tech_id = t["techniqueId"]
        del _TECHNIQUE_STORE[tech_id]

        return build_success_response(
            data=None,
            message="Technique deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.get(
    "/{techniqueId}/tactics",
    response_model=APIResponse,
    summary="Get tactics mapped to a technique",
)
def get_technique_tactics(techniqueId: str) -> APIResponse:
    try:
        all_techs = _all_techniques()
        t = find_technique(all_techs, techniqueId)
        if not t:
            raise APIErrorNotFound(f"Technique '{techniqueId}' not found.")

        tactic_str = t.get("tactic", "")
        t_upper = tactic_str.strip().upper()

        info = _TACTIC_INFO.get(t_upper, {
            "tactic": t_upper,
            "name": tactic_str,
            "shortName": tactic_str.lower().replace("_", "-").replace(" ", "-"),
            "description": "Custom tactic.",
            "order": 99,
        })

        tactic_response = MitreTacticResponse(**info)
        return build_success_response(
            data=[tactic_response.model_dump()],
            message="Tactics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.get(
    "/{techniqueId}/mitigations",
    response_model=APIResponse,
    summary="Get mitigations mapped to a technique",
)
def get_technique_mitigations(techniqueId: str) -> APIResponse:
    try:
        all_techs = _all_techniques()
        t = find_technique(all_techs, techniqueId)
        if not t:
            raise APIErrorNotFound(f"Technique '{techniqueId}' not found.")

        mitigations = t.get("mitigations", [])
        resp_items = []
        for m in mitigations:
            m_clean = m.strip()
            if not m_clean:
                continue
            mit_id = f"mit-{hashlib.sha256(m_clean.encode('utf-8')).hexdigest()[:16]}"
            resp_items.append(
                MitreMitigationResponse(
                    mitigation=m_clean,
                    mitigationId=mit_id,
                )
            )

        return build_success_response(
            data=[x.model_dump() for x in resp_items],
            message="Mitigations retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.get(
    "/{techniqueId}/summary",
    response_model=APIResponse,
    summary="Get structured summary of a technique",
)
def get_technique_summary(techniqueId: str) -> APIResponse:
    try:
        all_techs = _all_techniques()
        t = find_technique(all_techs, techniqueId)
        if not t:
            raise APIErrorNotFound(f"Technique '{techniqueId}' not found.")

        summary = build_technique_summary(t)
        return build_success_response(
            data=summary,
            message="Technique summary built successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@mitre_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create techniques",
)
def bulk_create_techniques(
    request: BulkCreateTechniquesRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for item in request.techniques:
            try:
                from services.mitre_attack_service import TacticEnum, build_mitre_technique
                t_enum = TacticEnum(item.tactic.strip().upper())
                mitre_tech = build_mitre_technique(
                    mitre_id=item.mitreId,
                    name=item.name,
                    tactic=t_enum,
                    created_at=item.createdAt,
                    description=item.description or "",
                    platforms=item.platforms,
                    detection=item.detection or "",
                    mitigations=item.mitigations,
                    references=item.references,
                )
                tech_id = mitre_tech.techniqueId
                if tech_id in _TECHNIQUE_STORE or tech_id in succeeded:
                    failed.append({"id": item.mitreId, "reason": f"Technique with ID '{tech_id}' already exists."})
                    continue

                _TECHNIQUE_STORE[tech_id] = {
                    "techniqueId": tech_id,
                    "techniqueKey": mitre_tech.techniqueKey,
                    "mitreId": mitre_tech.mitreId,
                    "name": mitre_tech.name,
                    "tactic": mitre_tech.tactic.value,
                    "description": mitre_tech.description,
                    "platforms": list(mitre_tech.platforms),
                    "detection": mitre_tech.detection,
                    "mitigations": list(mitre_tech.mitigations),
                    "references": list(mitre_tech.references),
                    "createdAt": mitre_tech.createdAt,
                    "severity": item.severity or "MEDIUM",
                    "dataSource": item.dataSource or "",
                    "revoked": bool(item.revoked),
                    "deprecated": bool(item.deprecated),
                    "tacticCount": 1,
                }
                succeeded.append(tech_id)
            except Exception as e:
                failed.append({"id": item.mitreId, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.techniques),
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


@mitre_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update techniques",
)
def bulk_update_techniques(
    request: BulkUpdateTechniquesRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for item in request.items:
            tech_id = item.techniqueId
            if tech_id not in _TECHNIQUE_STORE:
                failed.append({"id": tech_id, "reason": f"Technique '{tech_id}' not found."})
                continue

            try:
                existing = _TECHNIQUE_STORE[tech_id]
                from services.mitre_attack_service import TacticEnum, build_mitre_technique

                name = item.update.name if item.update.name is not None else existing.get("name")
                tactic_str = item.update.tactic if item.update.tactic is not None else existing.get("tactic")
                t_enum = TacticEnum(tactic_str.strip().upper())
                description = item.update.description if item.update.description is not None else existing.get("description")
                platforms = item.update.platforms if item.update.platforms is not None else existing.get("platforms")
                detection = item.update.detection if item.update.detection is not None else existing.get("detection")
                mitigations = item.update.mitigations if item.update.mitigations is not None else existing.get("mitigations")
                references = item.update.references if item.update.references is not None else existing.get("references")

                mitre_tech = build_mitre_technique(
                    mitre_id=existing.get("mitreId"),
                    name=name,
                    tactic=t_enum,
                    created_at=existing.get("createdAt"),
                    description=description,
                    platforms=platforms,
                    detection=detection,
                    mitigations=mitigations,
                    references=references,
                )

                severity = item.update.severity if item.update.severity is not None else existing.get("severity")
                dataSource = item.update.dataSource if item.update.dataSource is not None else existing.get("dataSource")
                revoked = item.update.revoked if item.update.revoked is not None else existing.get("revoked")
                deprecated = item.update.deprecated if item.update.deprecated is not None else existing.get("deprecated")

                _TECHNIQUE_STORE[tech_id] = {
                    "techniqueId": tech_id,
                    "techniqueKey": mitre_tech.techniqueKey,
                    "mitreId": mitre_tech.mitreId,
                    "name": mitre_tech.name,
                    "tactic": mitre_tech.tactic.value,
                    "description": mitre_tech.description,
                    "platforms": list(mitre_tech.platforms),
                    "detection": mitre_tech.detection,
                    "mitigations": list(mitre_tech.mitigations),
                    "references": list(mitre_tech.references),
                    "createdAt": mitre_tech.createdAt,
                    "severity": severity,
                    "dataSource": dataSource,
                    "revoked": bool(revoked),
                    "deprecated": bool(deprecated),
                    "tacticCount": 1,
                }
                succeeded.append(tech_id)
            except Exception as e:
                failed.append({"id": tech_id, "reason": str(e)})

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


@mitre_router.delete(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete techniques",
)
def bulk_delete_techniques(
    request: BulkDeleteTechniquesRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for tech_id in request.techniqueIds:
            if tech_id not in _TECHNIQUE_STORE:
                failed.append({"id": tech_id, "reason": f"Technique '{tech_id}' not found."})
                continue
            try:
                del _TECHNIQUE_STORE[tech_id]
                succeeded.append(tech_id)
            except Exception as e:
                failed.append({"id": tech_id, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.techniqueIds),
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
