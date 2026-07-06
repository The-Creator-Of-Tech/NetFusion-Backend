"""
Playbook API Router — Phase A4.10.1
===================================
REST interface for Playbook workflows.

Prefix  : /playbooks
Tag     : Playbooks
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
from api.workflow.playbook_models import (
    CreatePlaybookRequest,
    UpdatePlaybookRequest,
    PlaybookStepRequest,
    PlaybookStepResponse,
    PlaybookResponse,
    PlaybookListResponse,
    PlaybookStatisticsResponse,
    PlaybookSearchResponse,
    PlaybookSummaryResponse,
    BulkCreatePlaybooksRequest,
    BulkUpdatePlaybooksRequest,
    BulkDeletePlaybooksRequest,
    BulkOperationResult,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

playbook_router: APIRouter = APIRouter(
    prefix="/playbooks",
    tags=["Playbooks"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
# Dict[playbookId -> Playbook dict]
_PLAYBOOK_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _PLAYBOOK_STORE.clear()


def _all_playbooks() -> List[Dict[str, Any]]:
    """Return all playbooks ordered by name ASC."""
    return sorted(_PLAYBOOK_STORE.values(), key=lambda p: p.get("name", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_playbook(playbooks: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a playbook by playbookId, playbookKey, or name (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for p in playbooks:
        if p.get("playbookId", "").lower() == normalized:
            return p
        if p.get("playbookKey", "").lower() == normalized:
            return p
        if p.get("name", "").lower() == normalized:
            return p
    return None


def find_playbook_step(steps: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a step by stepId, stepKey, title, or stepNumber."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for s in steps:
        if s.get("stepId", "").lower() == normalized:
            return s
        if s.get("stepKey", "").lower() == normalized:
            return s
        if s.get("title", "").lower() == normalized:
            return s
        if str(s.get("stepNumber")) == normalized:
            return s
    return None


def search_playbooks(playbooks: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text, metadata, and step fields."""
    if not query or not query.strip():
        return list(playbooks)
    q = query.strip().lower()
    results = []
    for p in playbooks:
        if q in p.get("name", "").lower():
            results.append(p)
            continue
        if q in p.get("description", "").lower():
            results.append(p)
            continue
        if q in p.get("category", "").lower():
            results.append(p)
            continue
        if q in p.get("author", "").lower():
            results.append(p)
            continue
        if any(q in t.lower() for t in p.get("relatedThreatActors", [])):
            results.append(p)
            continue
        if any(q in c.lower() for c in p.get("relatedCampaigns", [])):
            results.append(p)
            continue
        if any(q in s.get("title", "").lower() or q in s.get("description", "").lower() for s in p.get("steps", [])):
            results.append(p)
            continue
    return results


def search_playbook_steps(steps: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across step fields."""
    if not query or not query.strip():
        return list(steps)
    q = query.strip().lower()
    results = []
    for s in steps:
        if q in s.get("title", "").lower():
            results.append(s)
            continue
        if q in s.get("description", "").lower():
            results.append(s)
            continue
        if q in s.get("expectedOutcome", "").lower():
            results.append(s)
            continue
        if q in s.get("stepType", "").lower():
            results.append(s)
            continue
    return results


def sort_playbooks(
    playbooks: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts playbooks deterministically, falling back to playbookId ASC."""
    valid_fields = {"playbookName", "createdAt", "updatedAt", "stepCount", "priority", "enabled"}
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

    def get_sort_key(p: Dict[str, Any]) -> Any:
        if sort_by == "playbookName":
            return p.get("name", "")
        elif sort_by == "createdAt":
            return p.get("createdAt", "")
        elif sort_by == "updatedAt":
            return p.get("updatedAt", "") or ""
        elif sort_by == "stepCount":
            return len(p.get("steps", []))
        elif sort_by == "priority":
            return p.get("priority", 1)
        elif sort_by == "enabled":
            return int(p.get("enabled", True))
        return ""

    reverse = (order == "desc")
    # Stable sort
    sorted_list = sorted(playbooks, key=lambda x: x.get("playbookId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_playbooks(
    playbooks: List[Dict[str, Any]],
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
    category: Optional[str] = None,
    author: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumSteps: Optional[int] = None,
    maximumSteps: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filters playbook records."""
    filtered = list(playbooks)

    if enabled is not None:
        filtered = [p for p in filtered if bool(p.get("enabled", True)) == enabled]

    if priority is not None:
        filtered = [p for p in filtered if p.get("priority") == priority]

    if category is not None:
        cat_val = category.strip().lower()
        filtered = [p for p in filtered if p.get("category", "").lower() == cat_val]

    if author is not None:
        auth_val = author.strip().lower()
        filtered = [p for p in filtered if auth_val in p.get("author", "").lower()]

    if projectId is not None:
        proj_val = projectId.strip()
        filtered = [p for p in filtered if p.get("projectId") == proj_val]

    if investigationId is not None:
        inv_val = investigationId.strip()
        filtered = [p for p in filtered if p.get("investigationId") == inv_val]

    if minimumSteps is not None:
        filtered = [p for p in filtered if len(p.get("steps", [])) >= minimumSteps]

    if maximumSteps is not None:
        filtered = [p for p in filtered if len(p.get("steps", [])) <= maximumSteps]

    if createdAfter is not None:
        after_val = createdAfter.strip()
        filtered = [p for p in filtered if p.get("createdAt", "") >= after_val]

    if createdBefore is not None:
        before_val = createdBefore.strip()
        filtered = [p for p in filtered if p.get("createdAt", "") <= before_val]

    return filtered


def paginate_playbooks(
    playbooks: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Paginates the playbook list."""
    total_items = len(playbooks)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = playbooks[start:end]
    return sliced, total_items


def build_playbook_summary(playbook: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a structured playbook summary."""
    name = playbook.get("name", "")
    steps_cnt = len(playbook.get("steps", []))
    sev = playbook.get("severity", "")
    status = playbook.get("status", "")
    enabled = playbook.get("enabled", True)
    priority = playbook.get("priority", 1)

    text = (
        f"Playbook '{name}' ({status}) has {steps_cnt} steps under severity {sev}. "
        f"It has priority {priority} and is currently {'enabled' if enabled else 'disabled'}."
    )
    return {
        "playbookId": playbook.get("playbookId", ""),
        "playbookName": name,
        "summaryText": text,
        "stepCount": steps_cnt,
        "severity": sev,
        "status": status,
        "enabled": enabled,
        "priority": priority,
    }


def calculate_playbook_statistics(playbooks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates aggregate statistics over playbooks."""
    total = len(playbooks)
    enabled = sum(1 for p in playbooks if p.get("enabled", True))
    disabled = total - enabled

    total_steps = sum(len(p.get("steps", [])) for p in playbooks)
    avg_steps = round(total_steps / total, 4) if total > 0 else 0.0

    total_priority = sum(p.get("priority", 1) for p in playbooks)
    avg_priority = round(total_priority / total, 4) if total > 0 else 0.0

    category_counts: Dict[str, int] = {}
    for p in playbooks:
        cat = p.get("category", "").strip()
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "totalPlaybooks": total,
        "enabledPlaybooks": enabled,
        "disabledPlaybooks": disabled,
        "averageSteps": avg_steps,
        "averagePriority": avg_priority,
        "categoryCounts": dict(sorted(category_counts.items())),
    }


def _to_store_dict(pb: Any, original_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert Playbook core object to dictionary store format."""
    steps_list = []
    for s in pb.steps:
        steps_list.append({
            "stepId": s.stepId,
            "stepKey": s.stepKey,
            "stepNumber": s.stepNumber,
            "title": s.title,
            "description": s.description,
            "stepType": s.stepType.value,
            "expectedOutcome": s.expectedOutcome,
            "relatedTechniques": list(s.relatedTechniques),
            "relatedCVEs": list(s.relatedCVEs),
            "relatedIOCs": list(s.relatedIOCs),
            "createdAt": s.createdAt,
        })

    return {
        "playbookId": pb.playbookId,
        "playbookKey": pb.playbookKey,
        "name": pb.name,
        "description": pb.description,
        "severity": pb.severity.value,
        "status": pb.status.value,
        "steps": steps_list,
        "relatedThreatActors": list(pb.relatedThreatActors),
        "relatedCampaigns": list(pb.relatedCampaigns),
        "confidence": pb.confidence,
        "createdAt": pb.createdAt,
        "updatedAt": original_dict.get("updatedAt"),
        "enabled": original_dict.get("enabled", True),
        "priority": original_dict.get("priority", 1),
        "category": original_dict.get("category", ""),
        "author": original_dict.get("author", ""),
        "projectId": original_dict.get("projectId", ""),
        "investigationId": original_dict.get("investigationId", ""),
    }


def _to_response_model(c: Dict[str, Any]) -> PlaybookResponse:
    """Helper to convert stored dictionary to PlaybookResponse model."""
    steps_resp = [
        PlaybookStepResponse(
            stepId=s["stepId"],
            stepKey=s["stepKey"],
            stepNumber=s["stepNumber"],
            title=s["title"],
            description=s["description"],
            stepType=s["stepType"],
            expectedOutcome=s["expectedOutcome"],
            relatedTechniques=list(s["relatedTechniques"]),
            relatedCVEs=list(s["relatedCVEs"]),
            relatedIOCs=list(s["relatedIOCs"]),
            createdAt=s["createdAt"],
        )
        for s in c.get("steps", [])
    ]

    return PlaybookResponse(
        playbookId=c["playbookId"],
        playbookKey=c["playbookKey"],
        name=c["name"],
        description=c["description"],
        severity=c["severity"],
        status=c["status"],
        steps=steps_resp,
        relatedThreatActors=list(c["relatedThreatActors"]),
        relatedCampaigns=list(c["relatedCampaigns"]),
        confidence=c["confidence"],
        createdAt=c["createdAt"],
        updatedAt=c.get("updatedAt"),
        enabled=c["enabled"],
        priority=c["priority"],
        category=c["category"],
        author=c["author"],
        projectId=c["projectId"],
        investigationId=c["investigationId"],
    )


# ---------------------------------------------------------------------------
# Step operations implementing immutable reconstruction
# ---------------------------------------------------------------------------

def _dict_to_playbook_object(d: Dict[str, Any]) -> Any:
    from services.playbook_service import Playbook, PlaybookStep, PlaybookStepTypeEnum, PlaybookSeverityEnum, PlaybookStatusEnum
    steps_objs = []
    for s in d.get("steps", []):
        steps_objs.append(
            PlaybookStep(
                stepId=s["stepId"],
                stepKey=s["stepKey"],
                stepNumber=s["stepNumber"],
                title=s["title"],
                description=s["description"],
                stepType=PlaybookStepTypeEnum(s["stepType"]),
                expectedOutcome=s["expectedOutcome"],
                relatedTechniques=tuple(s["relatedTechniques"]),
                relatedCVEs=tuple(s["relatedCVEs"]),
                relatedIOCs=tuple(s["relatedIOCs"]),
                createdAt=s["createdAt"],
            )
        )
    return Playbook(
        playbookId=d["playbookId"],
        playbookKey=d["playbookKey"],
        name=d["name"],
        description=d["description"],
        severity=PlaybookSeverityEnum(d["severity"]),
        status=PlaybookStatusEnum(d["status"]),
        steps=tuple(steps_objs),
        relatedThreatActors=tuple(d["relatedThreatActors"]),
        relatedCampaigns=tuple(d["relatedCampaigns"]),
        confidence=d["confidence"],
        createdAt=d["createdAt"],
    )

def append_playbook_step(playbook: Dict[str, Any], step_req: PlaybookStepRequest) -> Dict[str, Any]:
    """Appends step by rebuilding the immutable Playbook object using core service."""
    from services.playbook_service import build_playbook_step, PlaybookStepTypeEnum, add_playbook_step

    pb_obj = _dict_to_playbook_object(playbook)
    st = PlaybookStepTypeEnum(step_req.stepType.strip().upper())
    new_step = build_playbook_step(
        pb_obj.playbookId,
        step_number=step_req.stepNumber,
        title=step_req.title,
        step_type=st,
        created_at=step_req.createdAt,
        description=step_req.description,
        expected_outcome=step_req.expectedOutcome,
        related_techniques=step_req.relatedTechniques,
        related_cves=step_req.relatedCVEs,
        related_iocs=step_req.relatedIOCs,
    )
    new_pb = add_playbook_step(pb_obj, new_step)
    return _to_store_dict(new_pb, playbook)


def update_playbook_step(playbook: Dict[str, Any], step_id: str, step_req: PlaybookStepRequest) -> Dict[str, Any]:
    """Updates step by rebuilding the immutable Playbook object using core service."""
    from services.playbook_service import update_playbook_step as service_update_step, PlaybookStepTypeEnum

    pb_obj = _dict_to_playbook_object(playbook)
    st = PlaybookStepTypeEnum(step_req.stepType.strip().upper())
    new_pb = service_update_step(
        pb_obj,
        step_id,
        title=step_req.title,
        description=step_req.description,
        step_type=st,
        expected_outcome=step_req.expectedOutcome,
        related_techniques=step_req.relatedTechniques,
        related_cves=step_req.relatedCVEs,
        related_iocs=step_req.relatedIOCs,
    )
    if new_pb.playbookId == pb_obj.playbookId and len(new_pb.steps) == len(pb_obj.steps):
        if not any(s.stepId == step_id for s in pb_obj.steps):
            raise APIErrorNotFound(f"Step with ID '{step_id}' not found.")
    return _to_store_dict(new_pb, playbook)


def delete_playbook_step(playbook: Dict[str, Any], step_id: str) -> Dict[str, Any]:
    """Deletes step by rebuilding the immutable Playbook object using core service."""
    from services.playbook_service import remove_playbook_step

    pb_obj = _dict_to_playbook_object(playbook)
    if not any(s.stepId == step_id for s in pb_obj.steps):
        raise APIErrorNotFound(f"Step with ID '{step_id}' not found.")
    new_pb = remove_playbook_step(pb_obj, step_id)
    return _to_store_dict(new_pb, playbook)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@playbook_router.get(
    "/",
    response_model=APIResponse,
    summary="List playbook records",
)
def list_playbooks_endpoint(
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
    category: Optional[str] = None,
    author: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumSteps: Optional[int] = None,
    maximumSteps: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
    sortBy: str = "playbookName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_playbooks_list = _all_playbooks()

        filtered = filter_playbooks(
            all_playbooks_list,
            enabled=enabled,
            priority=priority,
            category=category,
            author=author,
            projectId=projectId,
            investigationId=investigationId,
            minimumSteps=minimumSteps,
            maximumSteps=maximumSteps,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_pbs = sort_playbooks(filtered, sortBy, sortOrder)
        paginated, total = paginate_playbooks(sorted_pbs, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]

        return build_paginated_response(
            items=[r.model_dump() for r in responses],
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Playbooks listed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get playbook statistics",
)
def get_statistics() -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        stats = calculate_playbook_statistics(all_playbooks_list)
        return build_success_response(
            data=stats,
            message="Statistics retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search playbook records",
)
def search_playbook_records(
    query: str = "",
    sortBy: str = "playbookName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_playbooks_list = _all_playbooks()
        searched = search_playbooks(all_playbooks_list, query)
        sorted_pbs = sort_playbooks(searched, sortBy, sortOrder)
        paginated, total = paginate_playbooks(sorted_pbs, page, pageSize)
        responses = [_to_response_model(c) for c in paginated]
        total_pages = math.ceil(total / pageSize) if total > 0 else 0

        search_data = PlaybookSearchResponse(
            playbooks=responses,
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


@playbook_router.get(
    "/{playbookId}",
    response_model=APIResponse,
    summary="Get playbook by ID",
)
def get_playbook(playbookId: str) -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="Playbook retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a playbook record",
)
def create_playbook(
    request: CreatePlaybookRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.playbook_service import (
            build_playbook_step,
            build_playbook,
            PlaybookStepTypeEnum,
            PlaybookSeverityEnum,
            PlaybookStatusEnum,
        )

        # Build PlaybookSteps
        steps_built = []
        for s in (request.steps or []):
            st = PlaybookStepTypeEnum(s.stepType.strip().upper())
            steps_built.append(
                build_playbook_step(
                    request.name,
                    step_number=s.stepNumber,
                    title=s.title,
                    step_type=st,
                    created_at=s.createdAt,
                    description=s.description,
                    expected_outcome=s.expectedOutcome,
                    related_techniques=s.relatedTechniques,
                    related_cves=s.relatedCVEs,
                    related_iocs=s.relatedIOCs,
                )
            )

        try:
            sev_enum = PlaybookSeverityEnum(request.severity.strip().upper())
            stat_enum = PlaybookStatusEnum(request.status.strip().upper())
            pb = build_playbook(
                name=request.name,
                severity=sev_enum,
                status=stat_enum,
                steps=steps_built,
                created_at=request.createdAt,
                description=request.description or "",
                related_threat_actors=request.relatedThreatActors,
                related_campaigns=request.relatedCampaigns,
                confidence=request.confidence,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = pb.playbookId
        if rec_id in _PLAYBOOK_STORE:
            raise APIErrorConflict(f"Playbook with ID '{rec_id}' (name '{request.name}') already exists.")

        # Reconvert steps for dict representation
        steps_list = []
        for s in pb.steps:
            steps_list.append({
                "stepId": s.stepId,
                "stepKey": s.stepKey,
                "stepNumber": s.stepNumber,
                "title": s.title,
                "description": s.description,
                "stepType": s.stepType.value,
                "expectedOutcome": s.expectedOutcome,
                "relatedTechniques": list(s.relatedTechniques),
                "relatedCVEs": list(s.relatedCVEs),
                "relatedIOCs": list(s.relatedIOCs),
                "createdAt": s.createdAt,
            })

        _PLAYBOOK_STORE[rec_id] = {
            "playbookId": rec_id,
            "playbookKey": pb.playbookKey,
            "name": pb.name,
            "description": pb.description,
            "severity": pb.severity.value,
            "status": pb.status.value,
            "steps": steps_list,
            "relatedThreatActors": list(pb.relatedThreatActors),
            "relatedCampaigns": list(pb.relatedCampaigns),
            "confidence": pb.confidence,
            "createdAt": pb.createdAt,
            "updatedAt": request.updatedAt,
            "enabled": bool(request.enabled),
            "priority": int(request.priority),
            "category": request.category or "",
            "author": request.author or "",
            "projectId": request.projectId or "",
            "investigationId": request.investigationId or "",
        }

        return build_success_response(
            data=_to_response_model(_PLAYBOOK_STORE[rec_id]).model_dump(),
            message="Playbook created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.put(
    "/{playbookId}",
    response_model=APIResponse,
    summary="Update a playbook record",
)
def update_playbook(
    playbookId: str,
    request: UpdatePlaybookRequest = Body(...)
) -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        rec_id = c["playbookId"]

        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")

        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.playbook_service import (
            build_playbook_step,
            build_playbook,
            PlaybookStepTypeEnum,
            PlaybookSeverityEnum,
            PlaybookStatusEnum,
        )

        name = request.name if request.name is not None else c.get("name")
        description = request.description if request.description is not None else c.get("description")
        severity_str = request.severity if request.severity is not None else c.get("severity")
        status_str = request.status if request.status is not None else c.get("status")
        related_threat_actors = request.relatedThreatActors if request.relatedThreatActors is not None else c.get("relatedThreatActors")
        related_campaigns = request.relatedCampaigns if request.relatedCampaigns is not None else c.get("relatedCampaigns")
        confidence = request.confidence if request.confidence is not None else c.get("confidence")

        # Handle steps
        if request.steps is not None:
            steps_built = []
            for s in request.steps:
                st = PlaybookStepTypeEnum(s.stepType.strip().upper())
                steps_built.append(
                    build_playbook_step(
                        name,
                        step_number=s.stepNumber,
                        title=s.title,
                        step_type=st,
                        created_at=s.createdAt,
                        description=s.description,
                        expected_outcome=s.expectedOutcome,
                        related_techniques=s.relatedTechniques,
                        related_cves=s.relatedCVEs,
                        related_iocs=s.relatedIOCs,
                    )
                )
        else:
            steps_built = []
            for s in c.get("steps", []):
                steps_built.append(
                    build_playbook_step(
                        rec_id,
                        step_number=s.get("stepNumber"),
                        title=s.get("title"),
                        step_type=PlaybookStepTypeEnum(s.get("stepType").strip().upper()),
                        created_at=s.get("createdAt"),
                        description=s.get("description"),
                        expected_outcome=s.get("expectedOutcome"),
                        related_techniques=s.get("relatedTechniques"),
                        related_cves=s.get("relatedCVEs"),
                        related_iocs=s.get("relatedIOCs"),
                    )
                )

        try:
            sev_enum = PlaybookSeverityEnum(severity_str.strip().upper())
            stat_enum = PlaybookStatusEnum(status_str.strip().upper())
            pb = build_playbook(
                name=name,
                severity=sev_enum,
                status=stat_enum,
                steps=steps_built,
                created_at=c.get("createdAt"),
                description=description,
                related_threat_actors=related_threat_actors,
                related_campaigns=related_campaigns,
                confidence=confidence,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        enabled = request.enabled if request.enabled is not None else c.get("enabled")
        priority = request.priority if request.priority is not None else c.get("priority")
        category = request.category if request.category is not None else c.get("category")
        author = request.author if request.author is not None else c.get("author")
        projectId = request.projectId if request.projectId is not None else c.get("projectId")
        investigationId = request.investigationId if request.investigationId is not None else c.get("investigationId")
        updatedAt = request.updatedAt if request.updatedAt is not None else c.get("updatedAt")

        # Reconvert steps
        steps_list = []
        for s in pb.steps:
            steps_list.append({
                "stepId": s.stepId,
                "stepKey": s.stepKey,
                "stepNumber": s.stepNumber,
                "title": s.title,
                "description": s.description,
                "stepType": s.stepType.value,
                "expectedOutcome": s.expectedOutcome,
                "relatedTechniques": list(s.relatedTechniques),
                "relatedCVEs": list(s.relatedCVEs),
                "relatedIOCs": list(s.relatedIOCs),
                "createdAt": s.createdAt,
            })

        _PLAYBOOK_STORE[rec_id] = {
            "playbookId": rec_id,
            "playbookKey": pb.playbookKey,
            "name": pb.name,
            "description": pb.description,
            "severity": pb.severity.value,
            "status": pb.status.value,
            "steps": steps_list,
            "relatedThreatActors": list(pb.relatedThreatActors),
            "relatedCampaigns": list(pb.relatedCampaigns),
            "confidence": pb.confidence,
            "createdAt": pb.createdAt,
            "updatedAt": updatedAt,
            "enabled": bool(enabled),
            "priority": int(priority),
            "category": category or "",
            "author": author or "",
            "projectId": projectId or "",
            "investigationId": investigationId or "",
        }

        return build_success_response(
            data=_to_response_model(_PLAYBOOK_STORE[rec_id]).model_dump(),
            message="Playbook updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.delete(
    "/{playbookId}",
    response_model=APIResponse,
    summary="Delete a playbook record",
)
def delete_playbook(playbookId: str) -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        rec_id = c["playbookId"]
        del _PLAYBOOK_STORE[rec_id]

        return build_success_response(
            data=None,
            message="Playbook deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get(
    "/{playbookId}/steps",
    response_model=APIResponse,
    summary="Get steps of a playbook",
)
def get_playbook_steps(playbookId: str) -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        steps_resp = [
            PlaybookStepResponse(
                stepId=s["stepId"],
                stepKey=s["stepKey"],
                stepNumber=s["stepNumber"],
                title=s["title"],
                description=s["description"],
                stepType=s["stepType"],
                expectedOutcome=s["expectedOutcome"],
                relatedTechniques=list(s["relatedTechniques"]),
                relatedCVEs=list(s["relatedCVEs"]),
                relatedIOCs=list(s["relatedIOCs"]),
                createdAt=s["createdAt"],
            )
            for s in c.get("steps", [])
        ]

        return build_success_response(
            data=[x.model_dump() for x in steps_resp],
            message="Playbook steps retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.post(
    "/{playbookId}/steps",
    response_model=APIResponse,
    summary="Append a step to a playbook",
)
def append_step(
    playbookId: str,
    request: PlaybookStepRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        # Check stepNumber conflict
        for s in c.get("steps", []):
            if s.get("stepNumber") == request.stepNumber:
                # Resolve by shifting/incrementing downstream or yielding conflict? Let's rebuild which shifts!
                # Actually, our append helper shifts conflicting numbers, so it's transparent.
                pass

        updated_playbook = append_playbook_step(c, request)
        old_id = c["playbookId"]
        new_id = updated_playbook["playbookId"]
        if old_id in _PLAYBOOK_STORE:
            del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[new_id] = updated_playbook

        return build_success_response(
            data=_to_response_model(updated_playbook).model_dump(),
            message="Playbook step appended successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.put(
    "/{playbookId}/steps/{stepId}",
    response_model=APIResponse,
    summary="Update a playbook step",
)
def update_step(
    playbookId: str,
    stepId: str,
    request: PlaybookStepRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        updated_playbook = update_playbook_step(c, stepId, request)
        old_id = c["playbookId"]
        new_id = updated_playbook["playbookId"]
        if old_id in _PLAYBOOK_STORE:
            del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[new_id] = updated_playbook

        return build_success_response(
            data=_to_response_model(updated_playbook).model_dump(),
            message="Playbook step updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.delete(
    "/{playbookId}/steps/{stepId}",
    response_model=APIResponse,
    summary="Delete a playbook step",
)
def delete_step(
    playbookId: str,
    stepId: str
) -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        updated_playbook = delete_playbook_step(c, stepId)
        old_id = c["playbookId"]
        new_id = updated_playbook["playbookId"]
        if old_id in _PLAYBOOK_STORE:
            del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[new_id] = updated_playbook

        return build_success_response(
            data=_to_response_model(updated_playbook).model_dump(),
            message="Playbook step deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get(
    "/{playbookId}/summary",
    response_model=APIResponse,
    summary="Get summary of a playbook",
)
def get_playbook_summary(playbookId: str) -> APIResponse:
    try:
        all_playbooks_list = _all_playbooks()
        c = find_playbook(all_playbooks_list, playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        summary = build_playbook_summary(c)
        return build_success_response(
            data=summary,
            message="Playbook summary built successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create playbook records",
)
def bulk_create_playbooks(
    request: BulkCreatePlaybooksRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.playbook_service import (
            build_playbook_step,
            build_playbook,
            PlaybookStepTypeEnum,
            PlaybookSeverityEnum,
            PlaybookStatusEnum,
        )

        for item in request.playbooks:
            try:
                # Build steps
                steps_built = []
                for s in (item.steps or []):
                    st = PlaybookStepTypeEnum(s.stepType.strip().upper())
                    steps_built.append(
                        build_playbook_step(
                            item.name,
                            step_number=s.stepNumber,
                            title=s.title,
                            step_type=st,
                            created_at=s.createdAt,
                            description=s.description,
                            expected_outcome=s.expectedOutcome,
                            related_techniques=s.relatedTechniques,
                            related_cves=s.relatedCVEs,
                            related_iocs=s.relatedIOCs,
                        )
                    )

                sev_enum = PlaybookSeverityEnum(item.severity.strip().upper())
                stat_enum = PlaybookStatusEnum(item.status.strip().upper())
                pb = build_playbook(
                    name=item.name,
                    severity=sev_enum,
                    status=stat_enum,
                    steps=steps_built,
                    created_at=item.createdAt,
                    description=item.description or "",
                    related_threat_actors=item.relatedThreatActors,
                    related_campaigns=item.relatedCampaigns,
                    confidence=item.confidence,
                )

                rec_id = pb.playbookId
                if rec_id in _PLAYBOOK_STORE or rec_id in succeeded:
                    failed.append({"id": item.name, "reason": f"Playbook with ID '{rec_id}' already exists."})
                    continue

                steps_list = []
                for s in pb.steps:
                    steps_list.append({
                        "stepId": s.stepId,
                        "stepKey": s.stepKey,
                        "stepNumber": s.stepNumber,
                        "title": s.title,
                        "description": s.description,
                        "stepType": s.stepType.value,
                        "expectedOutcome": s.expectedOutcome,
                        "relatedTechniques": list(s.relatedTechniques),
                        "relatedCVEs": list(s.relatedCVEs),
                        "relatedIOCs": list(s.relatedIOCs),
                        "createdAt": s.createdAt,
                    })

                _PLAYBOOK_STORE[rec_id] = {
                    "playbookId": rec_id,
                    "playbookKey": pb.playbookKey,
                    "name": pb.name,
                    "description": pb.description,
                    "severity": pb.severity.value,
                    "status": pb.status.value,
                    "steps": steps_list,
                    "relatedThreatActors": list(pb.relatedThreatActors),
                    "relatedCampaigns": list(pb.relatedCampaigns),
                    "confidence": pb.confidence,
                    "createdAt": pb.createdAt,
                    "updatedAt": item.updatedAt,
                    "enabled": bool(item.enabled),
                    "priority": int(item.priority),
                    "category": item.category or "",
                    "author": item.author or "",
                    "projectId": item.projectId or "",
                    "investigationId": item.investigationId or "",
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.name, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.playbooks),
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


@playbook_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update playbook records",
)
def bulk_update_playbooks(
    request: BulkUpdatePlaybooksRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.playbook_service import (
            build_playbook_step,
            build_playbook,
            PlaybookStepTypeEnum,
            PlaybookSeverityEnum,
            PlaybookStatusEnum,
        )

        for item in request.items:
            rec_id = None
            all_playbooks_list = _all_playbooks()
            existing = find_playbook(all_playbooks_list, item.playbookId)
            if existing:
                rec_id = existing["playbookId"]

            if not rec_id:
                failed.append({"id": item.playbookId, "reason": f"Playbook '{item.playbookId}' not found."})
                continue

            try:
                name = item.update.name if item.update.name is not None else existing.get("name")
                description = item.update.description if item.update.description is not None else existing.get("description")
                severity_str = item.update.severity if item.update.severity is not None else existing.get("severity")
                status_str = item.update.status if item.update.status is not None else existing.get("status")
                related_threat_actors = item.update.relatedThreatActors if item.update.relatedThreatActors is not None else existing.get("relatedThreatActors")
                related_campaigns = item.update.relatedCampaigns if item.update.relatedCampaigns is not None else existing.get("relatedCampaigns")
                confidence = item.update.confidence if item.update.confidence is not None else existing.get("confidence")

                # Handle steps
                if item.update.steps is not None:
                    steps_built = []
                    for s in item.update.steps:
                        st = PlaybookStepTypeEnum(s.stepType.strip().upper())
                        steps_built.append(
                            build_playbook_step(
                                name,
                                step_number=s.stepNumber,
                                title=s.title,
                                step_type=st,
                                created_at=s.createdAt,
                                description=s.description,
                                expected_outcome=s.expectedOutcome,
                                related_techniques=s.relatedTechniques,
                                related_cves=s.relatedCVEs,
                                related_iocs=s.relatedIOCs,
                            )
                        )
                else:
                    steps_built = []
                    for s in existing.get("steps", []):
                        steps_built.append(
                            build_playbook_step(
                                rec_id,
                                step_number=s.get("stepNumber"),
                                title=s.get("title"),
                                step_type=PlaybookStepTypeEnum(s.get("stepType").strip().upper()),
                                created_at=s.get("createdAt"),
                                description=s.get("description"),
                                expected_outcome=s.get("expectedOutcome"),
                                related_techniques=s.get("relatedTechniques"),
                                related_cves=s.get("relatedCVEs"),
                                related_iocs=s.get("relatedIOCs"),
                            )
                        )

                sev_enum = PlaybookSeverityEnum(severity_str.strip().upper())
                stat_enum = PlaybookStatusEnum(status_str.strip().upper())
                pb = build_playbook(
                    name=name,
                    severity=sev_enum,
                    status=stat_enum,
                    steps=steps_built,
                    created_at=existing.get("createdAt"),
                    description=description,
                    related_threat_actors=related_threat_actors,
                    related_campaigns=related_campaigns,
                    confidence=confidence,
                )

                enabled = item.update.enabled if item.update.enabled is not None else existing.get("enabled")
                priority = item.update.priority if item.update.priority is not None else existing.get("priority")
                category = item.update.category if item.update.category is not None else existing.get("category")
                author = item.update.author if item.update.author is not None else existing.get("author")
                projectId = item.update.projectId if item.update.projectId is not None else existing.get("projectId")
                investigationId = item.update.investigationId if item.update.investigationId is not None else existing.get("investigationId")
                updatedAt = item.update.updatedAt if item.update.updatedAt is not None else existing.get("updatedAt")

                # Reconvert steps
                steps_list = []
                for s in pb.steps:
                    steps_list.append({
                        "stepId": s.stepId,
                        "stepKey": s.stepKey,
                        "stepNumber": s.stepNumber,
                        "title": s.title,
                        "description": s.description,
                        "stepType": s.stepType.value,
                        "expectedOutcome": s.expectedOutcome,
                        "relatedTechniques": list(s.relatedTechniques),
                        "relatedCVEs": list(s.relatedCVEs),
                        "relatedIOCs": list(s.relatedIOCs),
                        "createdAt": s.createdAt,
                    })

                _PLAYBOOK_STORE[rec_id] = {
                    "playbookId": rec_id,
                    "playbookKey": pb.playbookKey,
                    "name": pb.name,
                    "description": pb.description,
                    "severity": pb.severity.value,
                    "status": pb.status.value,
                    "steps": steps_list,
                    "relatedThreatActors": list(pb.relatedThreatActors),
                    "relatedCampaigns": list(pb.relatedCampaigns),
                    "confidence": pb.confidence,
                    "createdAt": pb.createdAt,
                    "updatedAt": updatedAt,
                    "enabled": bool(enabled),
                    "priority": int(priority),
                    "category": category or "",
                    "author": author or "",
                    "projectId": projectId or "",
                    "investigationId": investigationId or "",
                }
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.playbookId, "reason": str(e)})

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


@playbook_router.delete(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete playbook records",
)
def bulk_delete_playbooks(
    request: BulkDeletePlaybooksRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        all_playbooks_list = _all_playbooks()
        for pb_id in request.playbookIds:
            existing = find_playbook(all_playbooks_list, pb_id)
            if not existing:
                failed.append({"id": pb_id, "reason": f"Playbook '{pb_id}' not found."})
                continue

            try:
                rec_id = existing["playbookId"]
                del _PLAYBOOK_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": pb_id, "reason": str(e)})

        result = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.playbookIds),
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
