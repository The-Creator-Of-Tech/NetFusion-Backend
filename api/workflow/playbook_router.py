"""
Playbook API Router — Canonical Schema
=======================================
All normalization uses normalizers.normalize_playbook().
All response models use the canonical PlaybookResponse aligned with Prisma.
"""
from __future__ import annotations
import math, uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body
from api.errors import (
    APILayerError, APIErrorConflict, APIErrorInternal,
    APIErrorNotFound, APIErrorValidation,
)
from api.models import APIResponse
from api.responses import build_success_response, build_paginated_response
from api.utils import exception_to_api_response, validate_pagination
from api.workflow.playbook_models import (
    CreatePlaybookRequest, UpdatePlaybookRequest,
    PlaybookStepRequest, PlaybookStepResponse, PlaybookResponse,
    PlaybookStatisticsResponse, PlaybookSearchResponse, PlaybookSummaryResponse,
    BulkCreatePlaybooksRequest, BulkUpdatePlaybooksRequest,
    BulkDeletePlaybooksRequest, BulkOperationResult,
)
from api.workflow.normalizers import normalize_playbook
from api.persistence import RepositoryBackedDict, WorkflowExecutionsStore, map_playbook

playbook_router = APIRouter(prefix="/playbooks", tags=["Playbooks"])
_PLAYBOOK_STORE = RepositoryBackedDict("playbook", "playbookId", map_playbook)
_EXECUTION_STORE = WorkflowExecutionsStore()

_PLAYBOOK_NS = uuid.UUID("6ba7b880-9dad-11d1-80b4-00c04fd430c8")


def _reset_store() -> None:
    _PLAYBOOK_STORE.clear()


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _to_response(raw: Dict[str, Any]) -> PlaybookResponse:
    c = normalize_playbook(raw)
    steps = [
        PlaybookStepResponse(
            stepId=s["stepId"], stepKey=s["stepKey"],
            stepNumber=s["stepNumber"], title=s["title"],
            description=s["description"], stepType=s["stepType"],
            expectedOutcome=s["expectedOutcome"],
            relatedTechniques=s["relatedTechniques"],
            relatedCVEs=s["relatedCVEs"], relatedIOCs=s["relatedIOCs"],
            createdAt=s["createdAt"],
        )
        for s in c["steps"]
    ]
    return PlaybookResponse(
        playbookId=c["playbookId"], playbookKey=c["playbookKey"],
        name=c["name"], description=c["description"],
        severity=c["severity"], status=c["status"],
        projectId=c["projectId"], investigationId=c["investigationId"],
        steps=steps,
        relatedThreatActors=c["relatedThreatActors"],
        relatedCampaigns=c["relatedCampaigns"],
        confidence=c["confidence"], createdAt=c["createdAt"],
        updatedAt=c["updatedAt"], enabled=c["enabled"],
        priority=c["priority"], category=c["category"], author=c["author"],
    )


def _all() -> List[Dict[str, Any]]:
    return sorted(
        [normalize_playbook(p) for p in _PLAYBOOK_STORE.values()],
        key=lambda p: p["name"],
    )


def _find(playbooks: List[Dict], ident: str) -> Optional[Dict]:
    n = ident.strip().lower()
    for p in playbooks:
        if p["playbookId"].lower() == n: return p
        if p["playbookKey"].lower() == n: return p
        if p["name"].lower() == n: return p
    return None


def _sort(items: List[Dict], sort_by: str, sort_order: str) -> List[Dict]:
    valid = {"playbookName", "createdAt", "updatedAt", "stepCount", "priority", "enabled"}
    if sort_by not in valid:
        raise APIErrorValidation("Invalid sort field.",
            details=[f"'{sort_by}' not supported. Valid: {sorted(valid)}"])
    if sort_order.lower() not in {"asc", "desc"}:
        raise APIErrorValidation("Invalid sort order.")

    def key(p):
        if sort_by == "playbookName": return p["name"]
        if sort_by == "stepCount":    return len(p["steps"])
        if sort_by == "enabled":      return int(p["enabled"])
        return p.get(sort_by, "") or ""

    base = sorted(items, key=lambda x: x["playbookId"])
    base.sort(key=key, reverse=(sort_order.lower() == "desc"))
    return base


def _normalise_dt(dt: str) -> str:
    """Strip sub-second precision so ISO-8601 comparisons are consistent.

    Stored dates arrive from the DB as ``"2026-07-06T12:00:00.000Z"``
    while filter parameters are typically ``"2026-07-06T12:00:00Z"``.
    Truncating at the seconds boundary makes string comparison reliable.
    """
    if not dt:
        return dt
    # Remove fractional seconds: "...00.000Z" → "...00Z"
    import re as _re
    return _re.sub(r"\.\d+Z$", "Z", dt.strip())


def _filter(items, enabled=None, priority=None, category=None,
             author=None, projectId=None, investigationId=None,
             minimumSteps=None, maximumSteps=None,
             createdAfter=None, createdBefore=None):
    r = list(items)
    if enabled         is not None: r = [p for p in r if bool(p["enabled"]) == enabled]
    if priority        is not None: r = [p for p in r if p["priority"] == priority]
    if category        is not None: r = [p for p in r if p["category"].lower() == category.strip().lower()]
    if author          is not None: r = [p for p in r if author.strip().lower() in p["author"].lower()]
    if projectId       is not None: r = [p for p in r if p["projectId"] == projectId.strip()]
    if investigationId is not None: r = [p for p in r if p["investigationId"] == investigationId.strip()]
    if minimumSteps    is not None: r = [p for p in r if len(p["steps"]) >= minimumSteps]
    if maximumSteps    is not None: r = [p for p in r if len(p["steps"]) <= maximumSteps]
    if createdAfter    is not None:
        _after = _normalise_dt(createdAfter)
        r = [p for p in r if _normalise_dt(p.get("createdAt", "")) >= _after]
    if createdBefore   is not None:
        _before = _normalise_dt(createdBefore)
        r = [p for p in r if _normalise_dt(p.get("createdAt", "")) <= _before]
    return r


def _paginate(items, page, page_size):
    total = len(items)
    start = (page - 1) * page_size
    return items[start:start + page_size], total


def _search(items: List[Dict], q: str) -> List[Dict]:
    if not q or not q.strip(): return list(items)
    ql = q.strip().lower()
    out = []
    for p in items:
        if (ql in p["name"].lower() or ql in p["description"].lower()
                or ql in p["category"].lower() or ql in p["author"].lower()
                or any(ql in a.lower() for a in p["relatedThreatActors"])
                or any(ql in c.lower() for c in p["relatedCampaigns"])
                or any(ql in s["title"].lower() for s in p["steps"])):
            out.append(p)
    return out


def _build_store_dict(pb_obj, req_dict: Dict) -> Dict:
    """Serialize a core Playbook object to store dict format."""
    steps_list = []
    for s in pb_obj.steps:
        steps_list.append({
            "stepId": s.stepId, "stepKey": s.stepKey,
            "stepNumber": s.stepNumber, "title": s.title,
            "description": s.description, "stepType": s.stepType.value,
            "expectedOutcome": s.expectedOutcome,
            "relatedTechniques": list(s.relatedTechniques),
            "relatedCVEs": list(s.relatedCVEs),
            "relatedIOCs": list(s.relatedIOCs),
            "createdAt": s.createdAt,
        })
    return {
        "playbookId":          pb_obj.playbookId,
        "playbookKey":         pb_obj.playbookKey,
        "name":                pb_obj.name,
        "description":         pb_obj.description,
        "severity":            pb_obj.severity.value,
        "status":              pb_obj.status.value,
        "steps":               steps_list,
        "relatedThreatActors": list(pb_obj.relatedThreatActors),
        "relatedCampaigns":    list(pb_obj.relatedCampaigns),
        "confidence":          pb_obj.confidence,
        "createdAt":           pb_obj.createdAt,
        "updatedAt":           req_dict.get("updatedAt"),
        "enabled":             bool(req_dict.get("enabled", True)),
        "priority":            int(req_dict.get("priority", 1)),
        "category":            req_dict.get("category", ""),
        "author":              req_dict.get("author", ""),
        "projectId":           req_dict.get("projectId", ""),
        "investigationId":     req_dict.get("investigationId") or "",
    }


def _stats(items: List[Dict]) -> Dict:
    total = len(items)
    enabled = sum(1 for p in items if p["enabled"])
    total_steps = sum(len(p["steps"]) for p in items)
    total_pri = sum(p["priority"] for p in items)
    cat: Dict[str, int] = {}
    for p in items:
        c = p["category"].strip()
        if c: cat[c] = cat.get(c, 0) + 1
    return {
        "totalPlaybooks":    total,
        "enabledPlaybooks":  enabled,
        "disabledPlaybooks": total - enabled,
        "averageSteps":      round(total_steps / total, 4) if total else 0.0,
        "averagePriority":   round(total_pri  / total, 4) if total else 0.0,
        "categoryCounts":    dict(sorted(cat.items())),
    }


def _summary(p: Dict) -> Dict:
    name = p["name"]; sev = p["severity"]; st = p["status"]
    cnt = len(p["steps"]); enabled = p["enabled"]; pri = p["priority"]
    return {
        "playbookId":   p["playbookId"],
        "playbookName": name,
        "summaryText":  (
            f"Playbook '{name}' ({st}) has {cnt} steps under severity {sev}. "
            f"Priority {pri}, {'enabled' if enabled else 'disabled'}."
        ),
        "stepCount": cnt, "severity": sev, "status": st,
        "enabled": enabled, "priority": pri,
    }


# ---------------------------------------------------------------------------
# Routes — List / Search / Statistics
# ---------------------------------------------------------------------------

@playbook_router.get("/", response_model=APIResponse, summary="List playbooks")
def list_playbooks(
    enabled: Optional[bool]=None, priority: Optional[int]=None,
    category: Optional[str]=None, author: Optional[str]=None,
    projectId: Optional[str]=None, investigationId: Optional[str]=None,
    minimumSteps: Optional[int]=None, maximumSteps: Optional[int]=None,
    createdAfter: Optional[str]=None, createdBefore: Optional[str]=None,
    sortBy: str="playbookName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _filter(_all(), enabled=enabled, priority=priority,
            category=category, author=author, projectId=projectId,
            investigationId=investigationId, minimumSteps=minimumSteps,
            maximumSteps=maximumSteps, createdAfter=createdAfter,
            createdBefore=createdBefore)
        items = _sort(items, sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        return build_paginated_response(
            items=[_to_response(x).model_dump() for x in page_items],
            page=page, page_size=pageSize, total_items=total,
            message="Playbooks listed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get("/statistics", response_model=APIResponse)
def get_statistics() -> APIResponse:
    try:
        return build_success_response(data=_stats(_all()),
            message="Statistics retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get("/search", response_model=APIResponse)
def search_playbooks(
    query: str="", sortBy: str="playbookName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _sort(_search(_all(), query), sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        total_pages = math.ceil(total / pageSize) if total else 1
        payload = PlaybookSearchResponse(
            playbooks=[_to_response(x) for x in page_items],
            total=total, page=page, pageSize=pageSize, totalPages=total_pages,
            query=query, sortBy=sortBy, sortOrder=sortOrder,
        )
        return build_success_response(data=payload.model_dump(),
            message="Search completed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Routes — CRUD
# ---------------------------------------------------------------------------

@playbook_router.get("/{playbookId}", response_model=APIResponse)
def get_playbook(playbookId: str) -> APIResponse:
    try:
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        return build_success_response(data=_to_response(c).model_dump(),
            message="Playbook retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.post("/", response_model=APIResponse)
def create_playbook(request: CreatePlaybookRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)

        from services.playbook_service import (
            build_playbook_step, build_playbook,
            PlaybookStepTypeEnum, PlaybookSeverityEnum, PlaybookStatusEnum,
        )
        steps_built = []
        for s in (request.steps or []):
            steps_built.append(build_playbook_step(
                request.name, step_number=s.stepNumber, title=s.title,
                step_type=PlaybookStepTypeEnum(s.stepType.strip().upper()),
                created_at=s.createdAt, description=s.description or "",
                expected_outcome=s.expectedOutcome or "",
                related_techniques=list(s.relatedTechniques or []),
                related_cves=list(s.relatedCVEs or []),
                related_iocs=list(s.relatedIOCs or []),
            ))

        pb = build_playbook(
            name=request.name,
            severity=PlaybookSeverityEnum(request.severity.strip().upper()),
            status=PlaybookStatusEnum(request.status.strip().upper()),
            steps=steps_built, created_at=request.createdAt,
            description=request.description or "",
            related_threat_actors=list(request.relatedThreatActors or []),
            related_campaigns=list(request.relatedCampaigns or []),
            confidence=request.confidence,
        )

        rec_id = pb.playbookId
        if rec_id in _PLAYBOOK_STORE:
            raise APIErrorConflict(f"Playbook '{rec_id}' already exists.")

        store_dict = _build_store_dict(pb, request.model_dump())
        _PLAYBOOK_STORE[rec_id] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Playbook created successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.put("/{playbookId}", response_model=APIResponse)
def update_playbook(playbookId: str, request: UpdatePlaybookRequest = Body(...)) -> APIResponse:
    try:
        if not request.has_any_field():
            raise APIErrorValidation("At least one update field must be provided.")
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)

        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        from services.playbook_service import (
            build_playbook_step, build_playbook,
            PlaybookStepTypeEnum, PlaybookSeverityEnum, PlaybookStatusEnum,
        )
        name        = request.name        if request.name        is not None else c["name"]
        description = request.description if request.description is not None else c["description"]
        severity    = request.severity    if request.severity    is not None else c["severity"]
        status      = request.status      if request.status      is not None else c["status"]
        rat         = request.relatedThreatActors if request.relatedThreatActors is not None else c["relatedThreatActors"]
        rc          = request.relatedCampaigns    if request.relatedCampaigns    is not None else c["relatedCampaigns"]
        confidence  = request.confidence  if request.confidence  is not None else c["confidence"]

        if request.steps is not None:
            steps_src = [(s, True) for s in request.steps]
        else:
            steps_src = [(s, False) for s in c["steps"]]

        steps_built = []
        for s_raw, is_req in steps_src:
            if is_req:
                steps_built.append(build_playbook_step(
                    name, step_number=s_raw.stepNumber, title=s_raw.title,
                    step_type=PlaybookStepTypeEnum(s_raw.stepType.strip().upper()),
                    created_at=s_raw.createdAt, description=s_raw.description or "",
                    expected_outcome=s_raw.expectedOutcome or "",
                    related_techniques=list(s_raw.relatedTechniques or []),
                    related_cves=list(s_raw.relatedCVEs or []),
                    related_iocs=list(s_raw.relatedIOCs or []),
                ))
            else:
                steps_built.append(build_playbook_step(
                    c["playbookId"],
                    step_number=s_raw["stepNumber"], title=s_raw["title"],
                    step_type=PlaybookStepTypeEnum(s_raw["stepType"].strip().upper()),
                    created_at=s_raw["createdAt"],
                    description=s_raw.get("description", ""),
                    expected_outcome=s_raw.get("expectedOutcome", ""),
                    related_techniques=list(s_raw.get("relatedTechniques", [])),
                    related_cves=list(s_raw.get("relatedCVEs", [])),
                    related_iocs=list(s_raw.get("relatedIOCs", [])),
                ))

        pb = build_playbook(
            name=name,
            severity=PlaybookSeverityEnum(severity.strip().upper()),
            status=PlaybookStatusEnum(status.strip().upper()),
            steps=steps_built, created_at=c["createdAt"],
            description=description or "",
            related_threat_actors=list(rat or []),
            related_campaigns=list(rc or []),
            confidence=confidence,
        )

        merged = dict(c)
        for field in ("enabled", "priority", "category", "author",
                      "projectId", "investigationId", "updatedAt"):
            val = getattr(request, field, None)
            if val is not None:
                merged[field] = val

        store_dict = _build_store_dict(pb, merged)
        old_id = c["playbookId"]
        # Preserve the original playbookId — a record's primary key must not
        # change on update even though build_playbook() recomputes a uuid5.
        store_dict["playbookId"] = old_id
        if old_id in _PLAYBOOK_STORE: del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[old_id] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Playbook updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.delete("/{playbookId}", response_model=APIResponse)
def delete_playbook(playbookId: str) -> APIResponse:
    try:
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        del _PLAYBOOK_STORE[c["playbookId"]]
        return build_success_response(data={"playbookId": c["playbookId"]},
            message="Playbook deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Steps sub-resource
# ---------------------------------------------------------------------------

@playbook_router.get("/{playbookId}/steps", response_model=APIResponse)
def get_steps(playbookId: str) -> APIResponse:
    try:
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        return build_success_response(
            data=[s for s in _to_response(c).model_dump()["steps"]],
            message="Steps retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.post("/{playbookId}/steps", response_model=APIResponse)
def append_step(playbookId: str, request: PlaybookStepRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        from services.playbook_service import (
            build_playbook_step, PlaybookStepTypeEnum, add_playbook_step,
        )
        from api.workflow.playbook_router import _dict_to_pb_obj
        pb_obj = _dict_to_pb_obj(c)
        new_step = build_playbook_step(
            pb_obj.playbookId, step_number=request.stepNumber, title=request.title,
            step_type=PlaybookStepTypeEnum(request.stepType.strip().upper()),
            created_at=request.createdAt, description=request.description or "",
            expected_outcome=request.expectedOutcome or "",
            related_techniques=list(request.relatedTechniques or []),
            related_cves=list(request.relatedCVEs or []),
            related_iocs=list(request.relatedIOCs or []),
        )
        new_pb = add_playbook_step(pb_obj, new_step)
        updated = _build_store_dict(new_pb, c)
        old_id = c["playbookId"]
        updated["playbookId"] = old_id   # preserve stable primary key
        if old_id in _PLAYBOOK_STORE: del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[old_id] = updated
        return build_success_response(data=_to_response(updated).model_dump(),
            message="Step appended successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.put("/{playbookId}/steps/{stepId}", response_model=APIResponse)
def update_step(playbookId: str, stepId: str,
                request: PlaybookStepRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        from services.playbook_service import (
            update_playbook_step as svc_update, PlaybookStepTypeEnum,
        )
        from api.workflow.playbook_router import _dict_to_pb_obj
        pb_obj = _dict_to_pb_obj(c)
        if not any(s.stepId == stepId for s in pb_obj.steps):
            raise APIErrorNotFound(f"Step '{stepId}' not found.")
        new_pb = svc_update(pb_obj, stepId,
            title=request.title, description=request.description or "",
            step_type=PlaybookStepTypeEnum(request.stepType.strip().upper()),
            expected_outcome=request.expectedOutcome or "",
            related_techniques=list(request.relatedTechniques or []),
            related_cves=list(request.relatedCVEs or []),
            related_iocs=list(request.relatedIOCs or []),
        )
        updated = _build_store_dict(new_pb, c)
        old_id = c["playbookId"]
        updated["playbookId"] = old_id   # preserve stable primary key
        if old_id in _PLAYBOOK_STORE: del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[old_id] = updated
        return build_success_response(data=_to_response(updated).model_dump(),
            message="Step updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.delete("/{playbookId}/steps/{stepId}", response_model=APIResponse)
def delete_step(playbookId: str, stepId: str) -> APIResponse:
    try:
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        from services.playbook_service import remove_playbook_step
        from api.workflow.playbook_router import _dict_to_pb_obj
        pb_obj = _dict_to_pb_obj(c)
        if not any(s.stepId == stepId for s in pb_obj.steps):
            raise APIErrorNotFound(f"Step '{stepId}' not found.")
        new_pb = remove_playbook_step(pb_obj, stepId)
        updated = _build_store_dict(new_pb, c)
        old_id = c["playbookId"]
        updated["playbookId"] = old_id   # preserve stable primary key
        if old_id in _PLAYBOOK_STORE: del _PLAYBOOK_STORE[old_id]
        _PLAYBOOK_STORE[old_id] = updated
        return build_success_response(data=_to_response(updated).model_dump(),
            message="Step deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get("/{playbookId}/summary", response_model=APIResponse)
def get_summary(playbookId: str) -> APIResponse:
    try:
        c = _find(_all(), playbookId)
        if not c: raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        return build_success_response(data=PlaybookSummaryResponse(**_summary(c)).model_dump(),
            message="Summary generated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Execution sub-resource
# ---------------------------------------------------------------------------

@playbook_router.post("/{playbookId}/execute", response_model=APIResponse,
                      status_code=201, summary="Execute a playbook")
def execute_playbook(playbookId: str) -> APIResponse:
    """
    Execute Endpoint → WorkflowExecution record created (RUNNING) →
    Execute every PlaybookStep → Update progress → Append logs →
    Persist updates → Mark COMPLETED or FAILED → Record finishedAt.
    """
    import logging as _logging
    _dbg = _logging.getLogger("execute_playbook.debug")
    if not _dbg.handlers:
        _h = _logging.StreamHandler()
        _h.setFormatter(_logging.Formatter("[DBG execute_playbook] %(message)s"))
        _dbg.addHandler(_h)
    _dbg.setLevel(_logging.DEBUG)

    try:
        # ── 1. Locate the playbook ──────────────────────────────────────────
        c = _find(_all(), playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")

        steps: List[Dict[str, Any]] = c.get("steps") or []
        total_steps = len(steps)

        # ── DEBUG: resolved playbook identity ──────────────────────────────
        _dbg.debug("RESOLVED playbook  id=%r  name=%r", c["playbookId"], c["name"])
        _dbg.debug("STEPS ARRAY  len=%d  steps=%s", total_steps, steps)
        started_at = datetime.utcnow().isoformat() + "Z"
        execution_id = str(uuid.uuid4())

        # ── 2. Create initial WorkflowExecution record (RUNNING, progress=0) ─
        _dbg.debug("CREATING execution  id=%r  playbookId=%r", execution_id, c["playbookId"])
        initial_record: Dict[str, Any] = {
            "executionId": execution_id,
            "playbookId": c["playbookId"],
            "status": "RUNNING",
            "progress": 0,
            "logs": [],
            "startedAt": started_at,
            "finishedAt": None,
            "triggeredBy": "manual",
            "totalSteps": total_steps,
            "completedSteps": 0,
            "failedSteps": 0,
            "stepResults": [],
        }
        _EXECUTION_STORE.create(initial_record)

        # ── DEBUG: confirm store.create returned ───────────────────────────
        _dbg.debug("STORE.create() returned (initial record persisted)")

        # ── 3. Execute each PlaybookStep sequentially ───────────────────────
        logs: List[Dict[str, Any]] = []
        step_results: List[Dict[str, Any]] = []
        completed_steps = 0
        failed_steps = 0
        final_status = "COMPLETED"

        def _append_log(level: str, message: str) -> None:
            logs.append({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": level,
                "message": message,
            })

        _append_log("INFO", f"Execution started for playbook '{c['name']}' "
                            f"({total_steps} step(s)).")

        for i, step in enumerate(steps):
            step_id     = step.get("stepId", f"step-{i+1}")
            step_number = step.get("stepNumber", i + 1)
            step_title  = step.get("title", f"Step {step_number}")
            step_type   = step.get("stepType", "MANUAL")

            # ── DEBUG: loop iteration ──────────────────────────────────────
            _dbg.debug("LOOP iteration i=%d  stepId=%r  stepNumber=%r  title=%r  stepType=%r",
                       i, step_id, step_number, step_title, step_type)

            _append_log("INFO", f"[{step_number}/{total_steps}] Starting step: "
                                f"{step_title} (type={step_type})")

            step_result: Dict[str, Any] = {
                "stepId": step_id,
                "stepNumber": step_number,
                "title": step_title,
                "stepType": step_type,
                "status": "EXECUTED",
                "executedAt": datetime.utcnow().isoformat() + "Z",
                "outputs": {},
            }

            try:
                # Simulate deterministic step execution.
                # For AUTOMATED steps we record expected outcome as output.
                # MANUAL steps are recorded as-is (requires human action in production).
                expected_outcome = step.get("expectedOutcome") or ""
                if expected_outcome:
                    step_result["outputs"]["expectedOutcome"] = expected_outcome

                related_techniques = step.get("relatedTechniques") or []
                if related_techniques:
                    step_result["outputs"]["relatedTechniques"] = related_techniques

                completed_steps += 1
                progress = int((completed_steps / total_steps) * 100) if total_steps else 100
                _append_log("INFO", f"[{step_number}/{total_steps}] Completed step: "
                                    f"{step_title} (progress={progress}%)")

                # ── Persist incremental progress after each step ────────────
                _update_payload = {
                    "progress": progress,
                    "logs": logs[:],
                    "completedSteps": completed_steps,
                    "failedSteps": failed_steps,
                    "stepResults": step_results + [step_result],
                }
                _dbg.debug("STORE.update() CALL  executionId=%r  payload=%s",
                           execution_id, _update_payload)
                _update_result = _EXECUTION_STORE.update(execution_id, _update_payload)
                _dbg.debug("STORE.update() RETURNED  result=%r", _update_result)

            except Exception as step_err:
                step_result["status"] = "FAILED"
                step_result["error"] = str(step_err)
                failed_steps += 1
                final_status = "FAILED"
                _append_log("ERROR", f"[{step_number}/{total_steps}] Step FAILED: "
                                     f"{step_title} — {step_err}")

            step_results.append(step_result)

        # ── 4. Finalize execution ───────────────────────────────────────────
        finished_at = datetime.utcnow().isoformat() + "Z"
        final_progress = 100 if final_status == "COMPLETED" else int(
            (completed_steps / total_steps) * 100) if total_steps else 0

        _append_log(
            "INFO" if final_status == "COMPLETED" else "ERROR",
            f"Execution {final_status}. "
            f"Steps: {completed_steps} completed, {failed_steps} failed."
        )

        # ── DEBUG: final store.update call ─────────────────────────────────
        _final_update_payload = {
            "status": final_status,
            "progress": final_progress,
            "logs": logs,
            "finishedAt": finished_at,
            "completedSteps": completed_steps,
            "failedSteps": failed_steps,
            "stepResults": step_results,
        }
        _dbg.debug("FINAL STORE.update() CALL  executionId=%r  payload=%s",
                   execution_id, _final_update_payload)
        _final_update_result = _EXECUTION_STORE.update(execution_id, _final_update_payload)
        _dbg.debug("FINAL STORE.update() RETURNED  result=%r", _final_update_result)

        # ── 5. Emit timeline audit event via persistence layer ──────────────
        try:
            from api.persistence import call_repository, ensure_uuid, map_timeline_event
            project_id = c.get("projectId") or ""
            investigation_id = c.get("investigationId") or ""
            if project_id:
                event_payload = {
                    "projectId": project_id,
                    "investigationId": investigation_id or project_id,
                    "title": f"Playbook Execution {final_status}: {c['name']}",
                    "description": (
                        f"Playbook '{c['name']}' executed with {total_steps} steps. "
                        f"Result: {final_status}. "
                        f"Completed: {completed_steps}, Failed: {failed_steps}."
                    ),
                    "type": "MANUAL_ACTION",
                    "createdBy": "system",
                    "updatedBy": "system",
                }
                mapped = map_timeline_event(event_payload)
                event_payload.update(mapped)
                call_repository("timelineEvent", "create", {"data": event_payload})
        except Exception:
            pass  # Timeline emission is best-effort; never fail execution

        # ── 6. Return the persisted execution record ────────────────────────
        # Reload from the store so the response reflects what was actually
        # persisted (including any UUID remapping done by ensure_uuid in
        # WorkflowExecutionsStore.create/update).  If the reload fails for any
        # reason, fall back to a locally-assembled dict so the caller always
        # receives a useful response.
        persisted = _EXECUTION_STORE.get_by_id(execution_id)
        _dbg.debug("STORE.get_by_id() RETURNED  %s", persisted)

        if persisted:
            # Augment the persisted record with the human-readable playbookName
            # (not stored in the WorkflowExecution table) so clients don't need
            # a second round-trip.
            result = dict(persisted)
            result.setdefault("playbookName", c["name"])
        else:
            # Fallback: build from local variables (store write may have failed).
            _dbg.debug("STORE.get_by_id() returned None — using local fallback")
            result = {
                "executionId": execution_id,
                "playbookId": c["playbookId"],
                "playbookName": c["name"],
                "status": final_status,
                "progress": final_progress,
                "logs": logs,
                "startedAt": started_at,
                "finishedAt": finished_at,
                "triggeredBy": "manual",
                "totalSteps": total_steps,
                "completedSteps": completed_steps,
                "failedSteps": failed_steps,
                "stepResults": step_results,
            }

        _dbg.debug("FINAL EXECUTION RECORD BEFORE RETURN  %s", result)
        return build_success_response(
            data=result,
            message=f"Playbook execution {final_status.lower()}.",
        )
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get("/{playbookId}/executions", response_model=APIResponse,
                     summary="List executions for a playbook")
def list_executions(playbookId: str) -> APIResponse:
    """Return all WorkflowExecution records for the given playbook."""
    try:
        c = _find(_all(), playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        executions = _EXECUTION_STORE.get_by_playbook(c["playbookId"])
        return build_success_response(
            data=executions,
            message=f"Found {len(executions)} execution(s).",
        )
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.get("/{playbookId}/executions/{executionId}", response_model=APIResponse,
                     summary="Get a single execution record")
def get_execution(playbookId: str, executionId: str) -> APIResponse:
    """Return a single WorkflowExecution record by its ID."""
    try:
        c = _find(_all(), playbookId)
        if not c:
            raise APIErrorNotFound(f"Playbook '{playbookId}' not found.")
        record = _EXECUTION_STORE.get_by_id(executionId)
        if not record:
            raise APIErrorNotFound(f"Execution '{executionId}' not found.")
        return build_success_response(data=record, message="Execution retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Private helper — build core Playbook object from stored dict
# ---------------------------------------------------------------------------

def _dict_to_pb_obj(d: Dict):
    from services.playbook_service import (
        Playbook, PlaybookStep, PlaybookStepTypeEnum,
        PlaybookSeverityEnum, PlaybookStatusEnum,
    )
    n = normalize_playbook(d)
    steps = []
    for s in n["steps"]:
        try:   st = PlaybookStepTypeEnum(s["stepType"].strip().upper())
        except ValueError: st = PlaybookStepTypeEnum("MANUAL")
        steps.append(PlaybookStep(
            stepId=s["stepId"], stepKey=s["stepKey"],
            stepNumber=s["stepNumber"], title=s["title"],
            description=s["description"], stepType=st,
            expectedOutcome=s["expectedOutcome"],
            relatedTechniques=tuple(s["relatedTechniques"]),
            relatedCVEs=tuple(s["relatedCVEs"]),
            relatedIOCs=tuple(s["relatedIOCs"]),
            createdAt=s["createdAt"],
        ))
    try:   sev  = PlaybookSeverityEnum(n["severity"].strip().upper())
    except ValueError: sev = PlaybookSeverityEnum("MEDIUM")
    try:   stat = PlaybookStatusEnum(n["status"].strip().upper())
    except ValueError: stat = PlaybookStatusEnum("DRAFT")
    return Playbook(
        playbookId=n["playbookId"], playbookKey=n["playbookKey"],
        name=n["name"], description=n["description"],
        severity=sev, status=stat, steps=tuple(steps),
        relatedThreatActors=tuple(n["relatedThreatActors"]),
        relatedCampaigns=tuple(n["relatedCampaigns"]),
        confidence=n["confidence"], createdAt=n["createdAt"],
    )


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

@playbook_router.post("/bulk/create", response_model=APIResponse)
def bulk_create(request: BulkCreatePlaybooksRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.playbook_service import (
            build_playbook_step, build_playbook,
            PlaybookStepTypeEnum, PlaybookSeverityEnum, PlaybookStatusEnum,
        )
        succeeded: List[str] = []; failed: List[Dict[str, str]] = []
        for item in request.playbooks:
            try:
                steps_built = [
                    build_playbook_step(
                        item.name, step_number=s.stepNumber, title=s.title,
                        step_type=PlaybookStepTypeEnum(s.stepType.strip().upper()),
                        created_at=s.createdAt, description=s.description or "",
                        expected_outcome=s.expectedOutcome or "",
                        related_techniques=list(s.relatedTechniques or []),
                        related_cves=list(s.relatedCVEs or []),
                        related_iocs=list(s.relatedIOCs or []),
                    ) for s in (item.steps or [])
                ]
                pb = build_playbook(
                    name=item.name,
                    severity=PlaybookSeverityEnum(item.severity.strip().upper()),
                    status=PlaybookStatusEnum(item.status.strip().upper()),
                    steps=steps_built, created_at=item.createdAt,
                    description=item.description or "",
                    related_threat_actors=list(item.relatedThreatActors or []),
                    related_campaigns=list(item.relatedCampaigns or []),
                    confidence=item.confidence,
                )
                rec_id = pb.playbookId
                if rec_id in _PLAYBOOK_STORE or rec_id in succeeded:
                    failed.append({"id": item.name, "reason": f"ID '{rec_id}' already exists."})
                    continue
                _PLAYBOOK_STORE[rec_id] = _build_store_dict(pb, item.model_dump())
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.name, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.playbooks), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk create completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.put("/bulk/update", response_model=APIResponse)
def bulk_update(request: BulkUpdatePlaybooksRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        succeeded: List[str] = []; failed: List[Dict[str, str]] = []
        for item in request.items:
            existing = _find(_all(), item.playbookId)
            if not existing:
                failed.append({"id": item.playbookId, "reason": "Not found."}); continue
            try:
                # Re-use single-update logic via a synthetic single PUT
                from services.playbook_service import (
                    build_playbook_step, build_playbook,
                    PlaybookStepTypeEnum, PlaybookSeverityEnum, PlaybookStatusEnum,
                )
                u = item.update
                name        = u.name        if u.name        is not None else existing["name"]
                description = u.description if u.description is not None else existing["description"]
                severity    = u.severity    if u.severity    is not None else existing["severity"]
                status      = u.status      if u.status      is not None else existing["status"]
                rat = u.relatedThreatActors if u.relatedThreatActors is not None else existing["relatedThreatActors"]
                rc  = u.relatedCampaigns    if u.relatedCampaigns    is not None else existing["relatedCampaigns"]
                confidence = u.confidence if u.confidence is not None else existing["confidence"]

                if u.steps is not None:
                    steps_built = [build_playbook_step(
                        name, step_number=s.stepNumber, title=s.title,
                        step_type=PlaybookStepTypeEnum(s.stepType.strip().upper()),
                        created_at=s.createdAt, description=s.description or "",
                        expected_outcome=s.expectedOutcome or "",
                        related_techniques=list(s.relatedTechniques or []),
                        related_cves=list(s.relatedCVEs or []),
                        related_iocs=list(s.relatedIOCs or []),
                    ) for s in u.steps]
                else:
                    steps_built = [build_playbook_step(
                        existing["playbookId"],
                        step_number=s["stepNumber"], title=s["title"],
                        step_type=PlaybookStepTypeEnum(s["stepType"].strip().upper()),
                        created_at=s["createdAt"],
                        description=s.get("description",""),
                        expected_outcome=s.get("expectedOutcome",""),
                        related_techniques=list(s.get("relatedTechniques",[])),
                        related_cves=list(s.get("relatedCVEs",[])),
                        related_iocs=list(s.get("relatedIOCs",[])),
                    ) for s in existing["steps"]]

                pb = build_playbook(
                    name=name,
                    severity=PlaybookSeverityEnum(severity.strip().upper()),
                    status=PlaybookStatusEnum(status.strip().upper()),
                    steps=steps_built, created_at=existing["createdAt"],
                    description=description or "",
                    related_threat_actors=list(rat or []),
                    related_campaigns=list(rc or []),
                    confidence=confidence,
                )
                merged = dict(existing)
                for f in ("enabled","priority","category","author",
                          "projectId","investigationId","updatedAt"):
                    v = getattr(u, f, None)
                    if v is not None: merged[f] = v
                store_dict = _build_store_dict(pb, merged)
                old_id = existing["playbookId"]
                store_dict["playbookId"] = old_id   # preserve stable primary key
                if old_id in _PLAYBOOK_STORE: del _PLAYBOOK_STORE[old_id]
                _PLAYBOOK_STORE[old_id] = store_dict
                succeeded.append(old_id)
            except Exception as e:
                failed.append({"id": item.playbookId, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.items), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk update completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@playbook_router.delete("/bulk/delete", response_model=APIResponse)
def bulk_delete(request: BulkDeletePlaybooksRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        succeeded: List[str] = []; failed: List[Dict[str, str]] = []
        for pid in request.playbookIds:
            existing = _find(_all(), pid)
            if not existing:
                failed.append({"id": pid, "reason": "Not found."}); continue
            try:
                del _PLAYBOOK_STORE[existing["playbookId"]]
                succeeded.append(existing["playbookId"])
            except Exception as e:
                failed.append({"id": pid, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.playbookIds), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk delete completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ===========================================================================
# Module-level aliases and programmatic helpers
# ===========================================================================
# The smoke-test and tracer expect these names to be importable directly from
# this module.  All aliases point at the existing route handlers or internal
# helpers defined above.
# ===========================================================================

# ── Store / data helpers ─────────────────────────────────────────────────────

def _all_playbooks() -> List[Dict[str, Any]]:
    """Return all normalised playbook dicts (alias for internal _all)."""
    return _all()


# ── Route-handler aliases (programmatic call surface) ────────────────────────

def list_playbooks_endpoint(**kwargs) -> APIResponse:
    """Alias: list_playbooks route handler called programmatically."""
    return list_playbooks(**kwargs)


def search_playbook_records(
    query: str = "",
    sortBy: str = "playbookName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    """Alias: search_playbooks route handler."""
    return search_playbooks(query=query, sortBy=sortBy, sortOrder=sortOrder,
                            page=page, pageSize=pageSize)


def get_playbook_steps(playbookId: str) -> APIResponse:
    """Alias: get_steps route handler."""
    return get_steps(playbookId)


def get_playbook_summary(playbookId: str) -> APIResponse:
    """Alias: get_summary route handler."""
    return get_summary(playbookId)


def bulk_create_playbooks(request: BulkCreatePlaybooksRequest) -> APIResponse:
    """Alias: bulk_create route handler."""
    return bulk_create(request)


def bulk_update_playbooks(request: BulkUpdatePlaybooksRequest) -> APIResponse:
    """Alias: bulk_update route handler."""
    return bulk_update(request)


def bulk_delete_playbooks(request: BulkDeletePlaybooksRequest) -> APIResponse:
    """Alias: bulk_delete route handler."""
    return bulk_delete(request)


# ── Pure utility helpers (programmatic, no HTTP context needed) ───────────────

def find_playbook(playbooks: List[Dict[str, Any]], playbook_id: str) -> Optional[Dict[str, Any]]:
    """Find a playbook dict from a list by id / name / key."""
    return _find(playbooks, playbook_id)


def find_playbook_step(
    playbooks: List[Dict[str, Any]], step_id: str
) -> Optional[Dict[str, Any]]:
    """Find a step dict from across all playbooks in a list."""
    for pb in playbooks:
        for s in pb.get("steps", []):
            if s.get("stepId") == step_id:
                return s
    return None


def search_playbook_steps(
    playbooks: List[Dict[str, Any]], query: str
) -> List[Dict[str, Any]]:
    """Return all step dicts whose title/description contain *query*."""
    if not query or not query.strip():
        return []
    ql = query.strip().lower()
    results: List[Dict[str, Any]] = []
    for pb in playbooks:
        for s in pb.get("steps", []):
            if ql in s.get("title", "").lower() or ql in s.get("description", "").lower():
                results.append(s)
    return results


def sort_playbooks(
    playbooks: List[Dict[str, Any]],
    sort_by: str = "playbookName",
    sort_order: str = "asc",
) -> List[Dict[str, Any]]:
    """Sort a list of playbook dicts. Accepts both camelCase and snake_case."""
    # Normalise field name so smoke-test callers using snake_case work too
    field_map = {
        "playbookname": "playbookName",
        "createdat": "createdAt",
        "updatedat": "updatedAt",
        "stepcount": "stepCount",
        "enabled": "enabled",
        "priority": "priority",
        "name": "playbookName",
    }
    normalized = field_map.get(sort_by.lower(), sort_by)
    return _sort(playbooks, normalized, sort_order)


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
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter a list of playbook dicts. Superset of _filter; adds severity/status."""
    result = _filter(
        playbooks,
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
    if severity is not None:
        result = [p for p in result if p.get("severity", "").upper() == severity.strip().upper()]
    if status is not None:
        result = [p for p in result if p.get("status", "").upper() == status.strip().upper()]
    return result


def paginate_playbooks(
    playbooks: List[Dict[str, Any]], page: int, page_size: int
) -> Tuple[List[Dict[str, Any]], Any]:
    """Paginate a list and return (page_items, pagination_meta_dict)."""
    items, total = _paginate(playbooks, page, page_size)
    total_pages = math.ceil(total / page_size) if total and page_size else 1

    class _Meta:
        def __init__(self):
            self.page = page
            self.pageSize = page_size
            self.totalItems = total
            self.totalPages = total_pages

    return items, _Meta()


def build_playbook_summary(playbook: Dict[str, Any]) -> Dict[str, Any]:
    """Return a summary dict for a single playbook dict."""
    return _summary(playbook)


def calculate_playbook_statistics(
    playbooks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute statistics over a list of playbook dicts."""
    return _stats(playbooks)
