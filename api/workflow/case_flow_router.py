"""
Case Flow API Router — Canonical Schema
========================================
All normalization via normalizers.normalize_case_flow() and
normalizers.normalize_case_flow_execution().

Key fixes applied:
  - investigationId is required in Prisma (non-nullable) — validated in request
  - CaseFlowExecution status "SUCCESS" → "COMPLETED"
  - CaseFlowStep.stepType default "INVESTIGATION" → "CREATED"
  - playbookId / automationId properly surfaced on response
"""
from __future__ import annotations
import math, uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body
from api.errors import (
    APILayerError, APIErrorConflict, APIErrorInternal,
    APIErrorNotFound, APIErrorValidation,
)
from api.models import APIResponse
from api.responses import build_success_response, build_paginated_response
from api.utils import exception_to_api_response, validate_pagination
from api.workflow.case_flow_models import (
    CreateCaseFlowRequest, UpdateCaseFlowRequest,
    CaseFlowStepRequest, CaseFlowStepResponse, CaseFlowExecutionResponse,
    CaseFlowResponse, CaseFlowStatisticsResponse, CaseFlowSearchResponse,
    CaseFlowSummaryResponse, BulkCreateCaseFlowsRequest, BulkUpdateCaseFlowsRequest,
    BulkDeleteCaseFlowsRequest, BulkOperationResult,
)
from api.workflow.normalizers import normalize_case_flow, normalize_case_flow_execution
from api.persistence import RepositoryBackedDict, CaseFlowExecutionsStore, map_case_flow

case_flow_router = APIRouter(prefix="/case-flow", tags=["Case Flow"])
_CASE_FLOW_STORE = RepositoryBackedDict("caseFlow", "caseFlowId", map_case_flow)
_EXECUTION_STORE = CaseFlowExecutionsStore()
_CASE_FLOW_NS    = uuid.UUID("6ba7b887-9dad-11d1-80b4-00c04fd430c8")


def _reset_store() -> None:
    _CASE_FLOW_STORE.clear()
    _EXECUTION_STORE.clear()


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _to_response(raw: Dict) -> CaseFlowResponse:
    c = normalize_case_flow(raw)
    steps = [CaseFlowStepResponse(**s) for s in c["steps"]]
    return CaseFlowResponse(
        caseFlowId=c["caseFlowId"],   caseFlowKey=c["caseFlowKey"],
        caseNumber=c["caseNumber"],   title=c["title"],
        description=c["description"], status=c["status"],
        priority=c["priority"],       projectId=c["projectId"],
        investigationId=c["investigationId"],
        playbookId=c["playbookId"],   automationId=c["automationId"],
        steps=steps,
        findingIds=c["findingIds"],   alertIds=c["alertIds"],
        evidenceIds=c["evidenceIds"], playbookIds=c["playbookIds"],
        assignedTo=c["assignedTo"],   owner=c["owner"],
        confidence=c["confidence"],   createdAt=c["createdAt"],
        updatedAt=c["updatedAt"],
    )


def _all() -> List[Dict]:
    return sorted(
        [normalize_case_flow(c) for c in _CASE_FLOW_STORE.values()],
        key=lambda c: c["title"],
    )


def _find(items: List[Dict], ident: str) -> Optional[Dict]:
    n = ident.strip().lower()
    for c in items:
        if c["caseFlowId"].lower() == n:   return c
        if c["caseFlowKey"].lower() == n:  return c
        if c["caseNumber"].lower() == n:   return c
        if c["title"].lower() == n:        return c
    return None


def _sort(items, sort_by, sort_order):
    valid = {"caseName","createdAt","updatedAt","priority","status","stepCount","executionCount"}
    if sort_by not in valid:
        raise APIErrorValidation("Invalid sort field.",
            details=[f"'{sort_by}' not supported. Valid: {sorted(valid)}"])
    if sort_order.lower() not in {"asc","desc"}:
        raise APIErrorValidation("Invalid sort order.")
    _PRI = {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    _STA = {"OPEN":5,"IN_PROGRESS":4,"ON_HOLD":3,"RESOLVED":2,"CLOSED":1}
    def key(c):
        if sort_by == "caseName":       return c["title"]
        if sort_by == "priority":       return _PRI.get(c["priority"],0)
        if sort_by == "status":         return _STA.get(c["status"],0)
        if sort_by == "stepCount":      return len(c["steps"])
        if sort_by == "executionCount": return len(_EXECUTION_STORE.get(c["caseFlowId"],[]))
        return c.get(sort_by,"") or ""
    base = sorted(items, key=lambda x: x["caseFlowId"])
    base.sort(key=key, reverse=(sort_order.lower()=="desc"))
    return base


def _filter(items, status=None, priority=None, owner=None, projectId=None,
             investigationId=None, playbookId=None, automationId=None,
             minimumSteps=None, maximumSteps=None, createdAfter=None, createdBefore=None):
    r = list(items)
    if status          is not None: r = [x for x in r if x["status"].lower()==status.strip().lower()]
    if priority        is not None: r = [x for x in r if x["priority"].lower()==priority.strip().lower()]
    if owner           is not None: r = [x for x in r if owner.strip().lower() in x["owner"].lower()]
    if projectId       is not None: r = [x for x in r if x["projectId"]==projectId.strip()]
    if investigationId is not None: r = [x for x in r if x["investigationId"]==investigationId.strip()]
    if playbookId      is not None: r = [x for x in r if playbookId.strip() in x["playbookIds"]]
    if automationId    is not None: r = [x for x in r if x["automationId"]==automationId.strip()]
    if minimumSteps    is not None: r = [x for x in r if len(x["steps"])>=minimumSteps]
    if maximumSteps    is not None: r = [x for x in r if len(x["steps"])<=maximumSteps]
    if createdAfter    is not None: r = [x for x in r if x["createdAt"]>=createdAfter.strip()]
    if createdBefore   is not None: r = [x for x in r if x["createdAt"]<=createdBefore.strip()]
    return r


def _paginate(items, page, size):
    total = len(items)
    return items[(page-1)*size:(page-1)*size+size], total


def _search(items, q):
    if not q or not q.strip(): return list(items)
    ql = q.strip().lower()
    return [c for c in items if (
        ql in c["title"].lower() or ql in c["description"].lower()
        or ql in c["owner"].lower() or ql in c["assignedTo"].lower()
        or any(ql in s["title"].lower() for s in c["steps"])
    )]


def _stats(items) -> Dict:
    total = len(items)
    open_c  = sum(1 for c in items if c["status"]=="OPEN")
    closed_c= sum(1 for c in items if c["status"]=="CLOSED")
    in_prog = sum(1 for c in items if c["status"]=="IN_PROGRESS")
    te = sum(len(_EXECUTION_STORE.get(c["caseFlowId"],[])) for c in items)
    ts = sum(len(c["steps"]) for c in items)
    _PRI = {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    tp = sum(_PRI.get(c["priority"],2) for c in items)
    sc: Dict[str,int] = {}
    for c in items:
        s = c["status"].strip()
        if s: sc[s] = sc.get(s,0)+1
    return {
        "totalCases":        total,
        "openCases":         open_c,
        "closedCases":       closed_c,
        "inProgressCases":   in_prog,
        "totalExecutions":   te,
        "averageSteps":      round(ts/total,4) if total else 0.0,
        "averageExecutions": round(te/total,4) if total else 0.0,
        "averagePriority":   round(tp/total,4) if total else 0.0,
        "statusCounts":      dict(sorted(sc.items())),
    }


def _summary(c: Dict) -> Dict:
    title = c["title"]; st = c["status"]; pri = c["priority"]
    sc = len(c["steps"]); ec = len(_EXECUTION_STORE.get(c["caseFlowId"],[]))
    owner = c["owner"]; conf = c["confidence"]
    return {
        "caseFlowId":    c["caseFlowId"],
        "caseName":      title,
        "summaryText": (
            f"Case '{title}' ({st}) has {sc} steps and {ec} executions. "
            f"{pri} priority, owner: {owner}, confidence: {conf}%."
        ),
        "stepCount": sc, "executionCount": ec,
        "status": st, "priority": pri, "owner": owner, "confidence": conf,
    }


def _to_store_dict(case_obj, req_dict: Dict) -> Dict:
    steps = []
    for s in case_obj.steps:
        steps.append({
            "stepId":      s.stepId,      "stepKey":     s.stepKey,
            "stepNumber":  s.stepNumber,  "stepType":    s.stepType.value,
            "title":       s.title,       "description": s.description,
            "assignedTo":  s.assignedTo,  "createdAt":   s.createdAt,
        })
    return {
        "caseFlowId":      case_obj.caseId,
        "caseFlowKey":     case_obj.caseKey,
        "caseNumber":      case_obj.caseNumber,
        "title":           case_obj.title,
        "description":     case_obj.description,
        "status":          case_obj.status.value,
        "priority":        case_obj.priority.value,
        "steps":           steps,
        "findingIds":      list(case_obj.findingIds),
        "alertIds":        list(case_obj.alertIds),
        "evidenceIds":     list(case_obj.evidenceIds),
        "playbookIds":     list(case_obj.playbookIds),
        "assignedTo":      case_obj.assignedTo,
        "confidence":      case_obj.confidence,
        "createdAt":       case_obj.createdAt,
        "updatedAt":       req_dict.get("updatedAt"),
        "projectId":       req_dict.get("projectId", ""),
        "investigationId": req_dict.get("investigationId", ""),
        "playbookId":      req_dict.get("playbookId") or "",
        "automationId":    req_dict.get("automationId") or "",
        "owner":           req_dict.get("owner", ""),
    }


def _dict_to_case_obj(d: Dict):
    from services.case_flow_service import (
        Case, CaseStep, CaseStepTypeEnum, CaseStatusEnum, CasePriorityEnum,
    )
    n = normalize_case_flow(d)
    steps = []
    for s in n["steps"]:
        try:   st = CaseStepTypeEnum(s["stepType"].strip().upper())
        except ValueError: st = CaseStepTypeEnum("CREATED")
        steps.append(CaseStep(
            stepId=s["stepId"],       stepKey=s["stepKey"],
            stepNumber=s["stepNumber"], stepType=st,
            title=s["title"],         description=s["description"],
            assignedTo=s["assignedTo"], createdAt=s["createdAt"],
        ))
    try:   stat = CaseStatusEnum(n["status"].strip().upper())
    except ValueError: stat = CaseStatusEnum("OPEN")
    try:   prio = CasePriorityEnum(n["priority"].strip().upper())
    except ValueError: prio = CasePriorityEnum("MEDIUM")
    return Case(
        caseId=n["caseFlowId"],   caseKey=n["caseFlowKey"],
        caseNumber=n["caseNumber"], title=n["title"],
        description=n["description"], status=stat, priority=prio,
        steps=tuple(steps),
        findingIds=tuple(n["findingIds"]),  alertIds=tuple(n["alertIds"]),
        evidenceIds=tuple(n["evidenceIds"]), playbookIds=tuple(n["playbookIds"]),
        assignedTo=n["assignedTo"],  confidence=n["confidence"],
        createdAt=n["createdAt"],
    )


# ---------------------------------------------------------------------------
# Routes — List / Search / Statistics
# ---------------------------------------------------------------------------

@case_flow_router.get("/", response_model=APIResponse)
def list_case_flows(
    status: Optional[str]=None, priority: Optional[str]=None,
    owner: Optional[str]=None, projectId: Optional[str]=None,
    investigationId: Optional[str]=None, playbookId: Optional[str]=None,
    automationId: Optional[str]=None,
    minimumSteps: Optional[int]=None, maximumSteps: Optional[int]=None,
    createdAfter: Optional[str]=None, createdBefore: Optional[str]=None,
    sortBy: str="caseName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _filter(_all(), status=status, priority=priority, owner=owner,
            projectId=projectId, investigationId=investigationId,
            playbookId=playbookId, automationId=automationId,
            minimumSteps=minimumSteps, maximumSteps=maximumSteps,
            createdAfter=createdAfter, createdBefore=createdBefore)
        items = _sort(items, sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        return build_paginated_response(
            items=[_to_response(x).model_dump() for x in page_items],
            page=page, page_size=pageSize, total_items=total,
            message="Cases retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get("/statistics", response_model=APIResponse)
def get_case_flow_statistics() -> APIResponse:
    try:
        return build_success_response(data=_stats(_all()),
            message="Case statistics computed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get("/search", response_model=APIResponse)
def search_case_flows_endpoint(
    q: str="", sortBy: str="caseName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _sort(_search(_all(), q), sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        total_pages = math.ceil(total/pageSize) if total else 1
        payload = CaseFlowSearchResponse(
            caseFlows=[_to_response(x) for x in page_items],
            total=total, page=page, pageSize=pageSize,
            totalPages=total_pages, query=q, sortBy=sortBy, sortOrder=sortOrder,
        )
        return build_success_response(data=payload.model_dump(),
            message="Search completed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Routes — CRUD
# ---------------------------------------------------------------------------

@case_flow_router.get("/{caseFlowId}", response_model=APIResponse)
def get_case_flow(caseFlowId: str) -> APIResponse:
    try:
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        return build_success_response(data=_to_response(c).model_dump(),
            message="Case retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.post("/", response_model=APIResponse)
def create_case_flow(request: CreateCaseFlowRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.case_flow_service import (
            build_case_step, build_case, CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum,
        )
        steps_built = []
        for s in (request.steps or []):
            steps_built.append(build_case_step(
                request.title, step_number=s.stepNumber,
                step_type=CaseStepTypeEnum(s.stepType.strip().upper()),
                title=s.title, created_at=s.createdAt,
                description=s.description or "", assigned_to=s.assignedTo or "",
            ))
        cb = build_case(
            title=request.title,
            priority=CasePriorityEnum(request.priority.strip().upper()),
            created_at=request.createdAt,
            description=request.description or "",
            status=CaseStatusEnum(request.status.strip().upper()),
            steps=steps_built,
            finding_ids=list(request.findingIds or []),
            alert_ids=list(request.alertIds or []),
            evidence_ids=list(request.evidenceIds or []),
            playbook_ids=list(request.playbookIds or []),
            assigned_to=request.assignedTo or "",
            confidence=request.confidence if request.confidence is not None else 100.0,
        )
        rec_id = cb.caseId
        if rec_id in _CASE_FLOW_STORE:
            raise APIErrorConflict(f"Case '{rec_id}' already exists.")
        store_dict = _to_store_dict(cb, request.model_dump())
        _CASE_FLOW_STORE[rec_id] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Case created successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.put("/{caseFlowId}", response_model=APIResponse)
def update_case_flow_route(caseFlowId: str,
                            request: UpdateCaseFlowRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        from services.case_flow_service import (
            update_case as svc_update, build_case_step,
            CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum,
        )
        case_obj = _dict_to_case_obj(c)
        sta_p  = CaseStatusEnum(request.status.strip().upper())   if request.status   else None
        prio_p = CasePriorityEnum(request.priority.strip().upper()) if request.priority else None
        title_p = request.title
        steps_p = None
        if request.steps is not None:
            steps_p = [build_case_step(
                title_p or case_obj.title,
                step_number=s.stepNumber,
                step_type=CaseStepTypeEnum(s.stepType.strip().upper()),
                title=s.title, created_at=s.createdAt,
                description=s.description or "", assigned_to=s.assignedTo or "",
            ) for s in request.steps]
        updated_list = svc_update(
            cases=[case_obj], case_id=case_obj.caseId,
            created_at=request.updatedAt or case_obj.createdAt,
            title=title_p, description=request.description,
            status=sta_p, priority=prio_p, steps=steps_p,
            finding_ids=request.findingIds, alert_ids=request.alertIds,
            evidence_ids=request.evidenceIds, playbook_ids=request.playbookIds,
            assigned_to=request.assignedTo, confidence=request.confidence,
        )
        if not updated_list: raise APIErrorInternal("Update failed.")
        merged = dict(c)
        for field in ("projectId","investigationId","playbookId","automationId",
                      "owner","updatedAt"):
            v = getattr(request, field, None)
            if v is not None: merged[field] = v
        store_dict = _to_store_dict(updated_list[0], merged)
        old_id = c["caseFlowId"]
        if old_id in _CASE_FLOW_STORE: del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[store_dict["caseFlowId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Case updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.delete("/{caseFlowId}", response_model=APIResponse)
def delete_case_flow(caseFlowId: str) -> APIResponse:
    try:
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        del _CASE_FLOW_STORE[c["caseFlowId"]]
        try: del _EXECUTION_STORE[c["caseFlowId"]]
        except Exception: pass
        return build_success_response(data={"caseFlowId": c["caseFlowId"]},
            message="Case deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Steps sub-resource
# ---------------------------------------------------------------------------

@case_flow_router.get("/{caseFlowId}/steps", response_model=APIResponse)
def get_case_steps(caseFlowId: str) -> APIResponse:
    try:
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        return build_success_response(
            data=_to_response(c).model_dump()["steps"],
            message="Steps retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.post("/{caseFlowId}/steps", response_model=APIResponse)
def append_step(caseFlowId: str, request: CaseFlowStepRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        from services.case_flow_service import (
            build_case_step, add_case_step, CaseStepTypeEnum,
        )
        case_obj = _dict_to_case_obj(c)
        new_step = build_case_step(
            case_obj.caseId, step_number=request.stepNumber,
            step_type=CaseStepTypeEnum(request.stepType.strip().upper()),
            title=request.title, created_at=request.createdAt,
            description=request.description or "", assigned_to=request.assignedTo or "",
        )
        new_case = add_case_step(case_obj, new_step, request.createdAt)
        store_dict = _to_store_dict(new_case, c)
        old_id = c["caseFlowId"]
        if old_id in _CASE_FLOW_STORE: del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[store_dict["caseFlowId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Step appended successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.put("/{caseFlowId}/steps/{stepId}", response_model=APIResponse)
def update_step(caseFlowId: str, stepId: str,
                request: CaseFlowStepRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        from services.case_flow_service import (
            update_case_step as svc_upd, CaseStepTypeEnum,
        )
        case_obj = _dict_to_case_obj(c)
        if not any(s.stepId == stepId for s in case_obj.steps):
            raise APIErrorNotFound(f"Step '{stepId}' not found.")
        new_case = svc_upd(case_obj, stepId, created_at=request.createdAt,
            title=request.title, description=request.description or "",
            step_type=CaseStepTypeEnum(request.stepType.strip().upper()),
            assigned_to=request.assignedTo or "")
        store_dict = _to_store_dict(new_case, c)
        old_id = c["caseFlowId"]
        if old_id in _CASE_FLOW_STORE: del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[store_dict["caseFlowId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Step updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.delete("/{caseFlowId}/steps/{stepId}", response_model=APIResponse)
def delete_step(caseFlowId: str, stepId: str) -> APIResponse:
    try:
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        from services.case_flow_service import remove_case_step
        case_obj = _dict_to_case_obj(c)
        if not any(s.stepId == stepId for s in case_obj.steps):
            raise APIErrorNotFound(f"Step '{stepId}' not found.")
        ts = case_obj.steps[0].createdAt if case_obj.steps else "2026-07-06T12:00:00Z"
        new_case = remove_case_step(case_obj, stepId, ts)
        store_dict = _to_store_dict(new_case, c)
        old_id = c["caseFlowId"]
        if old_id in _CASE_FLOW_STORE: del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[store_dict["caseFlowId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Step deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Execution endpoints — status uses CaseExecutionStatus (COMPLETED not SUCCESS)
# ---------------------------------------------------------------------------

@case_flow_router.post("/{caseFlowId}/execute", response_model=APIResponse)
def execute_case_flow_endpoint(
    caseFlowId: str, timestamp: str = Body(..., embed=True)
) -> APIResponse:
    try:
        if not timestamp or not timestamp.strip():
            raise APIErrorValidation("timestamp must be non-empty.")
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        case_id = c["caseFlowId"]
        exec_id = str(uuid.uuid5(_CASE_FLOW_NS, f"{case_id}:{timestamp}"))
        step_results = [{
            "stepId":    s["stepId"],  "title":    s["title"],
            "stepType":  s["stepType"],
            "status":    "COMPLETED",  # ← Prisma CaseExecutionStatus (was "SUCCESS")
            "message":   f"Step '{s['title']}' executed.",
            "output":    {"executedAt": timestamp},
        } for s in c["steps"]]
        execution = {
            "executionId": exec_id,   "caseFlowId":  case_id,
            "status":      "COMPLETED",  # ← Prisma CaseExecutionStatus
            "startedAt":   timestamp, "completedAt": timestamp,
            "stepResults": step_results,
        }
        _EXECUTION_STORE.setdefault(case_id, []).append(execution)
        return build_success_response(
            data=CaseFlowExecutionResponse(
                **normalize_case_flow_execution(execution)
            ).model_dump(),
            message="Case executed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get("/{caseFlowId}/executions", response_model=APIResponse)
def get_executions(caseFlowId: str) -> APIResponse:
    try:
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        execs = _EXECUTION_STORE.get(c["caseFlowId"], [])
        return build_success_response(
            data=[CaseFlowExecutionResponse(
                    **normalize_case_flow_execution(x)).model_dump()
                  for x in execs],
            message="Executions retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get("/{caseFlowId}/summary", response_model=APIResponse)
def get_case_flow_summary(caseFlowId: str) -> APIResponse:
    try:
        c = _find(_all(), caseFlowId)
        if not c: raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        return build_success_response(
            data=CaseFlowSummaryResponse(**_summary(c)).model_dump(),
            message="Summary generated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

@case_flow_router.post("/bulk/create", response_model=APIResponse)
def bulk_create_case_flows(request: BulkCreateCaseFlowsRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.case_flow_service import (
            build_case_step, build_case, CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum,
        )
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for item in request.caseFlows:
            try:
                steps_built = [build_case_step(
                    item.title, step_number=s.stepNumber,
                    step_type=CaseStepTypeEnum(s.stepType.strip().upper()),
                    title=s.title, created_at=s.createdAt,
                    description=s.description or "", assigned_to=s.assignedTo or "",
                ) for s in (item.steps or [])]
                cb = build_case(
                    title=item.title,
                    priority=CasePriorityEnum(item.priority.strip().upper()),
                    created_at=item.createdAt,
                    description=item.description or "",
                    status=CaseStatusEnum(item.status.strip().upper()),
                    steps=steps_built,
                    finding_ids=list(item.findingIds or []),
                    alert_ids=list(item.alertIds or []),
                    evidence_ids=list(item.evidenceIds or []),
                    playbook_ids=list(item.playbookIds or []),
                    assigned_to=item.assignedTo or "",
                    confidence=item.confidence if item.confidence is not None else 100.0,
                )
                rec_id = cb.caseId
                if rec_id in _CASE_FLOW_STORE or rec_id in succeeded:
                    failed.append({"id": item.title, "reason": f"ID '{rec_id}' exists."}); continue
                _CASE_FLOW_STORE[rec_id] = _to_store_dict(cb, item.model_dump())
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.title, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.caseFlows), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk create completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.put("/bulk/update", response_model=APIResponse)
def bulk_update_case_flows(request: BulkUpdateCaseFlowsRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.case_flow_service import (
            update_case as svc_update, build_case_step,
            CaseStatusEnum, CasePriorityEnum, CaseStepTypeEnum,
        )
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for item in request.items:
            existing = _find(_all(), item.caseFlowId)
            if not existing:
                failed.append({"id": item.caseFlowId, "reason": "Not found."}); continue
            try:
                u = item.update
                case_obj = _dict_to_case_obj(existing)
                sta_p  = CaseStatusEnum(u.status.strip().upper())   if u.status   else None
                prio_p = CasePriorityEnum(u.priority.strip().upper()) if u.priority else None
                steps_p = None
                if u.steps is not None:
                    steps_p = [build_case_step(
                        u.title or case_obj.title, step_number=s.stepNumber,
                        step_type=CaseStepTypeEnum(s.stepType.strip().upper()),
                        title=s.title, created_at=s.createdAt,
                        description=s.description or "", assigned_to=s.assignedTo or "",
                    ) for s in u.steps]
                updated_list = svc_update(
                    cases=[case_obj], case_id=case_obj.caseId,
                    created_at=u.updatedAt or case_obj.createdAt,
                    title=u.title, description=u.description,
                    status=sta_p, priority=prio_p, steps=steps_p,
                    finding_ids=u.findingIds, alert_ids=u.alertIds,
                    evidence_ids=u.evidenceIds, playbook_ids=u.playbookIds,
                    assigned_to=u.assignedTo, confidence=u.confidence,
                )
                if not updated_list:
                    failed.append({"id": item.caseFlowId, "reason": "Update failed."}); continue
                merged = dict(existing)
                for f in ("projectId","investigationId","playbookId","automationId",
                          "owner","updatedAt"):
                    v = getattr(u, f, None)
                    if v is not None: merged[f] = v
                store_dict = _to_store_dict(updated_list[0], merged)
                old_id = existing["caseFlowId"]
                if old_id in _CASE_FLOW_STORE: del _CASE_FLOW_STORE[old_id]
                _CASE_FLOW_STORE[store_dict["caseFlowId"]] = store_dict
                succeeded.append(store_dict["caseFlowId"])
            except Exception as e:
                failed.append({"id": item.caseFlowId, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.items), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk update completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.post("/bulk/delete", response_model=APIResponse)
def bulk_delete_case_flows(request: BulkDeleteCaseFlowsRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for cfid in request.caseFlowIds:
            existing = _find(_all(), cfid)
            if not existing:
                failed.append({"id": cfid, "reason": "Not found."}); continue
            try:
                del _CASE_FLOW_STORE[existing["caseFlowId"]]
                try: del _EXECUTION_STORE[existing["caseFlowId"]]
                except Exception: pass
                succeeded.append(existing["caseFlowId"])
            except Exception as e:
                failed.append({"id": cfid, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.caseFlowIds), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk delete completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))
