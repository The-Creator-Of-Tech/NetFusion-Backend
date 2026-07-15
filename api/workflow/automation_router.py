"""
Automation API Router — Canonical Schema
=========================================
All normalization via normalizers.normalize_automation() and
normalizers.normalize_automation_execution().

Key fixes applied:
  - AutomationStatus default "INACTIVE" → "DRAFT"
  - Execution status "SUCCESS" → "COMPLETED"
  - AutomationStep.action default "ALERT" → "CREATE_ALERT"
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
from api.workflow.automation_models import (
    CreateAutomationRequest, UpdateAutomationRequest,
    AutomationStepRequest, AutomationStepResponse, AutomationExecutionResponse,
    AutomationResponse, AutomationStatisticsResponse, AutomationSearchResponse,
    AutomationSummaryResponse, BulkCreateAutomationsRequest,
    BulkUpdateAutomationsRequest, BulkDeleteAutomationsRequest, BulkOperationResult,
)
from api.workflow.normalizers import normalize_automation, normalize_automation_execution
from api.persistence import RepositoryBackedDict, AutomationExecutionsStore, map_automation

automation_router = APIRouter(prefix="/automation", tags=["Automation Engine"])
_AUTOMATION_STORE = RepositoryBackedDict("automation", "automationId", map_automation)
_EXECUTION_STORE  = AutomationExecutionsStore()
_AUTOMATION_NS    = uuid.UUID("6ba7b886-9dad-11d1-80b4-00c04fd430c8")


def _reset_store() -> None:
    _AUTOMATION_STORE.clear()
    _EXECUTION_STORE.clear()


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _to_response(raw: Dict) -> AutomationResponse:
    c = normalize_automation(raw)
    steps = [AutomationStepResponse(**s) for s in c["steps"]]
    return AutomationResponse(
        automationId=c["automationId"], automationKey=c["automationKey"],
        name=c["name"], description=c["description"],
        status=c["status"], trigger=c["trigger"],
        projectId=c["projectId"], investigationId=c["investigationId"],
        playbookId=c["playbookId"], ruleId=c["ruleId"],
        steps=steps, priority=c["priority"],
        createdAt=c["createdAt"], updatedAt=c["updatedAt"],
        enabled=c["enabled"], category=c["category"], author=c["author"],
    )


def _all() -> List[Dict]:
    return sorted(
        [normalize_automation(a) for a in _AUTOMATION_STORE.values()],
        key=lambda a: a["name"],
    )


def _find(items: List[Dict], ident: str) -> Optional[Dict]:
    n = ident.strip().lower()
    for a in items:
        if a["automationId"].lower() == n:   return a
        if a["automationKey"].lower() == n:  return a
        if a["name"].lower() == n:           return a
    return None


def _sort(items, sort_by, sort_order):
    valid = {"automationName","createdAt","updatedAt","priority","enabled","stepCount","executionCount"}
    if sort_by not in valid:
        raise APIErrorValidation("Invalid sort field.",
            details=[f"'{sort_by}' not supported. Valid: {sorted(valid)}"])
    if sort_order.lower() not in {"asc","desc"}:
        raise APIErrorValidation("Invalid sort order.")
    def key(a):
        if sort_by == "automationName":  return a["name"]
        if sort_by == "stepCount":       return len(a["steps"])
        if sort_by == "executionCount":  return len(_EXECUTION_STORE.get(a["automationId"], []))
        if sort_by == "enabled":         return int(a["enabled"])
        return a.get(sort_by,"") or ""
    base = sorted(items, key=lambda x: x["automationId"])
    base.sort(key=key, reverse=(sort_order.lower()=="desc"))
    return base


def _filter(items, enabled=None, priority=None, category=None, author=None,
             projectId=None, investigationId=None, playbookId=None, ruleId=None,
             minimumSteps=None, maximumSteps=None, createdAfter=None, createdBefore=None):
    r = list(items)
    if enabled         is not None: r = [x for x in r if bool(x["enabled"])==enabled]
    if priority        is not None: r = [x for x in r if x["priority"]==priority]
    if category        is not None: r = [x for x in r if x["category"].lower()==category.strip().lower()]
    if author          is not None: r = [x for x in r if author.strip().lower() in x["author"].lower()]
    if projectId       is not None: r = [x for x in r if x["projectId"]==projectId.strip()]
    if investigationId is not None: r = [x for x in r if x["investigationId"]==investigationId.strip()]
    if playbookId      is not None: r = [x for x in r if x["playbookId"]==playbookId.strip()]
    if ruleId          is not None: r = [x for x in r if x["ruleId"]==ruleId.strip()]
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
    return [a for a in items if (
        ql in a["name"].lower() or ql in a["description"].lower()
        or ql in a["category"].lower() or ql in a["author"].lower()
        or ql in a["playbookId"].lower() or ql in a["ruleId"].lower()
        or any(ql in s["name"].lower() for s in a["steps"])
    )]


def _stats(items) -> Dict:
    total = len(items)
    enabled = sum(1 for a in items if a["enabled"])
    total_exec = sum(len(_EXECUTION_STORE.get(a["automationId"], [])) for a in items)
    ts = sum(len(a["steps"])  for a in items)
    tp = sum(a["priority"]    for a in items)
    cat: Dict[str,int] = {}
    for a in items:
        c = a["category"].strip()
        if c: cat[c] = cat.get(c,0)+1
    return {
        "totalAutomations":    total,
        "enabledAutomations":  enabled,
        "disabledAutomations": total-enabled,
        "totalExecutions":     total_exec,
        "averageSteps":        round(ts/total,4) if total else 0.0,
        "averageExecutions":   round(total_exec/total,4) if total else 0.0,
        "averagePriority":     round(tp/total,4) if total else 0.0,
        "categoryCounts":      dict(sorted(cat.items())),
    }


def _summary(a: Dict) -> Dict:
    name = a["name"]; st = a["status"]; tr = a["trigger"]
    sc = len(a["steps"]); ec = len(_EXECUTION_STORE.get(a["automationId"],[]))
    return {
        "automationId":   a["automationId"],
        "automationName": name,
        "summaryText": (
            f"Automation '{name}' ({st}) has {sc} steps and {ec} executions. "
            f"Triggered by {tr}, {'enabled' if a['enabled'] else 'disabled'}."
        ),
        "stepCount": sc, "executionCount": ec,
        "status": st, "trigger": tr,
        "enabled": a["enabled"], "priority": a["priority"],
    }


def _to_store_dict(auto_obj, req_dict: Dict) -> Dict:
    steps = []
    for s in auto_obj.steps:
        steps.append({
            "stepId":      s.stepId,      "stepKey":     s.stepKey,
            "stepNumber":  s.stepNumber,  "name":        s.name,
            "description": s.description, "action":      s.action.value,
            "parameters":  s.parameters,  "createdAt":   s.createdAt,
        })
    return {
        "automationId":    auto_obj.automationId,
        "automationKey":   auto_obj.automationKey,
        "name":            auto_obj.name,
        "description":     auto_obj.description,
        "status":          auto_obj.status.value,
        "trigger":         auto_obj.trigger.value,
        "steps":           steps,
        "priority":        auto_obj.priority,
        "createdAt":       auto_obj.createdAt,
        "updatedAt":       req_dict.get("updatedAt"),
        "enabled":         bool(req_dict.get("enabled", True)),
        "category":        req_dict.get("category", ""),
        "author":          req_dict.get("author", ""),
        "projectId":       req_dict.get("projectId", ""),
        "investigationId": req_dict.get("investigationId") or "",
        "playbookId":      req_dict.get("playbookId") or "",
        "ruleId":          req_dict.get("ruleId") or "",
    }


def _dict_to_auto_obj(d: Dict):
    from services.automation_engine_service import (
        Automation, AutomationStep, AutomationActionEnum,
        AutomationStatusEnum, AutomationTriggerEnum, build_automation,
    )
    n = normalize_automation(d)
    steps = []
    for s in n["steps"]:
        try:   act = AutomationActionEnum(s["action"].strip().upper())
        except ValueError: act = AutomationActionEnum("CREATE_ALERT")
        steps.append(AutomationStep(
            stepId=s["stepId"], stepKey=s["stepKey"],
            stepNumber=s["stepNumber"], name=s["name"],
            description=s["description"], action=act,
            parameters=s["parameters"], createdAt=s["createdAt"],
        ))
    try:   stat = AutomationStatusEnum(n["status"].strip().upper())
    except ValueError: stat = AutomationStatusEnum("DRAFT")
    try:   trig = AutomationTriggerEnum(n["trigger"].strip().upper())
    except ValueError: trig = AutomationTriggerEnum("MANUAL")
    return Automation(
        automationId=n["automationId"], automationKey=n["automationKey"],
        name=n["name"], description=n["description"],
        status=stat, trigger=trig, steps=tuple(steps),
        priority=n["priority"], createdAt=n["createdAt"],
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@automation_router.get("/", response_model=APIResponse)
def list_automations(
    enabled: Optional[bool]=None, priority: Optional[int]=None,
    category: Optional[str]=None, author: Optional[str]=None,
    projectId: Optional[str]=None, investigationId: Optional[str]=None,
    playbookId: Optional[str]=None, ruleId: Optional[str]=None,
    minimumSteps: Optional[int]=None, maximumSteps: Optional[int]=None,
    createdAfter: Optional[str]=None, createdBefore: Optional[str]=None,
    sortBy: str="automationName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _filter(_all(), enabled=enabled, priority=priority,
            category=category, author=author, projectId=projectId,
            investigationId=investigationId, playbookId=playbookId, ruleId=ruleId,
            minimumSteps=minimumSteps, maximumSteps=maximumSteps,
            createdAfter=createdAfter, createdBefore=createdBefore)
        items = _sort(items, sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        return build_paginated_response(
            items=[_to_response(x).model_dump() for x in page_items],
            page=page, page_size=pageSize, total_items=total,
            message="Automations retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get("/statistics", response_model=APIResponse)
def get_automation_statistics() -> APIResponse:
    try:
        return build_success_response(data=_stats(_all()),
            message="Statistics computed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get("/search", response_model=APIResponse)
def search_automations(
    q: str="", sortBy: str="automationName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _sort(_search(_all(), q), sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        total_pages = math.ceil(total/pageSize) if total else 1
        payload = AutomationSearchResponse(
            automations=[_to_response(x) for x in page_items],
            total=total, page=page, pageSize=pageSize,
            totalPages=total_pages, query=q, sortBy=sortBy, sortOrder=sortOrder,
        )
        return build_success_response(data=payload.model_dump(),
            message="Search completed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get("/{automationId}", response_model=APIResponse)
def get_automation(automationId: str) -> APIResponse:
    try:
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        return build_success_response(data=_to_response(c).model_dump(),
            message="Automation retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.post("/", response_model=APIResponse)
def create_automation(request: CreateAutomationRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.automation_engine_service import (
            build_automation_step, build_automation,
            AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum,
        )
        steps_built = [build_automation_step(
            request.name, step_number=s.stepNumber, name=s.name,
            action=AutomationActionEnum(s.action.strip().upper()),
            created_at=s.createdAt, description=s.description or "",
            parameters=s.parameters or {},
        ) for s in (request.steps or [])]

        ab = build_automation(
            name=request.name,
            trigger=AutomationTriggerEnum(request.trigger.strip().upper()),
            status=AutomationStatusEnum(request.status.strip().upper()),
            steps=steps_built, created_at=request.createdAt,
            description=request.description or "",
            priority=request.priority,
        )
        rec_id = ab.automationId
        if rec_id in _AUTOMATION_STORE:
            raise APIErrorConflict(f"Automation '{rec_id}' already exists.")
        store_dict = _to_store_dict(ab, request.model_dump())
        _AUTOMATION_STORE[rec_id] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Automation created successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.put("/{automationId}", response_model=APIResponse)
def update_automation_route(automationId: str,
                             request: UpdateAutomationRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        from services.automation_engine_service import (
            update_automation as svc_update, build_automation_step,
            AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum,
        )
        auto_obj = _dict_to_auto_obj(c)
        sta_p  = AutomationStatusEnum(request.status.strip().upper())   if request.status  else None
        trig_p = AutomationTriggerEnum(request.trigger.strip().upper())  if request.trigger else None
        steps_p = ([build_automation_step(
            request.name or auto_obj.name, step_number=s.stepNumber, name=s.name,
            action=AutomationActionEnum(s.action.strip().upper()),
            created_at=s.createdAt, description=s.description or "",
            parameters=s.parameters or {},
        ) for s in request.steps] if request.steps is not None else None)
        updated_list = svc_update(
            automations=[auto_obj], automation_id=auto_obj.automationId,
            created_at=request.updatedAt or auto_obj.createdAt,
            name=request.name, description=request.description,
            status=sta_p, trigger=trig_p, steps=steps_p, priority=request.priority,
        )
        if not updated_list: raise APIErrorInternal("Update failed.")
        merged = dict(c)
        for field in ("enabled","category","author","projectId","investigationId",
                      "playbookId","ruleId","updatedAt"):
            v = getattr(request, field, None)
            if v is not None: merged[field] = v
        store_dict = _to_store_dict(updated_list[0], merged)
        old_id = c["automationId"]
        if old_id in _AUTOMATION_STORE: del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[store_dict["automationId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Automation updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.delete("/{automationId}", response_model=APIResponse)
def delete_automation(automationId: str) -> APIResponse:
    try:
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        del _AUTOMATION_STORE[c["automationId"]]
        try: del _EXECUTION_STORE[c["automationId"]]
        except Exception: pass
        return build_success_response(data={"automationId": c["automationId"]},
            message="Automation deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Steps sub-resource
# ---------------------------------------------------------------------------

@automation_router.get("/{automationId}/steps", response_model=APIResponse)
def get_automation_steps(automationId: str) -> APIResponse:
    try:
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        return build_success_response(
            data=_to_response(c).model_dump()["steps"],
            message="Steps retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.post("/{automationId}/steps", response_model=APIResponse)
def append_automation_step(automationId: str,
                            request: AutomationStepRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        from services.automation_engine_service import (
            build_automation_step, add_automation_step, AutomationActionEnum,
        )
        auto_obj = _dict_to_auto_obj(c)
        new_step = build_automation_step(
            auto_obj.automationId, step_number=request.stepNumber, name=request.name,
            action=AutomationActionEnum(request.action.strip().upper()),
            created_at=request.createdAt, description=request.description or "",
            parameters=request.parameters or {}, validate=False,
        )
        new_auto = add_automation_step(auto_obj, new_step, request.createdAt)
        updated = _to_store_dict(new_auto, c)
        old_id = c["automationId"]
        if old_id in _AUTOMATION_STORE: del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[updated["automationId"]] = updated
        return build_success_response(data=_to_response(updated).model_dump(),
            message="Step appended successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.put("/{automationId}/steps/{stepId}", response_model=APIResponse)
def update_automation_step_route(automationId: str, stepId: str,
                                  request: AutomationStepRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        from services.automation_engine_service import (
            update_automation_step as svc_upd, AutomationActionEnum,
        )
        auto_obj = _dict_to_auto_obj(c)
        if not any(s.stepId == stepId for s in auto_obj.steps):
            raise APIErrorNotFound(f"Step '{stepId}' not found.")
        new_auto = svc_upd(auto_obj, stepId, created_at=request.createdAt,
            name=request.name, description=request.description or "",
            action=AutomationActionEnum(request.action.strip().upper()),
            parameters=request.parameters or {})
        updated = _to_store_dict(new_auto, c)
        old_id = c["automationId"]
        if old_id in _AUTOMATION_STORE: del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[updated["automationId"]] = updated
        return build_success_response(data=_to_response(updated).model_dump(),
            message="Step updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.delete("/{automationId}/steps/{stepId}", response_model=APIResponse)
def delete_automation_step_route(automationId: str, stepId: str) -> APIResponse:
    try:
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        from services.automation_engine_service import remove_automation_step
        auto_obj = _dict_to_auto_obj(c)
        if not any(s.stepId == stepId for s in auto_obj.steps):
            raise APIErrorNotFound(f"Step '{stepId}' not found.")
        ts = auto_obj.steps[0].createdAt if auto_obj.steps else "2026-07-06T12:00:00Z"
        new_auto = remove_automation_step(auto_obj, stepId, ts)
        updated = _to_store_dict(new_auto, c)
        old_id = c["automationId"]
        if old_id in _AUTOMATION_STORE: del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[updated["automationId"]] = updated
        return build_success_response(data=_to_response(updated).model_dump(),
            message="Step deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Execution endpoints — status uses AutomationExecutionStatus (COMPLETED not SUCCESS)
# ---------------------------------------------------------------------------

@automation_router.post("/{automationId}/execute", response_model=APIResponse)
def execute_automation(automationId: str, timestamp: str = Body(..., embed=True)) -> APIResponse:
    try:
        if not timestamp or not timestamp.strip():
            raise APIErrorValidation("timestamp must be non-empty.")
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        auto_id = c["automationId"]
        exec_id = str(uuid.uuid5(_AUTOMATION_NS, f"{auto_id}:{timestamp}"))
        step_results = [{
            "stepId": s["stepId"], "name": s["name"], "action": s["action"],
            "status": "COMPLETED",   # ← Prisma AutomationExecutionStatus
            "message": f"Step '{s['name']}' executed.",
            "output": {"executedAt": timestamp},
        } for s in c["steps"]]
        execution = {
            "executionId": exec_id, "automationId": auto_id,
            "status": "COMPLETED",   # ← Prisma AutomationExecutionStatus (was "SUCCESS")
            "startedAt": timestamp,  "completedAt": timestamp,
            "stepResults": step_results,
        }
        _EXECUTION_STORE.setdefault(auto_id, []).append(execution)
        return build_success_response(
            data=AutomationExecutionResponse(**normalize_automation_execution(execution)).model_dump(),
            message="Automation executed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get("/{automationId}/executions", response_model=APIResponse)
def get_executions(automationId: str) -> APIResponse:
    try:
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        execs = _EXECUTION_STORE.get(c["automationId"], [])
        return build_success_response(
            data=[AutomationExecutionResponse(**normalize_automation_execution(x)).model_dump()
                  for x in execs],
            message="Executions retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get("/{automationId}/summary", response_model=APIResponse)
def get_automation_summary(automationId: str) -> APIResponse:
    try:
        c = _find(_all(), automationId)
        if not c: raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        return build_success_response(
            data=AutomationSummaryResponse(**_summary(c)).model_dump(),
            message="Summary generated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

@automation_router.post("/bulk/create", response_model=APIResponse)
def bulk_create_automations(request: BulkCreateAutomationsRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.automation_engine_service import (
            build_automation_step, build_automation,
            AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum,
        )
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for item in request.automations:
            try:
                steps_built = [build_automation_step(
                    item.name, step_number=s.stepNumber, name=s.name,
                    action=AutomationActionEnum(s.action.strip().upper()),
                    created_at=s.createdAt, description=s.description or "",
                    parameters=s.parameters or {},
                ) for s in (item.steps or [])]
                ab = build_automation(
                    name=item.name,
                    trigger=AutomationTriggerEnum(item.trigger.strip().upper()),
                    status=AutomationStatusEnum(item.status.strip().upper()),
                    steps=steps_built, created_at=item.createdAt,
                    description=item.description or "", priority=item.priority,
                )
                rec_id = ab.automationId
                if rec_id in _AUTOMATION_STORE or rec_id in succeeded:
                    failed.append({"id": item.name, "reason": f"ID '{rec_id}' already exists."}); continue
                _AUTOMATION_STORE[rec_id] = _to_store_dict(ab, item.model_dump())
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.name, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.automations), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk create completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.put("/bulk/update", response_model=APIResponse)
def bulk_update_automations(request: BulkUpdateAutomationsRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.automation_engine_service import (
            update_automation as svc_update, build_automation_step,
            AutomationStatusEnum, AutomationTriggerEnum, AutomationActionEnum,
        )
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for item in request.items:
            existing = _find(_all(), item.automationId)
            if not existing:
                failed.append({"id": item.automationId, "reason": "Not found."}); continue
            try:
                u = item.update
                auto_obj = _dict_to_auto_obj(existing)
                sta_p  = AutomationStatusEnum(u.status.strip().upper())  if u.status  else None
                trig_p = AutomationTriggerEnum(u.trigger.strip().upper()) if u.trigger else None
                steps_p = ([build_automation_step(
                    u.name or auto_obj.name, step_number=s.stepNumber, name=s.name,
                    action=AutomationActionEnum(s.action.strip().upper()),
                    created_at=s.createdAt, description=s.description or "",
                    parameters=s.parameters or {},
                ) for s in u.steps] if u.steps is not None else None)
                updated_list = svc_update(
                    automations=[auto_obj], automation_id=auto_obj.automationId,
                    created_at=u.updatedAt or auto_obj.createdAt,
                    name=u.name, description=u.description,
                    status=sta_p, trigger=trig_p, steps=steps_p, priority=u.priority,
                )
                if not updated_list:
                    failed.append({"id": item.automationId, "reason": "Update failed."}); continue
                merged = dict(existing)
                for f in ("enabled","category","author","projectId","investigationId",
                          "playbookId","ruleId","updatedAt"):
                    v = getattr(u, f, None)
                    if v is not None: merged[f] = v
                store_dict = _to_store_dict(updated_list[0], merged)
                old_id = existing["automationId"]
                if old_id in _AUTOMATION_STORE: del _AUTOMATION_STORE[old_id]
                _AUTOMATION_STORE[store_dict["automationId"]] = store_dict
                succeeded.append(store_dict["automationId"])
            except Exception as e:
                failed.append({"id": item.automationId, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.items), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk update completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.post("/bulk/delete", response_model=APIResponse)
def bulk_delete_automations(request: BulkDeleteAutomationsRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for aid in request.automationIds:
            existing = _find(_all(), aid)
            if not existing:
                failed.append({"id": aid, "reason": "Not found."}); continue
            try:
                del _AUTOMATION_STORE[existing["automationId"]]
                try: del _EXECUTION_STORE[existing["automationId"]]
                except Exception: pass
                succeeded.append(existing["automationId"])
            except Exception as e:
                failed.append({"id": aid, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.automationIds), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk delete completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))
