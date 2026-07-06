"""
Automation API Router — Phase A4.10.3
======================================
REST interface for Automation Engine.
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
from api.workflow.automation_models import (
    CreateAutomationRequest,
    UpdateAutomationRequest,
    AutomationStepRequest,
    AutomationStepResponse,
    AutomationExecutionResponse,
    AutomationResponse,
    AutomationListResponse,
    AutomationStatisticsResponse,
    AutomationSearchResponse,
    AutomationSummaryResponse,
    BulkCreateAutomationsRequest,
    BulkUpdateAutomationsRequest,
    BulkDeleteAutomationsRequest,
    BulkOperationResult,
)

from services.automation_engine_service import (
    Automation,
    AutomationStep,
    AutomationStatusEnum,
    AutomationTriggerEnum,
    AutomationActionEnum,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

automation_router: APIRouter = APIRouter(
    prefix="/automation",
    tags=["Automation Engine"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
# Dict[automationId -> Automation dict]
_AUTOMATION_STORE: Dict[str, Dict[str, Any]] = {}

# Dict[automationId -> List[Execution dict]]
_EXECUTION_STORE: Dict[str, List[Dict[str, Any]]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _AUTOMATION_STORE.clear()
    _EXECUTION_STORE.clear()


def _all_automations() -> List[Dict[str, Any]]:
    """Return all automations ordered by name ASC."""
    return sorted(_AUTOMATION_STORE.values(), key=lambda a: a.get("name", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_automation(automations: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds an automation by automationId, automationKey, or name (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for a in automations:
        if a.get("automationId", "").lower() == normalized:
            return a
        if a.get("automationKey", "").lower() == normalized:
            return a
        if a.get("name", "").lower() == normalized:
            return a
    return None


def find_automation_step(steps: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a step by stepId, stepKey, name, or stepNumber."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for s in steps:
        if s.get("stepId", "").lower() == normalized:
            return s
        if s.get("stepKey", "").lower() == normalized:
            return s
        if s.get("name", "").lower() == normalized:
            return s
        if str(s.get("stepNumber")) == normalized:
            return s
    return None


def search_automations(automations: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text, metadata, trigger, and step fields."""
    if not query or not query.strip():
        return list(automations)
    q = query.strip().lower()
    results = []
    for a in automations:
        if q in a.get("name", "").lower():
            results.append(a)
            continue
        if q in a.get("description", "").lower():
            results.append(a)
            continue
        if q in a.get("category", "").lower():
            results.append(a)
            continue
        if q in a.get("author", "").lower():
            results.append(a)
            continue
        if q in a.get("playbookId", "").lower():
            results.append(a)
            continue
        if q in a.get("ruleId", "").lower():
            results.append(a)
            continue
        if any(q in s.get("name", "").lower() or q in s.get("description", "").lower() for s in a.get("steps", [])):
            results.append(a)
            continue
    return results


def search_automation_steps(steps: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across step fields."""
    if not query or not query.strip():
        return list(steps)
    q = query.strip().lower()
    results = []
    for s in steps:
        if q in s.get("name", "").lower():
            results.append(s)
            continue
        if q in s.get("description", "").lower():
            results.append(s)
            continue
        if q in s.get("action", "").lower():
            results.append(s)
            continue
    return results


def sort_automations(
    automations: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts automations deterministically, falling back to automationId ASC."""
    valid_fields = {"automationName", "createdAt", "updatedAt", "priority", "enabled", "stepCount", "executionCount"}
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

    def get_sort_key(a: Dict[str, Any]) -> Any:
        if sort_by == "automationName":
            return a.get("name", "")
        elif sort_by == "createdAt":
            return a.get("createdAt", "")
        elif sort_by == "updatedAt":
            return a.get("updatedAt", "") or ""
        elif sort_by == "priority":
            return a.get("priority", 100)
        elif sort_by == "enabled":
            return int(a.get("enabled", True))
        elif sort_by == "stepCount":
            return len(a.get("steps", []))
        elif sort_by == "executionCount":
            return len(_EXECUTION_STORE.get(a.get("automationId", ""), []))
        return ""

    reverse = (order == "desc")
    # Stable sort
    sorted_list = sorted(automations, key=lambda x: x.get("automationId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_automations(
    automations: List[Dict[str, Any]],
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
    category: Optional[str] = None,
    author: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    playbookId: Optional[str] = None,
    ruleId: Optional[str] = None,
    minimumSteps: Optional[int] = None,
    maximumSteps: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filters automations list matching all provided criteria."""
    filtered = list(automations)

    if enabled is not None:
        filtered = [a for a in filtered if bool(a.get("enabled", True)) == enabled]

    if priority is not None:
        filtered = [a for a in filtered if a.get("priority") == priority]

    if category is not None:
        cat_val = category.strip().lower()
        filtered = [a for a in filtered if a.get("category", "").lower() == cat_val]

    if author is not None:
        auth_val = author.strip().lower()
        filtered = [a for a in filtered if auth_val in a.get("author", "").lower()]

    if projectId is not None:
        proj_val = projectId.strip()
        filtered = [a for a in filtered if a.get("projectId") == proj_val]

    if investigationId is not None:
        inv_val = investigationId.strip()
        filtered = [a for a in filtered if a.get("investigationId") == inv_val]

    if playbookId is not None:
        pb_val = playbookId.strip()
        filtered = [a for a in filtered if a.get("playbookId") == pb_val]

    if ruleId is not None:
        r_val = ruleId.strip()
        filtered = [a for a in filtered if a.get("ruleId") == r_val]

    if minimumSteps is not None:
        filtered = [a for a in filtered if len(a.get("steps", [])) >= minimumSteps]

    if maximumSteps is not None:
        filtered = [a for a in filtered if len(a.get("steps", [])) <= maximumSteps]

    if createdAfter is not None:
        after_val = createdAfter.strip()
        filtered = [a for a in filtered if a.get("createdAt", "") >= after_val]

    if createdBefore is not None:
        before_val = createdBefore.strip()
        filtered = [a for a in filtered if a.get("createdAt", "") <= before_val]

    return filtered


def paginate_automations(
    automations: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Helper to paginate the dataset."""
    total_items = len(automations)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = automations[start:end]
    return sliced, total_items


def execute_automation(automation: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
    """Deterministically runs an automation step execution and stores logs."""
    import uuid
    from services.automation_engine_service import _AUTOMATION_NS

    auto_id = automation.get("automationId")
    execution_id = str(uuid.uuid5(_AUTOMATION_NS, f"{auto_id}:{timestamp}"))

    step_results = []
    status = "SUCCESS"
    for s in automation.get("steps", []):
        step_results.append({
            "stepId": s.get("stepId"),
            "name": s.get("name"),
            "action": s.get("action"),
            "status": "SUCCESS",
            "message": f"Step '{s.get('name')}' executed successfully.",
            "output": {"executedAt": timestamp, "parametersMatched": True}
        })

    execution = {
        "executionId": execution_id,
        "automationId": auto_id,
        "status": status,
        "startedAt": timestamp,
        "completedAt": timestamp,
        "stepResults": step_results,
    }

    _EXECUTION_STORE.setdefault(auto_id, []).append(execution)
    return execution


def build_automation_summary(automation: Dict[str, Any]) -> Dict[str, Any]:
    """Formulates a standard summary response for an automation."""
    name = automation.get("name", "")
    step_cnt = len(automation.get("steps", []))
    exec_cnt = len(_EXECUTION_STORE.get(automation.get("automationId", ""), []))
    status = automation.get("status", "")
    trigger = automation.get("trigger", "")
    enabled = automation.get("enabled", True)
    priority = automation.get("priority", 100)

    text = (
        f"Automation '{name}' ({status}) has {step_cnt} steps and {exec_cnt} executions. "
        f"It is triggered by {trigger} with priority {priority} and is {'enabled' if enabled else 'disabled'}."
    )
    return {
        "automationId": automation.get("automationId", ""),
        "automationName": name,
        "summaryText": text,
        "stepCount": step_cnt,
        "executionCount": exec_cnt,
        "status": status,
        "trigger": trigger,
        "enabled": enabled,
        "priority": priority,
    }


def calculate_automation_statistics(automations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes aggregate stats over the unique automations list."""
    total = len(automations)
    enabled = sum(1 for a in automations if a.get("enabled", True))
    disabled = total - enabled

    total_executions = sum(len(_EXECUTION_STORE.get(a.get("automationId", ""), [])) for a in automations)
    avg_executions = round(total_executions / total, 4) if total > 0 else 0.0

    total_steps = sum(len(a.get("steps", [])) for a in automations)
    avg_steps = round(total_steps / total, 4) if total > 0 else 0.0

    total_priority = sum(a.get("priority", 100) for a in automations)
    avg_priority = round(total_priority / total, 4) if total > 0 else 0.0

    category_counts: Dict[str, int] = {}
    for a in automations:
        cat = a.get("category", "").strip()
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "totalAutomations": total,
        "enabledAutomations": enabled,
        "disabledAutomations": disabled,
        "totalExecutions": total_executions,
        "averageSteps": avg_steps,
        "averageExecutions": avg_executions,
        "averagePriority": avg_priority,
        "categoryCounts": dict(sorted(category_counts.items())),
    }


def _dict_to_automation_object(d: Dict[str, Any]) -> Automation:
    """Helper to convert stored dictionary format to core Automation object."""
    steps_objs = []
    for s in d.get("steps", []):
        steps_objs.append(
            AutomationStep(
                stepId=s["stepId"],
                stepKey=s["stepKey"],
                stepNumber=s["stepNumber"],
                name=s["name"],
                description=s["description"],
                action=AutomationActionEnum(s["action"]),
                parameters=s["parameters"],
                createdAt=s["createdAt"],
            )
        )
    return Automation(
        automationId=d["automationId"],
        automationKey=d["automationKey"],
        name=d["name"],
        description=d["description"],
        status=AutomationStatusEnum(d["status"]),
        trigger=AutomationTriggerEnum(d["trigger"]),
        steps=tuple(steps_objs),
        priority=d["priority"],
        createdAt=d["createdAt"],
    )


def _to_store_dict(a: Automation, original_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert Automation core object to dictionary store format."""
    steps_list = []
    for s in a.steps:
        steps_list.append({
            "stepId": s.stepId,
            "stepKey": s.stepKey,
            "stepNumber": s.stepNumber,
            "name": s.name,
            "description": s.description,
            "action": s.action.value,
            "parameters": s.parameters,
            "createdAt": s.createdAt,
        })
    return {
        "automationId": a.automationId,
        "automationKey": a.automationKey,
        "name": a.name,
        "description": a.description,
        "status": a.status.value,
        "trigger": a.trigger.value,
        "steps": steps_list,
        "priority": a.priority,
        "createdAt": a.createdAt,
        "updatedAt": original_dict.get("updatedAt"),
        "enabled": original_dict.get("enabled", True),
        "category": original_dict.get("category", ""),
        "author": original_dict.get("author", ""),
        "projectId": original_dict.get("projectId", ""),
        "investigationId": original_dict.get("investigationId", ""),
        "playbookId": original_dict.get("playbookId", ""),
        "ruleId": original_dict.get("ruleId", ""),
    }


def _to_response_model(c: Dict[str, Any]) -> AutomationResponse:
    """Helper to convert stored dictionary to AutomationResponse model."""
    steps_resp = [
        AutomationStepResponse(
            stepId=s["stepId"],
            stepKey=s["stepKey"],
            stepNumber=s["stepNumber"],
            name=s["name"],
            description=s["description"],
            action=s["action"],
            parameters=s["parameters"],
            createdAt=s["createdAt"],
        )
        for s in c.get("steps", [])
    ]
    return AutomationResponse(
        automationId=c["automationId"],
        automationKey=c["automationKey"],
        name=c["name"],
        description=c["description"],
        status=c["status"],
        trigger=c["trigger"],
        steps=steps_resp,
        priority=c["priority"],
        createdAt=c["createdAt"],
        updatedAt=c.get("updatedAt"),
        enabled=c["enabled"],
        category=c["category"],
        author=c["author"],
        projectId=c["projectId"],
        investigationId=c["investigationId"],
        playbookId=c["playbookId"],
        ruleId=c["ruleId"],
    )


# ---------------------------------------------------------------------------
# Step operations implementing immutable reconstruction using core service
# ---------------------------------------------------------------------------

def append_automation_step(automation: Dict[str, Any], step_req: AutomationStepRequest) -> Dict[str, Any]:
    """Appends step by rebuilding the immutable Automation object using core service."""
    from services.automation_engine_service import build_automation_step, add_automation_step

    auto_obj = _dict_to_automation_object(automation)
    st = AutomationActionEnum(step_req.action.strip().upper())
    new_step = build_automation_step(
        auto_obj.automationId,
        step_number=step_req.stepNumber,
        name=step_req.name,
        action=st,
        created_at=step_req.createdAt,
        description=step_req.description or "",
        parameters=step_req.parameters or {},
        validate=False,
    )
    new_auto = add_automation_step(auto_obj, new_step, step_req.createdAt)
    return _to_store_dict(new_auto, automation)


def update_automation_step(automation: Dict[str, Any], step_id: str, step_req: AutomationStepRequest) -> Dict[str, Any]:
    """Updates step by rebuilding the immutable Automation object using core service."""
    from services.automation_engine_service import update_automation_step as service_update_step

    auto_obj = _dict_to_automation_object(automation)
    st = AutomationActionEnum(step_req.action.strip().upper())
    new_auto = service_update_step(
        auto_obj,
        step_id,
        created_at=step_req.createdAt,
        name=step_req.name,
        description=step_req.description or "",
        action=st,
        parameters=step_req.parameters or {},
    )
    if new_auto.automationId == auto_obj.automationId and len(new_auto.steps) == len(auto_obj.steps):
        if not any(s.stepId == step_id for s in auto_obj.steps):
            raise APIErrorNotFound(f"Step with ID '{step_id}' not found.")
    return _to_store_dict(new_auto, automation)


def delete_automation_step(automation: Dict[str, Any], step_id: str) -> Dict[str, Any]:
    """Deletes step by rebuilding the immutable Automation object using core service."""
    from services.automation_engine_service import remove_automation_step

    auto_obj = _dict_to_automation_object(automation)
    if not any(s.stepId == step_id for s in auto_obj.steps):
        raise APIErrorNotFound(f"Step with ID '{step_id}' not found.")
    ts = "2026-07-06T12:00:00Z"
    if auto_obj.steps:
        ts = auto_obj.steps[0].createdAt
    new_auto = remove_automation_step(auto_obj, step_id, ts)
    return _to_store_dict(new_auto, automation)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@automation_router.get(
    "/",
    response_model=APIResponse,
    summary="List automation records",
)
def list_automations_endpoint(
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
    category: Optional[str] = None,
    author: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    playbookId: Optional[str] = None,
    ruleId: Optional[str] = None,
    minimumSteps: Optional[int] = None,
    maximumSteps: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
    sortBy: str = "automationName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_automations_list = _all_automations()

        filtered = filter_automations(
            all_automations_list,
            enabled=enabled,
            priority=priority,
            category=category,
            author=author,
            projectId=projectId,
            investigationId=investigationId,
            playbookId=playbookId,
            ruleId=ruleId,
            minimumSteps=minimumSteps,
            maximumSteps=maximumSteps,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_list = sort_automations(filtered, sortBy, sortOrder)
        sliced, total = paginate_automations(sorted_list, page, pageSize)

        serialized = [_to_response_model(x).model_dump() for x in sliced]
        return build_paginated_response(
            items=serialized,
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Automations retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get automation statistics",
)
def get_automation_statistics_endpoint() -> APIResponse:
    try:
        all_automations_list = _all_automations()
        stats = calculate_automation_statistics(all_automations_list)
        payload = AutomationStatisticsResponse(**stats).model_dump()
        return build_success_response(
            data=payload,
            message="Automation statistics computed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search automations",
)
def search_automations_endpoint(
    q: str = "",
    sortBy: str = "automationName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_automations_list = _all_automations()

        searched = search_automations(all_automations_list, q)
        sorted_list = sort_automations(searched, sortBy, sortOrder)
        sliced, total = paginate_automations(sorted_list, page, pageSize)

        serialized = [_to_response_model(x).model_dump() for x in sliced]
        total_pages = math.ceil(total / pageSize) if total > 0 else 1

        search_data = AutomationSearchResponse(
            automations=serialized,
            total=total,
            page=page,
            pageSize=pageSize,
            totalPages=total_pages,
            query=q,
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


@automation_router.get(
    "/{automationId}",
    response_model=APIResponse,
    summary="Get automation by ID",
)
def get_automation(automationId: str) -> APIResponse:
    try:
        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="Automation retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.post(
    "/",
    response_model=APIResponse,
    summary="Create an automation record",
)
def create_automation(
    request: CreateAutomationRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.automation_engine_service import (
            build_automation_step,
            build_automation,
            AutomationStatusEnum,
            AutomationTriggerEnum,
            AutomationActionEnum,
        )

        # Build steps
        steps_built = []
        for s in (request.steps or []):
            st = AutomationActionEnum(s.action.strip().upper())
            steps_built.append(
                build_automation_step(
                    request.name,
                    step_number=s.stepNumber,
                    name=s.name,
                    action=st,
                    created_at=s.createdAt,
                    description=s.description or "",
                    parameters=s.parameters or {},
                )
            )

        try:
            stat_enum = AutomationStatusEnum(request.status.strip().upper())
            trig_enum = AutomationTriggerEnum(request.trigger.strip().upper())
            ab = build_automation(
                name=request.name,
                trigger=trig_enum,
                created_at=request.createdAt,
                description=request.description or "",
                status=stat_enum,
                steps=steps_built,
                priority=request.priority,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = ab.automationId
        if rec_id in _AUTOMATION_STORE:
            raise APIErrorConflict(f"Automation with ID '{rec_id}' already exists.")

        auto_dict = _to_store_dict(ab, request.model_dump())
        _AUTOMATION_STORE[rec_id] = auto_dict

        return build_success_response(
            data=_to_response_model(auto_dict).model_dump(),
            message="Automation created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.put(
    "/{automationId}",
    response_model=APIResponse,
    summary="Update an automation record",
)
def update_automation_route(
    automationId: str,
    request: UpdateAutomationRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        # Map to core Automation object
        auto_obj = _dict_to_automation_object(c)

        # Prepare parameters
        from services.automation_engine_service import (
            update_automation as service_update_auto,
            AutomationStatusEnum,
            AutomationTriggerEnum,
            AutomationActionEnum
        )

        name_param = request.name
        description_param = request.description

        status_param = None
        if request.status is not None:
            status_param = AutomationStatusEnum(request.status.strip().upper())

        trigger_param = None
        if request.trigger is not None:
            trigger_param = AutomationTriggerEnum(request.trigger.strip().upper())

        priority_param = request.priority

        steps_param = None
        if request.steps is not None:
            from services.automation_engine_service import build_automation_step
            steps_param = []
            for s in request.steps:
                steps_param.append(
                    build_automation_step(
                        name_param or auto_obj.name,
                        step_number=s.stepNumber,
                        name=s.name,
                        action=AutomationActionEnum(s.action.strip().upper()),
                        created_at=s.createdAt,
                        description=s.description or "",
                        parameters=s.parameters or {},
                    )
                )

        # Call update_automation
        updated_list = service_update_auto(
            automations=[auto_obj],
            automation_id=auto_obj.automationId,
            created_at=request.updatedAt or auto_obj.createdAt,
            name=name_param,
            description=description_param,
            status=status_param,
            trigger=trigger_param,
            steps=steps_param,
            priority=priority_param
        )

        if not updated_list:
            raise APIErrorInternal("Update failed.")

        updated_auto_obj = updated_list[0]

        # Merge other metadata/fields
        merged_dict = dict(c)
        if request.enabled is not None:
            merged_dict["enabled"] = request.enabled
        if request.category is not None:
            merged_dict["category"] = request.category
        if request.author is not None:
            merged_dict["author"] = request.author
        if request.projectId is not None:
            merged_dict["projectId"] = request.projectId
        if request.investigationId is not None:
            merged_dict["investigationId"] = request.investigationId
        if request.playbookId is not None:
            merged_dict["playbookId"] = request.playbookId
        if request.ruleId is not None:
            merged_dict["ruleId"] = request.ruleId
        if request.updatedAt is not None:
            merged_dict["updatedAt"] = request.updatedAt

        updated_dict = _to_store_dict(updated_auto_obj, merged_dict)

        old_id = c["automationId"]
        new_id = updated_dict["automationId"]
        if old_id in _AUTOMATION_STORE:
            del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[new_id] = updated_dict

        return build_success_response(
            data=_to_response_model(updated_dict).model_dump(),
            message="Automation updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.delete(
    "/{automationId}",
    response_model=APIResponse,
    summary="Delete an automation record",
)
def delete_automation(automationId: str) -> APIResponse:
    try:
        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        rec_id = c["automationId"]
        if rec_id in _AUTOMATION_STORE:
            del _AUTOMATION_STORE[rec_id]
        if rec_id in _EXECUTION_STORE:
            del _EXECUTION_STORE[rec_id]

        return build_success_response(
            data={"automationId": rec_id},
            message="Automation deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Steps sub-resource endpoints
# ---------------------------------------------------------------------------

@automation_router.get(
    "/{automationId}/steps",
    response_model=APIResponse,
    summary="Get steps of an automation",
)
def get_automation_steps(automationId: str) -> APIResponse:
    try:
        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        resp = _to_response_model(c)
        return build_success_response(
            data=[x.model_dump() for x in resp.steps],
            message="Automation steps retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.post(
    "/{automationId}/steps",
    response_model=APIResponse,
    summary="Append a step to an automation",
)
def append_step(
    automationId: str,
    request: AutomationStepRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        updated_automation = append_automation_step(c, request)
        old_id = c["automationId"]
        new_id = updated_automation["automationId"]
        if old_id in _AUTOMATION_STORE:
            del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[new_id] = updated_automation

        return build_success_response(
            data=_to_response_model(updated_automation).model_dump(),
            message="Automation step appended successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.put(
    "/{automationId}/steps/{stepId}",
    response_model=APIResponse,
    summary="Update an automation step",
)
def update_step(
    automationId: str,
    stepId: str,
    request: AutomationStepRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        updated_automation = update_automation_step(c, stepId, request)
        old_id = c["automationId"]
        new_id = updated_automation["automationId"]
        if old_id in _AUTOMATION_STORE:
            del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[new_id] = updated_automation

        return build_success_response(
            data=_to_response_model(updated_automation).model_dump(),
            message="Automation step updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.delete(
    "/{automationId}/steps/{stepId}",
    response_model=APIResponse,
    summary="Delete an automation step",
)
def delete_step(
    automationId: str,
    stepId: str
) -> APIResponse:
    try:
        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        updated_automation = delete_automation_step(c, stepId)
        old_id = c["automationId"]
        new_id = updated_automation["automationId"]
        if old_id in _AUTOMATION_STORE:
            del _AUTOMATION_STORE[old_id]
        _AUTOMATION_STORE[new_id] = updated_automation

        return build_success_response(
            data=_to_response_model(updated_automation).model_dump(),
            message="Automation step deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Execution endpoints
# ---------------------------------------------------------------------------

@automation_router.post(
    "/{automationId}/execute",
    response_model=APIResponse,
    summary="Execute an automation deterministically",
)
def execute_automation_endpoint(
    automationId: str,
    timestamp: str = Body(..., embed=True)
) -> APIResponse:
    try:
        if not timestamp or not timestamp.strip():
            raise APIErrorValidation("timestamp must be non-empty.")

        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        exec_dict = execute_automation(c, timestamp)
        payload = AutomationExecutionResponse(**exec_dict).model_dump()

        return build_success_response(
            data=payload,
            message="Automation executed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.get(
    "/{automationId}/executions",
    response_model=APIResponse,
    summary="Get execution logs of an automation",
)
def get_executions(automationId: str) -> APIResponse:
    try:
        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        executions = _EXECUTION_STORE.get(c["automationId"], [])
        payload = [AutomationExecutionResponse(**x).model_dump() for x in executions]

        return build_success_response(
            data=payload,
            message="Automation executions retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Summary endpoint
# ---------------------------------------------------------------------------

@automation_router.get(
    "/{automationId}/summary",
    response_model=APIResponse,
    summary="Get automation summary",
)
def get_automation_summary(automationId: str) -> APIResponse:
    try:
        all_automations_list = _all_automations()
        c = find_automation(all_automations_list, automationId)
        if not c:
            raise APIErrorNotFound(f"Automation '{automationId}' not found.")

        summary = build_automation_summary(c)
        payload = AutomationSummaryResponse(**summary).model_dump()
        return build_success_response(
            data=payload,
            message="Automation summary generated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Bulk Operations
# ---------------------------------------------------------------------------

@automation_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create automation records",
)
def bulk_create_automations(
    request: BulkCreateAutomationsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.automation_engine_service import (
            build_automation_step,
            build_automation,
            AutomationStatusEnum,
            AutomationTriggerEnum,
            AutomationActionEnum,
        )

        for item in request.automations:
            try:
                # Build steps
                steps_built = []
                for s in (item.steps or []):
                    st = AutomationActionEnum(s.action.strip().upper())
                    steps_built.append(
                        build_automation_step(
                            item.name,
                            step_number=s.stepNumber,
                            name=s.name,
                            action=st,
                            created_at=s.createdAt,
                            description=s.description or "",
                            parameters=s.parameters or {},
                        )
                    )

                stat_enum = AutomationStatusEnum(item.status.strip().upper())
                trig_enum = AutomationTriggerEnum(item.trigger.strip().upper())
                ab = build_automation(
                    name=item.name,
                    trigger=trig_enum,
                    created_at=item.createdAt,
                    description=item.description or "",
                    status=stat_enum,
                    steps=steps_built,
                    priority=item.priority,
                )

                rec_id = ab.automationId
                if rec_id in _AUTOMATION_STORE or rec_id in succeeded:
                    failed.append({"id": item.name, "reason": f"Automation '{rec_id}' already exists."})
                    continue

                auto_dict = _to_store_dict(ab, item.model_dump())
                _AUTOMATION_STORE[rec_id] = auto_dict
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.name, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.automations),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=res.model_dump(),
            message="Bulk creation completed.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update automation records",
)
def bulk_update_automations(
    request: BulkUpdateAutomationsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.automation_engine_service import (
            update_automation as service_update_auto,
            AutomationStatusEnum,
            AutomationTriggerEnum,
            AutomationActionEnum,
        )

        for item in request.items:
            rec_id = None
            all_automations_list = _all_automations()
            existing = find_automation(all_automations_list, item.automationId)
            if existing:
                rec_id = existing["automationId"]

            if not rec_id:
                failed.append({"id": item.automationId, "reason": f"Automation '{item.automationId}' not found."})
                continue

            try:
                auto_obj = _dict_to_automation_object(existing)

                name_param = item.update.name
                description_param = item.update.description

                status_param = None
                if item.update.status is not None:
                    status_param = AutomationStatusEnum(item.update.status.strip().upper())

                trigger_param = None
                if item.update.trigger is not None:
                    trigger_param = AutomationTriggerEnum(item.update.trigger.strip().upper())

                priority_param = item.update.priority

                steps_param = None
                if item.update.steps is not None:
                    from services.automation_engine_service import build_automation_step
                    steps_param = []
                    for s in item.update.steps:
                        steps_param.append(
                            build_automation_step(
                                name_param or auto_obj.name,
                                step_number=s.stepNumber,
                                name=s.name,
                                action=AutomationActionEnum(s.action.strip().upper()),
                                created_at=s.createdAt,
                                description=s.description or "",
                                parameters=s.parameters or {},
                            )
                        )

                updated_list = service_update_auto(
                    automations=[auto_obj],
                    automation_id=auto_obj.automationId,
                    created_at=item.update.updatedAt or auto_obj.createdAt,
                    name=name_param,
                    description=description_param,
                    status=status_param,
                    trigger=trigger_param,
                    steps=steps_param,
                    priority=priority_param
                )

                if not updated_list:
                    failed.append({"id": item.automationId, "reason": "Update failed."})
                    continue

                updated_auto_obj = updated_list[0]

                merged_dict = dict(existing)
                if item.update.enabled is not None:
                    merged_dict["enabled"] = item.update.enabled
                if item.update.category is not None:
                    merged_dict["category"] = item.update.category
                if item.update.author is not None:
                    merged_dict["author"] = item.update.author
                if item.update.projectId is not None:
                    merged_dict["projectId"] = item.update.projectId
                if item.update.investigationId is not None:
                    merged_dict["investigationId"] = item.update.investigationId
                if item.update.playbookId is not None:
                    merged_dict["playbookId"] = item.update.playbookId
                if item.update.ruleId is not None:
                    merged_dict["ruleId"] = item.update.ruleId
                if item.update.updatedAt is not None:
                    merged_dict["updatedAt"] = item.update.updatedAt

                updated_dict = _to_store_dict(updated_auto_obj, merged_dict)

                old_id = existing["automationId"]
                new_id = updated_dict["automationId"]
                if old_id in _AUTOMATION_STORE:
                    del _AUTOMATION_STORE[old_id]
                _AUTOMATION_STORE[new_id] = updated_dict

                succeeded.append(new_id)
            except Exception as e:
                failed.append({"id": item.automationId, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.items),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=res.model_dump(),
            message="Bulk update completed.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@automation_router.post(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete automation records",
)
def bulk_delete_automations(
    request: BulkDeleteAutomationsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for aid in request.automationIds:
            all_automations_list = _all_automations()
            existing = find_automation(all_automations_list, aid)
            if not existing:
                failed.append({"id": aid, "reason": f"Automation '{aid}' not found."})
                continue

            try:
                rec_id = existing["automationId"]
                if rec_id in _AUTOMATION_STORE:
                    del _AUTOMATION_STORE[rec_id]
                if rec_id in _EXECUTION_STORE:
                    del _EXECUTION_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": aid, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.automationIds),
            successCount=len(succeeded),
            failCount=len(failed),
        )
        return build_success_response(
            data=res.model_dump(),
            message="Bulk deletion completed.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))
