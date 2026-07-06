"""
Case Flow API Router — Phase A4.10.4
=====================================
REST interface for Case Flow Engine.
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
from api.workflow.case_flow_models import (
    CreateCaseFlowRequest,
    UpdateCaseFlowRequest,
    CaseFlowStepRequest,
    CaseFlowStepResponse,
    CaseFlowExecutionResponse,
    CaseFlowResponse,
    CaseFlowListResponse,
    CaseFlowStatisticsResponse,
    CaseFlowSearchResponse,
    CaseFlowSummaryResponse,
    BulkCreateCaseFlowsRequest,
    BulkUpdateCaseFlowsRequest,
    BulkDeleteCaseFlowsRequest,
    BulkOperationResult,
)

from services.case_flow_service import (
    Case,
    CaseStep,
    CaseStatusEnum,
    CasePriorityEnum,
    CaseStepTypeEnum,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

case_flow_router: APIRouter = APIRouter(
    prefix="/case-flow",
    tags=["Case Flow"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
# Dict[caseFlowId -> Case dict]
_CASE_FLOW_STORE: Dict[str, Dict[str, Any]] = {}

# Dict[caseFlowId -> List[Execution dict]]
_EXECUTION_STORE: Dict[str, List[Dict[str, Any]]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _CASE_FLOW_STORE.clear()
    _EXECUTION_STORE.clear()


def _all_cases() -> List[Dict[str, Any]]:
    """Return all cases ordered by title ASC."""
    return sorted(_CASE_FLOW_STORE.values(), key=lambda c: c.get("title", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_case_flow(cases: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a case flow by caseFlowId, caseFlowKey, caseNumber, or title (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for c in cases:
        if c.get("caseFlowId", "").lower() == normalized:
            return c
        if c.get("caseFlowKey", "").lower() == normalized:
            return c
        if c.get("caseNumber", "").lower() == normalized:
            return c
        if c.get("title", "").lower() == normalized:
            return c
    return None


def find_case_flow_step(steps: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
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


def search_case_flows(cases: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text, metadata, owner, and step fields."""
    if not query or not query.strip():
        return list(cases)
    q = query.strip().lower()
    results = []
    for c in cases:
        if q in c.get("title", "").lower():
            results.append(c)
            continue
        if q in c.get("description", "").lower():
            results.append(c)
            continue
        if q in c.get("owner", "").lower():
            results.append(c)
            continue
        if q in c.get("assignedTo", "").lower():
            results.append(c)
            continue
        if q in c.get("projectId", "").lower():
            results.append(c)
            continue
        if q in c.get("investigationId", "").lower():
            results.append(c)
            continue
        if q in c.get("automationId", "").lower():
            results.append(c)
            continue
        if any(q in s.get("title", "").lower() or q in s.get("description", "").lower() for s in c.get("steps", [])):
            results.append(c)
            continue
    return results


def search_case_flow_steps(steps: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
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
        if q in s.get("stepType", "").lower():
            results.append(s)
            continue
    return results


def sort_case_flows(
    cases: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts cases deterministically, falling back to caseFlowId ASC."""
    valid_fields = {"caseName", "createdAt", "updatedAt", "priority", "status", "stepCount", "executionCount"}
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

    from services.case_flow_service import _PRIORITY_ORDER, _STATUS_ORDER

    def get_sort_key(c: Dict[str, Any]) -> Any:
        if sort_by == "caseName":
            return c.get("title", "")
        elif sort_by == "createdAt":
            return c.get("createdAt", "")
        elif sort_by == "updatedAt":
            return c.get("updatedAt", "") or ""
        elif sort_by == "priority":
            p_val = c.get("priority", "LOW")
            try:
                p_enum = CasePriorityEnum(p_val.strip().upper())
                return _PRIORITY_ORDER.get(p_enum, 0)
            except ValueError:
                return 0
        elif sort_by == "status":
            s_val = c.get("status", "OPEN")
            try:
                s_enum = CaseStatusEnum(s_val.strip().upper())
                return _STATUS_ORDER.get(s_enum, 0)
            except ValueError:
                return 0
        elif sort_by == "stepCount":
            return len(c.get("steps", []))
        elif sort_by == "executionCount":
            return len(_EXECUTION_STORE.get(c.get("caseFlowId", ""), []))
        return ""

    reverse = (order == "desc")
    # Stable sort
    sorted_list = sorted(cases, key=lambda x: x.get("caseFlowId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_case_flows(
    cases: List[Dict[str, Any]],
    status: Optional[str] = None,
    priority: Optional[str] = None,
    owner: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    playbookId: Optional[str] = None,
    automationId: Optional[str] = None,
    minimumSteps: Optional[int] = None,
    maximumSteps: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filters cases list matching all provided criteria."""
    filtered = list(cases)

    if status is not None:
        st_val = status.strip().lower()
        filtered = [c for c in filtered if c.get("status", "").lower() == st_val]

    if priority is not None:
        p_val = priority.strip().lower()
        filtered = [c for c in filtered if c.get("priority", "").lower() == p_val]

    if owner is not None:
        owner_val = owner.strip().lower()
        filtered = [c for c in filtered if owner_val in c.get("owner", "").lower()]

    if projectId is not None:
        proj_val = projectId.strip()
        filtered = [c for c in filtered if c.get("projectId") == proj_val]

    if investigationId is not None:
        inv_val = investigationId.strip()
        filtered = [c for c in filtered if c.get("investigationId") == inv_val]

    if playbookId is not None:
        pb_val = playbookId.strip()
        filtered = [c for c in filtered if pb_val in c.get("playbookIds", ())]

    if automationId is not None:
        auto_val = automationId.strip()
        filtered = [c for c in filtered if c.get("automationId") == auto_val]

    if minimumSteps is not None:
        filtered = [c for c in filtered if len(c.get("steps", [])) >= minimumSteps]

    if maximumSteps is not None:
        filtered = [c for c in filtered if len(c.get("steps", [])) <= maximumSteps]

    if createdAfter is not None:
        after_val = createdAfter.strip()
        filtered = [c for c in filtered if c.get("createdAt", "") >= after_val]

    if createdBefore is not None:
        before_val = createdBefore.strip()
        filtered = [c for c in filtered if c.get("createdAt", "") <= before_val]

    return filtered


def paginate_case_flows(
    cases: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Helper to paginate the dataset."""
    total_items = len(cases)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = cases[start:end]
    return sliced, total_items


def execute_case_flow(case_flow: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
    """Deterministically runs a case flow execution and stores logs."""
    import uuid
    from services.case_flow_service import _CASE_FLOW_NS

    case_id = case_flow.get("caseFlowId")
    execution_id = str(uuid.uuid5(_CASE_FLOW_NS, f"{case_id}:{timestamp}"))

    step_results = []
    status = "SUCCESS"
    for s in case_flow.get("steps", []):
        step_results.append({
            "stepId": s.get("stepId"),
            "title": s.get("title"),
            "stepType": s.get("stepType"),
            "status": "SUCCESS",
            "message": f"Step '{s.get('title')}' executed successfully.",
            "output": {"executedAt": timestamp, "analystAction": "VERIFIED"}
        })

    execution = {
        "executionId": execution_id,
        "caseFlowId": case_id,
        "status": status,
        "startedAt": timestamp,
        "completedAt": timestamp,
        "stepResults": step_results,
    }

    _EXECUTION_STORE.setdefault(case_id, []).append(execution)
    return execution


def build_case_flow_summary(case: Dict[str, Any]) -> Dict[str, Any]:
    """Formulates a standard summary response for a case flow."""
    name = case.get("title", "")
    step_cnt = len(case.get("steps", []))
    exec_cnt = len(_EXECUTION_STORE.get(case.get("caseFlowId", ""), []))
    status = case.get("status", "")
    priority = case.get("priority", "")
    owner = case.get("owner", "")
    confidence = case.get("confidence", 100.0)

    text = (
        f"Case '{name}' ({status}) has {step_cnt} steps and {exec_cnt} executions. "
        f"It has {priority} priority, owned by {owner} with confidence {confidence}%."
    )
    return {
        "caseFlowId": case.get("caseFlowId", ""),
        "caseName": name,
        "summaryText": text,
        "stepCount": step_cnt,
        "executionCount": exec_cnt,
        "status": status,
        "priority": priority,
        "owner": owner,
        "confidence": confidence,
    }


def calculate_case_flow_statistics(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes aggregate stats over the unique cases list."""
    total = len(cases)
    open_c = sum(1 for c in cases if c.get("status") == "OPEN")
    closed_c = sum(1 for c in cases if c.get("status") == "CLOSED")
    in_prog = sum(1 for c in cases if c.get("status") == "IN_PROGRESS")

    total_executions = sum(len(_EXECUTION_STORE.get(c.get("caseFlowId", ""), [])) for c in cases)
    avg_executions = round(total_executions / total, 4) if total > 0 else 0.0

    total_steps = sum(len(c.get("steps", [])) for c in cases)
    avg_steps = round(total_steps / total, 4) if total > 0 else 0.0

    from services.case_flow_service import _PRIORITY_ORDER, CasePriorityEnum
    total_priority_val = 0
    for c in cases:
        p_val = c.get("priority", "LOW")
        try:
            p_enum = CasePriorityEnum(p_val.strip().upper())
            total_priority_val += _PRIORITY_ORDER.get(p_enum, 1)
        except ValueError:
            total_priority_val += 1
    avg_priority = round(total_priority_val / total, 4) if total > 0 else 0.0

    status_counts: Dict[str, int] = {}
    for c in cases:
        st = c.get("status", "").strip()
        if st:
            status_counts[st] = status_counts.get(st, 0) + 1

    return {
        "totalCases": total,
        "openCases": open_c,
        "closedCases": closed_c,
        "inProgressCases": in_prog,
        "totalExecutions": total_executions,
        "averageSteps": avg_steps,
        "averageExecutions": avg_executions,
        "averagePriority": avg_priority,
        "statusCounts": dict(sorted(status_counts.items())),
    }


def _dict_to_case_object(d: Dict[str, Any]) -> Case:
    """Helper to convert stored dictionary format to core Case object."""
    steps_objs = []
    for s in d.get("steps", []):
        steps_objs.append(
            CaseStep(
                stepId=s["stepId"],
                stepKey=s["stepKey"],
                stepNumber=s["stepNumber"],
                stepType=CaseStepTypeEnum(s["stepType"]),
                title=s["title"],
                description=s["description"],
                assignedTo=s["assignedTo"],
                createdAt=s["createdAt"],
            )
        )
    return Case(
        caseId=d["caseFlowId"],
        caseKey=d["caseFlowKey"],
        caseNumber=d["caseNumber"],
        title=d["title"],
        description=d["description"],
        status=CaseStatusEnum(d["status"]),
        priority=CasePriorityEnum(d["priority"]),
        steps=tuple(steps_objs),
        findingIds=tuple(d["findingIds"]),
        alertIds=tuple(d["alertIds"]),
        evidenceIds=tuple(d["evidenceIds"]),
        playbookIds=tuple(d["playbookIds"]),
        assignedTo=d["assignedTo"],
        confidence=d["confidence"],
        createdAt=d["createdAt"],
    )


def _to_store_dict(c: Case, original_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert Case core object to dictionary store format."""
    steps_list = []
    for s in c.steps:
        steps_list.append({
            "stepId": s.stepId,
            "stepKey": s.stepKey,
            "stepNumber": s.stepNumber,
            "stepType": s.stepType.value,
            "title": s.title,
            "description": s.description,
            "assignedTo": s.assignedTo,
            "createdAt": s.createdAt,
        })
    return {
        "caseFlowId": c.caseId,
        "caseFlowKey": c.caseKey,
        "caseNumber": c.caseNumber,
        "title": c.title,
        "description": c.description,
        "status": c.status.value,
        "priority": c.priority.value,
        "steps": steps_list,
        "findingIds": list(c.findingIds),
        "alertIds": list(c.alertIds),
        "evidenceIds": list(c.evidenceIds),
        "playbookIds": list(c.playbookIds),
        "assignedTo": c.assignedTo,
        "confidence": c.confidence,
        "createdAt": c.createdAt,
        "updatedAt": original_dict.get("updatedAt"),
        "projectId": original_dict.get("projectId", ""),
        "investigationId": original_dict.get("investigationId", ""),
        "automationId": original_dict.get("automationId", ""),
        "owner": original_dict.get("owner", ""),
    }


def _to_response_model(c: Dict[str, Any]) -> CaseFlowResponse:
    """Helper to convert stored dictionary to CaseFlowResponse model."""
    steps_resp = [
        CaseFlowStepResponse(
            stepId=s["stepId"],
            stepKey=s["stepKey"],
            stepNumber=s["stepNumber"],
            stepType=s["stepType"],
            title=s["title"],
            description=s["description"],
            assignedTo=s["assignedTo"],
            createdAt=s["createdAt"],
        )
        for s in c.get("steps", [])
    ]
    return CaseFlowResponse(
        caseFlowId=c["caseFlowId"],
        caseFlowKey=c["caseFlowKey"],
        caseNumber=c["caseNumber"],
        title=c["title"],
        description=c["description"],
        status=c["status"],
        priority=c["priority"],
        steps=steps_resp,
        findingIds=c["findingIds"],
        alertIds=c["alertIds"],
        evidenceIds=c["evidenceIds"],
        playbookIds=c["playbookIds"],
        assignedTo=c["assignedTo"],
        confidence=c["confidence"],
        createdAt=c["createdAt"],
        updatedAt=c.get("updatedAt"),
        projectId=c["projectId"],
        investigationId=c["investigationId"],
        automationId=c["automationId"],
        owner=c["owner"],
    )


# ---------------------------------------------------------------------------
# Step operations implementing immutable reconstruction using core service
# ---------------------------------------------------------------------------

def append_case_flow_step(case_flow: Dict[str, Any], step_req: CaseFlowStepRequest) -> Dict[str, Any]:
    """Appends step by rebuilding the immutable Case object using core service."""
    from services.case_flow_service import build_case_step, add_case_step

    case_obj = _dict_to_case_object(case_flow)
    st = CaseStepTypeEnum(step_req.stepType.strip().upper())
    new_step = build_case_step(
        case_obj.caseId,
        step_number=step_req.stepNumber,
        step_type=st,
        title=step_req.title,
        created_at=step_req.createdAt,
        description=step_req.description or "",
        assigned_to=step_req.assignedTo or "",
    )
    new_case = add_case_step(case_obj, new_step, step_req.createdAt)
    return _to_store_dict(new_case, case_flow)


def update_case_flow_step(case_flow: Dict[str, Any], step_id: str, step_req: CaseFlowStepRequest) -> Dict[str, Any]:
    """Updates step by rebuilding the immutable Case object using core service."""
    from services.case_flow_service import update_case_step as service_update_step

    case_obj = _dict_to_case_object(case_flow)
    st = CaseStepTypeEnum(step_req.stepType.strip().upper())
    new_case = service_update_step(
        case_obj,
        step_id,
        created_at=step_req.createdAt,
        title=step_req.title,
        description=step_req.description or "",
        step_type=st,
        assigned_to=step_req.assignedTo or "",
    )
    if new_case.caseId == case_obj.caseId and len(new_case.steps) == len(case_obj.steps):
        if not any(s.stepId == step_id for s in case_obj.steps):
            raise APIErrorNotFound(f"Step with ID '{step_id}' not found.")
    return _to_store_dict(new_case, case_flow)


def delete_case_flow_step(case_flow: Dict[str, Any], step_id: str) -> Dict[str, Any]:
    """Deletes step by rebuilding the immutable Case object using core service."""
    from services.case_flow_service import remove_case_step

    case_obj = _dict_to_case_object(case_flow)
    if not any(s.stepId == step_id for s in case_obj.steps):
        raise APIErrorNotFound(f"Step with ID '{step_id}' not found.")
    ts = "2026-07-06T12:00:00Z"
    if case_obj.steps:
        ts = case_obj.steps[0].createdAt
    new_case = remove_case_step(case_obj, step_id, ts)
    return _to_store_dict(new_case, case_flow)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@case_flow_router.get(
    "/",
    response_model=APIResponse,
    summary="List case flow records",
)
def list_case_flows_endpoint(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    owner: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    playbookId: Optional[str] = None,
    automationId: Optional[str] = None,
    minimumSteps: Optional[int] = None,
    maximumSteps: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
    sortBy: str = "caseName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_cases_list = _all_cases()

        filtered = filter_case_flows(
            all_cases_list,
            status=status,
            priority=priority,
            owner=owner,
            projectId=projectId,
            investigationId=investigationId,
            playbookId=playbookId,
            automationId=automationId,
            minimumSteps=minimumSteps,
            maximumSteps=maximumSteps,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_list = sort_case_flows(filtered, sortBy, sortOrder)
        sliced, total = paginate_case_flows(sorted_list, page, pageSize)

        serialized = [_to_response_model(x).model_dump() for x in sliced]
        return build_paginated_response(
            items=serialized,
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Cases retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get case flow statistics",
)
def get_case_flow_statistics_endpoint() -> APIResponse:
    try:
        all_cases_list = _all_cases()
        stats = calculate_case_flow_statistics(all_cases_list)
        payload = CaseFlowStatisticsResponse(**stats).model_dump()
        return build_success_response(
            data=payload,
            message="Case statistics computed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search case flows",
)
def search_case_flows_endpoint(
    q: str = "",
    sortBy: str = "caseName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_cases_list = _all_cases()

        searched = search_case_flows(all_cases_list, q)
        sorted_list = sort_case_flows(searched, sortBy, sortOrder)
        sliced, total = paginate_case_flows(sorted_list, page, pageSize)

        serialized = [_to_response_model(x).model_dump() for x in sliced]
        total_pages = math.ceil(total / pageSize) if total > 0 else 1

        search_data = CaseFlowSearchResponse(
            caseFlows=serialized,
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


@case_flow_router.get(
    "/{caseFlowId}",
    response_model=APIResponse,
    summary="Get case flow by ID",
)
def get_case_flow(caseFlowId: str) -> APIResponse:
    try:
        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="Case retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a case flow record",
)
def create_case_flow(
    request: CreateCaseFlowRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.case_flow_service import (
            build_case_step,
            build_case,
            CaseStatusEnum,
            CasePriorityEnum,
            CaseStepTypeEnum,
        )

        # Build steps
        steps_built = []
        for s in (request.steps or []):
            st = CaseStepTypeEnum(s.stepType.strip().upper())
            steps_built.append(
                build_case_step(
                    request.title,
                    step_number=s.stepNumber,
                    step_type=st,
                    title=s.title,
                    created_at=s.createdAt,
                    description=s.description or "",
                    assigned_to=s.assignedTo or "",
                )
            )

        try:
            stat_enum = CaseStatusEnum(request.status.strip().upper())
            prio_enum = CasePriorityEnum(request.priority.strip().upper())
            cb = build_case(
                title=request.title,
                priority=prio_enum,
                created_at=request.createdAt,
                description=request.description or "",
                status=stat_enum,
                steps=steps_built,
                finding_ids=request.findingIds or [],
                alert_ids=request.alertIds or [],
                evidence_ids=request.evidenceIds or [],
                playbook_ids=request.playbookIds or [],
                assigned_to=request.assignedTo or "",
                confidence=request.confidence if request.confidence is not None else 100.0,
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = cb.caseId
        if rec_id in _CASE_FLOW_STORE:
            raise APIErrorConflict(f"Case with ID '{rec_id}' already exists.")

        case_dict = _to_store_dict(cb, request.model_dump())
        _CASE_FLOW_STORE[rec_id] = case_dict

        return build_success_response(
            data=_to_response_model(case_dict).model_dump(),
            message="Case created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.put(
    "/{caseFlowId}",
    response_model=APIResponse,
    summary="Update a case flow record",
)
def update_case_flow_route(
    caseFlowId: str,
    request: UpdateCaseFlowRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        # Map to core Case object
        case_obj = _dict_to_case_object(c)

        # Prepare parameters
        from services.case_flow_service import (
            update_case as service_update_case,
            CaseStatusEnum,
            CasePriorityEnum,
            CaseStepTypeEnum
        )

        title_param = request.title
        description_param = request.description

        status_param = None
        if request.status is not None:
            status_param = CaseStatusEnum(request.status.strip().upper())

        priority_param = None
        if request.priority is not None:
            priority_param = CasePriorityEnum(request.priority.strip().upper())

        steps_param = None
        if request.steps is not None:
            from services.case_flow_service import build_case_step
            steps_param = []
            for s in request.steps:
                steps_param.append(
                    build_case_step(
                        title_param or case_obj.title,
                        step_number=s.stepNumber,
                        step_type=CaseStepTypeEnum(s.stepType.strip().upper()),
                        title=s.title,
                        created_at=s.createdAt,
                        description=s.description or "",
                        assigned_to=s.assignedTo or "",
                    )
                )

        finding_ids_param = request.findingIds
        alert_ids_param = request.alertIds
        evidence_ids_param = request.evidenceIds
        playbook_ids_param = request.playbookIds
        assigned_to_param = request.assignedTo
        confidence_param = request.confidence

        # Call update_case
        updated_list = service_update_case(
            cases=[case_obj],
            case_id=case_obj.caseId,
            created_at=request.updatedAt or case_obj.createdAt,
            title=title_param,
            description=description_param,
            status=status_param,
            priority=priority_param,
            steps=steps_param,
            finding_ids=finding_ids_param,
            alert_ids=alert_ids_param,
            evidence_ids=evidence_ids_param,
            playbook_ids=playbook_ids_param,
            assigned_to=assigned_to_param,
            confidence=confidence_param,
        )

        if not updated_list:
            raise APIErrorInternal("Update failed.")

        updated_case_obj = updated_list[0]

        # Merge other metadata/fields
        merged_dict = dict(c)
        if request.projectId is not None:
            merged_dict["projectId"] = request.projectId
        if request.investigationId is not None:
            merged_dict["investigationId"] = request.investigationId
        if request.automationId is not None:
            merged_dict["automationId"] = request.automationId
        if request.owner is not None:
            merged_dict["owner"] = request.owner
        if request.updatedAt is not None:
            merged_dict["updatedAt"] = request.updatedAt

        updated_dict = _to_store_dict(updated_case_obj, merged_dict)

        old_id = c["caseFlowId"]
        new_id = updated_dict["caseFlowId"]
        if old_id in _CASE_FLOW_STORE:
            del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[new_id] = updated_dict

        return build_success_response(
            data=_to_response_model(updated_dict).model_dump(),
            message="Case updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.delete(
    "/{caseFlowId}",
    response_model=APIResponse,
    summary="Delete a case flow record",
)
def delete_case_flow(caseFlowId: str) -> APIResponse:
    try:
        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        rec_id = c["caseFlowId"]
        if rec_id in _CASE_FLOW_STORE:
            del _CASE_FLOW_STORE[rec_id]
        if rec_id in _EXECUTION_STORE:
            del _EXECUTION_STORE[rec_id]

        return build_success_response(
            data={"caseFlowId": rec_id},
            message="Case deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Steps sub-resource endpoints
# ---------------------------------------------------------------------------

@case_flow_router.get(
    "/{caseFlowId}/steps",
    response_model=APIResponse,
    summary="Get steps of a case flow",
)
def get_case_steps(caseFlowId: str) -> APIResponse:
    try:
        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        resp = _to_response_model(c)
        return build_success_response(
            data=[x.model_dump() for x in resp.steps],
            message="Case steps retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.post(
    "/{caseFlowId}/steps",
    response_model=APIResponse,
    summary="Append a step to a case flow",
)
def append_step(
    caseFlowId: str,
    request: CaseFlowStepRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        updated_case = append_case_flow_step(c, request)
        old_id = c["caseFlowId"]
        new_id = updated_case["caseFlowId"]
        if old_id in _CASE_FLOW_STORE:
            del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[new_id] = updated_case

        return build_success_response(
            data=_to_response_model(updated_case).model_dump(),
            message="Case step appended successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.put(
    "/{caseFlowId}/steps/{stepId}",
    response_model=APIResponse,
    summary="Update a case flow step",
)
def update_step(
    caseFlowId: str,
    stepId: str,
    request: CaseFlowStepRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        updated_case = update_case_flow_step(c, stepId, request)
        old_id = c["caseFlowId"]
        new_id = updated_case["caseFlowId"]
        if old_id in _CASE_FLOW_STORE:
            del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[new_id] = updated_case

        return build_success_response(
            data=_to_response_model(updated_case).model_dump(),
            message="Case step updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.delete(
    "/{caseFlowId}/steps/{stepId}",
    response_model=APIResponse,
    summary="Delete a case flow step",
)
def delete_step(
    caseFlowId: str,
    stepId: str
) -> APIResponse:
    try:
        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        updated_case = delete_case_flow_step(c, stepId)
        old_id = c["caseFlowId"]
        new_id = updated_case["caseFlowId"]
        if old_id in _CASE_FLOW_STORE:
            del _CASE_FLOW_STORE[old_id]
        _CASE_FLOW_STORE[new_id] = updated_case

        return build_success_response(
            data=_to_response_model(updated_case).model_dump(),
            message="Case step deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Execution endpoints
# ---------------------------------------------------------------------------

@case_flow_router.post(
    "/{caseFlowId}/execute",
    response_model=APIResponse,
    summary="Execute a case flow deterministically",
)
def execute_case_flow_endpoint(
    caseFlowId: str,
    timestamp: str = Body(..., embed=True)
) -> APIResponse:
    try:
        if not timestamp or not timestamp.strip():
            raise APIErrorValidation("timestamp must be non-empty.")

        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        exec_dict = execute_case_flow(c, timestamp)
        payload = CaseFlowExecutionResponse(**exec_dict).model_dump()

        return build_success_response(
            data=payload,
            message="Case executed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@case_flow_router.get(
    "/{caseFlowId}/executions",
    response_model=APIResponse,
    summary="Get execution logs of a case flow",
)
def get_executions(caseFlowId: str) -> APIResponse:
    try:
        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        executions = _EXECUTION_STORE.get(c["caseFlowId"], [])
        payload = [CaseFlowExecutionResponse(**x).model_dump() for x in executions]

        return build_success_response(
            data=payload,
            message="Case executions retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Summary endpoint
# ---------------------------------------------------------------------------

@case_flow_router.get(
    "/{caseFlowId}/summary",
    response_model=APIResponse,
    summary="Get case flow summary",
)
def get_case_flow_summary(caseFlowId: str) -> APIResponse:
    try:
        all_cases_list = _all_cases()
        c = find_case_flow(all_cases_list, caseFlowId)
        if not c:
            raise APIErrorNotFound(f"Case Flow '{caseFlowId}' not found.")

        summary = build_case_flow_summary(c)
        payload = CaseFlowSummaryResponse(**summary).model_dump()
        return build_success_response(
            data=payload,
            message="Case summary generated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Bulk Operations
# ---------------------------------------------------------------------------

@case_flow_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create case flow records",
)
def bulk_create_case_flows(
    request: BulkCreateCaseFlowsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.case_flow_service import (
            build_case_step,
            build_case,
            CaseStatusEnum,
            CasePriorityEnum,
            CaseStepTypeEnum,
        )

        for item in request.caseFlows:
            try:
                # Build steps
                steps_built = []
                for s in (item.steps or []):
                    st = CaseStepTypeEnum(s.stepType.strip().upper())
                    steps_built.append(
                        build_case_step(
                            item.title,
                            step_number=s.stepNumber,
                            step_type=st,
                            title=s.title,
                            created_at=s.createdAt,
                            description=s.description or "",
                            assigned_to=s.assignedTo or "",
                        )
                    )

                stat_enum = CaseStatusEnum(item.status.strip().upper())
                prio_enum = CasePriorityEnum(item.priority.strip().upper())
                cb = build_case(
                    title=item.title,
                    priority=prio_enum,
                    created_at=item.createdAt,
                    description=item.description or "",
                    status=stat_enum,
                    steps=steps_built,
                    finding_ids=item.findingIds or [],
                    alert_ids=item.alertIds or [],
                    evidence_ids=item.evidenceIds or [],
                    playbook_ids=item.playbookIds or [],
                    assigned_to=item.assignedTo or "",
                    confidence=item.confidence if item.confidence is not None else 100.0,
                )

                rec_id = cb.caseId
                if rec_id in _CASE_FLOW_STORE or rec_id in succeeded:
                    failed.append({"id": item.title, "reason": f"Case '{rec_id}' already exists."})
                    continue

                case_dict = _to_store_dict(cb, item.model_dump())
                _CASE_FLOW_STORE[rec_id] = case_dict
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.title, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.caseFlows),
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


@case_flow_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update case flow records",
)
def bulk_update_case_flows(
    request: BulkUpdateCaseFlowsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.case_flow_service import (
            update_case as service_update_case,
            CaseStatusEnum,
            CasePriorityEnum,
            CaseStepTypeEnum,
        )

        for item in request.items:
            rec_id = None
            all_cases_list = _all_cases()
            existing = find_case_flow(all_cases_list, item.caseFlowId)
            if existing:
                rec_id = existing["caseFlowId"]

            if not rec_id:
                failed.append({"id": item.caseFlowId, "reason": f"Case Flow '{item.caseFlowId}' not found."})
                continue

            try:
                case_obj = _dict_to_case_object(existing)

                title_param = item.update.title
                description_param = item.update.description

                status_param = None
                if item.update.status is not None:
                    status_param = CaseStatusEnum(item.update.status.strip().upper())

                priority_param = None
                if item.update.priority is not None:
                    priority_param = CasePriorityEnum(item.update.priority.strip().upper())

                steps_param = None
                if item.update.steps is not None:
                    from services.case_flow_service import build_case_step
                    steps_param = []
                    for s in item.update.steps:
                        steps_param.append(
                            build_case_step(
                                title_param or case_obj.title,
                                step_number=s.stepNumber,
                                step_type=CaseStepTypeEnum(s.stepType.strip().upper()),
                                title=s.title,
                                created_at=s.createdAt,
                                description=s.description or "",
                                assigned_to=s.assignedTo or "",
                            )
                        )

                finding_ids_param = item.update.findingIds
                alert_ids_param = item.update.alertIds
                evidence_ids_param = item.update.evidenceIds
                playbook_ids_param = item.update.playbookIds
                assigned_to_param = item.update.assignedTo
                confidence_param = item.update.confidence

                updated_list = service_update_case(
                    cases=[case_obj],
                    case_id=case_obj.caseId,
                    created_at=item.update.updatedAt or case_obj.createdAt,
                    title=title_param,
                    description=description_param,
                    status=status_param,
                    priority=priority_param,
                    steps=steps_param,
                    finding_ids=finding_ids_param,
                    alert_ids=alert_ids_param,
                    evidence_ids=evidence_ids_param,
                    playbook_ids=playbook_ids_param,
                    assigned_to=assigned_to_param,
                    confidence=confidence_param,
                )

                if not updated_list:
                    failed.append({"id": item.caseFlowId, "reason": "Update failed."})
                    continue

                updated_case_obj = updated_list[0]

                merged_dict = dict(existing)
                if item.update.projectId is not None:
                    merged_dict["projectId"] = item.update.projectId
                if item.update.investigationId is not None:
                    merged_dict["investigationId"] = item.update.investigationId
                if item.update.automationId is not None:
                    merged_dict["automationId"] = item.update.automationId
                if item.update.owner is not None:
                    merged_dict["owner"] = item.update.owner
                if item.update.updatedAt is not None:
                    merged_dict["updatedAt"] = item.update.updatedAt

                updated_dict = _to_store_dict(updated_case_obj, merged_dict)

                old_id = existing["caseFlowId"]
                new_id = updated_dict["caseFlowId"]
                if old_id in _CASE_FLOW_STORE:
                    del _CASE_FLOW_STORE[old_id]
                _CASE_FLOW_STORE[new_id] = updated_dict

                succeeded.append(new_id)
            except Exception as e:
                failed.append({"id": item.caseFlowId, "reason": str(e)})

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


@case_flow_router.post(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete case flow records",
)
def bulk_delete_case_flows(
    request: BulkDeleteCaseFlowsRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for aid in request.caseFlowIds:
            all_cases_list = _all_cases()
            existing = find_case_flow(all_cases_list, aid)
            if not existing:
                failed.append({"id": aid, "reason": f"Case Flow '{aid}' not found."})
                continue

            try:
                rec_id = existing["caseFlowId"]
                if rec_id in _CASE_FLOW_STORE:
                    del _CASE_FLOW_STORE[rec_id]
                if rec_id in _EXECUTION_STORE:
                    del _EXECUTION_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": aid, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.caseFlowIds),
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
