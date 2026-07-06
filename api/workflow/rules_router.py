"""
Rules API Router — Phase A4.10.2
=================================
REST interface for Rules Engine.
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
from api.workflow.rules_models import (
    CreateRuleRequest,
    UpdateRuleRequest,
    RuleConditionRequest,
    RuleConditionResponse,
    RuleActionRequest,
    RuleActionResponse,
    RuleResponse,
    RuleListResponse,
    RuleStatisticsResponse,
    RuleSearchResponse,
    RuleSummaryResponse,
    BulkCreateRulesRequest,
    BulkUpdateRulesRequest,
    BulkDeleteRulesRequest,
    BulkOperationResult,
)

from services.rules_engine_service import (
    Rule,
    RuleCondition,
    RuleActionEnum,
    RuleSeverityEnum,
    RuleStatusEnum,
)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

rules_router: APIRouter = APIRouter(
    prefix="/rules",
    tags=["Rules Engine"],
)

# ---------------------------------------------------------------------------
# In-Memory Store
# ---------------------------------------------------------------------------
# Dict[ruleId -> Rule dict]
_RULE_STORE: Dict[str, Dict[str, Any]] = {}


def _reset_store() -> None:
    """Clear the in-memory store. Used by tests only."""
    _RULE_STORE.clear()


def _all_rules() -> List[Dict[str, Any]]:
    """Return all rules ordered by name ASC."""
    return sorted(_RULE_STORE.values(), key=lambda r: r.get("name", ""))


# ---------------------------------------------------------------------------
# Deterministic Utility Helpers
# ---------------------------------------------------------------------------

def find_rule(rules: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a rule by ruleId, ruleKey, or name (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for r in rules:
        if r.get("ruleId", "").lower() == normalized:
            return r
        if r.get("ruleKey", "").lower() == normalized:
            return r
        if r.get("name", "").lower() == normalized:
            return r
    return None


def find_rule_condition(conditions: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds a condition by conditionId, conditionKey, or field (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for c in conditions:
        if c.get("conditionId", "").lower() == normalized:
            return c
        if c.get("conditionKey", "").lower() == normalized:
            return c
        if c.get("field", "").lower() == normalized:
            return c
    return None


def find_rule_action(actions: List[Dict[str, Any]], identifier: str) -> Optional[Dict[str, Any]]:
    """Finds an action by actionId or actionType (case-insensitive)."""
    if not identifier:
        return None
    normalized = identifier.strip().lower()
    for a in actions:
        if a.get("actionId", "").lower() == normalized:
            return a
        if a.get("actionType", "").lower() == normalized:
            return a
    return None


def search_rules(rules: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across text, metadata, condition, and action fields."""
    if not query or not query.strip():
        return list(rules)
    q = query.strip().lower()
    results = []
    for r in rules:
        if q in r.get("name", "").lower():
            results.append(r)
            continue
        if q in r.get("description", "").lower():
            results.append(r)
            continue
        if q in r.get("category", "").lower():
            results.append(r)
            continue
        if q in r.get("author", "").lower():
            results.append(r)
            continue
        if any(q in c.get("field", "").lower() or q in c.get("value", "").lower() for c in r.get("conditions", [])):
            results.append(r)
            continue
        if any(q in a.get("actionType", "").lower() for a in r.get("actions", [])):
            results.append(r)
            continue
    return results


def search_rule_conditions(conditions: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across condition fields."""
    if not query or not query.strip():
        return list(conditions)
    q = query.strip().lower()
    results = []
    for c in conditions:
        if q in c.get("field", "").lower():
            results.append(c)
            continue
        if q in c.get("operator", "").lower():
            results.append(c)
            continue
        if q in c.get("value", "").lower():
            results.append(c)
            continue
    return results


def search_rule_actions(actions: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Searches case-insensitively across action fields."""
    if not query or not query.strip():
        return list(actions)
    q = query.strip().lower()
    results = []
    for a in actions:
        if q in a.get("actionType", "").lower():
            results.append(a)
            continue
    return results


def sort_rules(
    rules: List[Dict[str, Any]],
    sort_by: str,
    sort_order: str = "asc"
) -> List[Dict[str, Any]]:
    """Sorts rules deterministically, falling back to ruleId ASC."""
    valid_fields = {"ruleName", "createdAt", "updatedAt", "priority", "enabled", "conditionCount", "actionCount"}
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

    def get_sort_key(r: Dict[str, Any]) -> Any:
        if sort_by == "ruleName":
            return r.get("name", "")
        elif sort_by == "createdAt":
            return r.get("createdAt", "")
        elif sort_by == "updatedAt":
            return r.get("updatedAt", "") or ""
        elif sort_by == "priority":
            return r.get("priority", 100)
        elif sort_by == "enabled":
            return int(r.get("enabled", True))
        elif sort_by == "conditionCount":
            return len(r.get("conditions", []))
        elif sort_by == "actionCount":
            return len(r.get("actions", []))
        return ""

    reverse = (order == "desc")
    # Stable sort
    sorted_list = sorted(rules, key=lambda x: x.get("ruleId", ""))
    sorted_list.sort(key=get_sort_key, reverse=reverse)
    return sorted_list


def filter_rules(
    rules: List[Dict[str, Any]],
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    author: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumConditions: Optional[int] = None,
    maximumConditions: Optional[int] = None,
    minimumActions: Optional[int] = None,
    maximumActions: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filters rules list matching all provided criteria."""
    filtered = list(rules)

    if enabled is not None:
        filtered = [r for r in filtered if bool(r.get("enabled", True)) == enabled]

    if priority is not None:
        filtered = [r for r in filtered if r.get("priority") == priority]

    if category is not None:
        cat_val = category.strip().lower()
        filtered = [r for r in filtered if r.get("category", "").lower() == cat_val]

    if severity is not None:
        sev_val = severity.strip().upper()
        filtered = [r for r in filtered if r.get("severity", "").upper() == sev_val]

    if author is not None:
        auth_val = author.strip().lower()
        filtered = [r for r in filtered if auth_val in r.get("author", "").lower()]

    if projectId is not None:
        proj_val = projectId.strip()
        filtered = [r for r in filtered if r.get("projectId") == proj_val]

    if investigationId is not None:
        inv_val = investigationId.strip()
        filtered = [r for r in filtered if r.get("investigationId") == inv_val]

    if minimumConditions is not None:
        filtered = [r for r in filtered if len(r.get("conditions", [])) >= minimumConditions]

    if maximumConditions is not None:
        filtered = [r for r in filtered if len(r.get("conditions", [])) <= maximumConditions]

    if minimumActions is not None:
        filtered = [r for r in filtered if len(r.get("actions", [])) >= minimumActions]

    if maximumActions is not None:
        filtered = [r for r in filtered if len(r.get("actions", [])) <= maximumActions]

    if createdAfter is not None:
        after_val = createdAfter.strip()
        filtered = [r for r in filtered if r.get("createdAt", "") >= after_val]

    if createdBefore is not None:
        before_val = createdBefore.strip()
        filtered = [r for r in filtered if r.get("createdAt", "") <= before_val]

    return filtered


def paginate_rules(
    rules: List[Dict[str, Any]],
    page: int,
    page_size: int
) -> Tuple[List[Dict[str, Any]], int]:
    """Helper to paginate the dataset."""
    total_items = len(rules)
    start = (page - 1) * page_size
    end = start + page_size
    sliced = rules[start:end]
    return sliced, total_items


def build_rule_summary(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Formulates a standard summary response for a rule."""
    name = rule.get("name", "")
    cond_cnt = len(rule.get("conditions", []))
    act_cnt = len(rule.get("actions", []))
    sev = rule.get("severity", "")
    status = rule.get("status", "")
    enabled = rule.get("enabled", True)
    priority = rule.get("priority", 100)

    text = (
        f"Rule '{name}' ({status}) has {cond_cnt} conditions and {act_cnt} actions. "
        f"It is classification {sev} with priority {priority} and is {'enabled' if enabled else 'disabled'}."
    )
    return {
        "ruleId": rule.get("ruleId", ""),
        "ruleName": name,
        "summaryText": text,
        "conditionCount": cond_cnt,
        "actionCount": act_cnt,
        "severity": sev,
        "status": status,
        "enabled": enabled,
        "priority": priority,
    }


def calculate_rule_statistics(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes aggregate stats over the unique rules list."""
    total = len(rules)
    enabled = sum(1 for r in rules if r.get("enabled", True))
    disabled = total - enabled

    total_conditions = sum(len(r.get("conditions", [])) for r in rules)
    avg_conditions = round(total_conditions / total, 4) if total > 0 else 0.0

    total_actions = sum(len(r.get("actions", [])) for r in rules)
    avg_actions = round(total_actions / total, 4) if total > 0 else 0.0

    total_priority = sum(r.get("priority", 100) for r in rules)
    avg_priority = round(total_priority / total, 4) if total > 0 else 0.0

    category_counts: Dict[str, int] = {}
    for r in rules:
        cat = r.get("category", "").strip()
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "totalRules": total,
        "enabledRules": enabled,
        "disabledRules": disabled,
        "averageConditions": avg_conditions,
        "averageActions": avg_actions,
        "averagePriority": avg_priority,
        "categoryCounts": dict(sorted(category_counts.items())),
    }


def _dict_to_rule_object(d: Dict[str, Any]) -> Rule:
    """Helper to convert stored dictionary format to core Rule object."""
    conds = []
    for c in d.get("conditions", []):
        conds.append(
            RuleCondition(
                conditionId=c["conditionId"],
                conditionKey=c["conditionKey"],
                field=c["field"],
                operator=c["operator"],
                value=c["value"],
                createdAt=c["createdAt"],
            )
        )

    actions = []
    for a in d.get("actions", []):
        actions.append(RuleActionEnum(a["actionType"].strip().upper()))

    return Rule(
        ruleId=d["ruleId"],
        ruleKey=d["ruleKey"],
        name=d["name"],
        description=d["description"],
        severity=RuleSeverityEnum(d["severity"]),
        status=RuleStatusEnum(d["status"]),
        conditions=tuple(conds),
        actions=tuple(actions),
        priority=d["priority"],
        createdAt=d["createdAt"],
    )


def _to_store_dict(rule: Rule, original_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert Rule core object to dictionary store format."""
    conds_list = []
    for c in rule.conditions:
        conds_list.append({
            "conditionId": c.conditionId,
            "conditionKey": c.conditionKey,
            "field": c.field,
            "operator": c.operator,
            "value": c.value,
            "createdAt": c.createdAt,
        })

    import uuid
    from services.rules_engine_service import _RULES_NS

    orig_actions = {a["actionType"]: a for a in original_dict.get("actions", [])}
    actions_list = []
    for act in rule.actions:
        orig_act = orig_actions.get(act.value, {})
        actions_list.append({
            "actionId": orig_act.get("actionId") or str(uuid.uuid5(_RULES_NS, f"{rule.ruleId}:{act.value}")),
            "actionType": act.value,
            "parameters": orig_act.get("parameters") or {},
        })

    return {
        "ruleId": rule.ruleId,
        "ruleKey": rule.ruleKey,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity.value,
        "status": rule.status.value,
        "conditions": conds_list,
        "actions": actions_list,
        "priority": rule.priority,
        "createdAt": rule.createdAt,
        "updatedAt": original_dict.get("updatedAt"),
        "enabled": original_dict.get("enabled", True),
        "category": original_dict.get("category", ""),
        "author": original_dict.get("author", ""),
        "projectId": original_dict.get("projectId", ""),
        "investigationId": original_dict.get("investigationId", ""),
    }


def _to_response_model(c: Dict[str, Any]) -> RuleResponse:
    """Helper to convert stored dictionary to RuleResponse model."""
    conds_resp = [
        RuleConditionResponse(
            conditionId=s["conditionId"],
            conditionKey=s["conditionKey"],
            field=s["field"],
            operator=s["operator"],
            value=s["value"],
            createdAt=s["createdAt"],
        )
        for s in c.get("conditions", [])
    ]
    actions_resp = [
        RuleActionResponse(
            actionId=s["actionId"],
            actionType=s["actionType"],
            parameters=s["parameters"],
        )
        for s in c.get("actions", [])
    ]
    return RuleResponse(
        ruleId=c["ruleId"],
        ruleKey=c["ruleKey"],
        name=c["name"],
        description=c["description"],
        severity=c["severity"],
        status=c["status"],
        conditions=conds_resp,
        actions=actions_resp,
        priority=c["priority"],
        createdAt=c["createdAt"],
        updatedAt=c.get("updatedAt"),
        enabled=c["enabled"],
        category=c["category"],
        author=c["author"],
        projectId=c["projectId"],
        investigationId=c["investigationId"],
    )


# ---------------------------------------------------------------------------
# Step operations implementing immutable reconstruction using core service
# ---------------------------------------------------------------------------

def append_rule_condition(rule: Dict[str, Any], condition_req: RuleConditionRequest) -> Dict[str, Any]:
    """Appends rule condition by rebuilding the immutable Rule object."""
    from services.rules_engine_service import build_rule_condition, add_rule_condition

    rule_obj = _dict_to_rule_object(rule)
    new_cond = build_rule_condition(
        condition_req.field,
        condition_req.operator,
        condition_req.value,
        condition_req.createdAt,
        validate=False,
    )
    new_rule = add_rule_condition(rule_obj, new_cond)
    return _to_store_dict(new_rule, rule)


def update_rule_condition(rule: Dict[str, Any], condition_id: str, condition_req: RuleConditionRequest) -> Dict[str, Any]:
    """Updates rule condition by rebuilding the immutable Rule object."""
    from services.rules_engine_service import update_rule_condition as service_update_cond

    rule_obj = _dict_to_rule_object(rule)
    new_rule = service_update_cond(
        rule_obj,
        condition_id,
        field=condition_req.field,
        operator=condition_req.operator,
        value=condition_req.value,
        created_at=condition_req.createdAt,
    )
    if new_rule.ruleId == rule_obj.ruleId and len(new_rule.conditions) == len(rule_obj.conditions):
        if not any(c.conditionId == condition_id for c in rule_obj.conditions):
            raise APIErrorNotFound(f"Condition with ID '{condition_id}' not found.")
    return _to_store_dict(new_rule, rule)


def delete_rule_condition(rule: Dict[str, Any], condition_id: str) -> Dict[str, Any]:
    """Deletes rule condition by rebuilding the immutable Rule object."""
    from services.rules_engine_service import remove_rule_condition

    rule_obj = _dict_to_rule_object(rule)
    if not any(c.conditionId == condition_id for c in rule_obj.conditions):
        raise APIErrorNotFound(f"Condition with ID '{condition_id}' not found.")
    new_rule = remove_rule_condition(rule_obj, condition_id)
    return _to_store_dict(new_rule, rule)


def append_rule_action(rule: Dict[str, Any], action_req: RuleActionRequest) -> Dict[str, Any]:
    """Appends rule action by rebuilding the immutable Rule object."""
    act_type = action_req.actionType.strip().upper()
    existing = [a for a in rule.get("actions", []) if a["actionType"] == act_type]
    if existing:
        return dict(rule)

    import uuid
    from services.rules_engine_service import _RULES_NS, build_rule
    rule_id = rule.get("ruleId")
    action_id = str(uuid.uuid5(_RULES_NS, f"{rule_id}:{act_type}"))

    new_action = {
        "actionId": action_id,
        "actionType": act_type,
        "parameters": action_req.parameters or {},
    }

    all_actions = sorted(rule.get("actions", []) + [new_action], key=lambda x: x["actionType"])

    rule_obj = _dict_to_rule_object(rule)
    new_rule = build_rule(
        name=rule_obj.name,
        severity=rule_obj.severity,
        created_at=rule_obj.createdAt,
        description=rule_obj.description,
        status=rule_obj.status,
        conditions=list(rule_obj.conditions),
        actions=[RuleActionEnum(a["actionType"]) for a in all_actions],
        priority=rule_obj.priority,
        validate=False,
    )
    updated_dict = _to_store_dict(new_rule, rule)
    updated_dict["actions"] = all_actions
    return updated_dict


def update_rule_action(rule: Dict[str, Any], action_id: str, action_req: RuleActionRequest) -> Dict[str, Any]:
    """Updates rule action by rebuilding the immutable Rule object."""
    act_type = action_req.actionType.strip().upper()

    updated_actions = []
    found = False
    for a in rule.get("actions", []):
        if a["actionId"] == action_id:
            found = True
            updated_actions.append({
                "actionId": action_id,
                "actionType": act_type,
                "parameters": action_req.parameters or {},
            })
        else:
            updated_actions.append(a)

    if not found:
        raise APIErrorNotFound(f"Action with ID '{action_id}' not found.")

    from services.rules_engine_service import build_rule
    rule_obj = _dict_to_rule_object(rule)
    new_rule = build_rule(
        name=rule_obj.name,
        severity=rule_obj.severity,
        created_at=rule_obj.createdAt,
        description=rule_obj.description,
        status=rule_obj.status,
        conditions=list(rule_obj.conditions),
        actions=[RuleActionEnum(a["actionType"]) for a in updated_actions],
        priority=rule_obj.priority,
        validate=False,
    )
    updated_dict = _to_store_dict(new_rule, rule)
    updated_dict["actions"] = sorted(updated_actions, key=lambda x: x["actionType"])
    return updated_dict


def delete_rule_action(rule: Dict[str, Any], action_id: str) -> Dict[str, Any]:
    """Deletes rule action by rebuilding the immutable Rule object."""
    remaining_actions = []
    found = False
    for a in rule.get("actions", []):
        if a["actionId"] == action_id:
            found = True
        else:
            remaining_actions.append(a)

    if not found:
        raise APIErrorNotFound(f"Action with ID '{action_id}' not found.")

    from services.rules_engine_service import build_rule
    rule_obj = _dict_to_rule_object(rule)
    new_rule = build_rule(
        name=rule_obj.name,
        severity=rule_obj.severity,
        created_at=rule_obj.createdAt,
        description=rule_obj.description,
        status=rule_obj.status,
        conditions=list(rule_obj.conditions),
        actions=[RuleActionEnum(a["actionType"]) for a in remaining_actions],
        priority=rule_obj.priority,
        validate=False,
    )
    updated_dict = _to_store_dict(new_rule, rule)
    updated_dict["actions"] = sorted(remaining_actions, key=lambda x: x["actionType"])
    return updated_dict


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@rules_router.get(
    "/",
    response_model=APIResponse,
    summary="List rule records",
)
def list_rules_endpoint(
    enabled: Optional[bool] = None,
    priority: Optional[int] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    author: Optional[str] = None,
    projectId: Optional[str] = None,
    investigationId: Optional[str] = None,
    minimumConditions: Optional[int] = None,
    maximumConditions: Optional[int] = None,
    minimumActions: Optional[int] = None,
    maximumActions: Optional[int] = None,
    createdAfter: Optional[str] = None,
    createdBefore: Optional[str] = None,
    sortBy: str = "ruleName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_rules_list = _all_rules()

        filtered = filter_rules(
            all_rules_list,
            enabled=enabled,
            priority=priority,
            category=category,
            severity=severity,
            author=author,
            projectId=projectId,
            investigationId=investigationId,
            minimumConditions=minimumConditions,
            maximumConditions=maximumConditions,
            minimumActions=minimumActions,
            maximumActions=maximumActions,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )

        sorted_list = sort_rules(filtered, sortBy, sortOrder)
        sliced, total = paginate_rules(sorted_list, page, pageSize)

        serialized = [_to_response_model(x).model_dump() for x in sliced]
        return build_paginated_response(
            data=serialized,
            page=page,
            page_size=pageSize,
            total_items=total,
            message="Rules retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.get(
    "/statistics",
    response_model=APIResponse,
    summary="Get rule statistics",
)
def get_rule_statistics_endpoint() -> APIResponse:
    try:
        all_rules_list = _all_rules()
        stats = calculate_rule_statistics(all_rules_list)
        payload = RuleStatisticsResponse(**stats).model_dump()
        return build_success_response(
            data=payload,
            message="Rule statistics computed successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.get(
    "/search",
    response_model=APIResponse,
    summary="Search rules",
)
def search_rules_endpoint(
    q: str = "",
    sortBy: str = "ruleName",
    sortOrder: str = "asc",
    page: int = 1,
    pageSize: int = 50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        all_rules_list = _all_rules()

        searched = search_rules(all_rules_list, q)
        sorted_list = sort_rules(searched, sortBy, sortOrder)
        sliced, total = paginate_rules(sorted_list, page, pageSize)

        serialized = [_to_response_model(x).model_dump() for x in sliced]
        total_pages = math.ceil(total / pageSize) if total > 0 else 1

        search_data = RuleSearchResponse(
            rules=serialized,
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


@rules_router.get(
    "/{ruleId}",
    response_model=APIResponse,
    summary="Get rule by ID",
)
def get_rule(ruleId: str) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        return build_success_response(
            data=_to_response_model(c).model_dump(),
            message="Rule retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post(
    "/",
    response_model=APIResponse,
    summary="Create a rule record",
)
def create_rule(
    request: CreateRuleRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        from services.rules_engine_service import (
            build_rule_condition,
            build_rule,
            RuleSeverityEnum,
            RuleStatusEnum,
            RuleActionEnum,
        )

        # Build conditions
        conds_built = []
        for cd in (request.conditions or []):
            conds_built.append(
                build_rule_condition(
                    cd.field,
                    cd.operator,
                    cd.value,
                    cd.createdAt,
                    validate=False,
                )
            )

        # Build action enums
        actions_built = []
        for ac in (request.actions or []):
            actions_built.append(RuleActionEnum(ac.actionType.strip().upper()))

        try:
            sev_enum = RuleSeverityEnum(request.severity.strip().upper())
            stat_enum = RuleStatusEnum(request.status.strip().upper())
            rb = build_rule(
                name=request.name,
                severity=sev_enum,
                status=stat_enum,
                conditions=conds_built,
                actions=actions_built,
                priority=request.priority,
                created_at=request.createdAt,
                description=request.description or "",
            )
        except Exception as e:
            raise APIErrorValidation(str(e))

        rec_id = rb.ruleId
        if rec_id in _RULE_STORE:
            raise APIErrorConflict(f"Rule with ID '{rec_id}' (name '{request.name}') already exists.")

        # Re-map actions to preserve parameters
        import uuid
        from services.rules_engine_service import _RULES_NS
        actions_dict_list = []
        for ac in (request.actions or []):
            act_type = ac.actionType.strip().upper()
            actions_dict_list.append({
                "actionId": str(uuid.uuid5(_RULES_NS, f"{rec_id}:{act_type}")),
                "actionType": act_type,
                "parameters": ac.parameters or {},
            })

        rule_dict = _to_store_dict(rb, request.model_dump())
        rule_dict["actions"] = actions_dict_list

        _RULE_STORE[rec_id] = rule_dict

        return build_success_response(
            data=_to_response_model(rule_dict).model_dump(),
            message="Rule created successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put(
    "/{ruleId}",
    response_model=APIResponse,
    summary="Update a rule record",
)
def update_rule(
    ruleId: str,
    request: UpdateRuleRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        # Map to core Rule object
        rule_obj = _dict_to_rule_object(c)

        # Prepare parameters
        from services.rules_engine_service import (
            update_rule as service_update_rule,
            RuleSeverityEnum,
            RuleStatusEnum,
            RuleActionEnum
        )

        name_param = request.name
        description_param = request.description

        severity_param = None
        if request.severity is not None:
            severity_param = RuleSeverityEnum(request.severity.strip().upper())

        status_param = None
        if request.status is not None:
            status_param = RuleStatusEnum(request.status.strip().upper())

        priority_param = request.priority

        # Build conditions if supplied
        conditions_param = None
        if request.conditions is not None:
            from services.rules_engine_service import build_rule_condition
            conditions_param = []
            for cd in request.conditions:
                conditions_param.append(
                    build_rule_condition(
                        cd.field,
                        cd.operator,
                        cd.value,
                        cd.createdAt,
                        validate=False
                    )
                )

        # Build actions if supplied
        actions_param = None
        if request.actions is not None:
            actions_param = []
            for ac in request.actions:
                actions_param.append(RuleActionEnum(ac.actionType.strip().upper()))

        # Call update_rule
        updated_list = service_update_rule(
            rules=[rule_obj],
            rule_id=rule_obj.ruleId,
            updated_at=request.updatedAt or "2026-07-06T12:00:00Z",
            name=name_param,
            description=description_param,
            severity=severity_param,
            status=status_param,
            conditions=conditions_param,
            actions=actions_param,
            priority=priority_param
        )

        if not updated_list:
            raise APIErrorInternal("Update failed.")

        updated_rule_obj = updated_list[0]

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
        if request.updatedAt is not None:
            merged_dict["updatedAt"] = request.updatedAt

        # Re-map actions to preserve parameters
        if request.actions is not None:
            import uuid
            from services.rules_engine_service import _RULES_NS
            actions_dict_list = []
            for ac in request.actions:
                act_type = ac.actionType.strip().upper()
                actions_dict_list.append({
                    "actionId": str(uuid.uuid5(_RULES_NS, f"{updated_rule_obj.ruleId}:{act_type}")),
                    "actionType": act_type,
                    "parameters": ac.parameters or {},
                })
            merged_dict["actions"] = actions_dict_list

        updated_dict = _to_store_dict(updated_rule_obj, merged_dict)
        if request.actions is None:
            updated_dict["actions"] = merged_dict["actions"]

        old_id = c["ruleId"]
        new_id = updated_dict["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_dict

        return build_success_response(
            data=_to_response_model(updated_dict).model_dump(),
            message="Rule updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.delete(
    "/{ruleId}",
    response_model=APIResponse,
    summary="Delete a rule record",
)
def delete_rule(ruleId: str) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        rec_id = c["ruleId"]
        if rec_id in _RULE_STORE:
            del _RULE_STORE[rec_id]

        return build_success_response(
            data={"ruleId": rec_id},
            message="Rule deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Conditions sub-resource endpoints
# ---------------------------------------------------------------------------

@rules_router.get(
    "/{ruleId}/conditions",
    response_model=APIResponse,
    summary="Get conditions of a rule",
)
def get_rule_conditions_endpoint(ruleId: str) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        resp = _to_response_model(c)
        return build_success_response(
            data=[x.model_dump() for x in resp.conditions],
            message="Rule conditions retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post(
    "/{ruleId}/conditions",
    response_model=APIResponse,
    summary="Append a condition to a rule",
)
def append_condition(
    ruleId: str,
    request: RuleConditionRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        updated_rule = append_rule_condition(c, request)
        old_id = c["ruleId"]
        new_id = updated_rule["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_rule

        return build_success_response(
            data=_to_response_model(updated_rule).model_dump(),
            message="Rule condition appended successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put(
    "/{ruleId}/conditions/{conditionId}",
    response_model=APIResponse,
    summary="Update a rule condition",
)
def update_condition(
    ruleId: str,
    conditionId: str,
    request: RuleConditionRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        updated_rule = update_rule_condition(c, conditionId, request)
        old_id = c["ruleId"]
        new_id = updated_rule["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_rule

        return build_success_response(
            data=_to_response_model(updated_rule).model_dump(),
            message="Rule condition updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.delete(
    "/{ruleId}/conditions/{conditionId}",
    response_model=APIResponse,
    summary="Delete a rule condition",
)
def delete_condition(
    ruleId: str,
    conditionId: str
) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        updated_rule = delete_rule_condition(c, conditionId)
        old_id = c["ruleId"]
        new_id = updated_rule["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_rule

        return build_success_response(
            data=_to_response_model(updated_rule).model_dump(),
            message="Rule condition deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Actions sub-resource endpoints
# ---------------------------------------------------------------------------

@rules_router.get(
    "/{ruleId}/actions",
    response_model=APIResponse,
    summary="Get actions of a rule",
)
def get_rule_actions_endpoint(ruleId: str) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        resp = _to_response_model(c)
        return build_success_response(
            data=[x.model_dump() for x in resp.actions],
            message="Rule actions retrieved successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post(
    "/{ruleId}/actions",
    response_model=APIResponse,
    summary="Append an action to a rule",
)
def append_action(
    ruleId: str,
    request: RuleActionRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        updated_rule = append_rule_action(c, request)
        old_id = c["ruleId"]
        new_id = updated_rule["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_rule

        return build_success_response(
            data=_to_response_model(updated_rule).model_dump(),
            message="Rule action appended successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put(
    "/{ruleId}/actions/{actionId}",
    response_model=APIResponse,
    summary="Update a rule action",
)
def update_action(
    ruleId: str,
    actionId: str,
    request: RuleActionRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        updated_rule = update_rule_action(c, actionId, request)
        old_id = c["ruleId"]
        new_id = updated_rule["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_rule

        return build_success_response(
            data=_to_response_model(updated_rule).model_dump(),
            message="Rule action updated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.delete(
    "/{ruleId}/actions/{actionId}",
    response_model=APIResponse,
    summary="Delete a rule action",
)
def delete_action(
    ruleId: str,
    actionId: str
) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        updated_rule = delete_rule_action(c, actionId)
        old_id = c["ruleId"]
        new_id = updated_rule["ruleId"]
        if old_id in _RULE_STORE:
            del _RULE_STORE[old_id]
        _RULE_STORE[new_id] = updated_rule

        return build_success_response(
            data=_to_response_model(updated_rule).model_dump(),
            message="Rule action deleted successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Summary endpoint
# ---------------------------------------------------------------------------

@rules_router.get(
    "/{ruleId}/summary",
    response_model=APIResponse,
    summary="Get rule summary",
)
def get_rule_summary(ruleId: str) -> APIResponse:
    try:
        all_rules_list = _all_rules()
        c = find_rule(all_rules_list, ruleId)
        if not c:
            raise APIErrorNotFound(f"Rule '{ruleId}' not found.")

        summary = build_rule_summary(c)
        payload = RuleSummaryResponse(**summary).model_dump()
        return build_success_response(
            data=payload,
            message="Rule summary generated successfully.",
        )
    except APILayerError as e:
        return exception_to_api_response(e)
    except Exception as e:
        return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Bulk Operations
# ---------------------------------------------------------------------------

@rules_router.post(
    "/bulk/create",
    response_model=APIResponse,
    summary="Bulk create rule records",
)
def bulk_create_rules(
    request: BulkCreateRulesRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.rules_engine_service import (
            build_rule_condition,
            build_rule,
            RuleSeverityEnum,
            RuleStatusEnum,
            RuleActionEnum,
        )

        for item in request.rules:
            try:
                # Build conditions
                conds_built = []
                for cd in (item.conditions or []):
                    conds_built.append(
                        build_rule_condition(
                            cd.field,
                            cd.operator,
                            cd.value,
                            cd.createdAt,
                            validate=False,
                        )
                    )

                # Build actions
                actions_built = []
                for ac in (item.actions or []):
                    actions_built.append(RuleActionEnum(ac.actionType.strip().upper()))

                rb = build_rule(
                    name=item.name,
                    severity=RuleSeverityEnum(item.severity.strip().upper()),
                    status=RuleStatusEnum(item.status.strip().upper()),
                    conditions=conds_built,
                    actions=actions_built,
                    priority=item.priority,
                    created_at=item.createdAt,
                    description=item.description or "",
                )

                rec_id = rb.ruleId
                if rec_id in _RULE_STORE or rec_id in succeeded:
                    failed.append({"id": item.name, "reason": f"Rule '{rec_id}' already exists."})
                    continue

                import uuid
                from services.rules_engine_service import _RULES_NS
                actions_dict_list = []
                for ac in (item.actions or []):
                    act_type = ac.actionType.strip().upper()
                    actions_dict_list.append({
                        "actionId": str(uuid.uuid5(_RULES_NS, f"{rec_id}:{act_type}")),
                        "actionType": act_type,
                        "parameters": ac.parameters or {},
                    })

                rule_dict = _to_store_dict(rb, item.model_dump())
                rule_dict["actions"] = actions_dict_list

                _RULE_STORE[rec_id] = rule_dict
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.name, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.rules),
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


@rules_router.put(
    "/bulk/update",
    response_model=APIResponse,
    summary="Bulk update rule records",
)
def bulk_update_rules(
    request: BulkUpdateRulesRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        from services.rules_engine_service import (
            update_rule as service_update_rule,
            RuleSeverityEnum,
            RuleStatusEnum,
            RuleActionEnum,
        )

        for item in request.items:
            rec_id = None
            all_rules_list = _all_rules()
            existing = find_rule(all_rules_list, item.ruleId)
            if existing:
                rec_id = existing["ruleId"]

            if not rec_id:
                failed.append({"id": item.ruleId, "reason": f"Rule '{item.ruleId}' not found."})
                continue

            try:
                rule_obj = _dict_to_rule_object(existing)

                name_param = item.update.name
                description_param = item.update.description

                severity_param = None
                if item.update.severity is not None:
                    severity_param = RuleSeverityEnum(item.update.severity.strip().upper())

                status_param = None
                if item.update.status is not None:
                    status_param = RuleStatusEnum(item.update.status.strip().upper())

                priority_param = item.update.priority

                conditions_param = None
                if item.update.conditions is not None:
                    from services.rules_engine_service import build_rule_condition
                    conditions_param = []
                    for cd in item.update.conditions:
                        conditions_param.append(
                            build_rule_condition(
                                cd.field,
                                cd.operator,
                                cd.value,
                                cd.createdAt,
                                validate=False
                            )
                        )

                actions_param = None
                if item.update.actions is not None:
                    actions_param = []
                    for ac in item.update.actions:
                        actions_param.append(RuleActionEnum(ac.actionType.strip().upper()))

                updated_list = service_update_rule(
                    rules=[rule_obj],
                    rule_id=rule_obj.ruleId,
                    updated_at=item.update.updatedAt or "2026-07-06T12:00:00Z",
                    name=name_param,
                    description=description_param,
                    severity=severity_param,
                    status=status_param,
                    conditions=conditions_param,
                    actions=actions_param,
                    priority=priority_param
                )

                if not updated_list:
                    failed.append({"id": item.ruleId, "reason": "Update failed."})
                    continue

                updated_rule_obj = updated_list[0]

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
                if item.update.updatedAt is not None:
                    merged_dict["updatedAt"] = item.update.updatedAt

                if item.update.actions is not None:
                    import uuid
                    from services.rules_engine_service import _RULES_NS
                    actions_dict_list = []
                    for ac in item.update.actions:
                        act_type = ac.actionType.strip().upper()
                        actions_dict_list.append({
                            "actionId": str(uuid.uuid5(_RULES_NS, f"{updated_rule_obj.ruleId}:{act_type}")),
                            "actionType": act_type,
                            "parameters": ac.parameters or {},
                        })
                    merged_dict["actions"] = actions_dict_list

                updated_dict = _to_store_dict(updated_rule_obj, merged_dict)
                if item.update.actions is None:
                    updated_dict["actions"] = merged_dict["actions"]

                old_id = existing["ruleId"]
                new_id = updated_dict["ruleId"]
                if old_id in _RULE_STORE:
                    del _RULE_STORE[old_id]
                _RULE_STORE[new_id] = updated_dict

                succeeded.append(new_id)
            except Exception as e:
                failed.append({"id": item.ruleId, "reason": str(e)})

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


@rules_router.post(
    "/bulk/delete",
    response_model=APIResponse,
    summary="Bulk delete rule records",
)
def bulk_delete_rules(
    request: BulkDeleteRulesRequest = Body(...)
) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors:
            raise APIErrorValidation("Validation failed.", details=errors)

        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        for rid in request.ruleIds:
            all_rules_list = _all_rules()
            existing = find_rule(all_rules_list, rid)
            if not existing:
                failed.append({"id": rid, "reason": f"Rule '{rid}' not found."})
                continue

            try:
                rec_id = existing["ruleId"]
                if rec_id in _RULE_STORE:
                    del _RULE_STORE[rec_id]
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": rid, "reason": str(e)})

        res = BulkOperationResult(
            succeeded=succeeded,
            failed=failed,
            total=len(request.ruleIds),
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
