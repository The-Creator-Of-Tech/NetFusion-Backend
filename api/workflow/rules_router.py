"""
Rules API Router — Canonical Schema
=====================================
All normalization via normalizers.normalize_rule().
All response models use canonical RuleResponse aligned with Prisma.
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
from api.workflow.rules_models import (
    CreateRuleRequest, UpdateRuleRequest,
    RuleConditionRequest, RuleConditionResponse,
    RuleActionRequest, RuleActionResponse,
    RuleResponse, RuleStatisticsResponse, RuleSearchResponse,
    RuleSummaryResponse, BulkCreateRulesRequest, BulkUpdateRulesRequest,
    BulkDeleteRulesRequest, BulkOperationResult,
)
from api.workflow.normalizers import normalize_rule
from api.persistence import RepositoryBackedDict, map_rule

rules_router = APIRouter(prefix="/rules", tags=["Rules Engine"])
_RULE_STORE = RepositoryBackedDict("rule", "ruleId", map_rule)
_RULES_NS   = uuid.UUID("6ba7b884-9dad-11d1-80b4-00c04fd430c8")


def _reset_store() -> None:
    _RULE_STORE.clear()


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _to_response(raw: Dict) -> RuleResponse:
    c = normalize_rule(raw)
    conds = [RuleConditionResponse(**cd) for cd in c["conditions"]]
    acts  = [RuleActionResponse(**a)    for a  in c["actions"]]
    return RuleResponse(
        ruleId=c["ruleId"], ruleKey=c["ruleKey"],
        name=c["name"], description=c["description"],
        severity=c["severity"], status=c["status"],
        projectId=c["projectId"], investigationId=c["investigationId"],
        conditions=conds, actions=acts,
        priority=c["priority"], createdAt=c["createdAt"],
        updatedAt=c["updatedAt"], enabled=c["enabled"],
        category=c["category"], author=c["author"],
    )


def _all() -> List[Dict]:
    return sorted(
        [normalize_rule(r) for r in _RULE_STORE.values()],
        key=lambda r: r["name"],
    )


def _find(rules: List[Dict], ident: str) -> Optional[Dict]:
    n = ident.strip().lower()
    for r in rules:
        if r["ruleId"].lower() == n:  return r
        if r["ruleKey"].lower() == n: return r
        if r["name"].lower() == n:    return r
    return None


def _sort(items: List[Dict], sort_by: str, sort_order: str) -> List[Dict]:
    valid = {"ruleName","createdAt","updatedAt","priority","enabled","conditionCount","actionCount"}
    if sort_by not in valid:
        raise APIErrorValidation("Invalid sort field.",
            details=[f"'{sort_by}' not supported. Valid: {sorted(valid)}"])
    if sort_order.lower() not in {"asc","desc"}:
        raise APIErrorValidation("Invalid sort order.")
    def key(r):
        if sort_by == "ruleName":       return r["name"]
        if sort_by == "conditionCount": return len(r["conditions"])
        if sort_by == "actionCount":    return len(r["actions"])
        if sort_by == "enabled":        return int(r["enabled"])
        return r.get(sort_by,"") or ""
    base = sorted(items, key=lambda x: x["ruleId"])
    base.sort(key=key, reverse=(sort_order.lower()=="desc"))
    return base


def _filter(items, enabled=None, priority=None, category=None,
             severity=None, author=None, projectId=None,
             investigationId=None, minimumConditions=None,
             maximumConditions=None, minimumActions=None,
             maximumActions=None, createdAfter=None, createdBefore=None):
    r = list(items)
    if enabled           is not None: r = [x for x in r if bool(x["enabled"])==enabled]
    if priority          is not None: r = [x for x in r if x["priority"]==priority]
    if category          is not None: r = [x for x in r if x["category"].lower()==category.strip().lower()]
    if severity          is not None: r = [x for x in r if x["severity"].upper()==severity.strip().upper()]
    if author            is not None: r = [x for x in r if author.strip().lower() in x["author"].lower()]
    if projectId         is not None: r = [x for x in r if x["projectId"]==projectId.strip()]
    if investigationId   is not None: r = [x for x in r if x["investigationId"]==investigationId.strip()]
    if minimumConditions is not None: r = [x for x in r if len(x["conditions"])>=minimumConditions]
    if maximumConditions is not None: r = [x for x in r if len(x["conditions"])<=maximumConditions]
    if minimumActions    is not None: r = [x for x in r if len(x["actions"])>=minimumActions]
    if maximumActions    is not None: r = [x for x in r if len(x["actions"])<=maximumActions]
    if createdAfter      is not None: r = [x for x in r if x["createdAt"]>=createdAfter.strip()]
    if createdBefore     is not None: r = [x for x in r if x["createdAt"]<=createdBefore.strip()]
    return r


def _paginate(items, page, size):
    total = len(items)
    start = (page-1)*size
    return items[start:start+size], total


def _search(items, q):
    if not q or not q.strip(): return list(items)
    ql = q.strip().lower()
    out = []
    for r in items:
        if (ql in r["name"].lower() or ql in r["description"].lower()
                or ql in r["category"].lower() or ql in r["author"].lower()
                or any(ql in c["field"].lower() or ql in c["value"].lower()
                       for c in r["conditions"])
                or any(ql in a["actionType"].lower() for a in r["actions"])):
            out.append(r)
    return out


def _stats(items) -> Dict:
    total = len(items)
    enabled = sum(1 for r in items if r["enabled"])
    tc = sum(len(r["conditions"]) for r in items)
    ta = sum(len(r["actions"])    for r in items)
    tp = sum(r["priority"]        for r in items)
    cat: Dict[str,int] = {}
    for r in items:
        c = r["category"].strip()
        if c: cat[c] = cat.get(c,0)+1
    return {
        "totalRules":        total,
        "enabledRules":      enabled,
        "disabledRules":     total-enabled,
        "averageConditions": round(tc/total,4) if total else 0.0,
        "averageActions":    round(ta/total,4) if total else 0.0,
        "averagePriority":   round(tp/total,4) if total else 0.0,
        "categoryCounts":    dict(sorted(cat.items())),
    }


def _summary(r: Dict) -> Dict:
    name = r["name"]; sev = r["severity"]; st = r["status"]
    cc = len(r["conditions"]); ac = len(r["actions"])
    enabled = r["enabled"]; pri = r["priority"]
    return {
        "ruleId":         r["ruleId"],
        "ruleName":       name,
        "summaryText":    (
            f"Rule '{name}' ({st}) has {cc} conditions and {ac} actions. "
            f"Severity {sev}, priority {pri}, {'enabled' if enabled else 'disabled'}."
        ),
        "conditionCount": cc, "actionCount": ac,
        "severity": sev, "status": st, "enabled": enabled, "priority": pri,
    }


def _to_store_dict(rule_obj, req_dict: Dict) -> Dict:
    from services.rules_engine_service import _RULES_NS as NS
    conds = []
    for c in rule_obj.conditions:
        conds.append({"conditionId": c.conditionId, "conditionKey": c.conditionKey,
                      "field": c.field, "operator": c.operator,
                      "value": c.value, "createdAt": c.createdAt})
    acts = []
    orig_acts = {a["actionType"]: a for a in req_dict.get("actions", [])}
    for act in rule_obj.actions:
        orig = orig_acts.get(act.value, {})
        acts.append({
            "actionId":   orig.get("actionId") or str(uuid.uuid5(NS, f"{rule_obj.ruleId}:{act.value}")),
            "actionType": act.value,
            "parameters": orig.get("parameters") or {},
        })
    return {
        "ruleId":          rule_obj.ruleId,
        "ruleKey":         rule_obj.ruleKey,
        "name":            rule_obj.name,
        "description":     rule_obj.description,
        "severity":        rule_obj.severity.value,
        "status":          rule_obj.status.value,
        "conditions":      conds,
        "actions":         acts,
        "priority":        rule_obj.priority,
        "createdAt":       rule_obj.createdAt,
        "updatedAt":       req_dict.get("updatedAt"),
        "enabled":         bool(req_dict.get("enabled", True)),
        "category":        req_dict.get("category", ""),
        "author":          req_dict.get("author", ""),
        "projectId":       req_dict.get("projectId", ""),
        "investigationId": req_dict.get("investigationId") or "",
    }


def _dict_to_rule_obj(d: Dict):
    from services.rules_engine_service import (
        Rule, RuleCondition, RuleActionEnum, RuleSeverityEnum, RuleStatusEnum,
    )
    n = normalize_rule(d)
    conds = [RuleCondition(
        conditionId=c["conditionId"], conditionKey=c["conditionKey"],
        field=c["field"], operator=c["operator"],
        value=c["value"], createdAt=c["createdAt"],
    ) for c in n["conditions"]]
    acts = []
    for a in n["actions"]:
        try: acts.append(RuleActionEnum(a["actionType"].strip().upper()))
        except ValueError: pass
    try:   sev  = RuleSeverityEnum(n["severity"].strip().upper())
    except ValueError: sev = RuleSeverityEnum("MEDIUM")
    try:   stat = RuleStatusEnum(n["status"].strip().upper())
    except ValueError: stat = RuleStatusEnum("DRAFT")
    from services.rules_engine_service import build_rule
    return build_rule(
        name=n["name"], severity=sev, status=stat,
        conditions=conds, actions=acts,
        priority=n["priority"], created_at=n["createdAt"],
        description=n["description"], validate=False,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@rules_router.get("/", response_model=APIResponse)
def list_rules(
    enabled: Optional[bool]=None, priority: Optional[int]=None,
    category: Optional[str]=None, severity: Optional[str]=None,
    author: Optional[str]=None, projectId: Optional[str]=None,
    investigationId: Optional[str]=None,
    minimumConditions: Optional[int]=None, maximumConditions: Optional[int]=None,
    minimumActions: Optional[int]=None, maximumActions: Optional[int]=None,
    createdAfter: Optional[str]=None, createdBefore: Optional[str]=None,
    sortBy: str="ruleName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _filter(_all(), enabled=enabled, priority=priority,
            category=category, severity=severity, author=author,
            projectId=projectId, investigationId=investigationId,
            minimumConditions=minimumConditions, maximumConditions=maximumConditions,
            minimumActions=minimumActions, maximumActions=maximumActions,
            createdAfter=createdAfter, createdBefore=createdBefore)
        items = _sort(items, sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        return build_paginated_response(
            items=[_to_response(x).model_dump() for x in page_items],
            page=page, page_size=pageSize, total_items=total,
            message="Rules retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.get("/statistics", response_model=APIResponse)
def get_rule_statistics() -> APIResponse:
    try:
        return build_success_response(data=_stats(_all()),
            message="Rule statistics computed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.get("/search", response_model=APIResponse)
def search_rules_endpoint(
    q: str="", sortBy: str="ruleName", sortOrder: str="asc",
    page: int=1, pageSize: int=50,
) -> APIResponse:
    try:
        validate_pagination(page, pageSize)
        items = _sort(_search(_all(), q), sortBy, sortOrder)
        page_items, total = _paginate(items, page, pageSize)
        total_pages = math.ceil(total/pageSize) if total else 1
        payload = RuleSearchResponse(
            rules=[_to_response(x) for x in page_items],
            total=total, page=page, pageSize=pageSize,
            totalPages=total_pages, query=q, sortBy=sortBy, sortOrder=sortOrder,
        )
        return build_success_response(data=payload.model_dump(),
            message="Search completed successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.get("/{ruleId}", response_model=APIResponse)
def get_rule(ruleId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        return build_success_response(data=_to_response(c).model_dump(),
            message="Rule retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post("/", response_model=APIResponse)
def create_rule(request: CreateRuleRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.rules_engine_service import (
            build_rule_condition, build_rule,
            RuleSeverityEnum, RuleStatusEnum, RuleActionEnum,
        )
        conds = [build_rule_condition(c.field, c.operator, c.value, c.createdAt, validate=False)
                 for c in (request.conditions or [])]
        acts  = [RuleActionEnum(a.actionType.strip().upper()) for a in (request.actions or [])]
        rule_obj = build_rule(
            name=request.name,
            severity=RuleSeverityEnum(request.severity.strip().upper()),
            status=RuleStatusEnum(request.status.strip().upper()),
            conditions=conds, actions=acts,
            priority=request.priority, created_at=request.createdAt,
            description=request.description or "",
        )
        rec_id = rule_obj.ruleId
        if rec_id in _RULE_STORE:
            raise APIErrorConflict(f"Rule '{rec_id}' already exists.")

        # Enrich actions with IDs + parameters
        acts_dict = []
        for a in (request.actions or []):
            at = a.actionType.strip().upper()
            acts_dict.append({
                "actionId":   str(uuid.uuid5(_RULES_NS, f"{rec_id}:{at}")),
                "actionType": at,
                "parameters": a.parameters or {},
            })
        store_dict = _to_store_dict(rule_obj, {**request.model_dump(), "actions": acts_dict})
        _RULE_STORE[rec_id] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Rule created successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put("/{ruleId}", response_model=APIResponse)
def update_rule(ruleId: str, request: UpdateRuleRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        from services.rules_engine_service import (
            update_rule as svc_update,
            build_rule_condition, RuleSeverityEnum, RuleStatusEnum, RuleActionEnum,
        )
        rule_obj = _dict_to_rule_obj(c)
        sev_p = RuleSeverityEnum(request.severity.strip().upper()) if request.severity else None
        sta_p = RuleStatusEnum(request.status.strip().upper())    if request.status   else None
        conds_p = ([build_rule_condition(cd.field, cd.operator, cd.value, cd.createdAt, validate=False)
                    for cd in request.conditions] if request.conditions is not None else None)
        acts_p  = ([RuleActionEnum(a.actionType.strip().upper()) for a in request.actions]
                    if request.actions is not None else None)
        updated_list = svc_update(
            rules=[rule_obj], rule_id=rule_obj.ruleId,
            updated_at=request.updatedAt or "2026-07-06T12:00:00Z",
            name=request.name, description=request.description,
            severity=sev_p, status=sta_p,
            conditions=conds_p, actions=acts_p, priority=request.priority,
        )
        if not updated_list: raise APIErrorInternal("Update failed.")
        updated_obj = updated_list[0]
        merged = dict(c)
        for field in ("enabled","category","author","projectId","investigationId","updatedAt"):
            v = getattr(request, field, None)
            if v is not None: merged[field] = v

        if request.actions is not None:
            acts_dict = []
            for a in request.actions:
                at = a.actionType.strip().upper()
                acts_dict.append({
                    "actionId":   str(uuid.uuid5(_RULES_NS, f"{updated_obj.ruleId}:{at}")),
                    "actionType": at,
                    "parameters": a.parameters or {},
                })
            merged["actions"] = acts_dict

        store_dict = _to_store_dict(updated_obj, merged)
        if request.actions is None:
            store_dict["actions"] = merged["actions"]
        old_id = c["ruleId"]
        if old_id in _RULE_STORE: del _RULE_STORE[old_id]
        _RULE_STORE[store_dict["ruleId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Rule updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.delete("/{ruleId}", response_model=APIResponse)
def delete_rule(ruleId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        del _RULE_STORE[c["ruleId"]]
        return build_success_response(data={"ruleId": c["ruleId"]},
            message="Rule deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Conditions sub-resource
# ---------------------------------------------------------------------------

@rules_router.get("/{ruleId}/conditions", response_model=APIResponse)
def get_conditions(ruleId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        return build_success_response(
            data=[cd for cd in _to_response(c).model_dump()["conditions"]],
            message="Conditions retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post("/{ruleId}/conditions", response_model=APIResponse)
def append_condition(ruleId: str, request: RuleConditionRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        from services.rules_engine_service import build_rule_condition, add_rule_condition
        rule_obj = _dict_to_rule_obj(c)
        new_cond = build_rule_condition(request.field, request.operator, request.value,
                                        request.createdAt, validate=False)
        new_rule = add_rule_condition(rule_obj, new_cond)
        store_dict = _to_store_dict(new_rule, c)
        old_id = c["ruleId"]
        if old_id in _RULE_STORE: del _RULE_STORE[old_id]
        _RULE_STORE[store_dict["ruleId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Condition appended successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put("/{ruleId}/conditions/{conditionId}", response_model=APIResponse)
def update_condition(ruleId: str, conditionId: str,
                     request: RuleConditionRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        from services.rules_engine_service import update_rule_condition as svc_upd_cond
        rule_obj = _dict_to_rule_obj(c)
        if not any(cd.conditionId == conditionId for cd in rule_obj.conditions):
            raise APIErrorNotFound(f"Condition '{conditionId}' not found.")
        new_rule = svc_upd_cond(rule_obj, conditionId,
            field=request.field, operator=request.operator,
            value=request.value, created_at=request.createdAt)
        store_dict = _to_store_dict(new_rule, c)
        old_id = c["ruleId"]
        if old_id in _RULE_STORE: del _RULE_STORE[old_id]
        _RULE_STORE[store_dict["ruleId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Condition updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.delete("/{ruleId}/conditions/{conditionId}", response_model=APIResponse)
def delete_condition(ruleId: str, conditionId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        from services.rules_engine_service import remove_rule_condition
        rule_obj = _dict_to_rule_obj(c)
        if not any(cd.conditionId == conditionId for cd in rule_obj.conditions):
            raise APIErrorNotFound(f"Condition '{conditionId}' not found.")
        new_rule = remove_rule_condition(rule_obj, conditionId)
        store_dict = _to_store_dict(new_rule, c)
        old_id = c["ruleId"]
        if old_id in _RULE_STORE: del _RULE_STORE[old_id]
        _RULE_STORE[store_dict["ruleId"]] = store_dict
        return build_success_response(data=_to_response(store_dict).model_dump(),
            message="Condition deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Actions sub-resource
# ---------------------------------------------------------------------------

@rules_router.get("/{ruleId}/actions", response_model=APIResponse)
def get_actions(ruleId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        return build_success_response(
            data=[a for a in _to_response(c).model_dump()["actions"]],
            message="Actions retrieved successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post("/{ruleId}/actions", response_model=APIResponse)
def append_action(ruleId: str, request: RuleActionRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        at = request.actionType.strip().upper()
        if any(a["actionType"] == at for a in c["actions"]):
            return build_success_response(data=_to_response(c).model_dump(),
                message="Action already exists (idempotent).")
        new_action = {
            "actionId":   str(uuid.uuid5(_RULES_NS, f"{c['ruleId']}:{at}")),
            "actionType": at,
            "parameters": request.parameters or {},
        }
        updated_c = dict(c)
        updated_c["actions"] = sorted(c["actions"] + [new_action],
                                       key=lambda x: x["actionType"])
        _RULE_STORE[c["ruleId"]] = updated_c
        return build_success_response(data=_to_response(updated_c).model_dump(),
            message="Action appended successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put("/{ruleId}/actions/{actionId}", response_model=APIResponse)
def update_action(ruleId: str, actionId: str,
                  request: RuleActionRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        found = False
        new_acts = []
        for a in c["actions"]:
            if a["actionId"] == actionId:
                found = True
                new_acts.append({
                    "actionId":   actionId,
                    "actionType": request.actionType.strip().upper(),
                    "parameters": request.parameters or {},
                })
            else:
                new_acts.append(a)
        if not found: raise APIErrorNotFound(f"Action '{actionId}' not found.")
        updated_c = {**c, "actions": sorted(new_acts, key=lambda x: x["actionType"])}
        _RULE_STORE[c["ruleId"]] = updated_c
        return build_success_response(data=_to_response(updated_c).model_dump(),
            message="Action updated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.delete("/{ruleId}/actions/{actionId}", response_model=APIResponse)
def delete_action(ruleId: str, actionId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        remaining = [a for a in c["actions"] if a["actionId"] != actionId]
        if len(remaining) == len(c["actions"]):
            raise APIErrorNotFound(f"Action '{actionId}' not found.")
        updated_c = {**c, "actions": remaining}
        _RULE_STORE[c["ruleId"]] = updated_c
        return build_success_response(data=_to_response(updated_c).model_dump(),
            message="Action deleted successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.get("/{ruleId}/summary", response_model=APIResponse)
def get_rule_summary(ruleId: str) -> APIResponse:
    try:
        c = _find(_all(), ruleId)
        if not c: raise APIErrorNotFound(f"Rule '{ruleId}' not found.")
        return build_success_response(data=RuleSummaryResponse(**_summary(c)).model_dump(),
            message="Summary generated successfully.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


# ---------------------------------------------------------------------------
# Bulk operations
# ---------------------------------------------------------------------------

@rules_router.post("/bulk/create", response_model=APIResponse)
def bulk_create_rules(request: BulkCreateRulesRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.rules_engine_service import (
            build_rule_condition, build_rule,
            RuleSeverityEnum, RuleStatusEnum, RuleActionEnum,
        )
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for item in request.rules:
            try:
                conds = [build_rule_condition(c.field, c.operator, c.value, c.createdAt, validate=False)
                         for c in (item.conditions or [])]
                acts  = [RuleActionEnum(a.actionType.strip().upper()) for a in (item.actions or [])]
                rule_obj = build_rule(
                    name=item.name,
                    severity=RuleSeverityEnum(item.severity.strip().upper()),
                    status=RuleStatusEnum(item.status.strip().upper()),
                    conditions=conds, actions=acts,
                    priority=item.priority, created_at=item.createdAt,
                    description=item.description or "",
                )
                rec_id = rule_obj.ruleId
                if rec_id in _RULE_STORE or rec_id in succeeded:
                    failed.append({"id": item.name, "reason": f"ID '{rec_id}' already exists."}); continue
                acts_dict = [{
                    "actionId": str(uuid.uuid5(_RULES_NS, f"{rec_id}:{a.actionType.strip().upper()}")),
                    "actionType": a.actionType.strip().upper(),
                    "parameters": a.parameters or {},
                } for a in (item.actions or [])]
                store_dict = _to_store_dict(rule_obj, {**item.model_dump(), "actions": acts_dict})
                _RULE_STORE[rec_id] = store_dict
                succeeded.append(rec_id)
            except Exception as e:
                failed.append({"id": item.name, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.rules), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk create completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.put("/bulk/update", response_model=APIResponse)
def bulk_update_rules(request: BulkUpdateRulesRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        from services.rules_engine_service import (
            update_rule as svc_update, build_rule_condition,
            RuleSeverityEnum, RuleStatusEnum, RuleActionEnum,
        )
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for item in request.items:
            existing = _find(_all(), item.ruleId)
            if not existing:
                failed.append({"id": item.ruleId, "reason": "Not found."}); continue
            try:
                u = item.update
                rule_obj = _dict_to_rule_obj(existing)
                sev_p  = RuleSeverityEnum(u.severity.strip().upper()) if u.severity else None
                sta_p  = RuleStatusEnum(u.status.strip().upper())    if u.status   else None
                conds_p = ([build_rule_condition(c.field, c.operator, c.value, c.createdAt, validate=False)
                             for c in u.conditions] if u.conditions is not None else None)
                acts_p  = ([RuleActionEnum(a.actionType.strip().upper()) for a in u.actions]
                            if u.actions is not None else None)
                updated_list = svc_update(
                    rules=[rule_obj], rule_id=rule_obj.ruleId,
                    updated_at=u.updatedAt or "2026-07-06T12:00:00Z",
                    name=u.name, description=u.description,
                    severity=sev_p, status=sta_p,
                    conditions=conds_p, actions=acts_p, priority=u.priority,
                )
                if not updated_list:
                    failed.append({"id": item.ruleId, "reason": "Update failed."}); continue
                updated_obj = updated_list[0]
                merged = dict(existing)
                for f in ("enabled","category","author","projectId","investigationId","updatedAt"):
                    v = getattr(u, f, None)
                    if v is not None: merged[f] = v
                if u.actions is not None:
                    merged["actions"] = [{
                        "actionId": str(uuid.uuid5(_RULES_NS, f"{updated_obj.ruleId}:{a.actionType.strip().upper()}")),
                        "actionType": a.actionType.strip().upper(),
                        "parameters": a.parameters or {},
                    } for a in u.actions]
                store_dict = _to_store_dict(updated_obj, merged)
                if u.actions is None: store_dict["actions"] = merged["actions"]
                old_id = existing["ruleId"]
                if old_id in _RULE_STORE: del _RULE_STORE[old_id]
                _RULE_STORE[store_dict["ruleId"]] = store_dict
                succeeded.append(store_dict["ruleId"])
            except Exception as e:
                failed.append({"id": item.ruleId, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.items), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk update completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))


@rules_router.post("/bulk/delete", response_model=APIResponse)
def bulk_delete_rules(request: BulkDeleteRulesRequest = Body(...)) -> APIResponse:
    try:
        errors = request.validate_request()
        if errors: raise APIErrorValidation("Validation failed.", details=errors)
        succeeded: List[str]=[]; failed: List[Dict[str,str]]=[]
        for rid in request.ruleIds:
            existing = _find(_all(), rid)
            if not existing:
                failed.append({"id": rid, "reason": "Not found."}); continue
            try:
                del _RULE_STORE[existing["ruleId"]]
                succeeded.append(existing["ruleId"])
            except Exception as e:
                failed.append({"id": rid, "reason": str(e)})
        return build_success_response(
            data=BulkOperationResult(succeeded=succeeded, failed=failed,
                total=len(request.ruleIds), successCount=len(succeeded),
                failCount=len(failed)).model_dump(),
            message="Bulk delete completed.")
    except APILayerError as e: return exception_to_api_response(e)
    except Exception as e:     return exception_to_api_response(APIErrorInternal(str(e)))
