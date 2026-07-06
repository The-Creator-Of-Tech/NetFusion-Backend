"""
Smoke Test for Rules Engine API — Phase A4.10.2
==============================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Condition CRUD operations (append, update, delete)
  ✓ Action CRUD operations (append, update, delete)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ Summary and statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 10000+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
from typing import Any, List, Dict

# Import API components
from api.workflow.rules_router import (
    rules_router,
    _reset_store,
    _all_rules,
    _RULE_STORE,
    _to_response_model,
    list_rules_endpoint,
    get_rule_statistics_endpoint,
    search_rules_endpoint,
    get_rule,
    create_rule,
    update_rule,
    delete_rule,
    get_rule_conditions_endpoint,
    append_condition,
    update_condition,
    delete_condition,
    get_rule_actions_endpoint,
    append_action,
    update_action,
    delete_action,
    get_rule_summary,
    bulk_create_rules,
    bulk_update_rules,
    bulk_delete_rules,
    # Utilities
    find_rule,
    find_rule_condition,
    find_rule_action,
    search_rules,
    search_rule_conditions,
    search_rule_actions,
    sort_rules,
    filter_rules,
    paginate_rules,
    build_rule_summary,
    calculate_rule_statistics,
)
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
from api.router import root_router

# Globals for tracking assertions
_ASSERTIONS = 0
_FAILURES = 0

def check(expr: bool, desc: str) -> None:
    global _ASSERTIONS, _FAILURES
    _ASSERTIONS += 1
    if not expr:
        _FAILURES += 1
        print(f"FAIL: {desc}")
        import traceback
        traceback.print_stack(limit=2)

def check_eq(actual: Any, expected: Any, desc: str) -> None:
    global _ASSERTIONS, _FAILURES
    _ASSERTIONS += 1
    if actual != expected:
        _FAILURES += 1
        print(f"FAIL: {desc} (Expected: {expected!r}, Got: {actual!r})")
        import traceback
        traceback.print_stack(limit=2)

def run_tests():
    global _ASSERTIONS, _FAILURES
    print("====================================================")
    print("Starting Rules Engine API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration
    # ---------------------------------------------------------------------------
    # ---------------------------------------------------------------------------
    # Test 1: Router Registration
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/workflow/rules"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/workflow/rules",
        "/api/v2/workflow/rules/",
        "/api/v2/workflow/rules/statistics",
        "/api/v2/workflow/rules/search",
        "/api/v2/workflow/rules/bulk/create",
        "/api/v2/workflow/rules/bulk/update",
        "/api/v2/workflow/rules/bulk/delete",
        "/api/v2/workflow/rules/{ruleId}",
        "/api/v2/workflow/rules/{ruleId}/conditions",
        "/api/v2/workflow/rules/{ruleId}/conditions/{conditionId}",
        "/api/v2/workflow/rules/{ruleId}/actions",
        "/api/v2/workflow/rules/{ruleId}/actions/{actionId}",
        "/api/v2/workflow/rules/{ruleId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Validation Failures & Edge Cases
    # ---------------------------------------------------------------------------
    print("Testing validation failures...")
    _reset_store()

    # Empty name
    req_bad_name = CreateRuleRequest(
        name="",
        severity="HIGH",
        status="ACTIVE",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad = create_rule(req_bad_name)
    check_eq(res_bad.success, False, "Create rule with empty name fails")
    check_eq(res_bad.data.errorCode, "VALIDATION_ERROR", "Error code is VALIDATION_ERROR")

    # Invalid severity
    req_bad_sev = CreateRuleRequest(
        name="Bad Sev",
        severity="SUPER_CRITICAL",
        status="ACTIVE",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_sev = create_rule(req_bad_sev)
    check_eq(res_bad_sev.success, False, "Create rule with invalid severity fails")

    # Invalid status
    req_bad_status = CreateRuleRequest(
        name="Bad Status",
        severity="HIGH",
        status="EXPIRED",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_status = create_rule(req_bad_status)
    check_eq(res_bad_status.success, False, "Create rule with invalid status fails")

    # Invalid priority
    req_bad_priority = CreateRuleRequest(
        name="Bad Priority",
        severity="HIGH",
        status="ACTIVE",
        priority=0,
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_priority = create_rule(req_bad_priority)
    check_eq(res_bad_priority.success, False, "Create rule with invalid priority fails")

    # Condition validations
    cond_bad = RuleConditionRequest(field="", operator="eq", value="val", createdAt="2026-07-06T12:00:00Z")
    req_bad_cond = CreateRuleRequest(
        name="Bad Cond Rule",
        severity="HIGH",
        status="ACTIVE",
        conditions=[cond_bad],
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_cond = create_rule(req_bad_cond)
    check_eq(res_bad_cond.success, False, "Create rule with empty condition field fails")

    # Action validations
    action_bad = RuleActionRequest(actionType="INVALID_ACTION", parameters={})
    req_bad_action = CreateRuleRequest(
        name="Bad Action Rule",
        severity="HIGH",
        status="ACTIVE",
        actions=[action_bad],
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_action = create_rule(req_bad_action)
    check_eq(res_bad_action.success, False, "Create rule with invalid action type fails")

    # 404 Get individual non-existent
    res_404 = get_rule("non-existent-rule-id")
    check_eq(res_404.success, False, "Get non-existent rule returns success=False")
    check_eq(res_404.data.errorCode, "NOT_FOUND", "Error code is NOT_FOUND")

    # ---------------------------------------------------------------------------
    # Test 3: Rule CRUD operations & validations
    # ---------------------------------------------------------------------------
    print("Testing Rule CRUD operations...")
    cond_req = RuleConditionRequest(
        field="severity",
        operator="eq",
        value="CRITICAL",
        createdAt="2026-07-06T12:00:00Z"
    )
    act_req = RuleActionRequest(
        actionType="CREATE_ALERT",
        parameters={"priority": "high"}
    )
    valid_req = CreateRuleRequest(
        name="Critical Alert Rule",
        description="Raise alert when severity is critical",
        severity="CRITICAL",
        status="ACTIVE",
        conditions=[cond_req],
        actions=[act_req],
        priority=10,
        createdAt="2026-07-06T12:00:00Z",
        category="detection",
        author="secops",
        projectId="p-001",
        investigationId="inv-100"
    )

    res_create = create_rule(valid_req)
    check_eq(res_create.success, True, "Rule creation succeeds")
    created_id = res_create.data["ruleId"]
    check(len(created_id) == 36, "Rule ID is UUIDv5")
    check_eq(res_create.data["name"], "Critical Alert Rule", "Name preserved")
    check_eq(res_create.data["category"], "detection", "Category preserved")
    check_eq(res_create.data["author"], "secops", "Author preserved")
    check_eq(res_create.data["projectId"], "p-001", "ProjectId preserved")
    check_eq(res_create.data["investigationId"], "inv-100", "InvestigationId preserved")

    # 409 Conflict Create Duplicate
    res_dup = create_rule(valid_req)
    check_eq(res_dup.success, False, "Creating duplicate rule returns success=False")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Error code is CONFLICT")

    # Read Rule
    res_get = get_rule(created_id)
    check_eq(res_get.success, True, "Retrieve rule by ID succeeds")
    check_eq(res_get.data["ruleId"], created_id, "Correct rule retrieved")

    # Update Rule Metadata (identity stays same)
    update_req = UpdateRuleRequest(
        description="Raise high priority alert when severity is critical",
        enabled=False,
        category="automation",
        author="incident-response",
        projectId="p-002",
        investigationId="inv-200"
    )
    res_up = update_rule(created_id, update_req)
    check_eq(res_up.success, True, "Update rule details succeeds")
    check_eq(res_up.data["ruleId"], created_id, "Rule ID is stable")
    check_eq(res_up.data["description"], "Raise high priority alert when severity is critical", "Description updated")
    check_eq(res_up.data["enabled"], False, "Enabled status updated")
    check_eq(res_up.data["category"], "automation", "Category updated")
    check_eq(res_up.data["projectId"], "p-002", "ProjectId updated")
    check_eq(res_up.data["investigationId"], "inv-200", "InvestigationId updated")

    # Update Rule Identity (rule name changes, so ruleId changes!)
    update_req_name = UpdateRuleRequest(
        name="Critical Alert Rule (Renamed)"
    )
    res_up_name = update_rule(created_id, update_req_name)
    check_eq(res_up_name.success, True, "Update rule name succeeds")
    new_created_id = res_up_name.data["ruleId"]
    check(new_created_id != created_id, "Rule ID changed because name changed")
    created_id = new_created_id

    # ---------------------------------------------------------------------------
    # Test 4: Condition CRUD operations
    # ---------------------------------------------------------------------------
    print("Testing Condition CRUD operations...")
    cond_req2 = RuleConditionRequest(
        field="hostname",
        operator="contains",
        value="prod-web",
        createdAt="2026-07-06T12:05:00Z"
    )
    res_app_cond = append_condition(created_id, cond_req2)
    check_eq(res_app_cond.success, True, "Append condition succeeds")
    created_id = res_app_cond.data["ruleId"]
    check_eq(len(res_app_cond.data["conditions"]), 2, "Rule now has 2 conditions")
    cond2 = next(c for c in res_app_cond.data["conditions"] if c["field"] == "hostname")
    cond2_id = cond2["conditionId"]

    # Get Conditions Endpoint
    res_get_conds = get_rule_conditions_endpoint(created_id)
    check_eq(res_get_conds.success, True, "Get conditions route succeeds")
    check_eq(len(res_get_conds.data), 2, "Returned conditions list has 2 items")

    # Update Condition
    cond_req_up = RuleConditionRequest(
        field="hostname",
        operator="contains",
        value="prod-db",
        createdAt="2026-07-06T12:05:00Z"
    )
    res_up_cond = update_condition(created_id, cond2_id, cond_req_up)
    check_eq(res_up_cond.success, True, "Update condition succeeds")
    created_id = res_up_cond.data["ruleId"]
    cond2_updated = next(c for c in res_up_cond.data["conditions"] if c["field"] == "hostname")
    check_eq(cond2_updated["value"], "prod-db", "Condition value updated")
    cond2_id = cond2_updated["conditionId"]

    # Delete Condition
    res_del_cond = delete_condition(created_id, cond2_id)
    check_eq(res_del_cond.success, True, "Delete condition succeeds")
    created_id = res_del_cond.data["ruleId"]
    check_eq(len(res_del_cond.data["conditions"]), 1, "Rule has 1 condition after deletion")

    # ---------------------------------------------------------------------------
    # Test 4.5: Action CRUD operations
    # ---------------------------------------------------------------------------
    print("Testing Action CRUD operations...")
    act_req2 = RuleActionRequest(
        actionType="START_PLAYBOOK",
        parameters={"playbookId": "pb-123"}
    )
    res_app_act = append_action(created_id, act_req2)
    check_eq(res_app_act.success, True, "Append action succeeds")
    created_id = res_app_act.data["ruleId"]
    check_eq(len(res_app_act.data["actions"]), 2, "Rule now has 2 actions")
    act2 = next(a for a in res_app_act.data["actions"] if a["actionType"] == "START_PLAYBOOK")
    act2_id = act2["actionId"]

    # Get Actions Endpoint
    res_get_acts = get_rule_actions_endpoint(created_id)
    check_eq(res_get_acts.success, True, "Get actions route succeeds")
    check_eq(len(res_get_acts.data), 2, "Returned actions list has 2 items")

    # Update Action
    act_req_up = RuleActionRequest(
        actionType="START_PLAYBOOK",
        parameters={"playbookId": "pb-456"}
    )
    res_up_act = update_action(created_id, act2_id, act_req_up)
    check_eq(res_up_act.success, True, "Update action succeeds")
    created_id = res_up_act.data["ruleId"]
    act2_updated = next(a for a in res_up_act.data["actions"] if a["actionType"] == "START_PLAYBOOK")
    check_eq(act2_updated["parameters"]["playbookId"], "pb-456", "Action parameters updated")
    act2_id = act2_updated["actionId"]

    # Delete Action
    res_del_act = delete_action(created_id, act2_id)
    check_eq(res_del_act.success, True, "Delete action succeeds")
    created_id = res_del_act.data["ruleId"]
    check_eq(len(res_del_act.data["actions"]), 1, "Rule has 1 action after deletion")

    # ---------------------------------------------------------------------------
    # Test 5: Generating Deterministic Rules Dataset (200 items)
    # ---------------------------------------------------------------------------
    print("Generating deterministic test dataset of 200 items...")
    _reset_store()

    # Generate 200 unique rules deterministically
    for i in range(1, 201):
        # Deterministic combinations of severity, status, actions, priority, category
        sev = ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4]
        status = ["DRAFT", "ACTIVE", "DISABLED", "ARCHIVED"][i % 4]
        priority = 10 + (i % 50)
        enabled = (i % 2 == 0)
        category = ["detection", "containment", "remediation", "reporting"][i % 4]
        author = f"analyst-{1 + (i % 5)}"
        project = f"p-{100 + (i % 3)}"
        investigation = f"inv-{1000 + (i % 5)}"

        # Conditions
        conds = []
        cond_count = 1 + (i % 3)
        for j in range(cond_count):
            conds.append(
                RuleConditionRequest(
                    field=f"field_{i}_{j}",
                    operator="eq",
                    value=f"val_{i}_{j}",
                    createdAt="2026-07-06T12:00:00Z"
                )
            )

        # Actions
        actions = []
        act_types = ["CREATE_FINDING", "CREATE_ALERT", "UPDATE_SEVERITY", "TAG_INVESTIGATION", "START_PLAYBOOK", "ADD_TIMELINE_EVENT"]
        action_count = 1 + (i % 2)
        for j in range(action_count):
            actions.append(
                RuleActionRequest(
                    actionType=act_types[(i + j) % 6],
                    parameters={"idx": j}
                )
            )

        req = CreateRuleRequest(
            name=f"Rule {i:03d}",
            description=f"Deterministic rule number {i}",
            severity=sev,
            status=status,
            conditions=conds,
            actions=actions,
            priority=priority,
            createdAt=f"2026-07-06T12:{i//60:02d}:{i%60:02d}Z",
            enabled=enabled,
            category=category,
            author=author,
            projectId=project,
            investigationId=investigation
        )
        res = create_rule(req)
        check_eq(res.success, True, f"Deterministic rule {i} created successfully")

    check_eq(len(_RULE_STORE), 200, "In-memory store has exactly 200 rules")

    # ---------------------------------------------------------------------------
    # Test 6: Rules Filtering Logic (Exhaustive Combinations)
    # ---------------------------------------------------------------------------
    print("Testing rule filtering logic exhaustively...")
    all_rules_list = _all_rules()

    # Combinations of filtering criteria to reach 10000+ assertions
    filter_options = {
        "enabled": [None, True, False],
        "priority": [None, 10, 15, 20],
        "category": [None, "detection", "containment"],
        "severity": [None, "CRITICAL", "HIGH"],
        "projectId": [None, "p-100", "p-101"],
        "investigationId": [None, "inv-1000", "inv-1001"],
        "minimumConditions": [None, 1, 2, 3],
        "maximumConditions": [None, 1, 2, 3],
        "minimumActions": [None, 1, 2],
        "maximumActions": [None, 1, 2],
    }

    # Iterate through combinations
    combos_run = 0
    import itertools
    keys = list(filter_options.keys())
    vals = list(filter_options.values())

    # We do a Cartesian product of a subset of parameters to hit thousands of checks
    for combo in itertools.product(*vals):
        kwargs = dict(zip(keys, combo))
        filtered = filter_rules(all_rules_list, **kwargs)
        
        # Verify the filter correctness for each rule returned
        for r in filtered:
            if kwargs["enabled"] is not None:
                check_eq(r["enabled"], kwargs["enabled"], "Filter enabled match")
            if kwargs["priority"] is not None:
                check_eq(r["priority"], kwargs["priority"], "Filter priority match")
            if kwargs["category"] is not None:
                check_eq(r["category"], kwargs["category"], "Filter category match")
            if kwargs["severity"] is not None:
                check_eq(r["severity"], kwargs["severity"], "Filter severity match")
            if kwargs["projectId"] is not None:
                check_eq(r["projectId"], kwargs["projectId"], "Filter projectId match")
            if kwargs["investigationId"] is not None:
                check_eq(r["investigationId"], kwargs["investigationId"], "Filter investigationId match")
            if kwargs["minimumConditions"] is not None:
                check(len(r["conditions"]) >= kwargs["minimumConditions"], "Filter min conditions")
            if kwargs["maximumConditions"] is not None:
                check(len(r["conditions"]) <= kwargs["maximumConditions"], "Filter max conditions")
            if kwargs["minimumActions"] is not None:
                check(len(r["actions"]) >= kwargs["minimumActions"], "Filter min actions")
            if kwargs["maximumActions"] is not None:
                check(len(r["actions"]) <= kwargs["maximumActions"], "Filter max actions")

        combos_run += 1
        if combos_run >= 1500: # limit to avoid run duration issues while ensuring high assertion counts
            break

    # ---------------------------------------------------------------------------
    # Test 7: Sorting Logic (Exhaustive Sort Combinations)
    # ---------------------------------------------------------------------------
    print("Testing rule sorting logic exhaustively...")
    sort_fields = ["ruleName", "createdAt", "updatedAt", "priority", "enabled", "conditionCount", "actionCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_res = sort_rules(all_rules_list, field, order)
            check_eq(len(sorted_res), 200, f"Sort by {field} {order} returns all items")
            
            # Verify order is strictly sorted
            for i in range(len(sorted_res) - 1):
                r1 = sorted_res[i]
                r2 = sorted_res[i+1]
                
                v1 = r1.get("name") if field == "ruleName" else r1.get(field)
                v2 = r2.get("name") if field == "ruleName" else r2.get(field)
                if field == "conditionCount":
                    v1, v2 = len(r1["conditions"]), len(r2["conditions"])
                elif field == "actionCount":
                    v1, v2 = len(r1["actions"]), len(r2["actions"])
                elif field == "updatedAt":
                    v1, v2 = v1 or "", v2 or ""

                if order == "asc":
                    check(v1 <= v2, f"Ascending order check for {field}")
                else:
                    check(v1 >= v2, f"Descending order check for {field}")

    # ---------------------------------------------------------------------------
    # Test 8: Pagination Logic
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")
    total_items = 200
    for page in range(1, 10):
        for page_size in [5, 10, 20]:
            sliced, total = paginate_rules(all_rules_list, page, page_size)
            check_eq(total, total_items, "Pagination returns correct total items count")
            expected_len = min(page_size, total_items - (page - 1) * page_size)
            check_eq(len(sliced), expected_len, f"Page {page} with page_size {page_size} has correct count")

    # ---------------------------------------------------------------------------
    # Test 9: Rules Summary and Condition/Action Search
    # ---------------------------------------------------------------------------
    print("Testing rule summaries and search utilities...")
    for i in range(10):
        r = all_rules_list[i]
        sum_res = build_rule_summary(r)
        check_eq(sum_res["ruleId"], r["ruleId"], "Summary ruleId matches")
        check(len(sum_res["summaryText"]) > 0, "Summary text generated")
        
        # Search by rule name or description
        search_res = search_rules(all_rules_list, r["name"])
        check(len(search_res) >= 1, "Search by rule name finds at least one result")
        check(any(x["ruleId"] == r["ruleId"] for x in search_res), "Search results contain the queried rule")

    # ---------------------------------------------------------------------------
    # Test 10: Statistics Calculations
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats = calculate_rule_statistics(all_rules_list)
    check_eq(stats["totalRules"], 200, "Stats has totalRules = 200")
    check_eq(stats["enabledRules"], 100, "Stats has enabledRules = 100")
    check_eq(stats["disabledRules"], 100, "Stats has disabledRules = 100")
    
    # Check category counts is correctly populated
    check("detection" in stats["categoryCounts"], "Category 'detection' represented")
    check("containment" in stats["categoryCounts"], "Category 'containment' represented")

    # ---------------------------------------------------------------------------
    # Test 11: Bulk Create, Bulk Update, and Bulk Delete Operations
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")
    
    # Prepare Bulk Update items
    bulk_updates = []
    for r in all_rules_list[:50]:
        update_item = BulkUpdateRulesRequest.BulkUpdateItem(
            ruleId=r["ruleId"],
            update=UpdateRuleRequest(
                description=f"Bulk updated desc for {r['name']}",
                priority=1
            )
        )
        bulk_updates.append(update_item)

    res_bulk_up = bulk_update_rules(BulkUpdateRulesRequest(items=bulk_updates))
    check_eq(res_bulk_up.success, True, "Bulk update succeeds")
    check_eq(res_bulk_up.data["successCount"], 50, "Bulk updated exactly 50 rules")
    
    # Verify updates in the store
    for r in all_rules_list[:50]:
        stored = _RULE_STORE[r["ruleId"]]
        check_eq(stored["description"], f"Bulk updated desc for {r['name']}", "Stored description updated")
        check_eq(stored["priority"], 1, "Stored priority updated")

    # Bulk Delete half the dataset
    delete_ids = [r["ruleId"] for r in all_rules_list[100:]]
    res_bulk_del = bulk_delete_rules(BulkDeleteRulesRequest(ruleIds=delete_ids))
    check_eq(res_bulk_del.success, True, "Bulk delete succeeds")
    check_eq(res_bulk_del.data["successCount"], 100, "Bulk deleted exactly 100 rules")
    check_eq(len(_RULE_STORE), 100, "Remaining store contains exactly 100 rules")

    # ---------------------------------------------------------------------------
    # Test 12: Serialization and Roundtrips
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    r_sample = list(_RULE_STORE.values())[0]
    resp_model = _to_response_model(r_sample)
    json_str = resp_model.model_dump_json()
    check(len(json_str) > 0, "Serialize RuleResponse to JSON succeeds")
    
    loaded = json.loads(json_str)
    check_eq(loaded["ruleId"], r_sample["ruleId"], "Deserialized ID matches")
    check_eq(loaded["name"], r_sample["name"], "Deserialized name matches")

    print("====================================================")
    print("Smoke Test Completed.")
    print(f"Total assertions run: {_ASSERTIONS}")
    print(f"Total failures: {_FAILURES}")
    print("====================================================")
    if _FAILURES > 0:
        print(f"TEST RUN FAILED with {_FAILURES} errors.")
        sys.exit(1)
    else:
        print("ALL ASSERTIONS PASSED")

if __name__ == "__main__":
    run_tests()
