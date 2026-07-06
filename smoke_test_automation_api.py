"""
Smoke Test for Automation Engine API — Phase A4.10.3
====================================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Step CRUD operations (append, update, delete)
  ✓ Execution endpoints (execute_automation, get_executions)
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
from api.workflow.automation_router import (
    automation_router,
    _reset_store,
    _all_automations,
    _AUTOMATION_STORE,
    _EXECUTION_STORE,
    list_automations_endpoint,
    get_automation_statistics_endpoint,
    search_automations_endpoint,
    get_automation,
    create_automation,
    update_automation_route,
    delete_automation,
    get_automation_steps,
    append_step,
    update_step,
    delete_step,
    execute_automation_endpoint,
    get_executions,
    get_automation_summary,
    bulk_create_automations,
    bulk_update_automations,
    bulk_delete_automations,
    # Utilities
    find_automation,
    find_automation_step,
    search_automations,
    search_automation_steps,
    sort_automations,
    filter_automations,
    paginate_automations,
    execute_automation,
    build_automation_summary,
    calculate_automation_statistics,
    _to_response_model,
)
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
    print("Starting Automation Engine API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Prefix Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/workflow/automation"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/workflow/automation",
        "/api/v2/workflow/automation/",
        "/api/v2/workflow/automation/statistics",
        "/api/v2/workflow/automation/search",
        "/api/v2/workflow/automation/bulk/create",
        "/api/v2/workflow/automation/bulk/update",
        "/api/v2/workflow/automation/bulk/delete",
        "/api/v2/workflow/automation/{automationId}",
        "/api/v2/workflow/automation/{automationId}/steps",
        "/api/v2/workflow/automation/{automationId}/steps/{stepId}",
        "/api/v2/workflow/automation/{automationId}/execute",
        "/api/v2/workflow/automation/{automationId}/executions",
        "/api/v2/workflow/automation/{automationId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Store Initialization Check
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_AUTOMATION_STORE), 0, "Automation store starts empty")
    check_eq(len(_EXECUTION_STORE), 0, "Execution store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Validation Failures & Edge Cases
    # ---------------------------------------------------------------------------
    print("Testing validation failures...")

    # Empty name
    req_bad_name = CreateAutomationRequest(
        name="",
        status="ACTIVE",
        trigger="MANUAL",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad = create_automation(req_bad_name)
    check_eq(res_bad.success, False, "Create automation with empty name fails")
    check_eq(res_bad.data.errorCode, "VALIDATION_ERROR", "Error code is VALIDATION_ERROR")

    # Invalid status
    req_bad_status = CreateAutomationRequest(
        name="Bad Status",
        status="EXPIRED",
        trigger="MANUAL",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_status = create_automation(req_bad_status)
    check_eq(res_bad_status.success, False, "Create automation with invalid status fails")

    # Invalid trigger
    req_bad_trigger = CreateAutomationRequest(
        name="Bad Trigger",
        status="ACTIVE",
        trigger="INVALID_TRIGGER",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_trigger = create_automation(req_bad_trigger)
    check_eq(res_bad_trigger.success, False, "Create automation with invalid trigger fails")

    # Invalid priority
    req_bad_priority = CreateAutomationRequest(
        name="Bad Priority",
        status="ACTIVE",
        trigger="MANUAL",
        priority=0,
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_priority = create_automation(req_bad_priority)
    check_eq(res_bad_priority.success, False, "Create automation with priority 0 fails")

    # Step validations
    step_bad = AutomationStepRequest(
        stepNumber=0,
        name="Bad Step",
        action="CREATE_ALERT",
        createdAt="2026-07-06T12:00:00Z"
    )
    req_bad_step = CreateAutomationRequest(
        name="Bad Step Auto",
        status="ACTIVE",
        trigger="MANUAL",
        steps=[step_bad],
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_step = create_automation(req_bad_step)
    check_eq(res_bad_step.success, False, "Create automation with invalid step number fails")

    # 404 Get individual non-existent
    res_404 = get_automation("non-existent-id")
    check_eq(res_404.success, False, "Get non-existent returns success=False")
    check_eq(res_404.data.errorCode, "NOT_FOUND", "Error code is NOT_FOUND")

    # ---------------------------------------------------------------------------
    # Test 4: CRUD Operations
    # ---------------------------------------------------------------------------
    print("Testing CRUD operations...")
    step_req = AutomationStepRequest(
        stepNumber=1,
        name="Generate Incident Alert",
        action="CREATE_ALERT",
        parameters={"severity": "high"},
        createdAt="2026-07-06T12:00:00Z"
    )
    valid_req = CreateAutomationRequest(
        name="Auto Containment Flow",
        description="Fires on critical alerts to block hosts",
        status="ACTIVE",
        trigger="ALERT_CREATED",
        steps=[step_req],
        priority=10,
        createdAt="2026-07-06T12:00:00Z",
        category="containment",
        author="secops",
        projectId="p-001",
        investigationId="inv-100",
        playbookId="pb-999",
        ruleId="rule-111"
    )

    res_create = create_automation(valid_req)
    check_eq(res_create.success, True, "Automation creation succeeds")
    created_id = res_create.data["automationId"]
    check(len(created_id) == 36, "Automation ID is UUIDv5")
    check_eq(res_create.data["name"], "Auto Containment Flow", "Name matches")
    check_eq(res_create.data["category"], "containment", "Category matches")
    check_eq(res_create.data["author"], "secops", "Author matches")
    check_eq(res_create.data["playbookId"], "pb-999", "Playbook ID matches")
    check_eq(res_create.data["ruleId"], "rule-111", "Rule ID matches")

    # 409 Conflict Create Duplicate
    res_dup = create_automation(valid_req)
    check_eq(res_dup.success, False, "Creating duplicate returns success=False")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Error code is CONFLICT")

    # Read Automation
    res_get = get_automation(created_id)
    check_eq(res_get.success, True, "Get by ID succeeds")
    check_eq(res_get.data["automationId"], created_id, "Correct ID retrieved")

    # Update Automation
    update_req = UpdateAutomationRequest(
        description="Updated description",
        enabled=False,
        category="remediation"
    )
    res_up = update_automation_route(created_id, update_req)
    check_eq(res_up.success, True, "Update details succeeds")
    created_id = res_up.data["automationId"]
    check_eq(res_up.data["description"], "Updated description", "Description updated")
    check_eq(res_up.data["enabled"], False, "Enabled flag toggled")
    check_eq(res_up.data["category"], "remediation", "Category updated")

    # Restore to enabled
    update_req_restore = UpdateAutomationRequest(enabled=True)
    res_restore = update_automation_route(created_id, update_req_restore)
    check_eq(res_restore.success, True, "Restore enabled flag succeeds")
    created_id = res_restore.data["automationId"]

    # ---------------------------------------------------------------------------
    # Test 5: Step CRUD Operations
    # ---------------------------------------------------------------------------
    print("Testing Step CRUD operations...")
    step_req2 = AutomationStepRequest(
        stepNumber=2,
        name="Tag Investigation",
        action="TAG_INVESTIGATION",
        parameters={"tags": ["compromised"]},
        createdAt="2026-07-06T12:05:00Z"
    )
    res_app_step = append_step(created_id, step_req2)
    check_eq(res_app_step.success, True, "Append step succeeds")
    created_id = res_app_step.data["automationId"]
    check_eq(len(res_app_step.data["steps"]), 2, "Steps list size is 2")

    step2 = next(s for s in res_app_step.data["steps"] if s["name"] == "Tag Investigation")
    step2_id = step2["stepId"]

    # Get Steps
    res_get_steps = get_automation_steps(created_id)
    check_eq(res_get_steps.success, True, "Get steps route succeeds")
    check_eq(len(res_get_steps.data), 2, "Steps list size is 2")

    # Update Step
    step_req_up = AutomationStepRequest(
        stepNumber=2,
        name="Tag Investigation Comp",
        action="TAG_INVESTIGATION",
        parameters={"tags": ["compromised", "critical"]},
        createdAt="2026-07-06T12:05:00Z"
    )
    res_up_step = update_step(created_id, step2_id, step_req_up)
    check_eq(res_up_step.success, True, "Update step succeeds")
    created_id = res_up_step.data["automationId"]
    step2_updated = next(s for s in res_up_step.data["steps"] if s["stepId"] == step2_id)
    check_eq(step2_updated["name"], "Tag Investigation Comp", "Step name updated")

    # Delete Step
    res_del_step = delete_step(created_id, step2_id)
    check_eq(res_del_step.success, True, "Delete step succeeds")
    created_id = res_del_step.data["automationId"]
    check_eq(len(res_del_step.data["steps"]), 1, "Only 1 step remains")

    # ---------------------------------------------------------------------------
    # Test 6: Execution Logs Verification
    # ---------------------------------------------------------------------------
    print("Testing executions...")
    res_exec = execute_automation_endpoint(created_id, "2026-07-06T12:10:00Z")
    check_eq(res_exec.success, True, "Execute automation succeeds")
    check_eq(res_exec.data["status"], "SUCCESS", "Execution status is SUCCESS")
    check_eq(len(res_exec.data["stepResults"]), 1, "One step result returned")

    # Get Executions
    res_get_execs = get_executions(created_id)
    check_eq(res_get_execs.success, True, "Get executions succeeds")
    check_eq(len(res_get_execs.data), 1, "One execution log returned")
    check_eq(res_get_execs.data[0]["executionId"], res_exec.data["executionId"], "Execution ID matches")

    # Delete automation clears executions
    res_del = delete_automation(created_id)
    check_eq(res_del.success, True, "Delete automation succeeds")
    check_eq(len(_AUTOMATION_STORE), 0, "Store is empty")
    check_eq(len(_EXECUTION_STORE), 0, "Executions are cleared")

    # ---------------------------------------------------------------------------
    # Generating Dataset for Large-Scale Sort/Filter/Pagination Checks
    # ---------------------------------------------------------------------------
    print("Generating deterministic test dataset of 200 items...")
    bulk_req_items = []
    # Seed 200 items deterministically
    for i in range(1, 201):
        # Steps
        steps = []
        step_count = (i % 5) + 1  # 1 to 5 steps
        for j in range(1, step_count + 1):
            steps.append(
                AutomationStepRequest(
                    stepNumber=j,
                    name=f"Step {j} for Auto {i}",
                    action="CREATE_ALERT" if j % 2 == 0 else "TAG_INVESTIGATION",
                    parameters={"idx": i, "step": j},
                    createdAt=f"2026-07-06T12:{i:02d}:{j:02d}Z"
                )
            )

        enabled = (i % 3 != 0)  # Toggles true/false/true...
        category = "detection" if i % 2 == 0 else "remediation"
        priority = (i % 5) + 1  # 1 to 5

        bulk_req_items.append(
            CreateAutomationRequest(
                name=f"Automation Rule {i:03d}",
                description=f"Description of rule {i}",
                status="ACTIVE" if i % 2 == 0 else "DRAFT",
                trigger="RULE_MATCHED" if i % 2 == 0 else "MANUAL",
                steps=steps,
                priority=priority,
                createdAt=f"2026-07-06T12:{i:02d}:00Z",
                enabled=enabled,
                category=category,
                author=f"author-{i%4}",
                projectId=f"p-{i%3:03d}",
                investigationId=f"inv-{i%2:03d}",
                playbookId=f"pb-{i%5:03d}",
                ruleId=f"rule-{i%6:03d}"
            )
        )

    res_bulk = bulk_create_automations(BulkCreateAutomationsRequest(automations=bulk_req_items))
    check_eq(res_bulk.success, True, "Bulk create succeeds")
    check_eq(res_bulk.data["successCount"], 200, "200 automations created successfully")
    check_eq(len(_AUTOMATION_STORE), 200, "Store now has 200 items")

    # Fetch unique list from list endpoint for queries
    all_res = list_automations_endpoint(pageSize=200)
    automations_list = all_res.data
    check_eq(len(automations_list), 200, "All 200 items returned")

    # Trigger some mock executions to check executionCount sort
    # Execute even indices
    for idx, c in enumerate(automations_list):
        if idx % 2 == 0:
            execute_automation(c, f"2026-07-06T13:{idx:02d}:00Z")
            if idx % 4 == 0:
                # Add another execution to test multiple execution counts
                execute_automation(c, f"2026-07-06T13:{idx:02d}:30Z")

    # ---------------------------------------------------------------------------
    # Test 7: Exhaustive Filtering Checks (Target: ~1500 assertions)
    # ---------------------------------------------------------------------------
    print("Testing automation filtering logic exhaustively...")

    # 1. Category Filter
    for cat in ["detection", "remediation"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.category == cat)
        api_res = list_automations_endpoint(category=cat, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by category={cat} count matches")
        for item in api_res.data:
            check_eq(item["category"], cat, "Category matches")

    # 2. Enabled Toggles
    for flag in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.enabled == flag)
        api_res = list_automations_endpoint(enabled=flag, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by enabled={flag} count matches")
        for item in api_res.data:
            check_eq(item["enabled"], flag, "Enabled flag matches")

    # 3. Priority
    for prio in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if item.priority == prio)
        api_res = list_automations_endpoint(priority=prio, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by priority={prio} count matches")
        for item in api_res.data:
            check_eq(item["priority"], prio, "Priority matches")

    # 4. Author
    for auth in ["author-0", "author-1", "author-2", "author-3"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.author == auth)
        api_res = list_automations_endpoint(author=auth, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by author={auth} count matches")
        for item in api_res.data:
            check_eq(item["author"], auth, "Author matches")

    # 5. Project ID
    for pid in ["p-000", "p-001", "p-002"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.projectId == pid)
        api_res = list_automations_endpoint(projectId=pid, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by projectId={pid} count matches")
        for item in api_res.data:
            check_eq(item["projectId"], pid, "Project ID matches")

    # 6. Investigation ID
    for inv_id in ["inv-000", "inv-001"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.investigationId == inv_id)
        api_res = list_automations_endpoint(investigationId=inv_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by investigationId={inv_id} count matches")
        for item in api_res.data:
            check_eq(item["investigationId"], inv_id, "Investigation ID matches")

    # 7. Playbook ID
    for pb_id in ["pb-000", "pb-001", "pb-002", "pb-003", "pb-004"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.playbookId == pb_id)
        api_res = list_automations_endpoint(playbookId=pb_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by playbookId={pb_id} count matches")
        for item in api_res.data:
            check_eq(item["playbookId"], pb_id, "Playbook ID matches")

    # 8. Rule ID
    for r_id in ["rule-000", "rule-001", "rule-002", "rule-003", "rule-004", "rule-005"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.ruleId == r_id)
        api_res = list_automations_endpoint(ruleId=r_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by ruleId={r_id} count matches")
        for item in api_res.data:
            check_eq(item["ruleId"], r_id, "Rule ID matches")

    # 9. Step bounds
    for min_steps in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if len(item.steps) >= min_steps)
        api_res = list_automations_endpoint(minimumSteps=min_steps, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by minimumSteps={min_steps} count matches")
        for item in api_res.data:
            check(len(item["steps"]) >= min_steps, "Steps count within minimum bounds")

    for max_steps in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if len(item.steps) <= max_steps)
        api_res = list_automations_endpoint(maximumSteps=max_steps, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by maximumSteps={max_steps} count matches")
        for item in api_res.data:
            check(len(item["steps"]) <= max_steps, "Steps count within maximum bounds")

    # 10. Date bounds
    api_res = list_automations_endpoint(createdAfter="2026-07-06T12:05:00Z", createdBefore="2026-07-06T12:50:00Z", pageSize=200)
    expected_cnt = sum(1 for item in bulk_req_items if "2026-07-06T12:05:00Z" <= item.createdAt <= "2026-07-06T12:50:00Z")
    check_eq(len(api_res.data), expected_cnt, "Filter by created range matches")

    # ---------------------------------------------------------------------------
    # Test 8: Sorting Assertions (Target: ~6000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing automation sorting logic exhaustively...")

    sort_fields = ["automationName", "createdAt", "updatedAt", "priority", "enabled", "stepCount", "executionCount"]

    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_automations_endpoint(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data

            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]

                if field == "automationName":
                    v_curr, v_next = item_curr["name"], item_next["name"]
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]
                elif field == "updatedAt":
                    v_curr = item_curr["updatedAt"] or ""
                    v_next = item_next["updatedAt"] or ""
                elif field == "priority":
                    v_curr = item_curr["priority"]
                    v_next = item_next["priority"]
                elif field == "enabled":
                    v_curr = int(item_curr["enabled"])
                    v_next = int(item_next["enabled"])
                elif field == "stepCount":
                    v_curr = len(item_curr["steps"])
                    v_next = len(item_next["steps"])
                elif field == "executionCount":
                    v_curr = len(_EXECUTION_STORE.get(item_curr["automationId"], []))
                    v_next = len(_EXECUTION_STORE.get(item_next["automationId"], []))

                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["automationId"] <= item_next["automationId"], "Secondary sort constraint")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["automationId"] <= item_next["automationId"], "Secondary sort constraint in DESC")

    # ---------------------------------------------------------------------------
    # Test 9: Pagination Assertions (Target: ~750 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")

    for p_size in [5, 10, 20, 25, 40]:
        total_pages = math.ceil(200 / p_size)
        seen_ids = set()

        for p in range(1, total_pages + 1):
            api_res = list_automations_endpoint(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")

            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 200, "Total items is 200")
            check_eq(pagination["totalPages"], total_pages, "Total pages matches")

            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                aid = item["automationId"]
                check(aid not in seen_ids, f"Unique item {aid} on page {p}")
                seen_ids.add(aid)

        check_eq(len(seen_ids), 200, f"All 200 items covered in page size {p_size}")

    # ---------------------------------------------------------------------------
    # Test 10: Automation Summary and Steps Route checks (200 items * 5 = 1000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing automation summaries and steps list lookup...")

    for c in automations_list:
        # Steps route check
        steps_res = get_automation_steps(c["automationId"])
        check_eq(steps_res.success, True, "Retrieve steps succeeds")
        check_eq(len(steps_res.data), len(c["steps"]), "Correct number of steps returned")

        # Summary route check
        sum_res = get_automation_summary(c["automationId"])
        check_eq(sum_res.success, True, "Retrieve summary succeeds")
        check_eq(sum_res.data["automationId"], c["automationId"], "Summary automationId matches")
        check_eq(sum_res.data["automationName"], c["name"], "Summary name matches")
        check_eq(sum_res.data["stepCount"], len(c["steps"]), "Summary step count matches")
        check_eq(sum_res.data["enabled"], c["enabled"], "Summary enabled matches")

    # ---------------------------------------------------------------------------
    # Test 11: Statistics Calculations
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_automation_statistics_endpoint()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data

    check_eq(stats["totalAutomations"], 200, "Total automations is 200")
    check_eq(stats["enabledAutomations"], 134, "134 automations are enabled (i % 3 != 0)")
    check_eq(stats["disabledAutomations"], 66, "66 automations are disabled")
    check_eq(stats["totalExecutions"], 150, "Total executions in store is 150")
    check_eq(stats["averageSteps"], 3.0, "Average steps is 3.0")
    check_eq(stats["averagePriority"], 3.0, "Average priority is 3.0")

    # ---------------------------------------------------------------------------
    # Test 12: Bulk Update & Bulk Delete
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")

    # Bulk update category for even indexes
    bulk_up_items = []
    updated_ids = []
    for idx, c in enumerate(automations_list):
        if idx % 2 == 0:
            bulk_up_items.append(
                BulkUpdateAutomationsRequest.BulkUpdateItem(
                    automationId=c["automationId"],
                    update=UpdateAutomationRequest(
                        category="remediation-updated",
                        enabled=True,
                        priority=5,
                    )
                )
            )
            updated_ids.append(c["automationId"])

    bulk_up_res = bulk_update_automations(BulkUpdateAutomationsRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")

    # Verify updates in store
    for rec_id in updated_ids:
        c_stored = _AUTOMATION_STORE[rec_id]
        check_eq(c_stored["category"], "remediation-updated", "Category updated")
        check_eq(c_stored["enabled"], True, "Enabled is True")
        check_eq(c_stored["priority"], 5, "Priority is 5")

    # Bulk delete odd indexes
    bulk_del_ids = []
    for idx, c in enumerate(automations_list):
        if idx % 2 != 0:
            bulk_del_ids.append(c["automationId"])

    bulk_del_res = bulk_delete_automations(BulkDeleteAutomationsRequest(automationIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_AUTOMATION_STORE), 100, "100 automations remaining in store")

    # Clean up remaining
    remaining_ids = [c["automationId"] for c in _AUTOMATION_STORE.values()]
    cleanup_res = bulk_delete_automations(BulkDeleteAutomationsRequest(automationIds=remaining_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_AUTOMATION_STORE), 0, "Store is completely empty")

    # ---------------------------------------------------------------------------
    # Test 13: Search logic
    # ---------------------------------------------------------------------------
    # Repopulate 1 item to test search
    create_automation(valid_req)
    search_res = search_automations_endpoint(q="Containment")
    check_eq(search_res.success, True, "Search route succeeds")
    check_eq(search_res.data["total"], 1, "Exactly one matches query 'Containment'")

    # ---------------------------------------------------------------------------
    # Test 14: Serialization & Deserialization
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    json_str = valid_req.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["name"], "Auto Containment Flow", "JSON serialization is correct")

    deserialized = CreateAutomationRequest(**parsed)
    check_eq(deserialized.name, "Auto Containment Flow", "Deserialization roundtrip matches")

    print("====================================================")
    print(f"Smoke Test Completed.")
    print(f"Total assertions run: {_ASSERTIONS}")
    print(f"Total failures: {_FAILURES}")
    print("====================================================")

    if _FAILURES == 0:
        try:
            print("ALL ASSERTIONS PASSED ✓")
        except UnicodeEncodeError:
            print("ALL ASSERTIONS PASSED")
        sys.exit(0)
    else:
        print(f"{_FAILURES} ASSERTION(S) FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
