"""
Smoke Test for Case Flow API — Phase A4.10.4
============================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Step CRUD operations (append, update, delete)
  ✓ Execution endpoints (execute_case_flow, get_executions)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ Summary and statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 12000+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
from typing import Any, List, Dict

# Import API components
from api.workflow.case_flow_router import (
    case_flow_router,
    _reset_store,
    _all_cases,
    _CASE_FLOW_STORE,
    _EXECUTION_STORE,
    list_case_flows_endpoint,
    get_case_flow_statistics_endpoint,
    search_case_flows_endpoint,
    get_case_flow,
    create_case_flow,
    update_case_flow_route,
    delete_case_flow,
    get_case_steps,
    append_step,
    update_step,
    delete_step,
    execute_case_flow_endpoint,
    get_executions,
    get_case_flow_summary,
    bulk_create_case_flows,
    bulk_update_case_flows,
    bulk_delete_case_flows,
    # Utilities
    find_case_flow,
    find_case_flow_step,
    search_case_flows,
    search_case_flow_steps,
    sort_case_flows,
    filter_case_flows,
    paginate_case_flows,
    execute_case_flow,
    build_case_flow_summary,
    calculate_case_flow_statistics,
    _to_response_model,
)
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
    print("Starting Case Flow API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Prefix Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/workflow/case-flow"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/workflow/case-flow",
        "/api/v2/workflow/case-flow/",
        "/api/v2/workflow/case-flow/statistics",
        "/api/v2/workflow/case-flow/search",
        "/api/v2/workflow/case-flow/bulk/create",
        "/api/v2/workflow/case-flow/bulk/update",
        "/api/v2/workflow/case-flow/bulk/delete",
        "/api/v2/workflow/case-flow/{caseFlowId}",
        "/api/v2/workflow/case-flow/{caseFlowId}/steps",
        "/api/v2/workflow/case-flow/{caseFlowId}/steps/{stepId}",
        "/api/v2/workflow/case-flow/{caseFlowId}/execute",
        "/api/v2/workflow/case-flow/{caseFlowId}/executions",
        "/api/v2/workflow/case-flow/{caseFlowId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Store Initialization Check
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_CASE_FLOW_STORE), 0, "Case Flow store starts empty")
    check_eq(len(_EXECUTION_STORE), 0, "Execution store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Validation Failures & Edge Cases
    # ---------------------------------------------------------------------------
    print("Testing validation failures...")

    # Empty title
    req_bad_title = CreateCaseFlowRequest(
        title="",
        status="OPEN",
        priority="MEDIUM",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad = create_case_flow(req_bad_title)
    check_eq(res_bad.success, False, "Create case with empty title fails")
    check_eq(res_bad.data.errorCode, "VALIDATION_ERROR", "Error code is VALIDATION_ERROR")

    # Invalid status
    req_bad_status = CreateCaseFlowRequest(
        title="Bad Status",
        status="EXPIRED",
        priority="MEDIUM",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_status = create_case_flow(req_bad_status)
    check_eq(res_bad_status.success, False, "Create case with invalid status fails")

    # Invalid priority
    req_bad_priority = CreateCaseFlowRequest(
        title="Bad Priority",
        status="OPEN",
        priority="SUPER_HIGH",
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_priority = create_case_flow(req_bad_priority)
    check_eq(res_bad_priority.success, False, "Create case with invalid priority fails")

    # Invalid confidence
    req_bad_conf = CreateCaseFlowRequest(
        title="Bad Conf",
        status="OPEN",
        priority="MEDIUM",
        confidence=150.0,
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_conf = create_case_flow(req_bad_conf)
    check_eq(res_bad_conf.success, False, "Create case with confidence out of bounds fails")

    # Step validations
    step_bad = CaseFlowStepRequest(
        stepNumber=0,
        stepType="CREATED",
        title="Bad Step",
        createdAt="2026-07-06T12:00:00Z"
    )
    req_bad_step = CreateCaseFlowRequest(
        title="Bad Step Case",
        status="OPEN",
        priority="MEDIUM",
        steps=[step_bad],
        createdAt="2026-07-06T12:00:00Z"
    )
    res_bad_step = create_case_flow(req_bad_step)
    check_eq(res_bad_step.success, False, "Create case with invalid step number fails")

    # 404 Get individual non-existent
    res_404 = get_case_flow("non-existent-id")
    check_eq(res_404.success, False, "Get non-existent returns success=False")
    check_eq(res_404.data.errorCode, "NOT_FOUND", "Error code is NOT_FOUND")

    # ---------------------------------------------------------------------------
    # Test 4: CRUD Operations
    # ---------------------------------------------------------------------------
    print("Testing CRUD operations...")
    step_req = CaseFlowStepRequest(
        stepNumber=1,
        stepType="CREATED",
        title="Initialize Incident Investigation",
        description="Assign security analyst and gather telemetry",
        createdAt="2026-07-06T12:00:00Z"
    )
    valid_req = CreateCaseFlowRequest(
        title="Intrusion Alert in Production Cluster",
        description="Fires on alerts related to unauthorized root access",
        status="OPEN",
        priority="HIGH",
        steps=[step_req],
        findingIds=["find-111"],
        alertIds=["alert-222"],
        evidenceIds=["ev-333"],
        playbookIds=["pb-444"],
        assignedTo="analyst-alice",
        confidence=90.0,
        createdAt="2026-07-06T12:00:00Z",
        projectId="p-001",
        investigationId="inv-100",
        automationId="auto-999",
        owner="secops-owner"
    )

    res_create = create_case_flow(valid_req)
    check_eq(res_create.success, True, "Case creation succeeds")
    created_id = res_create.data["caseFlowId"]
    check(len(created_id) == 36, "Case ID is UUIDv5")
    check_eq(res_create.data["title"], "Intrusion Alert in Production Cluster", "Title matches")
    check_eq(res_create.data["owner"], "secops-owner", "Owner matches")
    check_eq(res_create.data["assignedTo"], "analyst-alice", "Assigned analyst matches")
    check_eq(res_create.data["projectId"], "p-001", "Project ID matches")

    # 409 Conflict Create Duplicate
    res_dup = create_case_flow(valid_req)
    check_eq(res_dup.success, False, "Creating duplicate returns success=False")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Error code is CONFLICT")

    # Read Case Flow
    res_get = get_case_flow(created_id)
    check_eq(res_get.success, True, "Get by ID succeeds")
    check_eq(res_get.data["caseFlowId"], created_id, "Correct ID retrieved")

    # Update Case Flow
    update_req = UpdateCaseFlowRequest(
        description="Updated case description",
        status="IN_PROGRESS",
        confidence=95.0
    )
    res_up = update_case_flow_route(created_id, update_req)
    check_eq(res_up.success, True, "Update details succeeds")
    created_id = res_up.data["caseFlowId"]
    check_eq(res_up.data["description"], "Updated case description", "Description updated")
    check_eq(res_up.data["status"], "IN_PROGRESS", "Status updated")
    check_eq(res_up.data["confidence"], 95.0, "Confidence updated")

    # Restore status to OPEN
    update_req_restore = UpdateCaseFlowRequest(status="OPEN")
    res_restore = update_case_flow_route(created_id, update_req_restore)
    check_eq(res_restore.success, True, "Restore status succeeds")
    created_id = res_restore.data["caseFlowId"]

    # ---------------------------------------------------------------------------
    # Test 5: Step CRUD Operations
    # ---------------------------------------------------------------------------
    print("Testing Step CRUD operations...")
    step_req2 = CaseFlowStepRequest(
        stepNumber=2,
        stepType="CONTAINED",
        title="Isolate Compromised Node",
        description="Block incoming traffic from security group",
        createdAt="2026-07-06T12:05:00Z"
    )
    res_app_step = append_step(created_id, step_req2)
    check_eq(res_app_step.success, True, "Append step succeeds")
    created_id = res_app_step.data["caseFlowId"]
    check_eq(len(res_app_step.data["steps"]), 2, "Steps list size is 2")

    step2 = next(s for s in res_app_step.data["steps"] if s["title"] == "Isolate Compromised Node")
    step2_id = step2["stepId"]

    # Get Steps
    res_get_steps = get_case_steps(created_id)
    check_eq(res_get_steps.success, True, "Get steps route succeeds")
    check_eq(len(res_get_steps.data), 2, "Steps list size is 2")

    # Update Step
    step_req_up = CaseFlowStepRequest(
        stepNumber=2,
        stepType="CONTAINED",
        title="Isolate Compromised Node V2",
        description="Block incoming traffic and detach IAM role",
        createdAt="2026-07-06T12:05:00Z"
    )
    res_up_step = update_step(created_id, step2_id, step_req_up)
    check_eq(res_up_step.success, True, "Update step succeeds")
    created_id = res_up_step.data["caseFlowId"]
    step2_updated = next(s for s in res_up_step.data["steps"] if s["stepId"] == step2_id)
    check_eq(step2_updated["title"], "Isolate Compromised Node V2", "Step title updated")

    # Delete Step
    res_del_step = delete_step(created_id, step2_id)
    check_eq(res_del_step.success, True, "Delete step succeeds")
    created_id = res_del_step.data["caseFlowId"]
    check_eq(len(res_del_step.data["steps"]), 1, "Only 1 step remains")

    # ---------------------------------------------------------------------------
    # Test 6: Execution Logs Verification
    # ---------------------------------------------------------------------------
    print("Testing executions...")
    res_exec = execute_case_flow_endpoint(created_id, "2026-07-06T12:10:00Z")
    check_eq(res_exec.success, True, "Execute case succeeds")
    check_eq(res_exec.data["status"], "SUCCESS", "Execution status is SUCCESS")
    check_eq(len(res_exec.data["stepResults"]), 1, "One step result returned")

    # Get Executions
    res_get_execs = get_executions(created_id)
    check_eq(res_get_execs.success, True, "Get executions succeeds")
    check_eq(len(res_get_execs.data), 1, "One execution log returned")
    check_eq(res_get_execs.data[0]["executionId"], res_exec.data["executionId"], "Execution ID matches")

    # Delete case clears executions
    res_del = delete_case_flow(created_id)
    check_eq(res_del.success, True, "Delete case succeeds")
    check_eq(len(_CASE_FLOW_STORE), 0, "Store is empty")
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
                CaseFlowStepRequest(
                    stepNumber=j,
                    stepType="CREATED" if j % 2 == 0 else "CLOSED",
                    title=f"Step {j} for Case {i}",
                    description=f"Description {j} of {i}",
                    assignedTo=f"agent-{i%4}",
                    createdAt=f"2026-07-06T12:{i:02d}:{j:02d}Z"
                )
            )

        status = "OPEN" if i % 3 == 0 else ("CLOSED" if i % 3 == 1 else "IN_PROGRESS")
        priority = "CRITICAL" if i % 4 == 0 else ("HIGH" if i % 4 == 1 else ("MEDIUM" if i % 4 == 2 else "LOW"))

        bulk_req_items.append(
            CreateCaseFlowRequest(
                title=f"Incident Case {i:03d}",
                description=f"Description of case {i}",
                status=status,
                priority=priority,
                steps=steps,
                findingIds=[f"find-{i%5:03d}"],
                alertIds=[f"alert-{i%6:03d}"],
                evidenceIds=[f"ev-{i%7:03d}"],
                playbookIds=[f"pb-{i%8:03d}"],
                assignedTo=f"analyst-{i%4}",
                confidence=float(50 + (i % 50)),
                createdAt=f"2026-07-06T12:{i:02d}:00Z",
                projectId=f"p-{i%3:03d}",
                investigationId=f"inv-{i%2:03d}",
                automationId=f"auto-{i%5:03d}",
                owner=f"owner-{i%4}"
            )
        )

    res_bulk = bulk_create_case_flows(BulkCreateCaseFlowsRequest(caseFlows=bulk_req_items))
    check_eq(res_bulk.success, True, "Bulk create succeeds")
    check_eq(res_bulk.data["successCount"], 200, "200 cases created successfully")
    check_eq(len(_CASE_FLOW_STORE), 200, "Store now has 200 items")

    # Fetch unique list from list endpoint for queries
    all_res = list_case_flows_endpoint(pageSize=200)
    cases_list = all_res.data
    check_eq(len(cases_list), 200, "All 200 items returned")

    # Trigger some mock executions to check executionCount sort
    # Execute even indices
    for idx, c in enumerate(cases_list):
        if idx % 2 == 0:
            execute_case_flow(c, f"2026-07-06T13:{idx:02d}:00Z")
            if idx % 4 == 0:
                execute_case_flow(c, f"2026-07-06T13:{idx:02d}:30Z")

    # ---------------------------------------------------------------------------
    # Test 7: Exhaustive Filtering Checks (Target: ~2000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing case filtering logic exhaustively...")

    # 1. Status Filter
    for st in ["OPEN", "CLOSED", "IN_PROGRESS"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.status == st)
        api_res = list_case_flows_endpoint(status=st, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by status={st} count matches")
        for item in api_res.data:
            check_eq(item["status"], st, "Status matches")

    # 2. Priority Filter
    for prio in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.priority == prio)
        api_res = list_case_flows_endpoint(priority=priority, pageSize=200) # wait: let's use prio instead of priority loop variable!
        # Ah, we must use `priority=prio`! Let's write `priority=prio` in code.

    # Let's write the correct loops for filters:
    for prio in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.priority == prio)
        api_res = list_case_flows_endpoint(priority=prio, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by priority={prio} count matches")
        for item in api_res.data:
            check_eq(item["priority"], prio, "Priority matches")

    # 3. Owner
    for own in ["owner-0", "owner-1", "owner-2", "owner-3"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.owner == own)
        api_res = list_case_flows_endpoint(owner=own, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by owner={own} count matches")
        for item in api_res.data:
            check_eq(item["owner"], own, "Owner matches")

    # 4. Project ID
    for pid in ["p-000", "p-001", "p-002"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.projectId == pid)
        api_res = list_case_flows_endpoint(projectId=pid, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by projectId={pid} count matches")
        for item in api_res.data:
            check_eq(item["projectId"], pid, "Project ID matches")

    # 5. Investigation ID
    for inv_id in ["inv-000", "inv-001"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.investigationId == inv_id)
        api_res = list_case_flows_endpoint(investigationId=inv_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by investigationId={inv_id} count matches")
        for item in api_res.data:
            check_eq(item["investigationId"], inv_id, "Investigation ID matches")

    # 6. Playbook ID
    for pb_id in ["pb-000", "pb-001", "pb-002", "pb-003", "pb-004", "pb-005", "pb-006", "pb-007"]:
        expected_cnt = sum(1 for item in bulk_req_items if pb_id in item.playbookIds)
        api_res = list_case_flows_endpoint(playbookId=pb_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by playbookId={pb_id} count matches")
        for item in api_res.data:
            check(pb_id in item["playbookIds"], "Playbook ID list contains filter query")

    # 7. Automation ID
    for auto_id in ["auto-000", "auto-001", "auto-002", "auto-003", "auto-004"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.automationId == auto_id)
        api_res = list_case_flows_endpoint(automationId=auto_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by automationId={auto_id} count matches")
        for item in api_res.data:
            check_eq(item["automationId"], auto_id, "Automation ID matches")

    # 8. Step bounds
    for min_steps in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if len(item.steps) >= min_steps)
        api_res = list_case_flows_endpoint(minimumSteps=min_steps, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by minimumSteps={min_steps} count matches")
        for item in api_res.data:
            check(len(item["steps"]) >= min_steps, "Steps count within minimum bounds")

    for max_steps in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if len(item.steps) <= max_steps)
        api_res = list_case_flows_endpoint(maximumSteps=max_steps, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by maximumSteps={max_steps} count matches")
        for item in api_res.data:
            check(len(item["steps"]) <= max_steps, "Steps count within maximum bounds")

    # 9. Date bounds
    api_res = list_case_flows_endpoint(createdAfter="2026-07-06T12:05:00Z", createdBefore="2026-07-06T12:50:00Z", pageSize=200)
    expected_cnt = sum(1 for item in bulk_req_items if "2026-07-06T12:05:00Z" <= item.createdAt <= "2026-07-06T12:50:00Z")
    check_eq(len(api_res.data), expected_cnt, "Filter by created range matches")

    # ---------------------------------------------------------------------------
    # Test 8: Sorting Assertions (Target: ~6000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing case sorting logic exhaustively...")

    sort_fields = ["caseName", "createdAt", "updatedAt", "priority", "status", "stepCount", "executionCount"]

    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_case_flows_endpoint(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data

            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]

                if field == "caseName":
                    v_curr, v_next = item_curr["title"], item_next["title"]
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]
                elif field == "updatedAt":
                    v_curr = item_curr["updatedAt"] or ""
                    v_next = item_next["updatedAt"] or ""
                elif field == "priority":
                    from services.case_flow_service import _PRIORITY_ORDER, CasePriorityEnum
                    v_curr = _PRIORITY_ORDER[CasePriorityEnum(item_curr["priority"])]
                    v_next = _PRIORITY_ORDER[CasePriorityEnum(item_next["priority"])]
                elif field == "status":
                    from services.case_flow_service import _STATUS_ORDER, CaseStatusEnum
                    v_curr = _STATUS_ORDER[CaseStatusEnum(item_curr["status"])]
                    v_next = _STATUS_ORDER[CaseStatusEnum(item_next["status"])]
                elif field == "stepCount":
                    v_curr = len(item_curr["steps"])
                    v_next = len(item_next["steps"])
                elif field == "executionCount":
                    v_curr = len(_EXECUTION_STORE.get(item_curr["caseFlowId"], []))
                    v_next = len(_EXECUTION_STORE.get(item_next["caseFlowId"], []))

                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["caseFlowId"] <= item_next["caseFlowId"], "Secondary sort constraint")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["caseFlowId"] <= item_next["caseFlowId"], "Secondary sort constraint in DESC")

    # ---------------------------------------------------------------------------
    # Test 9: Pagination Assertions (Target: ~750 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")

    for p_size in [5, 10, 20, 25, 40]:
        total_pages = math.ceil(200 / p_size)
        seen_ids = set()

        for p in range(1, total_pages + 1):
            api_res = list_case_flows_endpoint(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")

            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 200, "Total items is 200")
            check_eq(pagination["totalPages"], total_pages, "Total pages matches")

            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                aid = item["caseFlowId"]
                check(aid not in seen_ids, f"Unique item {aid} on page {p}")
                seen_ids.add(aid)

        check_eq(len(seen_ids), 200, f"All 200 items covered in page size {p_size}")

    # ---------------------------------------------------------------------------
    # Test 10: Case Flow Summary and Steps Route checks (200 items * 5 = 1000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing case summaries and steps list lookup...")

    for c in cases_list:
        # Steps route check
        steps_res = get_case_steps(c["caseFlowId"])
        check_eq(steps_res.success, True, "Retrieve steps succeeds")
        check_eq(len(steps_res.data), len(c["steps"]), "Correct number of steps returned")
        for s_idx, s in enumerate(steps_res.data):
            check_eq(s["stepNumber"], c["steps"][s_idx]["stepNumber"], "Step number matches")
            check_eq(s["stepType"], c["steps"][s_idx]["stepType"], "Step type matches")
            check_eq(s["title"], c["steps"][s_idx]["title"], "Step title matches")
            check_eq(s["assignedTo"], c["steps"][s_idx]["assignedTo"], "Step assignedTo matches")

        # Summary route check
        sum_res = get_case_flow_summary(c["caseFlowId"])
        check_eq(sum_res.success, True, "Retrieve summary succeeds")
        check_eq(sum_res.data["caseFlowId"], c["caseFlowId"], "Summary caseFlowId matches")
        check_eq(sum_res.data["caseName"], c["title"], "Summary title matches")
        check_eq(sum_res.data["stepCount"], len(c["steps"]), "Summary step count matches")

    # ---------------------------------------------------------------------------
    # Test 11: Statistics Calculations
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_case_flow_statistics_endpoint()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data

    check_eq(stats["totalCases"], 200, "Total cases is 200")
    check_eq(stats["openCases"], 66, "66 cases are OPEN")
    check_eq(stats["closedCases"], 67, "67 cases are CLOSED")
    check_eq(stats["inProgressCases"], 67, "67 cases are IN_PROGRESS")
    check_eq(stats["totalExecutions"], 150, "Total executions in store is 150")
    check_eq(stats["averageSteps"], 3.0, "Average steps is 3.0")

    # ---------------------------------------------------------------------------
    # Test 12: Bulk Update & Bulk Delete
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")

    # Bulk update description and confidence for even indexes
    bulk_up_items = []
    updated_ids = []
    for idx, c in enumerate(cases_list):
        if idx % 2 == 0:
            bulk_up_items.append(
                BulkUpdateCaseFlowsRequest.BulkUpdateItem(
                    caseFlowId=c["caseFlowId"],
                    update=UpdateCaseFlowRequest(
                        description="Bulk updated description",
                        confidence=85.0
                    )
                )
            )
            updated_ids.append(c["caseFlowId"])

    bulk_up_res = bulk_update_case_flows(BulkUpdateCaseFlowsRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")

    # Verify updates in store
    for rec_id in updated_ids:
        c_stored = _CASE_FLOW_STORE[rec_id]
        check_eq(c_stored["description"], "Bulk updated description", "Description updated")
        check_eq(c_stored["confidence"], 85.0, "Confidence updated")

    # Bulk delete odd indexes
    bulk_del_ids = []
    for idx, c in enumerate(cases_list):
        if idx % 2 != 0:
            bulk_del_ids.append(c["caseFlowId"])

    bulk_del_res = bulk_delete_case_flows(BulkDeleteCaseFlowsRequest(caseFlowIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_CASE_FLOW_STORE), 100, "100 cases remaining in store")

    # Clean up remaining
    remaining_ids = [c["caseFlowId"] for c in _CASE_FLOW_STORE.values()]
    cleanup_res = bulk_delete_case_flows(BulkDeleteCaseFlowsRequest(caseFlowIds=remaining_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_CASE_FLOW_STORE), 0, "Store is completely empty")

    # ---------------------------------------------------------------------------
    # Test 13: Search logic
    # ---------------------------------------------------------------------------
    # Repopulate 1 item to test search
    create_case_flow(valid_req)
    search_res = search_case_flows_endpoint(q="Production")
    check_eq(search_res.success, True, "Search route succeeds")
    check_eq(search_res.data["total"], 1, "Exactly one matches query 'Production'")

    # ---------------------------------------------------------------------------
    # Test 14: Serialization & Deserialization
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    json_str = valid_req.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["title"], "Intrusion Alert in Production Cluster", "JSON serialization is correct")

    deserialized = CreateCaseFlowRequest(**parsed)
    check_eq(deserialized.title, "Intrusion Alert in Production Cluster", "Deserialization roundtrip matches")

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
