"""
Smoke Test for Playbook Workflow API — Phase A4.10.1
===================================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Step CRUD operations (append, update, delete)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ Summary and statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 6500+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
from typing import Any, List, Dict

# Import API components
from api.workflow.playbook_router import (
    playbook_router,
    _reset_store,
    _all_playbooks,
    _PLAYBOOK_STORE,
    list_playbooks_endpoint,
    get_statistics,
    search_playbook_records,
    get_playbook,
    create_playbook,
    update_playbook,
    delete_playbook,
    get_playbook_steps,
    append_step,
    update_step,
    delete_step,
    get_playbook_summary,
    bulk_create_playbooks,
    bulk_update_playbooks,
    bulk_delete_playbooks,
    # Utilities
    find_playbook,
    find_playbook_step,
    search_playbooks,
    search_playbook_steps,
    sort_playbooks,
    filter_playbooks,
    paginate_playbooks,
    build_playbook_summary,
    calculate_playbook_statistics,
)
from api.workflow.playbook_models import (
    CreatePlaybookRequest,
    UpdatePlaybookRequest,
    PlaybookStepRequest,
    PlaybookStepResponse,
    PlaybookResponse,
    PlaybookListResponse,
    PlaybookStatisticsResponse,
    PlaybookSearchResponse,
    PlaybookSummaryResponse,
    BulkCreatePlaybooksRequest,
    BulkUpdatePlaybooksRequest,
    BulkDeletePlaybooksRequest,
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
    print("Starting Playbook Workflow API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Metadata Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/workflow/playbooks"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/workflow/playbooks",
        "/api/v2/workflow/playbooks/",
        "/api/v2/workflow/playbooks/statistics",
        "/api/v2/workflow/playbooks/search",
        "/api/v2/workflow/playbooks/bulk/create",
        "/api/v2/workflow/playbooks/bulk/update",
        "/api/v2/workflow/playbooks/bulk/delete",
        "/api/v2/workflow/playbooks/{playbookId}",
        "/api/v2/workflow/playbooks/{playbookId}/steps",
        "/api/v2/workflow/playbooks/{playbookId}/steps/{stepId}",
        "/api/v2/workflow/playbooks/{playbookId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Store Initialization Check
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_PLAYBOOK_STORE), 0, "Playbook store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Playbook CRUD & Validation
    # ---------------------------------------------------------------------------
    print("Testing Playbook CRUD operations & validations...")

    # Empty name validation
    bad_req1 = CreatePlaybookRequest(
        name="", severity="HIGH", status="ACTIVE", confidence=90.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_playbook(bad_req1)
    check_eq(res.success, False, "Create fails with empty name")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad confidence bounds
    bad_req2 = CreatePlaybookRequest(
        name="Playbook A", severity="HIGH", status="ACTIVE", confidence=-10.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_playbook(bad_req2)
    check_eq(res.success, False, "Create fails with confidence < 0")

    bad_req3 = CreatePlaybookRequest(
        name="Playbook A", severity="HIGH", status="ACTIVE", confidence=150.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_playbook(bad_req3)
    check_eq(res.success, False, "Create fails with confidence > 100")

    # Successful Playbook Creation
    valid_req = CreatePlaybookRequest(
        name="Incident Response for APT29",
        description="Standard IR steps to contain and recover from APT29 Cozy Bear attacks.",
        severity="CRITICAL",
        status="ACTIVE",
        confidence=95.0,
        createdAt="2026-07-06T12:00:00Z",
        enabled=True,
        priority=3,
        category="Containment",
        author="SecOps Lead",
        projectId="PRJ-101",
        investigationId="INV-999",
        steps=[
            PlaybookStepRequest(
                stepNumber=1,
                title="Isolate Host",
                description="Network isolate the compromised host endpoint.",
                stepType="CONTAINMENT",
                expectedOutcome="Host is unreachable on local subnet and internet.",
                relatedTechniques=["T1059"],
                relatedCVEs=["CVE-2021-44228"],
                relatedIOCs=["192.168.1.100"],
                createdAt="2026-07-06T12:00:00Z"
            )
        ]
    )
    res = create_playbook(valid_req)
    check_eq(res.success, True, "Create succeeds with valid request")
    created_id = res.data["playbookId"]
    check(created_id is not None, "Playbook ID generated")
    check_eq(res.data["name"], "Incident Response for APT29", "Name matches")
    check_eq(len(res.data["steps"]), 1, "Has 1 step")

    # Duplicate detection -> CONFLICT
    res_dup = create_playbook(valid_req)
    check_eq(res_dup.success, False, "Duplicate playbook yields error")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Duplicate yields CONFLICT")

    # Retrieve Playbook
    res_get = get_playbook(created_id)
    check_eq(res_get.success, True, "Get playbook by ID succeeds")
    check_eq(res_get.data["playbookId"], created_id, "Correct ID returned")

    # Retrieve by name
    res_get_name = get_playbook("incident response for apt29")
    check_eq(res_get_name.success, True, "Get playbook by name succeeds")

    # Retrieve missing -> NOT_FOUND
    res_get_missing = get_playbook("missing_id")
    check_eq(res_get_missing.success, False, "Get missing playbook fails")
    check_eq(res_get_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Update playbook (non-existent)
    res_up_missing = update_playbook("missing_id", UpdatePlaybookRequest(name="Updated Name"))
    check_eq(res_up_missing.success, False, "Update missing playbook fails")
    check_eq(res_up_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Update playbook (successful)
    up_req = UpdatePlaybookRequest(
        description="Updated playbook description.",
        confidence=85.0,
        enabled=False,
        priority=1,
    )
    res_up = update_playbook(created_id, up_req)
    check_eq(res_up.success, True, "Update playbook succeeds")
    check_eq(res_up.data["description"], "Updated playbook description.", "Description updated")
    check_eq(res_up.data["confidence"], 85.0, "Confidence updated")
    check_eq(res_up.data["enabled"], False, "Enabled updated to False")
    check_eq(res_up.data["priority"], 1, "Priority updated to 1")


    # ---------------------------------------------------------------------------
    # Test 4: Step CRUD operations
    # ---------------------------------------------------------------------------
    print("Testing Step CRUD operations...")

    # Append Step
    step_req2 = PlaybookStepRequest(
        stepNumber=2,
        title="Analyze RAM Dump",
        description="Acquire and inspect RAM memory dump using volatility.",
        stepType="AUTOMATED",
        expectedOutcome="Identified rogue processes and active network connections.",
        relatedTechniques=["T1071"],
        createdAt="2026-07-06T12:05:00Z"
    )
    res_app_step = append_step(created_id, step_req2)
    check_eq(res_app_step.success, True, "Append step succeeds")
    created_id = res_app_step.data["playbookId"]
    check_eq(len(res_app_step.data["steps"]), 2, "Playbook now has 2 steps")
    step2_id = res_app_step.data["steps"][1]["stepId"]

    # Get Steps Endpoint
    res_get_steps = get_playbook_steps(created_id)
    check_eq(res_get_steps.success, True, "Get steps route succeeds")
    check_eq(len(res_get_steps.data), 2, "Returned steps list has 2 items")

    # Update Step
    step_req_up = PlaybookStepRequest(
        stepNumber=2,
        title="Analyze Memory Dump (Updated)",
        description="Perform volatility scan on endpoint memory dump.",
        stepType="AUTOMATED",
        expectedOutcome="Identified system processes.",
        createdAt="2026-07-06T12:05:00Z"
    )
    res_up_step = update_step(created_id, step2_id, step_req_up)
    check_eq(res_up_step.success, True, "Update step succeeds")
    created_id = res_up_step.data["playbookId"]
    check_eq(res_up_step.data["steps"][1]["title"], "Analyze Memory Dump (Updated)", "Step title updated")

    # Delete Step
    res_del_step = delete_step(created_id, step2_id)
    check_eq(res_del_step.success, True, "Delete step succeeds")
    created_id = res_del_step.data["playbookId"]
    check_eq(len(res_del_step.data["steps"]), 1, "Playbook has 1 step after deletion")


    # ---------------------------------------------------------------------------
    # Test 5: Generating Deterministic Playbook Dataset (150 items)
    # ---------------------------------------------------------------------------
    print("Generating deterministic test dataset of 200 items...")
    _reset_store()

    categories = ["Containment", "Eradication", "Recovery", "Verification", "Preparation"]
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    statuses = ["DRAFT", "ACTIVE", "DEPRECATED", "ARCHIVED"]
    authors = ["Alice", "Bob", "Charlie", "David"]

    bulk_req_items = []
    for i in range(1, 201):
        name = f"Playbook-{100 + i}"
        sev = severities[i % len(severities)]
        stat = statuses[i % len(statuses)]
        cat = categories[i % len(categories)]
        auth = authors[i % len(authors)]
        priority = (i % 5) + 1

        # Make varying number of steps: 1 to 5 steps
        steps_req = []
        for s_num in range(1, (i % 5) + 2):
            steps_req.append(
                PlaybookStepRequest(
                    stepNumber=s_num,
                    title=f"Step-{s_num} for Playbook-{i}",
                    description=f"Description of step {s_num}",
                    stepType="MANUAL" if s_num % 2 == 0 else "AUTOMATED",
                    expectedOutcome=f"Step outcome {s_num}",
                    relatedTechniques=[f"T100{s_num}"],
                    relatedCVEs=[f"CVE-2026-{3000 + i}"],
                    relatedIOCs=[f"192.168.0.{i}"],
                    createdAt=f"2026-07-06T12:{s_num % 60:02d}:00Z"
                )
            )

        bulk_req_items.append(
            CreatePlaybookRequest(
                name=name,
                description=f"Deterministic description of playbook {i}.",
                severity=sev,
                status=stat,
                steps=steps_req,
                relatedThreatActors=[f"Actor-{i % 4}"],
                relatedCampaigns=[f"Campaign-{i % 3}"],
                confidence=60.0 + (i % 40),
                createdAt=f"2026-07-06T12:{i % 60:02d}:00Z",
                enabled=(i % 3 != 0),
                priority=priority,
                category=cat,
                author=auth,
                projectId=f"PRJ-{100 + (i % 5)}",
                investigationId=f"INV-{200 + (i % 10)}",
                updatedAt=f"2026-07-06T13:{i % 60:02d}:00Z"
            )
        )

    bulk_res = bulk_create_playbooks(BulkCreatePlaybooksRequest(playbooks=bulk_req_items))
    check_eq(bulk_res.success, True, "Bulk create succeeds")
    check_eq(bulk_res.data["successCount"], 200, "200 playbooks created successfully")
    check_eq(bulk_res.data["failCount"], 0, "No failures in bulk create")
    check_eq(len(_PLAYBOOK_STORE), 200, "200 playbooks in store")

    playbooks_list = _all_playbooks()


    # ---------------------------------------------------------------------------
    # Test 6: Filtering Assertions (Target: ~3000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing playbook filtering logic exhaustively...")

    # 1. Enabled filter
    for enabled_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.enabled == enabled_val)
        api_res = list_playbooks_endpoint(enabled=enabled_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by enabled={enabled_val} count matches")
        for item in api_res.data:
            check_eq(item["enabled"], enabled_val, "Enabled attribute matches")

    # 2. Priority filter
    for pr in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if item.priority == pr)
        api_res = list_playbooks_endpoint(priority=pr, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by priority={pr} count matches")
        for item in api_res.data:
            check_eq(item["priority"], pr, "Priority attribute matches")

    # 3. Category filter
    for cat in categories:
        expected_cnt = sum(1 for item in bulk_req_items if item.category == cat)
        api_res = list_playbooks_endpoint(category=cat, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by category={cat} count matches")
        for item in api_res.data:
            check_eq(item["category"], cat, "Category matches")

    # 4. Author filter
    for auth in authors:
        expected_cnt = sum(1 for item in bulk_req_items if item.author == auth)
        api_res = list_playbooks_endpoint(author=auth, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by author={auth} count matches")
        for item in api_res.data:
            check_eq(item["author"], auth, "Author matches")

    # 5. Project ID filter
    for p_idx in range(5):
        prj_id = f"PRJ-{100 + p_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.projectId == prj_id)
        api_res = list_playbooks_endpoint(projectId=prj_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by projectId={prj_id} count matches")
        for item in api_res.data:
            check_eq(item["projectId"], prj_id, "Project ID matches")

    # 6. Investigation ID filter
    for inv_idx in range(10):
        inv_id = f"INV-{200 + inv_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.investigationId == inv_id)
        api_res = list_playbooks_endpoint(investigationId=inv_id, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by investigationId={inv_id} count matches")
        for item in api_res.data:
            check_eq(item["investigationId"], inv_id, "Investigation ID matches")

    # 7. Steps count filter bounds
    for min_steps in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if len(item.steps) >= min_steps)
        api_res = list_playbooks_endpoint(minimumSteps=min_steps, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by minimumSteps={min_steps} count matches")
        for item in api_res.data:
            check(len(item["steps"]) >= min_steps, "Steps count within minimum bounds")

    for max_steps in range(1, 6):
        expected_cnt = sum(1 for item in bulk_req_items if len(item.steps) <= max_steps)
        api_res = list_playbooks_endpoint(maximumSteps=max_steps, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Filter by maximumSteps={max_steps} count matches")
        for item in api_res.data:
            check(len(item["steps"]) <= max_steps, "Steps count within maximum bounds")

    # 8. Date bounds
    api_res = list_playbooks_endpoint(createdAfter="2026-07-06T12:00:00Z", createdBefore="2026-07-06T12:30:00Z", pageSize=200)
    expected_cnt = sum(1 for item in bulk_req_items if "2026-07-06T12:00:00Z" <= item.createdAt <= "2026-07-06T12:30:00Z")
    check_eq(len(api_res.data), expected_cnt, "Filter by created range matches")


    # ---------------------------------------------------------------------------
    # Test 7: Sorting Assertions (Target: ~1800 assertions)
    # ---------------------------------------------------------------------------
    print("Testing playbook sorting logic exhaustively...")

    sort_fields = ["playbookName", "createdAt", "updatedAt", "stepCount", "priority", "enabled"]

    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_playbooks_endpoint(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data

            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]

                if field == "playbookName":
                    v_curr, v_next = item_curr["name"], item_next["name"]
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]
                elif field == "updatedAt":
                    v_curr = item_curr["updatedAt"] or ""
                    v_next = item_next["updatedAt"] or ""
                elif field == "stepCount":
                    v_curr = len(item_curr["steps"])
                    v_next = len(item_next["steps"])
                elif field == "priority":
                    v_curr = item_curr["priority"]
                    v_next = item_next["priority"]
                elif field == "enabled":
                    v_curr = int(item_curr["enabled"])
                    v_next = int(item_next["enabled"])

                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["playbookId"] <= item_next["playbookId"], "Secondary sort constraint")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["playbookId"] <= item_next["playbookId"], "Secondary sort constraint in DESC")


    # ---------------------------------------------------------------------------
    # Test 8: Pagination Assertions (Target: ~750 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")

    for p_size in [5, 10, 20, 25, 40]:
        total_pages = math.ceil(200 / p_size)
        seen_ids = set()

        for p in range(1, total_pages + 1):
            api_res = list_playbooks_endpoint(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")

            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 200, "Total items is 200")
            check_eq(pagination["totalPages"], total_pages, "Total pages matches")

            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                pid = item["playbookId"]
                check(pid not in seen_ids, f"Unique item {pid} on page {p}")
                seen_ids.add(pid)

        check_eq(len(seen_ids), 200, f"All 200 items covered in page size {p_size}")


    # ---------------------------------------------------------------------------
    # Test 9: Playbook summary & steps check (150 items * ~6 = 900 assertions)
    # ---------------------------------------------------------------------------
    print("Testing playbook summaries and steps list lookup...")

    for c in playbooks_list:
        # Steps route check
        steps_res = get_playbook_steps(c["playbookId"])
        check_eq(steps_res.success, True, "Retrieve steps succeeds")
        check_eq(len(steps_res.data), len(c["steps"]), "Correct number of steps returned")

        # Summary route check
        sum_res = get_playbook_summary(c["playbookId"])
        check_eq(sum_res.success, True, "Retrieve summary succeeds")
        check_eq(sum_res.data["playbookId"], c["playbookId"], "Summary playbookId matches")
        check_eq(sum_res.data["playbookName"], c["name"], "Summary name matches")
        check_eq(sum_res.data["stepCount"], len(c["steps"]), "Summary step count matches")
        check_eq(sum_res.data["enabled"], c["enabled"], "Summary enabled matches")


    # ---------------------------------------------------------------------------
    # Test 10: Statistics Calculations
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_statistics()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data

    check_eq(stats["totalPlaybooks"], 200, "Total playbooks is 200")
    check_eq(stats["enabledPlaybooks"], 134, "134 playbooks are enabled (i % 3 != 0)")
    check_eq(stats["disabledPlaybooks"], 66, "66 playbooks are disabled")
    check_eq(stats["averageSteps"], 3.0, "Average steps is 3.0")
    check_eq(stats["averagePriority"], 3.0, "Average priority is 3.0")


    # ---------------------------------------------------------------------------
    # Test 11: Bulk Update & Bulk Delete
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")

    # Bulk update category for even indexes
    bulk_up_items = []
    updated_ids = []
    for idx, c in enumerate(playbooks_list):
        if idx % 2 == 0:
            bulk_up_items.append(
                BulkUpdatePlaybooksRequest.BulkUpdateItem(
                    playbookId=c["playbookId"],
                    update=UpdatePlaybookRequest(
                        category="Incident Response",
                        enabled=True,
                        priority=5,
                    )
                )
            )
            updated_ids.append(c["playbookId"])

    bulk_up_res = bulk_update_playbooks(BulkUpdatePlaybooksRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")

    # Verify updates in store
    for rec_id in updated_ids:
        c_stored = _PLAYBOOK_STORE[rec_id]
        check_eq(c_stored["category"], "Incident Response", "Category updated")
        check_eq(c_stored["enabled"], True, "Enabled is True")
        check_eq(c_stored["priority"], 5, "Priority is 5")

    # Bulk delete odd indexes
    bulk_del_ids = []
    for idx, c in enumerate(playbooks_list):
        if idx % 2 != 0:
            bulk_del_ids.append(c["playbookId"])

    bulk_del_res = bulk_delete_playbooks(BulkDeletePlaybooksRequest(playbookIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_PLAYBOOK_STORE), 100, "100 playbooks remaining in store")

    # Clean up remaining
    remaining_ids = [c["playbookId"] for c in _PLAYBOOK_STORE.values()]
    cleanup_res = bulk_delete_playbooks(BulkDeletePlaybooksRequest(playbookIds=remaining_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_PLAYBOOK_STORE), 0, "Store is completely empty")


    # ---------------------------------------------------------------------------
    # Test 12: Search logic
    # ---------------------------------------------------------------------------
    # Repopulate 1 item to test search
    create_playbook(valid_req)
    search_res = search_playbook_records(query="APT29")
    check_eq(search_res.success, True, "Search route succeeds")
    check_eq(search_res.data["total"], 1, "Exactly one matches query 'APT29'")


    # ---------------------------------------------------------------------------
    # Test 13: Serialization & Deserialization
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    json_str = valid_req.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["name"], "Incident Response for APT29", "JSON serialization is correct")

    deserialized = CreatePlaybookRequest(**parsed)
    check_eq(deserialized.name, "Incident Response for APT29", "Deserialization roundtrip matches")

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
