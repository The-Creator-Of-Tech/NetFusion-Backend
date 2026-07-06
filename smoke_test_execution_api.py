"""
Smoke Test — AI Execution API (Phase A4.8.7 - Part B)
===================================================
Target: 1100+ assertions, 0 failures.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.execution_router import (
    execution_router,
    _reset_store,
    _EXECUTION_STORE,
    list_executions,
    get_execution_statistics,
    get_execution,
    create_execution,
    update_execution,
    delete_execution,
    run_registered_execution,
    get_execution_status,
    search_executions_endpoint,
    bulk_create_executions_route,
    bulk_update_executions_route,
    bulk_delete_executions_route,
    retry_execution_route,
    cancel_execution_route,
    get_execution_summary_route,
    # Helpers
    find_execution,
    sort_executions,
    filter_executions,
    paginate_executions,
    search_executions,
    retry_execution,
    cancel_execution,
    build_execution_summary,
    calculate_execution_usage,
    get_execution_status_helper,
)
from api.ai.execution_models import (
    CreateExecutionRequest,
    UpdateExecutionRequest,
    ExecutionResponse,
    ExecutionListResponse,
    ExecutionStatisticsResponse,
    BulkCreateExecutionsRequest,
    BulkUpdateExecutionsRequest,
    BulkDeleteExecutionsRequest,
    BulkOperationResult,
)
from services.ai_execution_service import (
    build_execution_request,
    build_execution_response,
    build_execution_metadata,
    build_execution_result,
)

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------
_PASS = 0
_FAIL = 0

def _eq(a, b, label: str) -> None:
    global _PASS, _FAIL
    if a == b:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: {a!r} != {b!r}")

def _ne(a, b, label: str) -> None:
    global _PASS, _FAIL
    if a != b:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected not-equal but got {a!r}")

def _is(obj, typ, label: str) -> None:
    global _PASS, _FAIL
    if isinstance(obj, typ):
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected {typ.__name__}, got {type(obj).__name__}")

def _true(v, label: str) -> None:
    global _PASS, _FAIL
    if v:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected True")

def _false(v, label: str) -> None:
    global _PASS, _FAIL
    if not v:
        _PASS += 1
    else:
        _FAIL += 1
        print(f"  FAIL [{label}]: expected False")

# ---------------------------------------------------------------------------
# Run Tests
# ---------------------------------------------------------------------------

def run_tests() -> None:
    global _PASS, _FAIL
    print("Starting AI Execution API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in execution_router.routes}
    expected_paths = {
        "/execution", "/execution/statistics", "/execution/search",
        "/execution/bulk/create", "/execution/bulk/update", "/execution/bulk/delete",
        "/execution/{executionId}", "/execution/{executionId}/execute",
        "/execution/{executionId}/status", "/execution/{executionId}/retry",
        "/execution/{executionId}/cancel", "/execution/{executionId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (120 items -> 1440+ assertions)
    # =======================================================================
    sessions = []
    for i in range(120):
        req = build_execution_request(
            provider      = "groq" if i % 2 == 0 else "openai",
            model         = f"model-{i % 3}",
            system_prompt = f"System prompt {i:03d}",
            user_prompt   = f"User prompt {i:03d}",
            created_at    = f"2026-07-03T12:{i:02d}:00Z",
            temperature   = 0.1 * (i % 5),
            max_tokens    = 100 + i,
            stream        = False,
            request_id    = f"req-{(i % 4):02d}",
            session_id    = f"sess-{i:03d}",
            strategy      = "priority",
            validate      = False,
        )
        
        resp = None
        if i % 3 != 0:
            resp = build_execution_response(
                execution_id      = req.executionId,
                provider          = req.provider,
                model             = req.model,
                content           = f"Response content {i:03d}",
                finish_reason     = "stop",
                created_at        = f"2026-07-03T12:{i:02d}:30Z",
                prompt_tokens     = 10 * i,
                completion_tokens = 5 * i,
                estimated_cost    = 0.001 * i,
                latency_ms        = 10 * i,
                validate          = False,
            )

        meta = build_execution_metadata(
            execution_id       = req.executionId,
            provider           = req.provider,
            model              = req.model,
            strategy           = req.strategy,
            attempt_number     = 1,
            total_attempts     = 1,
            processing_time_ms = 50 * i,
            success            = (i % 3 != 0),
            error              = None if i % 3 != 0 else "Execution failed stub.",
        )
        
        pkg = build_execution_result(req, resp, meta)
        
        session_dict = {
            "package"       : pkg,
            "projectId"     : f"proj-{(i % 5)}",
            "userId"        : f"user-{(i % 3)}",
            "status"        : "COMPLETED" if (i % 3 != 0) else "FAILED",
            "executionName" : f"Execution Name {i:03d}",
        }
        sessions.append(session_dict)

    sort_fields = ["createdAt", "updatedAt", "executionName", "status", "processingTimeMs", "totalTokens"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_executions(sessions, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 120, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(119):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["package"]
                c2 = s2["package"]
                
                if field == "totalTokens":
                    v1 = c1.response.totalTokens if c1.response is not None else 0
                    v2 = c2.response.totalTokens if c2.response is not None else 0
                elif field == "processingTimeMs":
                    v1 = c1.metadata.processingTimeMs
                    v2 = c2.metadata.processingTimeMs
                elif field == "status":
                    v1 = s1.get("status").lower()
                    v2 = s2.get("status").lower()
                elif field == "executionName":
                    v1 = s1.get("executionName").lower()
                    v2 = s2.get("executionName").lower()
                elif field in ("createdAt", "updatedAt"):
                    v1 = c1.request.createdAt
                    v2 = c2.request.createdAt
                
                if reverse:
                    _true(v1 >= v2, f"Sort verification: {field} desc index {k}")
                else:
                    _true(v1 <= v2, f"Sort verification: {field} asc index {k}")

    # =======================================================================
    # 3. Filtering Helper Verification
    # =======================================================================
    filters = [
        ({"status": "COMPLETED"}, 80),
        ({"status": "FAILED"}, 40),
        ({"userId": "user-0"}, 40),
        ({"userId": "user-1"}, 40),
        ({"projectId": "proj-0"}, 24),
        ({"minimumTokens": 100}, 76),
        ({"maximumTokens": 50}, 42),
        ({"minimumLatency": 200}, 67),
        ({"maximumLatency": 500}, 74),
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 79),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 20),
        ({"status": "COMPLETED", "userId": "user-1"}, 40),
    ]
    for filt, expected_count in filters:
        filtered = filter_executions(
            sessions,
            status=filt.get("status"),
            provider=filt.get("provider"),
            model=filt.get("model"),
            userId=filt.get("userId"),
            projectId=filt.get("projectId"),
            minimumTokens=filt.get("minimumTokens"),
            maximumTokens=filt.get("maximumTokens"),
            minimumLatency=filt.get("minimumLatency"),
            maximumLatency=filt.get("maximumLatency"),
            createdAfter=filt.get("createdAfter"),
            createdBefore=filt.get("createdBefore"),
        )
        _eq(len(filtered), expected_count, f"Filter count: {filt}")

    # =======================================================================
    # 4. Pagination Helper Verification
    # =======================================================================
    for page in [1, 2, 3]:
        for page_size in [5, 10]:
            slice_res, pag = paginate_executions(sessions, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 120, "TotalItems meta")
            _eq(pag.totalPages, math.ceil(120 / page_size), "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & execution actions
    # =======================================================================
    _reset_store()

    # Empty stats
    stats_resp = get_execution_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalExecutions"], 0, "Empty totalExecutions")

    # Create (register shell)
    body1 = CreateExecutionRequest(
        provider="groq",
        model="llama-3.3-70b-versatile",
        systemPrompt="System instructions",
        userPrompt="Scan context info",
        createdAt="2026-07-03T12:00:00Z",
        projectId="proj-sec",
        userId="analyst-9",
        status="ACTIVE"
    )
    resp1 = create_execution(body1)
    _eq(resp1.success, True, "Create execution shell")
    eid1 = resp1.data["executionId"]
    _true(eid1 is not None, "Valid executionId returned")

    # Duplicate detection
    dup_resp = create_execution(body1)
    _eq(dup_resp.success, False, "Duplicate create failed")
    _eq(dup_resp.data.errorCode, "CONFLICT", "Conflict error code")

    # Get execution record
    get1 = get_execution(eid1)
    _eq(get1.data["projectId"], "proj-sec", "projectId metadata")
    _eq(get1.data["status"], "PENDING", "initial status is PENDING")

    # Status check
    status_resp1 = get_execution_status(eid1)
    _eq(status_resp1.data["status"], "PENDING", "status is PENDING")

    # Run execute
    run_resp = run_registered_execution(eid1)
    _eq(run_resp.success, True, "Execute execution shell")
    _eq(run_resp.data["status"], "COMPLETED", "Executed status moves to COMPLETED")

    # Retry execution
    retry_resp = retry_execution_route(eid1, maxAttempts=3)
    _eq(retry_resp.success, True, "Retry run successful")
    _eq(retry_resp.data["status"], "COMPLETED", "Retried status stays COMPLETED")

    # Summary check
    sum_resp = get_execution_summary_route(eid1)
    _eq(sum_resp.success, True, "Summary retrieval")
    _true("ID=" in sum_resp.data["summary"], "Summary lists details")

    # Update execution details
    upd1 = UpdateExecutionRequest(status="FAILED", projectId="completed-proj")
    upd_resp1 = update_execution(eid1, upd1)
    _eq(upd_resp1.success, True, "Update details")
    _eq(upd_resp1.data["status"], "FAILED", "Updated status")
    _eq(upd_resp1.data["projectId"], "completed-proj", "Updated project ID")

    # Cancel execution (validates state validation on cancel)
    cancel_resp = cancel_execution_route(eid1)
    _eq(cancel_resp.success, False, "Cannot cancel execution in 'FAILED' status")

    # Create another shell and cancel it
    resp2 = create_execution(CreateExecutionRequest(
        provider="groq",
        model="llama-3.3-70b-versatile",
        systemPrompt="System instructions 2",
        userPrompt="Scan context info 2",
        createdAt="2026-07-03T12:05:00Z",
    ))
    eid2 = resp2.data["executionId"]
    cancel_resp2 = cancel_execution_route(eid2)
    _eq(cancel_resp2.success, True, "Cancel pending execution succeeds")
    _eq(cancel_resp2.data["status"], "CANCELLED", "Cancelled status")

    # Statistics check
    stats_resp2 = get_execution_statistics()
    _eq(stats_resp2.data["totalExecutions"], 2, "Stats totalExecutions = 2")
    _eq(stats_resp2.data["statusCounts"]["CANCELLED"], 1, "statusCounts has CANCELLED")
    _ne(stats_resp2.data["averageExecutionSize"], 0.0, "averageExecutionSize is non-zero")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_executions = []
    for j in range(5):
        bulk_executions.append(CreateExecutionRequest(
            provider="groq",
            model="llama-3.3-70b-versatile",
            systemPrompt=f"Bulk system {j}",
            userPrompt=f"Bulk user {j}",
            createdAt=f"2026-07-03T13:{j:02d}:00Z",
            projectId=f"proj-{j}",
            userId=f"analyst-{j}",
        ))
    bulk_req = BulkCreateExecutionsRequest(executions=bulk_executions)
    bulk_resp = bulk_create_executions_route(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create executions")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search executions
    search_resp = search_executions_endpoint(q="Bulk system", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk system'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["executions"]), 3, "Page slice size")

    # Bulk Update
    eids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for eid in eids_to_update:
        update_items.append({
            "executionId": eid,
            "update": UpdateExecutionRequest(status="COMPLETED")
        })
    bulk_upd_req = BulkUpdateExecutionsRequest(items=update_items)
    bulk_upd_resp = bulk_update_executions_route(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for eid in eids_to_update:
        p_get = get_execution(eid)
        _eq(p_get.data["status"], "COMPLETED", "Bulk status updated")

    # Bulk Delete
    eids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteExecutionsRequest(executionIds=eids_to_delete)
    bulk_del_resp = bulk_delete_executions_route(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    # Validation failures on empty fields
    val_fail_req = CreateExecutionRequest(
        provider="", model="", systemPrompt="", userPrompt="", createdAt=""
    )
    _eq(len(val_fail_req.validate_request()), 4, "Validation fails for empty fields")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
