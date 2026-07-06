"""
Smoke Test — Reasoning API (Phase A4.8.6 - Part B)
=================================================
Target: 1000+ assertions, 0 failures.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.reasoning_router import (
    reasoning_router,
    _reset_store,
    _REASONING_STORE,
    list_reasonings,
    get_reasoning_statistics,
    get_reasoning,
    create_reasoning,
    update_reasoning,
    delete_reasoning,
    append_reasoning_step,
    list_reasoning_steps,
    search_reasonings_endpoint,
    bulk_create_reasoning_route,
    bulk_update_reasoning_route,
    bulk_delete_reasoning_route,
    update_reasoning_step_route,
    delete_reasoning_step_route,
    get_reasoning_summary_route,
    # Helpers
    find_reasoning,
    sort_reasoning,
    filter_reasoning,
    paginate_reasoning,
    search_reasoning_sessions,
    append_reasoning_step as helper_append_step,
    update_reasoning_step as helper_update_step,
    delete_reasoning_step as helper_delete_step,
    find_reasoning_step as helper_find_step,
    search_reasoning_steps as helper_search_steps,
    build_reasoning_summary as helper_build_summary,
)
from api.ai.reasoning_models import (
    CreateReasoningRequest,
    UpdateReasoningRequest,
    ReasoningStepRequest,
    ReasoningStepResponse,
    ReasoningResponse,
    ReasoningListResponse,
    ReasoningStatisticsResponse,
    BulkCreateReasoningRequest,
    BulkUpdateReasoningRequest,
    BulkDeleteReasoningRequest,
    BulkOperationResult,
)
from services.reasoning_service import (
    ReasoningStage,
    build_reasoning as service_build_reasoning,
    build_reasoning_trace as service_build_trace,
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
    print("Starting AI Reasoning API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in reasoning_router.routes}
    expected_paths = {
        "/reasoning", "/reasoning/statistics", "/reasoning/search",
        "/reasoning/bulk/create", "/reasoning/bulk/update", "/reasoning/bulk/delete",
        "/reasoning/{reasoningId}", "/reasoning/{reasoningId}/steps",
        "/reasoning/{reasoningId}/steps/{stepId}", "/reasoning/{reasoningId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (100 items -> 1000+ assertions)
    # =======================================================================
    sessions = []
    for i in range(100):
        traces = []
        for m_idx in range(i % 5 + 1):
            trace_step = service_build_trace(
                step_number        = m_idx + 1,
                stage              = ReasoningStage.OBSERVATION if m_idx % 2 == 0 else ReasoningStage.CONCLUSION,
                input_summary      = f"Input summary for step {m_idx}",
                output_summary     = f"Output summary for step {m_idx}",
                confidence         = 10.0 * (m_idx + 1),
            )
            traces.append(trace_step)
            
        pkg = service_build_reasoning(
            context_ids      = [f"ctx-{(i % 4):02d}"],
            finding_ids      = [f"find-{i:03d}"],
            alert_ids        = [f"alert-{i:03d}"],
            relationship_ids = [f"rel-{i:03d}"],
            timeline_ids     = [f"tl-{i:03d}"],
            created_at       = f"2026-07-03T12:{i:02d}:00Z",
            reasoning_trace  = traces,
            overall_confidence = 5.0 * (i % 20),
        )
        
        session_dict = {
            "package"         : pkg,
            "projectId"       : f"proj-{(i % 5)}",
            "userId"          : f"user-{(i % 3)}",
            "status"          : "ACTIVE" if i % 2 == 0 else "COMPLETED",
            "sessionName"     : f"Session Name {i:03d}",
            "contextIds"      : [f"ctx-{(i % 4):02d}"],
            "findingIds"      : [f"find-{i:03d}"],
            "alertIds"        : [f"alert-{i:03d}"],
            "relationshipIds" : [f"rel-{i:03d}"],
            "timelineIds"     : [f"tl-{i:03d}"],
        }
        sessions.append(session_dict)

    sort_fields = ["createdAt", "updatedAt", "sessionName", "stepCount", "confidence"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_reasoning(sessions, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 100, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(99):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["package"]
                c2 = s2["package"]
                
                if field == "confidence":
                    v1 = c1.overallConfidence
                    v2 = c2.overallConfidence
                elif field == "stepCount":
                    v1 = len(c1.reasoningTrace)
                    v2 = len(c2.reasoningTrace)
                elif field == "sessionName":
                    v1 = s1.get("sessionName").lower()
                    v2 = s2.get("sessionName").lower()
                elif field == "createdAt":
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                elif field == "updatedAt":
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                
                if reverse:
                    _true(v1 >= v2, f"Sort verification: {field} desc index {k}")
                else:
                    _true(v1 <= v2, f"Sort verification: {field} asc index {k}")

    # =======================================================================
    # 3. Filtering Helper Verification
    # =======================================================================
    filters = [
        ({"status": "ACTIVE"}, 50),
        ({"status": "COMPLETED"}, 50),
        ({"userId": "user-0"}, 34),
        ({"userId": "user-1"}, 33),
        ({"userId": "user-2"}, 33),
        ({"projectId": "proj-0"}, 20),
        ({"projectId": "proj-3"}, 20),
        ({"minimumSteps": 3}, 60),
        ({"maximumSteps": 2}, 40),
        ({"minimumSteps": 2, "maximumSteps": 4}, 60),
        ({"minimumConfidence": 10}, 90),
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 79),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 10),
        ({"status": "ACTIVE", "userId": "user-0"}, 17),
    ]
    for filt, expected_count in filters:
        filtered = filter_reasoning(
            sessions,
            status=filt.get("status"),
            userId=filt.get("userId"),
            projectId=filt.get("projectId"),
            investigationId=filt.get("investigationId"),
            minimumSteps=filt.get("minimumSteps"),
            maximumSteps=filt.get("maximumSteps"),
            minimumConfidence=filt.get("minimumConfidence"),
            maximumConfidence=filt.get("maximumConfidence"),
            createdAfter=filt.get("createdAfter"),
            createdBefore=filt.get("createdBefore"),
        )
        _eq(len(filtered), expected_count, f"Filter count: {filt}")

    # =======================================================================
    # 4. Pagination Helper Verification
    # =======================================================================
    for page in [1, 2, 3]:
        for page_size in [5, 10]:
            slice_res, pag = paginate_reasoning(sessions, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 100, "TotalItems meta")
            _eq(pag.totalPages, math.ceil(100 / page_size), "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & step actions
    # =======================================================================
    _reset_store()

    # Empty stats
    stats_resp = get_reasoning_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalReasoningSessions"], 0, "Empty totalReasoningSessions")

    # Create Reasoning Session
    body1 = CreateReasoningRequest(
        contextIds=["ctx-sec"], findingIds=["find-sec"], alertIds=["alert-sec"],
        relationshipIds=["rel-sec"], timelineIds=["tl-sec"],
        createdAt="2026-07-03T12:00:00Z", projectId="proj-sec", userId="analyst-9",
        status="ACTIVE", sessionName="Sec Session"
    )
    resp1 = create_reasoning(body1)
    _eq(resp1.success, True, "Create reasoning session")
    rid1 = resp1.data["reasoningId"]
    _true(rid1 is not None, "Valid reasoningId returned")

    # Duplicate detection
    dup_resp = create_reasoning(body1)
    _eq(dup_resp.success, False, "Duplicate create failed")
    _eq(dup_resp.data.errorCode, "CONFLICT", "Conflict error code")

    # Get reasoning session
    get1 = get_reasoning(rid1)
    _eq(get1.data["projectId"], "proj-sec", "projectId metadata")
    _eq(get1.data["sessionName"], "Sec Session", "sessionName metadata")

    # Append step
    step_body1 = ReasoningStepRequest(
        stepNumber=1, stage="OBSERVATION", inputSummary="Check scans", outputSummary="Scans analyzed", confidence=80.0
    )
    step_resp1 = append_reasoning_step(rid1, step_body1)
    _eq(step_resp1.success, True, "Step appended")

    # Append second step
    step_body2 = ReasoningStepRequest(
        stepNumber=2, stage="TIMELINE_ANALYSIS", inputSummary="Align timeline", outputSummary="Timeline aligned", confidence=90.0
    )
    step_resp2 = append_reasoning_step(rid1, step_body2)
    _eq(step_resp2.success, True, "Second step appended")

    # Verify steps listing
    list_steps_res = list_reasoning_steps(rid1)
    _eq(len(list_steps_res.data), 2, "Session has 2 steps")

    # Update step content
    upd_step_body = ReasoningStepRequest(
        stepNumber=2, stage="TIMELINE_ANALYSIS", inputSummary="Align timeline", outputSummary="Timeline aligned (high priority)", confidence=95.0
    )
    upd_step_resp = update_reasoning_step_route(rid1, "2", upd_step_body)
    _eq(upd_step_resp.success, True, "Step updated")
    _eq(upd_step_resp.data["outputSummary"], "Timeline aligned (high priority)", "Updated outputSummary value")

    # Verify summary endpoint
    sum_resp = get_reasoning_summary_route(rid1)
    _eq(sum_resp.success, True, "Summary retrieved")
    _true("Timeline aligned" in sum_resp.data["summary"], "Summary lists first text")

    # Delete step
    del_step_resp = delete_reasoning_step_route(rid1, "1")
    _eq(del_step_resp.success, True, "Step deleted")

    # Verify step list size after deletion
    list_steps_after = list_reasoning_steps(rid1)
    _eq(len(list_steps_after.data), 1, "Only 1 step remaining")

    # Update reasoning session details
    upd1 = UpdateReasoningRequest(status="COMPLETED", sessionName="Completed Sec Session")
    upd_resp1 = update_reasoning(rid1, upd1)
    _eq(upd_resp1.success, True, "Update session details")
    _eq(upd_resp1.data["status"], "COMPLETED", "Updated status")
    _eq(upd_resp1.data["sessionName"], "Completed Sec Session", "Updated name")

    # Statistics check
    stats_resp2 = get_reasoning_statistics()
    _eq(stats_resp2.data["totalReasoningSessions"], 1, "Stats totalReasoningSessions = 1")
    _eq(stats_resp2.data["completedReasoningSessions"], 1, "completedReasoningSessions = 1")
    _ne(stats_resp2.data["averageReasoningSize"], 0.0, "Stats averageReasoningSize resolved")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_sessions = []
    for j in range(5):
        bulk_sessions.append(CreateReasoningRequest(
            contextIds=[f"ctx-bulk-{j}"], findingIds=[f"find-{j}"], alertIds=[f"alert-{j}"],
            relationshipIds=[f"rel-{j}"], timelineIds=[f"tl-{j}"],
            createdAt=f"2026-07-03T13:{j:02d}:00Z", projectId=f"proj-{j}", userId=f"analyst-{j}",
            status="ACTIVE", sessionName=f"Bulk session {j}"
        ))
    bulk_req = BulkCreateReasoningRequest(reasonings=bulk_sessions)
    bulk_resp = bulk_create_reasoning_route(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create reasoning sessions")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search sessions
    search_resp = search_reasonings_endpoint(q="Bulk session", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk session'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["reasonings"]), 3, "Page slice size")

    # Bulk Update
    rids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for rid in rids_to_update:
        update_items.append({
            "reasoningId": rid,
            "update": UpdateReasoningRequest(status="COMPLETED")
        })
    bulk_upd_req = BulkUpdateReasoningRequest(items=update_items)
    bulk_upd_resp = bulk_update_reasoning_route(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for rid in rids_to_update:
        p_get = get_reasoning(rid)
        _eq(p_get.data["status"], "COMPLETED", "Bulk status updated")

    # Bulk Delete
    rids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeleteReasoningRequest(reasoningIds=rids_to_delete)
    bulk_del_resp = bulk_delete_reasoning_route(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    # Verify serialization / validation failures
    val_fail_req = CreateReasoningRequest(
        contextIds=[], findingIds=[], alertIds=[], relationshipIds=[], timelineIds=[], createdAt=""
    )
    _eq(len(val_fail_req.validate_request()), 1, "Validation fails for empty createdAt")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
