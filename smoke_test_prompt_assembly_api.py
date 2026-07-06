"""
Smoke Test — Prompt Assembly API (Phase A4.8.5 - Part B)
======================================================
Target: 900+ assertions, 0 failures.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Optional, Tuple

from api.ai.prompt_assembly_router import (
    prompt_assembly_router,
    _reset_store,
    _PROMPT_STORE,
    list_prompts,
    get_prompt_statistics,
    get_prompt,
    create_prompt,
    update_prompt,
    delete_prompt,
    append_prompt_section_route,
    list_prompt_sections,
    search_prompts_endpoint,
    bulk_create_prompts_route,
    bulk_update_prompts_route,
    bulk_delete_prompts_route,
    update_prompt_section_route,
    delete_prompt_section_route,
    get_prompt_summary,
    # Helpers
    find_prompt,
    sort_prompts,
    filter_prompts,
    paginate_prompts,
    append_prompt_section,
    update_prompt_section,
    delete_prompt_section,
    find_prompt_section,
    search_prompt_sections,
    build_prompt_summary,
)
from api.ai.prompt_assembly_models import (
    CreatePromptRequest,
    UpdatePromptRequest,
    PromptSectionRequest,
    PromptSectionResponse,
    PromptResponse,
    PromptListResponse,
    PromptStatisticsResponse,
    BulkCreatePromptsRequest,
    BulkUpdatePromptsRequest,
    BulkDeletePromptsRequest,
    BulkOperationResult,
)
from services.prompt_assembly_service import (
    build_prompt_section as service_build_section,
    build_prompt_package as service_build_package,
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
    print("Starting AI Prompt Assembly API Part B Smoke Test...")

    # =======================================================================
    # 1. Router Registration Checks
    # =======================================================================
    paths = {r.path for r in prompt_assembly_router.routes}
    expected_paths = {
        "/prompts", "/prompts/statistics", "/prompts/search",
        "/prompts/bulk/create", "/prompts/bulk/update", "/prompts/bulk/delete",
        "/prompts/{promptId}", "/prompts/{promptId}/sections",
        "/prompts/{promptId}/sections/{sectionId}", "/prompts/{promptId}/summary"
    }
    for p in expected_paths:
        _true(p in paths, f"Path {p} registered")

    # =======================================================================
    # 2. Programmatic Sort Testing (95 items -> 950+ assertions)
    # =======================================================================
    prompts = []
    for i in range(95):
        sections = []
        for m_idx in range(i % 5 + 1):
            sec = service_build_section(
                title            = f"Section Title {i:03d} - {m_idx}",
                content          = f"content {i} section {m_idx}",
                priority         = 10 * m_idx,
            )
            sections.append(sec)
            
        pkg = service_build_package(
            reasoning_id     = f"res-{(i % 4):02d}",
            context_id       = f"ctx-{i:03d}",
            investigation_id = f"inv-{i:03d}",
            system_prompt    = f"System prompt {i:03d}",
            user_prompt      = f"User prompt {i:03d}",
            created_at       = f"2026-07-03T12:{i:02d}:00Z",
            sections         = sections,
        )
        
        session_dict = {
            "package"    : pkg,
            "projectId"  : f"proj-{(i % 5)}",
            "userId"     : f"user-{(i % 3)}",
            "status"     : "ACTIVE" if i % 2 == 0 else "ARCHIVED",
            "promptName" : f"Prompt Name {i:03d}",
        }
        prompts.append(session_dict)

    sort_fields = ["createdAt", "updatedAt", "promptName", "sectionCount", "tokenCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            sorted_list = sort_prompts(prompts, sort_by=field, sort_order=order)
            _eq(len(sorted_list), 95, f"Sort by {field} {order} length")
            reverse = (order == "desc")
            
            for k in range(94):
                s1 = sorted_list[k]
                s2 = sorted_list[k+1]
                
                c1 = s1["package"]
                c2 = s2["package"]
                
                if field == "tokenCount":
                    v1 = c1.metadata.estimatedTokens
                    v2 = c2.metadata.estimatedTokens
                elif field == "sectionCount":
                    v1 = len(c1.sections)
                    v2 = len(c2.sections)
                elif field == "promptName":
                    v1 = s1.get("promptName").lower()
                    v2 = s2.get("promptName").lower()
                elif field == "createdAt":
                    v1 = c1.createdAt
                    v2 = c2.createdAt
                elif field == "updatedAt":
                    # fallback to createdAt
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
        ({"status": "ACTIVE"}, 48),
        ({"status": "ARCHIVED"}, 47),
        ({"userId": "user-0"}, 32),
        ({"userId": "user-1"}, 32),
        ({"userId": "user-2"}, 31),
        ({"projectId": "proj-0"}, 19),
        ({"projectId": "proj-3"}, 19),
        ({"minimumSections": 3}, 57),
        ({"maximumSections": 2}, 38),
        ({"minimumSections": 2, "maximumSections": 4}, 57),
        ({"minimumTokens": 10}, 76),
        ({"createdAfter": "2026-07-03T12:20:00Z"}, 74),
        ({"createdBefore": "2026-07-03T12:10:00Z"}, 10),
        ({"status": "ACTIVE", "userId": "user-0"}, 16),
    ]
    for filt, expected_count in filters:
        filtered = filter_prompts(
            prompts,
            status=filt.get("status"),
            userId=filt.get("userId"),
            projectId=filt.get("projectId"),
            investigationId=filt.get("investigationId"),
            minimumSections=filt.get("minimumSections"),
            maximumSections=filt.get("maximumSections"),
            minimumTokens=filt.get("minimumTokens"),
            maximumTokens=filt.get("maximumTokens"),
            createdAfter=filt.get("createdAfter"),
            createdBefore=filt.get("createdBefore"),
        )
        _eq(len(filtered), expected_count, f"Filter count: {filt}")

    # =======================================================================
    # 4. Pagination Helper Verification
    # =======================================================================
    for page in [1, 2, 3]:
        for page_size in [5, 10]:
            slice_res, pag = paginate_prompts(prompts, page, page_size)
            _eq(pag.page, page, "Page meta")
            _eq(pag.pageSize, page_size, "PageSize meta")
            _eq(pag.totalItems, 95, "TotalItems meta")
            _eq(pag.totalPages, math.ceil(95 / page_size), "TotalPages")
            _eq(len(slice_res), page_size, "Slice size")

    # =======================================================================
    # 5. REST Endpoint CRUD & section actions
    # =======================================================================
    _reset_store()

    # Empty stats
    stats_resp = get_prompt_statistics()
    _eq(stats_resp.success, True, "Stats fetch success")
    _eq(stats_resp.data["totalPrompts"], 0, "Empty totalPrompts")
    _eq(stats_resp.data["averagePromptSize"], 0.0, "Empty averagePromptSize")

    # Create Prompt Package
    body1 = CreatePromptRequest(
        reasoningId="res-sec", contextId="ctx-sec", investigationId="inv-sec",
        systemPrompt="You are a firewall assistant.", userPrompt="Analyze the scan.",
        createdAt="2026-07-03T12:00:00Z", projectId="proj-sec", userId="analyst-9",
        status="ACTIVE", promptName="Sec Prompt"
    )
    resp1 = create_prompt(body1)
    _eq(resp1.success, True, "Create prompt package")
    pid1 = resp1.data["packageId"]
    _true(pid1 is not None, "Valid packageId returned")

    # Duplicate detection
    dup_resp = create_prompt(body1)
    _eq(dup_resp.success, False, "Duplicate create failed")
    _eq(dup_resp.data.errorCode, "CONFLICT", "Conflict error code")

    # Get prompt package
    get1 = get_prompt(pid1)
    _eq(get1.data["projectId"], "proj-sec", "projectId metadata")
    _eq(get1.data["promptName"], "Sec Prompt", "promptName metadata")

    # Append section
    sec_body1 = PromptSectionRequest(
        title="Evidence Summary", content="Port scan from 10.0.0.5 detected.", priority=100
    )
    sec_resp1 = append_prompt_section_route(pid1, sec_body1)
    _eq(sec_resp1.success, True, "Section appended")
    sid1 = sec_resp1.data["sectionId"]

    # Append second section
    sec_body2 = PromptSectionRequest(
        title="Reasoning Summary", content="Matched port scan behavior.", priority=90
    )
    sec_resp2 = append_prompt_section_route(pid1, sec_body2)
    _eq(sec_resp2.success, True, "Second section appended")
    sid2 = sec_resp2.data["sectionId"]

    # Verify sections listing
    list_sections_res = list_prompt_sections(pid1)
    _eq(len(list_sections_res.data), 2, "Prompt has 2 sections")

    # Update section content
    upd_sec_body = PromptSectionRequest(
        title="Reasoning Summary", content="Matched port scan behavior (high severity).", priority=95
    )
    upd_sec_resp = update_prompt_section_route(pid1, sid2, upd_sec_body)
    if not upd_sec_resp.success:
        print(f"Update failed with message: {upd_sec_resp.message}, details: {upd_sec_resp.data.details if hasattr(upd_sec_resp.data, 'details') else None}")
    _eq(upd_sec_resp.success, True, "Section updated")
    _eq(upd_sec_resp.data["content"] if upd_sec_resp.success else None, "Matched port scan behavior (high severity).", "Updated content value")

    # Verify summary endpoint
    sum_resp = get_prompt_summary(pid1)
    _eq(sum_resp.success, True, "Summary retrieved")
    _true("Port scan" in sum_resp.data["summary"], "Summary lists first text")

    # Delete section
    del_sec_resp = delete_prompt_section_route(pid1, sid1)
    _eq(del_sec_resp.success, True, "Section deleted")

    # Verify section list size after deletion
    list_sections_after = list_prompt_sections(pid1)
    _eq(len(list_sections_after.data), 1, "Only 1 section remaining")

    # Update prompt package status
    upd1 = UpdatePromptRequest(status="ARCHIVED", promptName="Archived Sec Prompt")
    upd_resp1 = update_prompt(pid1, upd1)
    _eq(upd_resp1.success, True, "Update prompt package")
    _eq(upd_resp1.data["status"], "ARCHIVED", "Updated status")
    _eq(upd_resp1.data["promptName"], "Archived Sec Prompt", "Updated name")

    # Statistics check
    stats_resp2 = get_prompt_statistics()
    _eq(stats_resp2.data["totalPrompts"], 1, "Stats totalPrompts = 1")
    _eq(stats_resp2.data["archivedPrompts"], 1, "Prompts archived = 1")
    _ne(stats_resp2.data["averagePromptSize"], 0.0, "Stats averagePromptSize resolved")

    # =======================================================================
    # 6. Bulk Operations
    # =======================================================================
    bulk_prompts = []
    for j in range(5):
        bulk_prompts.append(CreatePromptRequest(
            reasoningId=f"res-bulk-{j}", contextId=f"ctx-bulk-{j}", investigationId="inv-bulk",
            systemPrompt="Firewall", userPrompt="Analyze", createdAt=f"2026-07-03T13:{j:02d}:00Z",
            projectId=f"proj-{j}", userId=f"analyst-{j}", status="ACTIVE", promptName=f"Bulk prompt {j}"
        ))
    bulk_req = BulkCreatePromptsRequest(prompts=bulk_prompts)
    bulk_resp = bulk_create_prompts_route(bulk_req)
    _eq(bulk_resp.success, True, "Bulk create prompts")
    _eq(bulk_resp.data["successCount"], 5, "Bulk create count")

    # Search prompts
    search_resp = search_prompts_endpoint(q="Bulk prompt", page=1, pageSize=3)
    _eq(search_resp.success, True, "Search for 'Bulk prompt'")
    _eq(search_resp.data["total"], 5, "Search total items matching")
    _eq(len(search_resp.data["prompts"]), 3, "Page slice size")

    # Bulk Update
    pids_to_update = bulk_resp.data["succeeded"][:2]
    update_items = []
    for pid in pids_to_update:
        update_items.append({
            "promptId": pid,
            "update": UpdatePromptRequest(status="ARCHIVED")
        })
    bulk_upd_req = BulkUpdatePromptsRequest(items=update_items)
    bulk_upd_resp = bulk_update_prompts_route(bulk_upd_req)
    _eq(bulk_upd_resp.success, True, "Bulk update success")
    _eq(bulk_upd_resp.data["successCount"], 2, "Bulk update successCount")

    # Verify state
    for pid in pids_to_update:
        p_get = get_prompt(pid)
        _eq(p_get.data["status"], "ARCHIVED", "Bulk status updated")

    # Bulk Delete
    pids_to_delete = bulk_resp.data["succeeded"]
    bulk_del_req = BulkDeletePromptsRequest(promptIds=pids_to_delete)
    bulk_del_resp = bulk_delete_prompts_route(bulk_del_req)
    _eq(bulk_del_resp.success, True, "Bulk delete success")
    _eq(bulk_del_resp.data["successCount"], 5, "Bulk delete successCount")

    # Verify serialization / validation failures
    val_fail_req = CreatePromptRequest(
        reasoningId="", contextId="ctx", investigationId="inv",
        systemPrompt="Sys", userPrompt="User", createdAt="2026-07-03"
    )
    _eq(len(val_fail_req.validate_request()), 1, "Validation fails for empty reasoningId")

    print(f"\nSmoke Test Completed! Passed: {_PASS}, Failed: {_FAIL}")
    if _FAIL > 0:
        raise RuntimeError(f"Smoke test failed with {_FAIL} failures!")

if __name__ == "__main__":
    run_tests()
