"""
Smoke Test for MITRE ATT&CK API — Phase A4.9.1
==============================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ Tactics and mitigations lookups
  ✓ Technique summary generation
  ✓ Statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 1800+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
import hashlib
from typing import Any, List, Dict

# Import API components
from api.knowledge.mitre_router import (
    mitre_router,
    _reset_store,
    _all_techniques,
    _TACTIC_INFO,
    _TECHNIQUE_STORE,
    list_techniques,
    get_statistics,
    search_mitre_techniques,
    get_technique,
    create_technique,
    update_technique,
    delete_technique,
    get_technique_tactics,
    get_technique_mitigations,
    get_technique_summary,
    bulk_create_techniques,
    bulk_update_techniques,
    bulk_delete_techniques,
    # Utilities
    find_technique,
    search_techniques,
    sort_techniques,
    filter_techniques,
    paginate_techniques,
    build_technique_summary,
    calculate_technique_statistics,
)
from api.knowledge.mitre_models import (
    CreateTechniqueRequest,
    UpdateTechniqueRequest,
    TechniqueResponse,
    TechniqueListResponse,
    TechniqueStatisticsResponse,
    TechniqueSearchResponse,
    MitreTacticResponse,
    MitreMitigationResponse,
    BulkCreateTechniquesRequest,
    BulkUpdateTechniquesRequest,
    BulkDeleteTechniquesRequest,
    BulkOperationResult,
)
from api.router import root_router
from services.mitre_attack_service import TacticEnum

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
    print("Starting MITRE ATT&CK API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Metadata Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/knowledge/mitre"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/knowledge/mitre",
        "/api/v2/knowledge/mitre/",
        "/api/v2/knowledge/mitre/statistics",
        "/api/v2/knowledge/mitre/search",
        "/api/v2/knowledge/mitre/bulk/create",
        "/api/v2/knowledge/mitre/bulk/update",
        "/api/v2/knowledge/mitre/bulk/delete",
        "/api/v2/knowledge/mitre/{techniqueId}",
        "/api/v2/knowledge/mitre/{techniqueId}/tactics",
        "/api/v2/knowledge/mitre/{techniqueId}/mitigations",
        "/api/v2/knowledge/mitre/{techniqueId}/summary",
    }
    
    # Strip trailing slashes or normalize routes
    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}
    
    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: In-Memory Store Cleanup
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_TECHNIQUE_STORE), 0, "Store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Basic CRUD Operations & Validation (Single items)
    # ---------------------------------------------------------------------------
    print("Testing CRUD operations & validation...")
    
    # Validation failures on creation
    # Invalid mitreId (empty)
    bad_req1 = CreateTechniqueRequest(
        mitreId="", name="Test", tactic="EXECUTION", createdAt="2026-07-06T10:00:00Z"
    )
    res = create_technique(bad_req1)
    check_eq(res.success, False, "Create fails with empty mitreId")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error code is VALIDATION_ERROR")
    check(any("mitreId" in detail for detail in res.data.details), "Details contain mitreId error")

    # Invalid mitreId (does not start with T)
    bad_req2 = CreateTechniqueRequest(
        mitreId="A1059", name="Test", tactic="EXECUTION", createdAt="2026-07-06T10:00:00Z"
    )
    res = create_technique(bad_req2)
    check_eq(res.success, False, "Create fails with non-T mitreId")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error code is VALIDATION_ERROR")

    # Invalid tactic enum
    bad_req3 = CreateTechniqueRequest(
        mitreId="T1059", name="Test", tactic="INVALID_TACTIC", createdAt="2026-07-06T10:00:00Z"
    )
    res = create_technique(bad_req3)
    check_eq(res.success, False, "Create fails with invalid tactic")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error code is VALIDATION_ERROR")

    # Successful creation
    valid_req = CreateTechniqueRequest(
        mitreId="T1059",
        name="Command and Scripting Interpreter",
        tactic="EXECUTION",
        description="Adversaries may abuse command and scripting interpreters.",
        platforms=["windows", "linux", "macos"],
        detection="Monitor process execution.",
        mitigations=["Restrict tool usage", "Use application control"],
        references=["https://attack.mitre.org/techniques/T1059/"],
        createdAt="2026-07-06T10:00:00Z",
        severity="HIGH",
        dataSource="Process creation",
    )
    res = create_technique(valid_req)
    check_eq(res.success, True, "Create succeeds with valid request")
    created_id = res.data["techniqueId"]
    check(created_id is not None, "Technique ID is generated")
    check_eq(res.data["mitreId"], "T1059", "mitreId is upper-cased and saved")
    check_eq(res.data["severity"], "HIGH", "Severity is set")
    check_eq(res.data["dataSource"], "Process creation", "DataSource is set")

    # Duplicate creation -> CONFLICT
    res_dup = create_technique(valid_req)
    check_eq(res_dup.success, False, "Duplicate create fails")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Duplicate yields CONFLICT error")

    # Retrieve technique
    res_get = get_technique(created_id)
    check_eq(res_get.success, True, "Retrieve by ID succeeds")
    check_eq(res_get.data["techniqueId"], created_id, "Correct ID returned")

    # Retrieve by mitreId (case-insensitive)
    res_get_mitre = get_technique("t1059")
    check_eq(res_get_mitre.success, True, "Retrieve by mitreId succeeds")
    check_eq(res_get_mitre.data["techniqueId"], created_id, "Correct ID returned")

    # Retrieve missing -> NOT_FOUND
    res_get_missing = get_technique("T9999")
    check_eq(res_get_missing.success, False, "Retrieve missing yields failure")
    check_eq(res_get_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Update technique - Validation fail (no fields)
    res_up_empty = update_technique(created_id, UpdateTechniqueRequest())
    check_eq(res_up_empty.success, False, "Empty update fails")
    check_eq(res_up_empty.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Update technique - Validation fail (invalid tactic)
    res_up_bad = update_technique(created_id, UpdateTechniqueRequest(tactic="BAD"))
    check_eq(res_up_bad.success, False, "Bad tactic update fails")

    # Successful update
    up_req = UpdateTechniqueRequest(
        name="Updated Scripting Interpreter",
        severity="CRITICAL",
        revoked=True,
    )
    res_up = update_technique(created_id, up_req)
    check_eq(res_up.success, True, "Valid update succeeds")
    check_eq(res_up.data["name"], "Updated Scripting Interpreter", "Name updated")
    check_eq(res_up.data["severity"], "CRITICAL", "Severity updated to CRITICAL")
    check_eq(res_up.data["revoked"], True, "Revoked updated to True")
    # Assert other fields did not change
    check_eq(res_up.data["createdAt"], "2026-07-06T10:00:00Z", "createdAt is immutable")
    check_eq(res_up.data["mitreId"], "T1059", "mitreId did not change")

    # Update missing -> NOT_FOUND
    res_up_missing = update_technique("T9999", up_req)
    check_eq(res_up_missing.success, False, "Update missing fails")
    check_eq(res_up_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Delete technique
    res_del = delete_technique(created_id)
    check_eq(res_del.success, True, "Delete succeeds")
    check_eq(len(_TECHNIQUE_STORE), 0, "Store is empty again")

    # Delete missing -> NOT_FOUND
    res_del_missing = delete_technique(created_id)
    check_eq(res_del_missing.success, False, "Delete missing fails")
    check_eq(res_del_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")


    # ---------------------------------------------------------------------------
    # Test 4: Generating Deterministic Dataset for Filtering, Sorting, Pagination
    # ---------------------------------------------------------------------------
    print("Generating deterministic test dataset of 100 items...")
    _reset_store()
    
    tactics = list(TacticEnum)
    
    # Create 100 items using bulk create
    bulk_req_items = []
    for i in range(1, 101):
        mitre_id = f"T1{i:03d}"
        tactic_enum = tactics[i % len(tactics)]
        
        platforms = []
        if i % 2 == 0: platforms.append("windows")
        if i % 3 == 0: platforms.append("linux")
        if i % 5 == 0: platforms.append("macos")
        if not platforms: platforms.append("containers")
        
        mitigations = [f"Mitigation {i}-1", f"Mitigation {i}-2"]
        references = [f"https://attack.mitre.org/techniques/T1{i:03d}"]
        
        # Severity cycle
        severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        severity = severities[i % len(severities)]
        
        bulk_req_items.append(
            CreateTechniqueRequest(
                mitreId=mitre_id,
                name=f"Technique Name {i}",
                tactic=tactic_enum.value,
                description=f"Thorough description of technique {i} with key terms.",
                platforms=platforms,
                detection=f"Detailed detection advice for technique {i}.",
                mitigations=mitigations,
                references=references,
                createdAt=f"2026-07-06T10:{i%60:02d}:00Z",
                severity=severity,
                dataSource=f"Data Source {i % 4}",
                revoked=(i % 10 == 0),
                deprecated=(i % 15 == 0),
            )
        )
        
    bulk_res = bulk_create_techniques(BulkCreateTechniquesRequest(techniques=bulk_req_items))
    check_eq(bulk_res.success, True, "Bulk create of 100 techniques succeeds")
    check_eq(bulk_res.data["successCount"], 100, "100 items created successfully")
    check_eq(bulk_res.data["failCount"], 0, "0 failures during bulk create")
    check_eq(len(_TECHNIQUE_STORE), 100, "100 items in store")

    # Keep a copy of the list of techniques for checking
    techs_list = _all_techniques()


    # ---------------------------------------------------------------------------
    # Test 5: Filtering Assertions (Target: ~600 assertions)
    # ---------------------------------------------------------------------------
    print("Testing filtering logic exhaustively...")
    
    # We will test all tactics
    for t_enum in tactics:
        # Expected count in our dataset
        expected_cnt = sum(1 for item in bulk_req_items if item.tactic == t_enum.value)
        
        # Filter through API
        api_res = list_techniques(tactic=t_enum.value, pageSize=200)
        check_eq(api_res.success, True, f"Filter by tactic {t_enum.value} succeeds")
        check_eq(len(api_res.data), expected_cnt, f"Correct count for tactic {t_enum.value}")
        
        # Verify fields in each returned item
        for item in api_res.data:
            check_eq(item["tactic"], t_enum.value, f"Tactic is {t_enum.value}")

    # Platform filtering
    for platform in ["windows", "linux", "macos", "containers"]:
        expected_cnt = sum(1 for item in bulk_req_items if platform in item.platforms)
        api_res = list_techniques(platform=platform, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Correct count for platform {platform}")
        for item in api_res.data:
            check(platform in item["platforms"], f"Item platforms contain {platform}")

    # Revoked & Deprecated filtering
    for r_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.revoked == r_val)
        api_res = list_techniques(revoked=r_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Correct count for revoked={r_val}")
        for item in api_res.data:
            check_eq(item["revoked"], r_val, f"Item revoked matches {r_val}")

    for d_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.deprecated == d_val)
        api_res = list_techniques(deprecated=d_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Correct count for deprecated={d_val}")
        for item in api_res.data:
            check_eq(item["deprecated"], d_val, f"Item deprecated matches {d_val}")

    # Substring detection & mitigation filtering
    api_res = list_techniques(detection="Detailed detection advice for technique 55", pageSize=200)
    check_eq(len(api_res.data), 1, "Filter by detection substring matches exactly 1")
    check_eq(api_res.data[0]["mitreId"], "T1055", "Found correct technique for detection filter")

    api_res = list_techniques(mitigation="Mitigation 44-1", pageSize=200)
    check_eq(len(api_res.data), 1, "Filter by mitigation substring matches exactly 1")
    check_eq(api_res.data[0]["mitreId"], "T1044", "Found correct technique for mitigation filter")

    # Data Source filtering
    for ds in ["Data Source 0", "Data Source 1", "Data Source 2", "Data Source 3"]:
        expected_cnt = sum(1 for item in bulk_req_items if item.dataSource == ds)
        api_res = list_techniques(dataSource=ds, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Correct count for dataSource={ds}")
        for item in api_res.data:
            check_eq(item["dataSource"], ds, f"Item dataSource matches {ds}")


    # ---------------------------------------------------------------------------
    # Test 6: Sorting Assertions (Target: ~600 assertions)
    # ---------------------------------------------------------------------------
    print("Testing sorting logic exhaustively...")
    
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    sort_fields = ["techniqueId", "techniqueName", "createdAt", "severity", "tacticCount"]
    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_techniques(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data
            
            # Assert correct order
            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]
                
                # Extract values
                if field == "techniqueId":
                    v_curr, v_next = item_curr["techniqueId"], item_next["techniqueId"]
                elif field == "techniqueName":
                    v_curr, v_next = item_curr["name"], item_next["name"]
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]
                elif field == "severity":
                    v_curr = severity_order.get(item_curr["severity"].lower(), -1)
                    v_next = severity_order.get(item_next["severity"].lower(), -1)
                elif field == "tacticCount":
                    v_curr, v_next = item_curr["tacticCount"], item_next["tacticCount"]
                
                # Check sort constraint
                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    # If equal, secondary sort must be techniqueId ASC
                    if v_curr == v_next:
                        check(item_curr["techniqueId"] <= item_next["techniqueId"], f"Secondary sort: {item_curr['techniqueId']} <= {item_next['techniqueId']}")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    # If equal, secondary sort must still be techniqueId ASC!
                    if v_curr == v_next:
                        check(item_curr["techniqueId"] <= item_next["techniqueId"], f"Secondary sort in DESC: {item_curr['techniqueId']} <= {item_next['techniqueId']}")


    # ---------------------------------------------------------------------------
    # Test 7: Pagination Assertions (Target: ~200 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")
    
    # Request different page sizes
    for p_size in [5, 10, 20, 25]:
        total_pages = math.ceil(100 / p_size)
        seen_ids = set()
        
        for p in range(1, total_pages + 1):
            api_res = list_techniques(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")
            
            # Check pagination metadata
            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 100, "Total items is 100")
            check_eq(pagination["totalPages"], total_pages, "Total pages is correct")
            
            # Check items
            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                tid = item["techniqueId"]
                check(tid not in seen_ids, f"Unique item {tid} on page {p}")
                seen_ids.add(tid)
                
        check_eq(len(seen_ids), 100, f"All 100 items covered in page size {p_size}")

    # Out of bounds page size or page
    # Page too high -> empty data, but valid pagination envelope
    api_res = list_techniques(page=6, pageSize=20)
    check_eq(api_res.success, True, "Out of bounds page succeeds")
    check_eq(len(api_res.data), 0, "No items returned")
    
    # Negative / zero pagination validation failure
    res_bad_page = list_techniques(page=0)
    check_eq(res_bad_page.success, False, "Page=0 fails validation")
    check_eq(res_bad_page.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")
    
    res_bad_size = list_techniques(pageSize=0)
    check_eq(res_bad_size.success, False, "pageSize=0 fails validation")


    # ---------------------------------------------------------------------------
    # Test 8: Search Assertions
    # ---------------------------------------------------------------------------
    print("Testing search logic...")
    
    # Query matching multiple items
    search_res = search_mitre_techniques(query="key terms")
    check_eq(search_res.success, True, "Search succeeds")
    # All 100 items have "key terms" in description
    check_eq(search_res.data["total"], 100, "All 100 match substring")
    check_eq(len(search_res.data["techniques"]), 50, "Default page size is 50")
    
    # Pagination in search
    search_res_p2 = search_mitre_techniques(query="key terms", page=2, pageSize=60)
    check_eq(len(search_res_p2.data["techniques"]), 40, "Correct page 2 slice size")
    check_eq(search_res_p2.data["totalPages"], 2, "Correct search total pages")

    # Specific query matching exactly 1
    search_res_1 = search_mitre_techniques(query="Technique Name 87")
    check_eq(search_res_1.data["total"], 1, "Exactly one matches specific name")
    check_eq(search_res_1.data["techniques"][0]["mitreId"], "T1087", "Correct technique found")

    # Search case-insensitivity
    search_res_case = search_mitre_techniques(query="tEchNiquE nAmE 87")
    check_eq(search_res_case.data["total"], 1, "Search is case-insensitive")


    # ---------------------------------------------------------------------------
    # Test 9: Tactics Lookups (100 items * ~4 assertions = 400 assertions)
    # ---------------------------------------------------------------------------
    print("Testing tactics lookups...")
    for idx, t in enumerate(techs_list):
        res_t = get_technique_tactics(t["techniqueId"])
        check_eq(res_t.success, True, "Tactic lookup succeeds")
        check_eq(len(res_t.data), 1, "Returns exactly 1 tactic response")
        
        tactic_resp = res_t.data[0]
        check_eq(tactic_resp["tactic"], t["tactic"], "Tactic value matches technique tactic")
        # Registry mapping checks
        expected_tactic_info = _TACTIC_INFO.get(t["tactic"])
        if expected_tactic_info:
            check_eq(tactic_resp["name"], expected_tactic_info["name"], "Tactic name matches registry")
            check_eq(tactic_resp["description"], expected_tactic_info["description"], "Description matches registry")
            check_eq(tactic_resp["order"], expected_tactic_info["order"], "Order matches registry")


    # ---------------------------------------------------------------------------
    # Test 10: Mitigations Lookups (100 items * ~3 assertions = 300 assertions)
    # ---------------------------------------------------------------------------
    print("Testing mitigations lookups...")
    for idx, t in enumerate(techs_list):
        res_m = get_technique_mitigations(t["techniqueId"])
        check_eq(res_m.success, True, "Mitigation lookup succeeds")
        
        mitigations = t["mitigations"]
        check_eq(len(res_m.data), len(mitigations), "Number of returned mitigations matches technique")
        
        for m_resp, m_orig in zip(res_m.data, mitigations):
            check_eq(m_resp["mitigation"], m_orig, "Mitigation text matches")
            expected_id = f"mit-{hashlib.sha256(m_orig.strip().encode('utf-8')).hexdigest()[:16]}"
            check_eq(m_resp["mitigationId"], expected_id, "Mitigation ID is deterministic and correct")


    # ---------------------------------------------------------------------------
    # Test 11: Summary Lookups (100 items * ~5 assertions = 500 assertions)
    # ---------------------------------------------------------------------------
    print("Testing technique summaries...")
    for idx, t in enumerate(techs_list):
        res_s = get_technique_summary(t["techniqueId"])
        check_eq(res_s.success, True, "Summary lookup succeeds")
        
        summary_data = res_s.data
        check_eq(summary_data["mitreId"], t["mitreId"], "mitreId matches")
        check_eq(summary_data["name"], t["name"], "name matches")
        check_eq(summary_data["tactic"], t["tactic"], "tactic matches")
        
        expected_platforms_str = ", ".join(t["platforms"])
        expected_text = (
            f"MITRE ATT&CK Technique {t['mitreId']} ({t['name']}) "
            f"belongs to tactic {t['tactic']}. Applicable platforms: {expected_platforms_str}. "
            f"It has {len(t['mitigations'])} documented mitigations."
        )
        check_eq(summary_data["summaryText"], expected_text, "Summary text matches precisely")


    # ---------------------------------------------------------------------------
    # Test 12: Statistics Retrieval & Calculations
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_statistics()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data
    
    # Assert statistical counts
    check_eq(stats["totalTechniques"], 100, "Total techniques is 100")
    check_eq(stats["revokedTechniques"], 10, "10 techniques are revoked (index divisible by 10)")
    check_eq(stats["deprecatedTechniques"], 6, "6 techniques are deprecated (index divisible by 15)")
    check_eq(stats["averageTactics"], 1.0, "Average tactics per technique is 1.0")
    
    # Tactic counts check
    expected_tactic_counts = {}
    for item in bulk_req_items:
        t = item.tactic
        expected_tactic_counts[t] = expected_tactic_counts.get(t, 0) + 1
    check_eq(stats["tacticCounts"], dict(sorted(expected_tactic_counts.items())), "Tactic counts match expected")

    # Platform counts check
    expected_platform_counts = {}
    for item in bulk_req_items:
        for p in item.platforms:
            expected_platform_counts[p] = expected_platform_counts.get(p, 0) + 1
    check_eq(stats["platformCounts"], dict(sorted(expected_platform_counts.items())), "Platform counts match expected")


    # ---------------------------------------------------------------------------
    # Test 13: Bulk Update & Bulk Delete Operations
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")
    
    # Bulk update: modify severity and descriptions of all even techniques
    bulk_up_items = []
    updated_ids = []
    for idx, t in enumerate(techs_list):
        if idx % 2 == 0:
            tech_id = t["techniqueId"]
            updated_ids.append(tech_id)
            bulk_up_items.append(
                BulkUpdateTechniquesRequest.BulkUpdateItem(
                    techniqueId=tech_id,
                    update=UpdateTechniqueRequest(
                        description=f"Bulk updated description {idx}.",
                        severity="CRITICAL",
                    )
                )
            )
            
    bulk_up_res = bulk_update_techniques(BulkUpdateTechniquesRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")
    
    # Verify updates in store
    for tech_id in updated_ids:
        t_stored = _TECHNIQUE_STORE[tech_id]
        check(t_stored["description"].startswith("Bulk updated description"), "Description is updated")
        check_eq(t_stored["severity"], "CRITICAL", "Severity is CRITICAL")

    # Bulk delete: delete the odd indexed techniques
    bulk_del_ids = []
    for idx, t in enumerate(techs_list):
        if idx % 2 != 0:
            bulk_del_ids.append(t["techniqueId"])
            
    bulk_del_res = bulk_delete_techniques(BulkDeleteTechniquesRequest(techniqueIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_TECHNIQUE_STORE), 50, "50 items remaining in store")

    # Clean up the rest
    remaining_ids = list(_TECHNIQUE_STORE.keys())
    cleanup_res = bulk_delete_techniques(BulkDeleteTechniquesRequest(techniqueIds=remaining_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_TECHNIQUE_STORE), 0, "Store is completely empty")


    # ---------------------------------------------------------------------------
    # Test 14: Serialization / Roundtrip Checks
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    
    sample_item = CreateTechniqueRequest(
        mitreId="T1001",
        name="Data Obfuscation",
        tactic="COMMAND_AND_CONTROL",
        createdAt="2026-07-06T12:00:00Z",
    )
    
    # Model dump
    dumped = sample_item.model_dump()
    check_eq(dumped["mitreId"], "T1001", "Model dumps properly")
    
    # Model serialization to JSON
    json_str = sample_item.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["mitreId"], "T1001", "JSON serialization is correct")
    
    # Deserialization check
    deserialized = CreateTechniqueRequest(**parsed)
    check_eq(deserialized.mitreId, "T1001", "Deserialization roundtrip matches")

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
