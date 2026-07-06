"""
Smoke Test for Threat Intelligence API — Phase A4.9.4
=====================================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ Relationships and campaigns lookups
  ✓ Threat summary generation
  ✓ Statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 6000+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
import hashlib
from typing import Any, List, Dict

# Import API components
from api.knowledge.threat_router import (
    threat_router,
    _reset_store,
    _all_threats,
    _THREAT_STORE,
    _CAMPAIGN_STORE,
    list_threats,
    get_statistics,
    search_threat_records,
    get_threat,
    create_threat,
    update_threat,
    delete_threat,
    get_relationships,
    get_campaigns,
    get_threat_summary_route,
    bulk_create_threats,
    bulk_update_threats,
    bulk_delete_threats,
    # Utilities
    find_threat,
    search_threats,
    sort_threats,
    filter_threats,
    paginate_threats,
    build_threat_summary,
    calculate_threat_statistics,
)
from api.knowledge.threat_models import (
    CreateThreatRequest,
    UpdateThreatRequest,
    ThreatResponse,
    ThreatListResponse,
    ThreatStatisticsResponse,
    ThreatSearchResponse,
    ThreatRelationshipResponse,
    ThreatCampaignResponse,
    BulkCreateThreatsRequest,
    BulkUpdateThreatsRequest,
    BulkDeleteThreatsRequest,
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
    print("Starting Threat Intelligence API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Metadata Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/knowledge/threat"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/knowledge/threat",
        "/api/v2/knowledge/threat/",
        "/api/v2/knowledge/threat/statistics",
        "/api/v2/knowledge/threat/search",
        "/api/v2/knowledge/threat/bulk/create",
        "/api/v2/knowledge/threat/bulk/update",
        "/api/v2/knowledge/threat/bulk/delete",
        "/api/v2/knowledge/threat/{threatId}",
        "/api/v2/knowledge/threat/{threatId}/relationships",
        "/api/v2/knowledge/threat/{threatId}/campaigns",
        "/api/v2/knowledge/threat/{threatId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Store Initialization Check
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_THREAT_STORE), 0, "Threat store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Basic CRUD Operations & Validation (Single items)
    # ---------------------------------------------------------------------------
    print("Testing CRUD operations & validation...")

    # Empty threatName
    bad_req1 = CreateThreatRequest(
        threatName="", confidence="HIGH", severity="HIGH", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_threat(bad_req1)
    check_eq(res.success, False, "Create fails with empty threatName")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad confidence member
    bad_req2 = CreateThreatRequest(
        threatName="APT99", confidence="BAD_CONF", severity="HIGH", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_threat(bad_req2)
    check_eq(res.success, False, "Create fails with bad confidence")

    # Bad severity member
    bad_req3 = CreateThreatRequest(
        threatName="APT99", confidence="HIGH", severity="UNKNOWN", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_threat(bad_req3)
    check_eq(res.success, False, "Create fails with bad severity")

    # Successful creation
    valid_req = CreateThreatRequest(
        threatName="APT29",
        aliases=["Cozy Bear", "Nobelium"],
        description="Russian state-sponsored threat group.",
        country="RU",
        motivation="Espionage",
        confidence="HIGH",
        severity="HIGH",
        active=True,
        malware=["Cobalt Strike", "WellMess"],
        industry=["Government", "Think Tanks"],
        relatedTechniques=["T1059", "T1071"],
        relatedCVEs=["CVE-2021-44228"],
        relatedIOCs=["1.1.1.1"],
        createdAt="2026-07-06T12:00:00Z",
    )
    res = create_threat(valid_req)
    check_eq(res.success, True, "Create succeeds with valid request")
    created_id = res.data["threatId"]
    check(created_id is not None, "Threat ID is generated")
    check_eq(res.data["threatName"], "APT29", "name saved correctly")
    check_eq(res.data["country"], "RU", "country is RU")
    check_eq(res.data["active"], True, "active is True")

    # Duplicate creation -> CONFLICT
    res_dup = create_threat(valid_req)
    check_eq(res_dup.success, False, "Duplicate create fails")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Duplicate yields CONFLICT")

    # Retrieve
    res_get = get_threat(created_id)
    check_eq(res_get.success, True, "Retrieve by ID succeeds")
    check_eq(res_get.data["threatId"], created_id, "Correct threatId returned")

    # Retrieve by name (case-insensitive)
    res_get_name = get_threat("apt29")
    check_eq(res_get_name.success, True, "Retrieve by name succeeds")

    # Retrieve missing -> NOT_FOUND
    res_get_missing = get_threat("nonexistent_id")
    check_eq(res_get_missing.success, False, "Retrieve missing fails")
    check_eq(res_get_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Update - Validation fail (no fields)
    res_up_empty = update_threat(created_id, UpdateThreatRequest())
    check_eq(res_up_empty.success, False, "Empty update fails")
    check_eq(res_up_empty.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Successful update
    up_req = UpdateThreatRequest(
        description="Updated description of Cozy Bear.",
        confidence="VERIFIED",
        severity="CRITICAL",
        active=False,
    )
    res_up = update_threat(created_id, up_req)
    check_eq(res_up.success, True, "Valid update succeeds")
    check_eq(res_up.data["description"], "Updated description of Cozy Bear.", "Description updated")
    check_eq(res_up.data["confidence"], "VERIFIED", "confidence updated to VERIFIED")
    check_eq(res_up.data["severity"], "CRITICAL", "severity updated to CRITICAL")
    check_eq(res_up.data["active"], False, "active updated to False")

    # Update missing -> NOT_FOUND
    res_up_missing = update_threat("nonexistent_id", up_req)
    check_eq(res_up_missing.success, False, "Update missing fails")
    check_eq(res_up_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Delete
    res_del = delete_threat(created_id)
    check_eq(res_del.success, True, "Delete succeeds")
    check_eq(len(_THREAT_STORE), 0, "Store is empty again")

    # Delete missing -> NOT_FOUND
    res_del_missing = delete_threat(created_id)
    check_eq(res_del_missing.success, False, "Delete missing fails")
    check_eq(res_del_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")


    # ---------------------------------------------------------------------------
    # Test 4: Generating Deterministic Dataset for Filtering, Sorting, Pagination
    # ---------------------------------------------------------------------------
    print("Generating deterministic Threat test dataset of 160 items...")
    _reset_store()

    countries = ["US", "RU", "CN", "IR", "KP", "VN"]
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidences = ["LOW", "MEDIUM", "HIGH", "VERIFIED"]

    bulk_req_items = []
    for i in range(1, 161):
        name = f"Threat-Actor-{100 + i}"
        sev = severities[i % len(severities)]
        conf = confidences[i % len(confidences)]
        country = countries[i % len(countries)]
        motivation = f"motivation-{i % 3}"

        bulk_req_items.append(
            CreateThreatRequest(
                threatName=name,
                aliases=[f"Alias-{i}"],
                description=f"Detailed description of threat actor {i}.",
                country=country,
                motivation=motivation,
                confidence=conf,
                severity=sev,
                active=(i % 5 != 0),
                malware=[f"malware-{i % 5}"],
                industry=[f"industry-{i % 4}"],
                relatedTechniques=[f"T100{i % 10}"],
                relatedCVEs=[f"CVE-2026-{2000 + i}"],
                relatedIOCs=[f"10.0.0.{i}"],
                createdAt=f"2026-07-06T12:{i % 60:02d}:00Z",
                updatedAt=f"2026-07-06T13:{i % 60:02d}:00Z",
            )
        )

    bulk_res = bulk_create_threats(BulkCreateThreatsRequest(threats=bulk_req_items))
    check_eq(bulk_res.success, True, "Bulk create succeeds")
    check_eq(bulk_res.data["successCount"], 160, "160 Threats created successfully")
    check_eq(bulk_res.data["failCount"], 0, "0 failures in bulk create")
    check_eq(len(_THREAT_STORE), 160, "160 items in threat store")

    threats_list = _all_threats()

    # Populate campaign store for relationships/campaigns tests
    # Let's map campaigns to actors. A campaign can be linked to threat actor IDs.
    for i in range(1, 10):
        camp_id = f"campaign_id_{i}"
        # link to threat actors: Cozy Bear, Nobelium, and indices i, i+10
        linked_actors = [threats_list[i]["threatId"], threats_list[i + 10]["threatId"]]
        _CAMPAIGN_STORE[camp_id] = {
            "campaignId": camp_id,
            "campaignKey": f"key_{i}",
            "name": f"Operation-Campaign-{i}",
            "description": f"Campaign description {i}",
            "startDate": "2026-01-01",
            "endDate": "2026-06-01",
            "threatActors": linked_actors,
            "relatedTechniques": ["T1059"],
            "relatedCVEs": ["CVE-2021-44228"],
            "relatedIOCs": ["1.1.1.1"],
            "confidence": "HIGH",
            "createdAt": "2026-07-06T12:00:00Z",
        }


    # ---------------------------------------------------------------------------
    # Test 5: Filtering Assertions (Target: ~2400 assertions)
    # ---------------------------------------------------------------------------
    print("Testing filtering logic exhaustively...")

    # 1. Motivation/Actor filter
    for i in range(1, 6):
        actor_name = f"Threat-Actor-{100 + i}"
        api_res = list_threats(actor=actor_name, pageSize=200)
        check_eq(len(api_res.data), 1, "Exactly one matches actor query")

    # 2. Country filter
    for ctry in countries:
        expected_cnt = sum(1 for item in bulk_req_items if item.country == ctry)
        api_res = list_threats(country=ctry, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for country {ctry}")
        for item in api_res.data:
            check_eq(item["country"], ctry, "Country matches")

    # 3. Confidence filter
    for conf in confidences:
        expected_cnt = sum(1 for item in bulk_req_items if item.confidence == conf)
        api_res = list_threats(confidence=conf, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for confidence {conf}")
        for item in api_res.data:
            check_eq(item["confidence"], conf, "Confidence matches")

    # 4. Severity filter
    for sev in severities:
        expected_cnt = sum(1 for item in bulk_req_items if item.severity == sev)
        api_res = list_threats(severity=sev, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for severity {sev}")
        for item in api_res.data:
            check_eq(item["severity"], sev, "Severity matches")

    # 5. Active filter
    for act_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.active == act_val)
        api_res = list_threats(active=act_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for active={act_val}")
        for item in api_res.data:
            check_eq(item["active"], act_val, "Active matches")

    # 6. Malware filter
    for mal_idx in range(5):
        mal_name = f"malware-{mal_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if mal_name in item.malware)
        api_res = list_threats(malware=mal_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for malware {mal_name}")
        for item in api_res.data:
            check(mal_name in item["malware"], "Malware present")

    # 7. Industry filter
    for ind_idx in range(4):
        ind_name = f"industry-{ind_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if ind_name in item.industry)
        api_res = list_threats(industry=ind_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for industry {ind_name}")
        for item in api_res.data:
            check(ind_name in item["industry"], "Industry present")

    # 8. Confidence Range filter
    conf_weight = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "VERIFIED": 100.0}
    conf_ranges = [(0.0, 50.0), (50.0, 80.0), (75.0, 100.0)]
    for min_c, max_c in conf_ranges:
        expected_cnt = sum(1 for item in bulk_req_items if min_c <= conf_weight.get(item.confidence) <= max_c)
        api_res = list_threats(minimumConfidence=min_c, maximumConfidence=max_c, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for confidence weight [{min_c}, {max_c}]")
        for item in api_res.data:
            weight = conf_weight.get(item["confidence"])
            check(min_c <= weight <= max_c, f"Weight {weight} is in range")


    # ---------------------------------------------------------------------------
    # Test 6: Sorting Assertions (Target: ~1200 assertions)
    # ---------------------------------------------------------------------------
    print("Testing sorting logic exhaustively...")

    confidence_order = {"low": 1, "medium": 2, "high": 3, "verified": 4}
    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    sort_fields = ["threatName", "confidence", "severity", "createdAt", "updatedAt"]

    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_threats(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data

            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]

                if field == "threatName":
                    v_curr, v_next = item_curr["threatName"], item_next["threatName"]
                elif field == "confidence":
                    v_curr = confidence_order.get(item_curr["confidence"].lower(), -1)
                    v_next = confidence_order.get(item_next["confidence"].lower(), -1)
                elif field == "severity":
                    v_curr = severity_order.get(item_curr["severity"].lower(), -1)
                    v_next = severity_order.get(item_next["severity"].lower(), -1)
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]
                elif field == "updatedAt":
                    v_curr = item_curr["updatedAt"] or ""
                    v_next = item_next["updatedAt"] or ""

                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["threatId"] <= item_next["threatId"], f"Secondary sort: {item_curr['threatId']} <= {item_next['threatId']}")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["threatId"] <= item_next["threatId"], f"Secondary sort in DESC: {item_curr['threatId']} <= {item_next['threatId']}")


    # ---------------------------------------------------------------------------
    # Test 7: Pagination Assertions (Target: ~400 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")

    for p_size in [5, 10, 20, 32]:
        total_pages = math.ceil(160 / p_size)
        seen_ids = set()

        for p in range(1, total_pages + 1):
            api_res = list_threats(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")

            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 160, "Total items is 160")
            check_eq(pagination["totalPages"], total_pages, "Total pages matches")

            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                tid = item["threatId"]
                check(tid not in seen_ids, f"Unique item {tid} on page {p}")
                seen_ids.add(tid)

        check_eq(len(seen_ids), 160, f"All 160 items covered in page size {p_size}")


    # ---------------------------------------------------------------------------
    # Test 8: Search Assertions
    # ---------------------------------------------------------------------------
    print("Testing search logic...")

    search_res = search_threat_records(query="Detailed")
    check_eq(search_res.success, True, "Search succeeds")
    check_eq(search_res.data["total"], 160, "All 160 match query")
    check_eq(len(search_res.data["threats"]), 50, "Default page size is 50")

    search_res_1 = search_threat_records(query="Threat-Actor-177")
    check_eq(search_res_1.data["total"], 1, "Exactly one matches specific actorName")


    # ---------------------------------------------------------------------------
    # Test 9: Relationships and Campaigns lookups (120 items * ~6 assertions = 720 assertions)
    # ---------------------------------------------------------------------------
    print("Testing Relationships and Campaigns lookups...")
    for c in threats_list:
        # Relationships lookup
        rel_res = get_relationships(c["threatId"])
        check_eq(rel_res.success, True, "Relationships lookup succeeds")
        check(len(rel_res.data) >= 3, "Returns at least CVE, Technique, and IOC relationships")
        for rel in rel_res.data:
            check_eq(rel["sourceThreatId"], c["threatId"], "Source ID matches")

        # Campaigns lookup
        camp_res = get_campaigns(c["threatId"])
        check_eq(camp_res.success, True, "Campaigns lookup succeeds")
        for camp in camp_res.data:
            check(c["threatId"] in camp["threatActors"], "Actor ID present in campaign threatActors list")


    # ---------------------------------------------------------------------------
    # Test 10: Threat Summary lookup (120 items * ~4 assertions = 480 assertions)
    # ---------------------------------------------------------------------------
    print("Testing Threat summary lookup...")
    for c in threats_list:
        sum_res = get_threat_summary_route(c["threatId"])
        check_eq(sum_res.success, True, "Summary lookup succeeds")
        check_eq(sum_res.data["threatId"], c["threatId"], "Summary threatId matches")
        check_eq(sum_res.data["threatName"], c["name"], "Summary name matches")


    # ---------------------------------------------------------------------------
    # Test 11: Statistics Calculation
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_statistics()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data

    check_eq(stats["totalThreats"], 160, "Total threats is 160")
    check_eq(stats["activeThreats"], 128, "128 Threats are active (i % 5 != 0)")
    check_eq(stats["averageConfidence"], 62.5, "Average confidence is 62.5")
    check_eq(stats["averageSeverity"], 2.5, "Average severity is 2.5")


    # ---------------------------------------------------------------------------
    # Test 12: Bulk Update & Bulk Delete
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")

    # Bulk update description for even indexes
    bulk_up_items = []
    updated_ids = []
    for idx, c in enumerate(threats_list):
        if idx % 2 == 0:
            bulk_up_items.append(
                BulkUpdateThreatsRequest.BulkUpdateItem(
                    threatId=c["threatId"],
                    update=UpdateThreatRequest(
                        description=f"Bulk updated threat description {idx}.",
                        confidence="VERIFIED",
                        severity="CRITICAL",
                    )
                )
            )
            updated_ids.append(c["threatId"])

    bulk_up_res = bulk_update_threats(BulkUpdateThreatsRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")

    # Verify updates in store
    for rec_id in updated_ids:
        c_stored = _THREAT_STORE[rec_id]
        check(c_stored["description"].startswith("Bulk updated threat description"), "Description is updated")
        check_eq(c_stored["confidence"], "VERIFIED", "Confidence is VERIFIED")
        check_eq(c_stored["severity"], "CRITICAL", "Severity is CRITICAL")

    # Bulk delete odd indexes
    bulk_del_ids = []
    for idx, c in enumerate(threats_list):
        if idx % 2 != 0:
            bulk_del_ids.append(c["threatId"])

    bulk_del_res = bulk_delete_threats(BulkDeleteThreatsRequest(threatIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_THREAT_STORE), 80, "80 items remaining in store")

    # Clean up remaining
    remaining_ids = [c["threatId"] for c in _THREAT_STORE.values()]
    cleanup_res = bulk_delete_threats(BulkDeleteThreatsRequest(threatIds=remaining_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_THREAT_STORE), 0, "Store is completely empty")


    # ---------------------------------------------------------------------------
    # Test 13: Serialization & Deserialization
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    sample_threat = CreateThreatRequest(
        threatName="APT29",
        confidence="HIGH",
        severity="HIGH",
        createdAt="2026-07-06T12:00:00Z",
    )

    dumped = sample_threat.model_dump()
    check_eq(dumped["threatName"], "APT29", "Model dumps properly")

    json_str = sample_threat.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["threatName"], "APT29", "JSON serialization is correct")

    deserialized = CreateThreatRequest(**parsed)
    check_eq(deserialized.threatName, "APT29", "Deserialization roundtrip matches")

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
