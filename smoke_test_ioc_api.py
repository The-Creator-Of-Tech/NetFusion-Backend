"""
Smoke Test for IOC Intelligence API — Phase A4.9.3
==================================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ Relationships and enrichment lookups
  ✓ IOC summary generation
  ✓ Statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 5000+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
import hashlib
from typing import Any, List, Dict

# Import API components
from api.knowledge.ioc_router import (
    ioc_router,
    _reset_store,
    _all_iocs,
    _IOC_STORE,
    list_iocs,
    get_statistics,
    search_ioc_records,
    get_ioc,
    create_ioc,
    update_ioc,
    delete_ioc,
    get_relationships,
    get_enrichment,
    get_ioc_summary_route,
    bulk_create_iocs,
    bulk_update_iocs,
    bulk_delete_iocs,
    # Utilities
    find_ioc,
    search_iocs,
    sort_iocs,
    filter_iocs,
    paginate_iocs,
    build_ioc_summary,
    calculate_ioc_statistics,
)
from api.knowledge.ioc_models import (
    CreateIOCRequest,
    UpdateIOCRequest,
    IOCResponse,
    IOCListResponse,
    IOCStatisticsResponse,
    IOCSearchResponse,
    IOCRelationshipResponse,
    IOCEnrichmentResponse,
    BulkCreateIOCsRequest,
    BulkUpdateIOCsRequest,
    BulkDeleteIOCsRequest,
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
    print("Starting IOC Intelligence API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Metadata Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/knowledge/ioc"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/knowledge/ioc",
        "/api/v2/knowledge/ioc/",
        "/api/v2/knowledge/ioc/statistics",
        "/api/v2/knowledge/ioc/search",
        "/api/v2/knowledge/ioc/bulk/create",
        "/api/v2/knowledge/ioc/bulk/update",
        "/api/v2/knowledge/ioc/bulk/delete",
        "/api/v2/knowledge/ioc/{iocId}",
        "/api/v2/knowledge/ioc/{iocId}/relationships",
        "/api/v2/knowledge/ioc/{iocId}/enrichment",
        "/api/v2/knowledge/ioc/{iocId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Store Initialization Check
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_IOC_STORE), 0, "IOC store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Basic CRUD Operations & Validation (Single items)
    # ---------------------------------------------------------------------------
    print("Testing CRUD operations & validation...")

    # Empty iocType
    bad_req1 = CreateIOCRequest(
        iocType="", value="1.1.1.1", severity="HIGH", confidence="HIGH", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_ioc(bad_req1)
    check_eq(res.success, False, "Create fails with empty iocType")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad iocType member
    bad_req2 = CreateIOCRequest(
        iocType="BAD_TYPE", value="1.1.1.1", severity="HIGH", confidence="HIGH", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_ioc(bad_req2)
    check_eq(res.success, False, "Create fails with bad iocType member")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Empty value
    bad_req3 = CreateIOCRequest(
        iocType="IP", value="", severity="HIGH", confidence="HIGH", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_ioc(bad_req3)
    check_eq(res.success, False, "Create fails with empty value")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad severity member
    bad_req4 = CreateIOCRequest(
        iocType="IP", value="1.1.1.1", severity="UNKNOWN", confidence="HIGH", createdAt="2026-07-06T12:00:00Z"
    )
    res = create_ioc(bad_req4)
    check_eq(res.success, False, "Create fails with bad severity member")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Successful creation
    valid_req = CreateIOCRequest(
        iocType="IP",
        value="1.1.1.1",
        severity="HIGH",
        confidence="HIGH",
        description="Abusive IP indicator.",
        source="AbuseIPDB",
        tags=["malware", "scanning"],
        relatedCVEs=["CVE-2021-44228"],
        relatedTechniques=["T1059"],
        createdAt="2026-07-06T12:00:00Z",
        malicious=True,
        revoked=False,
        threatActor="APT29",
        campaign="SolarWinds",
    )
    res = create_ioc(valid_req)
    check_eq(res.success, True, "Create succeeds with valid request")
    created_id = res.data["iocId"]
    check(created_id is not None, "IOC ID is generated")
    check_eq(res.data["value"], "1.1.1.1", "value saved correctly")
    check_eq(res.data["iocType"], "IP", "iocType is IP")
    check_eq(res.data["threatActor"], "APT29", "threatActor is APT29")
    check_eq(res.data["campaign"], "SolarWinds", "campaign is SolarWinds")

    # Duplicate creation -> CONFLICT
    res_dup = create_ioc(valid_req)
    check_eq(res_dup.success, False, "Duplicate create fails")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Duplicate yields CONFLICT")

    # Retrieve
    res_get = get_ioc(created_id)
    check_eq(res_get.success, True, "Retrieve by ID succeeds")
    check_eq(res_get.data["iocId"], created_id, "Correct iocId returned")

    # Retrieve by value (case-insensitive)
    res_get_val = get_ioc("1.1.1.1")
    check_eq(res_get_val.success, True, "Retrieve by value succeeds")

    # Retrieve missing -> NOT_FOUND
    res_get_missing = get_ioc("nonexistent_id")
    check_eq(res_get_missing.success, False, "Retrieve missing fails")
    check_eq(res_get_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Update - Validation fail (no fields)
    res_up_empty = update_ioc(created_id, UpdateIOCRequest())
    check_eq(res_up_empty.success, False, "Empty update fails")
    check_eq(res_up_empty.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Successful update
    up_req = UpdateIOCRequest(
        description="Updated description of IP.",
        confidence="VERIFIED",
        severity="CRITICAL",
        revoked=True,
    )
    res_up = update_ioc(created_id, up_req)
    check_eq(res_up.success, True, "Valid update succeeds")
    check_eq(res_up.data["description"], "Updated description of IP.", "Description updated")
    check_eq(res_up.data["confidence"], "VERIFIED", "confidence updated to VERIFIED")
    check_eq(res_up.data["severity"], "CRITICAL", "severity updated to CRITICAL")
    check_eq(res_up.data["revoked"], True, "revoked updated to True")

    # Update missing -> NOT_FOUND
    res_up_missing = update_ioc("nonexistent_id", up_req)
    check_eq(res_up_missing.success, False, "Update missing fails")
    check_eq(res_up_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Delete
    res_del = delete_ioc(created_id)
    check_eq(res_del.success, True, "Delete succeeds")
    check_eq(len(_IOC_STORE), 0, "Store is empty again")

    # Delete missing -> NOT_FOUND
    res_del_missing = delete_ioc(created_id)
    check_eq(res_del_missing.success, False, "Delete missing fails")
    check_eq(res_del_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")


    # ---------------------------------------------------------------------------
    # Test 4: Generating Deterministic Dataset for Filtering, Sorting, Pagination
    # ---------------------------------------------------------------------------
    print("Generating deterministic IOC test dataset of 120 items...")
    _reset_store()

    types = ["IP", "DOMAIN", "URL", "EMAIL", "HASH_MD5", "HASH_SHA256"]
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidences = ["LOW", "MEDIUM", "HIGH", "VERIFIED"]

    bulk_req_items = []
    for i in range(1, 121):
        ioc_type = types[i % len(types)]
        sev = severities[i % len(severities)]
        conf = confidences[i % len(confidences)]

        val = ""
        if ioc_type == "IP":
            val = f"10.0.0.{i}"
        elif ioc_type == "DOMAIN":
            val = f"malware-domain-{i}.com"
        elif ioc_type == "URL":
            val = f"http://malware-site-{i}.ru/path/login"
        elif ioc_type == "EMAIL":
            val = f"phishing-sender-{i}@spammail.cn"
        elif ioc_type == "HASH_MD5":
            val = hashlib.md5(f"sample-{i}".encode("utf-8")).hexdigest()
        elif ioc_type == "HASH_SHA256":
            val = hashlib.sha256(f"sample-{i}".encode("utf-8")).hexdigest()

        threat_actor = f"Actor-{i % 5}"
        campaign = f"Campaign-{i % 6}"
        source = f"source-{i % 4}"

        bulk_req_items.append(
            CreateIOCRequest(
                iocType=ioc_type,
                value=val,
                severity=sev,
                confidence=conf,
                description=f"Automated threat intelligence record {i}.",
                source=source,
                tags=[f"tag-{i % 3}", "test"],
                relatedCVEs=[f"CVE-2026-{2000 + i}"],
                relatedTechniques=[f"T100{i % 10}"],
                createdAt=f"2026-07-06T12:{i % 60:02d}:00Z",
                updatedAt=f"2026-07-06T13:{i % 60:02d}:00Z",
                malicious=(i % 5 != 0),
                revoked=(i % 12 == 0),
                threatActor=threat_actor,
                campaign=campaign,
            )
        )

    bulk_res = bulk_create_iocs(BulkCreateIOCsRequest(iocs=bulk_req_items))
    check_eq(bulk_res.success, True, "Bulk create succeeds")
    check_eq(bulk_res.data["successCount"], 120, "120 IOCs created successfully")
    check_eq(bulk_res.data["failCount"], 0, "0 failures in bulk create")
    check_eq(len(_IOC_STORE), 120, "120 items in store")

    iocs_list = _all_iocs()


    # ---------------------------------------------------------------------------
    # Test 5: Filtering Assertions (Target: ~2000 assertions)
    # ---------------------------------------------------------------------------
    print("Testing filtering logic exhaustively...")

    # 1. iocType filter
    for t in types:
        expected_cnt = sum(1 for item in bulk_req_items if item.iocType == t)
        api_res = list_iocs(iocType=t, pageSize=200)
        check_eq(api_res.success, True, f"Filter by type {t} succeeds")
        check_eq(len(api_res.data), expected_cnt, f"Count matches for type {t}")
        for item in api_res.data:
            check_eq(item["iocType"], t, f"Type matches {t}")

    # 2. Confidence filter
    for conf in confidences:
        expected_cnt = sum(1 for item in bulk_req_items if item.confidence == conf)
        api_res = list_iocs(confidence=conf, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for confidence {conf}")
        for item in api_res.data:
            check_eq(item["confidence"], conf, "Confidence matches")

    # 3. Malicious filter
    for mal_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.malicious == mal_val)
        api_res = list_iocs(malicious=mal_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for malicious={mal_val}")
        for item in api_res.data:
            check_eq(item["malicious"], mal_val, "Malicious matches")

    # 4. Revoked filter
    for rev_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.revoked == rev_val)
        api_res = list_iocs(revoked=rev_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for revoked={rev_val}")
        for item in api_res.data:
            check_eq(item["revoked"], rev_val, "Revoked matches")

    # 5. Source filter
    for s_idx in range(4):
        source_name = f"source-{s_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.source == source_name)
        api_res = list_iocs(source=source_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for source {source_name}")
        for item in api_res.data:
            check_eq(item["source"], source_name, "Source matches")

    # 6. Threat Actor filter
    for ta_idx in range(5):
        ta_name = f"Actor-{ta_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.threatActor == ta_name)
        api_res = list_iocs(threatActor=ta_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for actor {ta_name}")
        for item in api_res.data:
            check_eq(item["threatActor"], ta_name, "Threat Actor matches")

    # 7. Campaign filter
    for cmp_idx in range(6):
        cmp_name = f"Campaign-{cmp_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.campaign == cmp_name)
        api_res = list_iocs(campaign=cmp_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for campaign {cmp_name}")
        for item in api_res.data:
            check_eq(item["campaign"], cmp_name, "Campaign matches")

    # 8. Confidence Range filter
    conf_weight = {"LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "VERIFIED": 100.0}
    conf_ranges = [(0.0, 50.0), (50.0, 80.0), (75.0, 100.0)]
    for min_c, max_c in conf_ranges:
        expected_cnt = sum(1 for item in bulk_req_items if min_c <= conf_weight.get(item.confidence) <= max_c)
        api_res = list_iocs(minimumConfidence=min_c, maximumConfidence=max_c, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for confidence weight [{min_c}, {max_c}]")
        for item in api_res.data:
            weight = conf_weight.get(item["confidence"])
            check(min_c <= weight <= max_c, f"Weight {weight} is in range")


    # ---------------------------------------------------------------------------
    # Test 6: Sorting Assertions (Target: ~1200 assertions)
    # ---------------------------------------------------------------------------
    print("Testing sorting logic exhaustively...")

    confidence_order = {"low": 1, "medium": 2, "high": 3, "verified": 4}
    sort_fields = ["iocType", "iocValue", "confidence", "createdAt", "updatedAt"]

    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_iocs(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data

            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]

                if field == "iocType":
                    v_curr, v_next = item_curr["iocType"], item_next["iocType"]
                elif field == "iocValue":
                    v_curr, v_next = item_curr["value"], item_next["value"]
                elif field == "confidence":
                    v_curr = confidence_order.get(item_curr["confidence"].lower(), -1)
                    v_next = confidence_order.get(item_next["confidence"].lower(), -1)
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]
                elif field == "updatedAt":
                    v_curr = item_curr["updatedAt"] or ""
                    v_next = item_next["updatedAt"] or ""

                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["iocId"] <= item_next["iocId"], f"Secondary sort: {item_curr['iocId']} <= {item_next['iocId']}")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["iocId"] <= item_next["iocId"], f"Secondary sort in DESC: {item_curr['iocId']} <= {item_next['iocId']}")


    # ---------------------------------------------------------------------------
    # Test 7: Pagination Assertions (Target: ~400 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")

    for p_size in [6, 12, 24, 30]:
        total_pages = math.ceil(120 / p_size)
        seen_ids = set()

        for p in range(1, total_pages + 1):
            api_res = list_iocs(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")

            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 120, "Total items is 120")
            check_eq(pagination["totalPages"], total_pages, "Total pages matches")

            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                iid = item["iocId"]
                check(iid not in seen_ids, f"Unique item {iid} on page {p}")
                seen_ids.add(iid)

        check_eq(len(seen_ids), 120, f"All 120 items covered in page size {p_size}")


    # ---------------------------------------------------------------------------
    # Test 8: Search Assertions
    # ---------------------------------------------------------------------------
    print("Testing search logic...")

    search_res = search_ioc_records(query="Automated")
    check_eq(search_res.success, True, "Search succeeds")
    check_eq(search_res.data["total"], 120, "All 120 match substring")
    check_eq(len(search_res.data["iocs"]), 50, "Default page size is 50")

    search_res_1 = search_ioc_records(query="Actor-2")
    check_eq(search_res_1.data["total"], 24, "24 match Actor-2 (120/5)")


    # ---------------------------------------------------------------------------
    # Test 9: Relationships and Enrichment lookups (120 items * ~6 assertions = 720 assertions)
    # ---------------------------------------------------------------------------
    print("Testing Relationships and Enrichment lookups...")
    for c in iocs_list:
        # Relationships lookup
        rel_res = get_relationships(c["iocId"])
        check_eq(rel_res.success, True, "Relationships lookup succeeds")
        check(len(rel_res.data) >= 2, "Returns at least CVE and Technique relationships")
        for rel in rel_res.data:
            check_eq(rel["sourceIocId"], c["iocId"], "Source ID matches")

        # Enrichment lookup
        enrich_res = get_enrichment(c["iocId"])
        check_eq(enrich_res.success, True, "Enrichment lookup succeeds")
        check_eq(enrich_res.data["iocId"], c["iocId"], "Enrichment iocId matches")
        check_eq(enrich_res.data["value"], c["value"], "Enrichment value matches")
        check_eq(enrich_res.data["malicious"], c["malicious"], "Enrichment malicious matches")


    # ---------------------------------------------------------------------------
    # Test 10: IOC Summary lookup (120 items * ~4 assertions = 480 assertions)
    # ---------------------------------------------------------------------------
    print("Testing IOC summary lookup...")
    for c in iocs_list:
        sum_res = get_ioc_summary_route(c["iocId"])
        check_eq(sum_res.success, True, "Summary lookup succeeds")
        check_eq(sum_res.data["iocId"], c["iocId"], "Summary iocId matches")
        check_eq(sum_res.data["value"], c["value"], "Summary value matches")
        check_eq(sum_res.data["iocType"], c["iocType"], "Summary type matches")


    # ---------------------------------------------------------------------------
    # Test 11: Statistics Calculation
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_statistics()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data

    check_eq(stats["totalIOCs"], 120, "Total IOCs is 120")
    check_eq(stats["maliciousIOCs"], 96, "96 IOCs are malicious (i % 5 != 0)")
    check_eq(stats["revokedIOCs"], 10, "10 IOCs are revoked (i % 12 == 0)")
    
    # Average confidence: LOW=25, MEDIUM=50, HIGH=75, VERIFIED=100
    # Equal distribution over index modulo 4: average confidence should be exactly (25 + 50 + 75 + 100) / 4 = 62.5
    check_eq(stats["averageConfidence"], 62.5, "Average confidence is 62.5")


    # ---------------------------------------------------------------------------
    # Test 12: Bulk Update & Bulk Delete
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")

    # Bulk update description for even indexes
    bulk_up_items = []
    updated_ids = []
    for idx, c in enumerate(iocs_list):
        if idx % 2 == 0:
            bulk_up_items.append(
                BulkUpdateIOCsRequest.BulkUpdateItem(
                    iocId=c["iocId"],
                    update=UpdateIOCRequest(
                        description=f"Bulk updated description {idx}.",
                        confidence="VERIFIED",
                        severity="CRITICAL",
                    )
                )
            )
            updated_ids.append(c["iocId"])

    bulk_up_res = bulk_update_iocs(BulkUpdateIOCsRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")

    # Verify updates in store
    for rec_id in updated_ids:
        c_stored = _IOC_STORE[rec_id]
        check(c_stored["description"].startswith("Bulk updated description"), "Description is updated")
        check_eq(c_stored["confidence"], "VERIFIED", "Confidence is VERIFIED")
        check_eq(c_stored["severity"], "CRITICAL", "Severity is CRITICAL")

    # Bulk delete odd indexes
    bulk_del_ids = []
    for idx, c in enumerate(iocs_list):
        if idx % 2 != 0:
            bulk_del_ids.append(c["iocId"])

    bulk_del_res = bulk_delete_iocs(BulkDeleteIOCsRequest(iocIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_IOC_STORE), 60, "60 items remaining in store")

    # Clean up remaining
    remaining_ids = [c["iocId"] for c in _IOC_STORE.values()]
    cleanup_res = bulk_delete_iocs(BulkDeleteIOCsRequest(iocIds=remaining_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_IOC_STORE), 0, "Store is completely empty")


    # ---------------------------------------------------------------------------
    # Test 13: Serialization & Deserialization
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    sample_ioc = CreateIOCRequest(
        iocType="IP",
        value="1.1.1.1",
        severity="MEDIUM",
        confidence="HIGH",
        createdAt="2026-07-06T12:00:00Z",
    )

    dumped = sample_ioc.model_dump()
    check_eq(dumped["value"], "1.1.1.1", "Model dumps properly")

    json_str = sample_ioc.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["value"], "1.1.1.1", "JSON serialization is correct")

    deserialized = CreateIOCRequest(**parsed)
    check_eq(deserialized.value, "1.1.1.1", "Deserialization roundtrip matches")

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
