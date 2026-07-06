"""
Smoke Test for CVE Intelligence API — Phase A4.9.2
==================================================
Validates:
  ✓ CRUD operations (create, read, update, delete)
  ✓ Search, sorting, filtering, and pagination
  ✓ Bulk operations (create, update, delete)
  ✓ CVSS details and affected products lookups
  ✓ CVE summary generation
  ✓ Statistics calculation
  ✓ Router registration and serialization
  ✓ Error validations (404, 409, 422)
  ✓ Complete deterministic behavior

Target: 4500+ assertions.
"""

from __future__ import annotations

import sys
import json
import math
import hashlib
from typing import Any, List, Dict

# Import API components
from api.knowledge.cve_router import (
    cve_router,
    _reset_store,
    _all_cves,
    _CVE_STORE,
    list_cves,
    get_statistics,
    search_cve_records,
    get_cve,
    create_cve,
    update_cve,
    delete_cve,
    get_cve_cvss,
    get_cve_products,
    get_cve_summary,
    bulk_create_cves,
    bulk_update_cves,
    bulk_delete_cves,
    # Utilities
    find_cve,
    search_cves,
    sort_cves,
    filter_cves,
    paginate_cves,
    build_cve_summary,
    calculate_cve_statistics,
)
from api.knowledge.cve_models import (
    CreateCVERequest,
    UpdateCVERequest,
    CVEResponse,
    CVEListResponse,
    CVEStatisticsResponse,
    CVESearchResponse,
    CVSSResponse,
    AffectedProductResponse,
    BulkCreateCVEsRequest,
    BulkUpdateCVEsRequest,
    BulkDeleteCVEsRequest,
    BulkOperationResult,
)
from api.router import root_router
from services.cve_intelligence_service import SeverityEnum

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
    print("Starting CVE Intelligence API Smoke Test...")
    print("====================================================")

    # ---------------------------------------------------------------------------
    # Test 1: Router Registration & Metadata Check
    # ---------------------------------------------------------------------------
    print("Testing router registration...")
    found_paths = set()
    for route in root_router.routes:
        if route.path.startswith("/api/v2/knowledge/cve"):
            found_paths.add(route.path)

    expected_paths = {
        "/api/v2/knowledge/cve",
        "/api/v2/knowledge/cve/",
        "/api/v2/knowledge/cve/statistics",
        "/api/v2/knowledge/cve/search",
        "/api/v2/knowledge/cve/bulk/create",
        "/api/v2/knowledge/cve/bulk/update",
        "/api/v2/knowledge/cve/bulk/delete",
        "/api/v2/knowledge/cve/{cveId}",
        "/api/v2/knowledge/cve/{cveId}/cvss",
        "/api/v2/knowledge/cve/{cveId}/products",
        "/api/v2/knowledge/cve/{cveId}/summary",
    }

    normalized_found = {p.rstrip("/") for p in found_paths}
    normalized_expected = {p.rstrip("/") for p in expected_paths}

    for p in normalized_expected:
        check(p in normalized_found, f"Expected route registered: {p}")

    # ---------------------------------------------------------------------------
    # Test 2: Store Initialization Check
    # ---------------------------------------------------------------------------
    _reset_store()
    check_eq(len(_CVE_STORE), 0, "CVE store starts empty")

    # ---------------------------------------------------------------------------
    # Test 3: Basic CRUD Operations & Validation (Single items)
    # ---------------------------------------------------------------------------
    print("Testing CRUD operations & validation...")

    # Empty cveId
    bad_req1 = CreateCVERequest(
        cveId="", severity="MEDIUM", cvssScore=5.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_cve(bad_req1)
    check_eq(res.success, False, "Create fails with empty cveId")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad cveId format
    bad_req2 = CreateCVERequest(
        cveId="CVE-2026-abc", severity="MEDIUM", cvssScore=5.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_cve(bad_req2)
    check_eq(res.success, False, "Create fails with bad cveId format")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad CVSS score (> 10)
    bad_req3 = CreateCVERequest(
        cveId="CVE-2026-0001", severity="MEDIUM", cvssScore=11.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_cve(bad_req3)
    check_eq(res.success, False, "Create fails with CVSS score > 10.0")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Bad severity
    bad_req4 = CreateCVERequest(
        cveId="CVE-2026-0001", severity="UNKNOWN", cvssScore=5.0, createdAt="2026-07-06T12:00:00Z"
    )
    res = create_cve(bad_req4)
    check_eq(res.success, False, "Create fails with invalid severity")
    check_eq(res.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Successful creation
    valid_req = CreateCVERequest(
        cveId="CVE-2026-0001",
        description="Vulnerability in Test Software.",
        severity="HIGH",
        cvssScore=8.5,
        publishedDate="2026-07-01",
        modifiedDate="2026-07-02",
        references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0001"],
        affectedPlatforms=["linux", "windows"],
        createdAt="2026-07-06T12:00:00Z",
        exploited=True,
        patched=False,
        vendor="TestVendor",
        product="TestProduct",
    )
    res = create_cve(valid_req)
    check_eq(res.success, True, "Create succeeds with valid request")
    created_id = res.data["recordId"]
    check(created_id is not None, "CVE Record ID is generated")
    check_eq(res.data["cveId"], "CVE-2026-0001", "cveId saved correctly")
    check_eq(res.data["severity"], "HIGH", "severity is HIGH")
    check_eq(res.data["exploited"], True, "exploited is True")

    # Duplicate creation -> CONFLICT
    res_dup = create_cve(valid_req)
    check_eq(res_dup.success, False, "Duplicate create fails")
    check_eq(res_dup.data.errorCode, "CONFLICT", "Duplicate yields CONFLICT")

    # Retrieve
    res_get = get_cve(created_id)
    check_eq(res_get.success, True, "Retrieve by ID succeeds")
    check_eq(res_get.data["recordId"], created_id, "Correct recordId returned")

    # Retrieve by cveId (case-insensitive)
    res_get_cve = get_cve("cve-2026-0001")
    check_eq(res_get_cve.success, True, "Retrieve by cveId succeeds")

    # Retrieve missing -> NOT_FOUND
    res_get_missing = get_cve("CVE-2026-9999")
    check_eq(res_get_missing.success, False, "Retrieve missing fails")
    check_eq(res_get_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Update - Validation fail (no fields)
    res_up_empty = update_cve(created_id, UpdateCVERequest())
    check_eq(res_up_empty.success, False, "Empty update fails")
    check_eq(res_up_empty.data.errorCode, "VALIDATION_ERROR", "Error is VALIDATION_ERROR")

    # Update - Validation fail (cvss out of range)
    res_up_bad = update_cve(created_id, UpdateCVERequest(cvssScore=-1.0))
    check_eq(res_up_bad.success, False, "Invalid score update fails")

    # Successful update
    up_req = UpdateCVERequest(
        description="Updated description of vulnerability.",
        cvssScore=9.0,
        severity="CRITICAL",
        patched=True,
    )
    res_up = update_cve(created_id, up_req)
    check_eq(res_up.success, True, "Valid update succeeds")
    check_eq(res_up.data["description"], "Updated description of vulnerability.", "Description updated")
    check_eq(res_up.data["cvssScore"], 9.0, "cvssScore updated to 9.0")
    check_eq(res_up.data["severity"], "CRITICAL", "severity updated to CRITICAL")
    check_eq(res_up.data["patched"], True, "patched updated to True")

    # Update missing -> NOT_FOUND
    res_up_missing = update_cve("CVE-2026-9999", up_req)
    check_eq(res_up_missing.success, False, "Update missing fails")
    check_eq(res_up_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")

    # Delete
    res_del = delete_cve(created_id)
    check_eq(res_del.success, True, "Delete succeeds")
    check_eq(len(_CVE_STORE), 0, "Store is empty again")

    # Delete missing -> NOT_FOUND
    res_del_missing = delete_cve(created_id)
    check_eq(res_del_missing.success, False, "Delete missing fails")
    check_eq(res_del_missing.data.errorCode, "NOT_FOUND", "Error is NOT_FOUND")


    # ---------------------------------------------------------------------------
    # Test 4: Generating Deterministic Dataset for Filtering, Sorting, Pagination
    # ---------------------------------------------------------------------------
    print("Generating deterministic CVE test dataset of 120 items...")
    _reset_store()

    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    bulk_req_items = []
    for i in range(1, 121):
        cve_id = f"CVE-2026-{1000 + i}"
        sev = severities[i % len(severities)]
        cvss = round(1.0 + (i % 91) * 0.1, 1) # CVSS Score in [1.0, 10.0]

        vendor = f"Vendor-{i % 5}"
        product = f"Product-{i % 6}"

        affected_prods = [
            AffectedProductResponse(
                vendor=vendor,
                product=product,
                version=f"v{i}.0",
                patched=(i % 3 == 0)
            )
        ]

        cvss_details = CVSSResponse(
            baseScore=cvss,
            severity=sev,
            vectorString=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/V:{cvss}",
            exploitabilityScore=3.0,
            impactScore=6.0,
        )

        bulk_req_items.append(
            CreateCVERequest(
                cveId=cve_id,
                description=f"Detailed description of vulnerability {i} in the library.",
                severity=sev,
                cvssScore=cvss,
                publishedDate=f"2026-07-{i % 28 + 1:02d}",
                modifiedDate=f"2026-07-{i % 28 + 1:02d}",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                affectedPlatforms=[f"platform-{i % 3}"],
                createdAt=f"2026-07-06T12:{i % 60:02d}:00Z",
                exploited=(i % 4 == 0),
                patched=(i % 3 == 0),
                vendor=vendor,
                product=product,
                affectedProducts=affected_prods,
                cvssDetails=cvss_details,
            )
        )

    bulk_res = bulk_create_cves(BulkCreateCVEsRequest(cves=bulk_req_items))
    check_eq(bulk_res.success, True, "Bulk create succeeds")
    check_eq(bulk_res.data["successCount"], 120, "120 CVEs created successfully")
    check_eq(bulk_res.data["failCount"], 0, "0 failures in bulk create")
    check_eq(len(_CVE_STORE), 120, "120 items in store")

    cves_list = _all_cves()


    # ---------------------------------------------------------------------------
    # Test 5: Filtering Assertions (Target: ~1500 assertions)
    # ---------------------------------------------------------------------------
    print("Testing filtering logic exhaustively...")

    # 1. Severity filter
    for sev in severities:
        expected_cnt = sum(1 for item in bulk_req_items if item.severity == sev)
        api_res = list_cves(severity=sev, pageSize=200)
        check_eq(api_res.success, True, f"Filter by severity {sev} succeeds")
        check_eq(len(api_res.data), expected_cnt, f"Count matches for severity {sev}")
        for item in api_res.data:
            check_eq(item["severity"], sev, f"Severity is {sev}")

    # 2. Vendor filter
    for v_idx in range(5):
        vendor_name = f"Vendor-{v_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.vendor == vendor_name)
        api_res = list_cves(vendor=vendor_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for vendor {vendor_name}")
        for item in api_res.data:
            check_eq(item["vendor"], vendor_name, "Vendor matches")

    # 3. Product filter
    for p_idx in range(6):
        product_name = f"Product-{p_idx}"
        expected_cnt = sum(1 for item in bulk_req_items if item.product == product_name)
        api_res = list_cves(product=product_name, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for product {product_name}")
        for item in api_res.data:
            check_eq(item["product"], product_name, "Product matches")

    # 4. Exploited filter
    for exp_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.exploited == exp_val)
        api_res = list_cves(exploited=exp_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for exploited={exp_val}")
        for item in api_res.data:
            check_eq(item["exploited"], exp_val, "Exploited matches")

    # 5. Patched filter
    for pat_val in [True, False]:
        expected_cnt = sum(1 for item in bulk_req_items if item.patched == pat_val)
        api_res = list_cves(patched=pat_val, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for patched={pat_val}")
        for item in api_res.data:
            check_eq(item["patched"], pat_val, "Patched matches")

    # 6. CVSS score range filter
    cvss_ranges = [(0.0, 5.0), (5.0, 8.0), (8.0, 10.0), (2.0, 9.5)]
    for min_c, max_c in cvss_ranges:
        expected_cnt = sum(1 for item in bulk_req_items if min_c <= item.cvssScore <= max_c)
        api_res = list_cves(minimumCVSS=min_c, maximumCVSS=max_c, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for CVSS [{min_c}, {max_c}]")
        for item in api_res.data:
            check(min_c <= item["cvssScore"] <= max_c, f"CVSS score {item['cvssScore']} is in range")

    # 7. Date range filter
    date_ranges = [("2026-07-05", "2026-07-20"), ("2026-07-01", "2026-07-10")]
    for after, before in date_ranges:
        expected_cnt = sum(1 for item in bulk_req_items if after <= item.publishedDate <= before)
        api_res = list_cves(publishedAfter=after, publishedBefore=before, pageSize=200)
        check_eq(len(api_res.data), expected_cnt, f"Count matches for dates [{after}, {before}]")
        for item in api_res.data:
            check(after <= item["publishedDate"] <= before, f"Published date {item['publishedDate']} is in range")


    # ---------------------------------------------------------------------------
    # Test 6: Sorting Assertions (Target: ~1200 assertions)
    # ---------------------------------------------------------------------------
    print("Testing sorting logic exhaustively...")

    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    sort_fields = ["cveId", "publishedDate", "severity", "cvssScore", "createdAt"]

    for field in sort_fields:
        for order in ["asc", "desc"]:
            api_res = list_cves(sortBy=field, sortOrder=order, pageSize=200)
            check_eq(api_res.success, True, f"Sorting by {field} {order} succeeds")
            items = api_res.data

            for idx in range(len(items) - 1):
                item_curr = items[idx]
                item_next = items[idx + 1]

                if field == "cveId":
                    v_curr, v_next = item_curr["cveId"], item_next["cveId"]
                elif field == "publishedDate":
                    v_curr, v_next = item_curr["publishedDate"], item_next["publishedDate"]
                elif field == "severity":
                    v_curr = severity_order.get(item_curr["severity"].lower(), -1)
                    v_next = severity_order.get(item_next["severity"].lower(), -1)
                elif field == "cvssScore":
                    v_curr, v_next = item_curr["cvssScore"], item_next["cvssScore"]
                elif field == "createdAt":
                    v_curr, v_next = item_curr["createdAt"], item_next["createdAt"]

                if order == "asc":
                    check(v_curr <= v_next, f"ASC order constraint: {v_curr} <= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["cveId"] <= item_next["cveId"], f"Secondary sort: {item_curr['cveId']} <= {item_next['cveId']}")
                else:
                    check(v_curr >= v_next, f"DESC order constraint: {v_curr} >= {v_next}")
                    if v_curr == v_next:
                        check(item_curr["cveId"] <= item_next["cveId"], f"Secondary sort in DESC: {item_curr['cveId']} <= {item_next['cveId']}")


    # ---------------------------------------------------------------------------
    # Test 7: Pagination Assertions (Target: ~400 assertions)
    # ---------------------------------------------------------------------------
    print("Testing pagination logic...")

    for p_size in [6, 12, 24, 30]:
        total_pages = math.ceil(120 / p_size)
        seen_ids = set()

        for p in range(1, total_pages + 1):
            api_res = list_cves(page=p, pageSize=p_size)
            check_eq(api_res.success, True, f"Page {p} of size {p_size} succeeds")

            pagination = api_res.metadata["pagination"]
            check_eq(pagination["page"], p, "Current page matches")
            check_eq(pagination["pageSize"], p_size, "Page size matches")
            check_eq(pagination["totalItems"], 120, "Total items is 120")
            check_eq(pagination["totalPages"], total_pages, "Total pages matches")

            check_eq(len(api_res.data), p_size, f"Returned item count is {p_size}")
            for item in api_res.data:
                cid = item["recordId"]
                check(cid not in seen_ids, f"Unique item {cid} on page {p}")
                seen_ids.add(cid)

        check_eq(len(seen_ids), 120, f"All 120 items covered in page size {p_size}")


    # ---------------------------------------------------------------------------
    # Test 8: Search Assertions
    # ---------------------------------------------------------------------------
    print("Testing search logic...")

    search_res = search_cve_records(query="library")
    check_eq(search_res.success, True, "Search succeeds")
    check_eq(search_res.data["total"], 120, "All 120 match substring")
    check_eq(len(search_res.data["cves"]), 50, "Default page size is 50")

    search_res_1 = search_cve_records(query="CVE-2026-1077")
    check_eq(search_res_1.data["total"], 1, "Exactly one matches specific cveId")
    check_eq(search_res_1.data["cves"][0]["cveId"], "CVE-2026-1077", "Correct CVE found")


    # ---------------------------------------------------------------------------
    # Test 9: CVSS and Products lookups (120 items * ~6 assertions = 720 assertions)
    # ---------------------------------------------------------------------------
    print("Testing CVSS and Products lookups...")
    for c in cves_list:
        # CVSS lookup
        cvss_res = get_cve_cvss(c["recordId"])
        check_eq(cvss_res.success, True, "CVSS lookup succeeds")
        check_eq(cvss_res.data["baseScore"], c["cvssScore"], "CVSS score matches")
        check_eq(cvss_res.data["severity"], c["severity"], "CVSS severity matches")

        # Products lookup
        prod_res = get_cve_products(c["recordId"])
        check_eq(prod_res.success, True, "Products lookup succeeds")
        check_eq(len(prod_res.data), 1, "Returns exactly 1 product response")
        check_eq(prod_res.data[0]["vendor"], c["vendor"], "Product vendor matches")
        check_eq(prod_res.data[0]["product"], c["product"], "Product name matches")


    # ---------------------------------------------------------------------------
    # Test 10: CVE Summary lookup (120 items * ~4 assertions = 480 assertions)
    # ---------------------------------------------------------------------------
    print("Testing CVE summary lookup...")
    for c in cves_list:
        sum_res = get_cve_summary(c["recordId"])
        check_eq(sum_res.success, True, "Summary lookup succeeds")
        check_eq(sum_res.data["cveId"], c["cveId"], "Summary cveId matches")
        check_eq(sum_res.data["severity"], c["severity"], "Summary severity matches")
        check_eq(sum_res.data["cvssScore"], c["cvssScore"], "Summary score matches")


    # ---------------------------------------------------------------------------
    # Test 11: Statistics Calculation
    # ---------------------------------------------------------------------------
    print("Testing statistics calculations...")
    stats_res = get_statistics()
    check_eq(stats_res.success, True, "Get statistics succeeds")
    stats = stats_res.data

    check_eq(stats["totalCVEs"], 120, "Total CVEs is 120")
    check_eq(stats["exploitedCVEs"], 30, "30 CVEs are exploited (i % 4 == 0)")
    check_eq(stats["patchedCVEs"], 40, "40 CVEs are patched (i % 3 == 0)")
    
    # Check severity counts
    expected_severity_counts = {}
    for item in bulk_req_items:
        s = item.severity
        expected_severity_counts[s] = expected_severity_counts.get(s, 0) + 1
    check_eq(stats["severityCounts"], dict(sorted(expected_severity_counts.items())), "Severity counts match expected")

    # Check vendor counts
    expected_vendor_counts = {}
    for item in bulk_req_items:
        v = item.vendor
        expected_vendor_counts[v] = expected_vendor_counts.get(v, 0) + 1
    check_eq(stats["vendorCounts"], dict(sorted(expected_vendor_counts.items())), "Vendor counts match expected")


    # ---------------------------------------------------------------------------
    # Test 12: Bulk Update & Bulk Delete
    # ---------------------------------------------------------------------------
    print("Testing bulk update & bulk delete...")

    # Bulk update description and severity for even indexes
    bulk_up_items = []
    updated_ids = []
    for idx, c in enumerate(cves_list):
        if idx % 2 == 0:
            bulk_up_items.append(
                BulkUpdateCVEsRequest.BulkUpdateItem(
                    cveId=c["cveId"],
                    update=UpdateCVERequest(
                        description=f"Bulk updated CVE description {idx}.",
                        severity="CRITICAL",
                        cvssScore=10.0,
                    )
                )
            )
            updated_ids.append(c["recordId"])

    bulk_up_res = bulk_update_cves(BulkUpdateCVEsRequest(items=bulk_up_items))
    check_eq(bulk_up_res.success, True, "Bulk update succeeds")
    check_eq(bulk_up_res.data["successCount"], len(updated_ids), "All updates succeed")
    check_eq(bulk_up_res.data["failCount"], 0, "No failures in bulk update")

    # Verify updates in store
    for rec_id in updated_ids:
        c_stored = _CVE_STORE[rec_id]
        check(c_stored["description"].startswith("Bulk updated CVE description"), "Description is updated")
        check_eq(c_stored["severity"], "CRITICAL", "Severity is CRITICAL")
        check_eq(c_stored["cvssScore"], 10.0, "cvssScore is 10.0")

    # Bulk delete odd indexes
    bulk_del_ids = []
    for idx, c in enumerate(cves_list):
        if idx % 2 != 0:
            bulk_del_ids.append(c["cveId"])

    bulk_del_res = bulk_delete_cves(BulkDeleteCVEsRequest(cveIds=bulk_del_ids))
    check_eq(bulk_del_res.success, True, "Bulk delete succeeds")
    check_eq(bulk_del_res.data["successCount"], len(bulk_del_ids), "Correct delete success count")
    check_eq(len(_CVE_STORE), 60, "60 items remaining in store")

    # Clean up remaining
    remaining_cve_ids = [c["cveId"] for c in _CVE_STORE.values()]
    cleanup_res = bulk_delete_cves(BulkDeleteCVEsRequest(cveIds=remaining_cve_ids))
    check_eq(cleanup_res.success, True, "Final bulk delete succeeds")
    check_eq(len(_CVE_STORE), 0, "Store is completely empty")


    # ---------------------------------------------------------------------------
    # Test 13: Serialization & Deserialization
    # ---------------------------------------------------------------------------
    print("Testing serialization and roundtrips...")
    sample_cve = CreateCVERequest(
        cveId="CVE-2026-9999",
        severity="MEDIUM",
        cvssScore=5.0,
        createdAt="2026-07-06T12:00:00Z",
    )

    dumped = sample_cve.model_dump()
    check_eq(dumped["cveId"], "CVE-2026-9999", "Model dumps properly")

    json_str = sample_cve.model_dump_json()
    parsed = json.loads(json_str)
    check_eq(parsed["cveId"], "CVE-2026-9999", "JSON serialization is correct")

    deserialized = CreateCVERequest(**parsed)
    check_eq(deserialized.cveId, "CVE-2026-9999", "Deserialization roundtrip matches")

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
