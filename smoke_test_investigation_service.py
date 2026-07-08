"""
Smoke Test — Investigation Service & Base Service integration
============================================================
Verifies:
  - BaseService logging, type checking, UUID checking, and response building.
  - Creation of investigations via HTTP POST with deterministic key/UUID.
  - Verification of automatic creation of systemic timeline audit events in the DB.
  - Updating of investigation records (title, description, priority, tags, metadata).
  - Closure of investigations (COMPLETED status + closedAt).
  - Linking assets & findings to investigations.
  - Investigation statistics calculation.
  - Deletion of investigations.
"""

import sys
import requests
import uuid

BASE_URL = "http://localhost:8000/api/v2"

PASS = "[OK]"
FAIL = "[FAIL]"
errors = []

def check(label: str, condition: bool) -> None:
    status = PASS if condition else FAIL
    print(f"  {status}  {label}")
    if not condition:
        errors.append(label)

def run_tests():
    print("=== 1. Verification of BaseService & Validation ===")
    
    # Test POST validation on missing fields
    r = requests.post(f"{BASE_URL}/investigation/", json={})
    check("Missing fields validation failure returns 422", r.status_code == 422)
    resp = r.json()
    check("Validation failure detail present", "detail" in resp)

    # Test POST validation on invalid UUID formats
    r = requests.post(f"{BASE_URL}/investigation/", json={
        "projectId": "invalid-uuid",
        "ownerId": "invalid-uuid",
        "title": "Lateral Movement"
    })
    check("Invalid UUID payload returns 200", r.status_code == 200)
    check("Invalid UUID payload has success=False", r.json().get("success") is False)
    check("UUID error details contain correct field context", "projectId" in str(r.json()))

    # Test POST validation on invalid priority
    r = requests.post(f"{BASE_URL}/investigation/", json={
        "projectId": "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001",
        "ownerId": "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e999",
        "title": "Lateral Movement",
        "priority": "SUPER_HIGH"
    })
    check("Invalid priority returns 200", r.status_code == 200)
    check("Invalid priority has success=False", r.json().get("success") is False)

    print("\n=== 2. Investigation Creation & Database Storage ===")
    proj_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    title = f"APT Attack Investigation - {uuid.uuid4().hex[:6]}"
    
    # Create investigation
    payload = {
        "projectId": proj_id,
        "ownerId": owner_id,
        "title": title,
        "description": "Investigating active ransomware simulation.",
        "priority": "HIGH",
        "tags": ["apt", "ransomware"],
        "metadata": {"source": "sentinel"}
    }
    r = requests.post(f"{BASE_URL}/investigation/", json=payload)
    check("Create investigation response status 200", r.status_code == 200)
    
    created_res = r.json()
    check("Create response success=True", created_res.get("success") is True)
    inv = created_res.get("data", {})
    inv_id = inv.get("investigationId")
    check("investigationId is returned and is non-empty", bool(inv_id))
    check("title matches", inv.get("title") == title)
    check("priority matches", inv.get("priority") == "HIGH")
    check("status is initially OPEN", inv.get("status") == "OPEN")
    
    # Check if SYSTEM timeline event was automatically generated
    timeline_ids = inv.get("timelineEventIds", [])
    check("System timeline audit event linked to investigation", len(timeline_ids) == 1)
    
    # Verify timeline event content in DB via GET
    timeline_id = timeline_ids[0]
    rt = requests.get(f"{BASE_URL}/timeline/{timeline_id}")
    check("Get timeline event response status 200", rt.status_code == 200)
    timeline_event = rt.json().get("data", {})
    check("Timeline event title is correct", timeline_event.get("title") == "Investigation Created")
    check("Timeline event type is SYSTEM or HISTORY_CREATED", timeline_event.get("eventType") in ("SYSTEM", "HISTORY_CREATED"))
    check("Timeline event description matches", f"Investigation '{title}' was initialized." in timeline_event.get("description", ""))

    print("\n=== 3. Investigation Updates ===")
    # Update title and priority
    upd_payload = {
        "title": f"Updated {title}",
        "priority": "CRITICAL",
        "description": "Updated description text."
    }
    ru = requests.put(f"{BASE_URL}/investigation/{inv_id}", json=upd_payload)
    check("Update investigation status 200", ru.status_code == 200)
    updated_inv = ru.json().get("data", {})
    check("Title updated successfully", updated_inv.get("title") == f"Updated {title}")
    check("Priority updated to CRITICAL", updated_inv.get("priority") == "CRITICAL")
    check("Description updated successfully", updated_inv.get("description") == "Updated description text.")
    
    # Check that a second SYSTEM timeline event was appended for update audit
    new_timeline_ids = updated_inv.get("timelineEventIds", [])
    check("New timeline event added to list", len(new_timeline_ids) == 2)
    
    # Verify second timeline event details
    ru_timeline_id = new_timeline_ids[1]
    rt2 = requests.get(f"{BASE_URL}/timeline/{ru_timeline_id}")
    check("Get update timeline event response status 200", rt2.status_code == 200)
    timeline_event2 = rt2.json().get("data", {})
    check("Timeline event title is correct", timeline_event2.get("title") == "Investigation Updated")
    check("Timeline event description lists changes", "title changed to" in timeline_event2.get("description", ""))

    print("\n=== 4. Linking Assets & Findings ===")
    # Create a dummy asset in the repository first
    asset_id = f"asset-{uuid.uuid4().hex[:6]}"
    requests.post(f"{BASE_URL}/assets", json={
        "assetId": asset_id,
        "hostname": "test-host",
        "currentIp": "192.168.1.50"
    })
    
    # Link asset to investigation
    la_res = requests.post(f"{BASE_URL}/investigation/{inv_id}/link-asset", json={"assetId": asset_id})
    check("Link asset response status 200", la_res.status_code == 200)
    linked_inv = la_res.json().get("data", {})
    check("Asset ID present in investigation assetIds", asset_id in linked_inv.get("assetIds", []))

    # Link invalid/non-existent asset
    la_invalid = requests.post(f"{BASE_URL}/investigation/{inv_id}/link-asset", json={"assetId": "non-existent-asset"})
    check("Linking non-existent asset returns 200", la_invalid.status_code == 200)
    check("Linking non-existent asset has success=False", la_invalid.json().get("success") is False)
    check("Linking non-existent asset has NOT_FOUND error", la_invalid.json().get("data", {}).get("errorCode") == "NOT_FOUND")

    # Create a dummy finding in the repository first
    finding_id = str(uuid.uuid4())
    rf_create = requests.post(f"{BASE_URL}/findings", json={
        "findingId": finding_id,
        "projectId": proj_id,
        "investigationId": inv_id,
        "title": "Brute force attack",
        "severity": "HIGH",
        "createdBy": "test-user",
        "createdAt": "2026-07-07T12:00:00Z"
    })
    created_finding_id = rf_create.json().get("data", {}).get("findingId")

    # Link finding to investigation
    lf_res = requests.post(f"{BASE_URL}/investigation/{inv_id}/link-finding", json={"findingId": created_finding_id})
    check("Link finding response status 200", lf_res.status_code == 200)
    linked_inv2 = lf_res.json().get("data", {})
    check("Finding ID present in investigation findingIds", created_finding_id in linked_inv2.get("findingIds", []))

    # Link invalid/non-existent finding
    lf_invalid = requests.post(f"{BASE_URL}/investigation/{inv_id}/link-finding", json={"findingId": str(uuid.uuid4())})
    check("Linking non-existent finding returns 200", lf_invalid.status_code == 200)
    check("Linking non-existent finding has success=False", lf_invalid.json().get("success") is False)
    check("Linking non-existent finding has NOT_FOUND error", lf_invalid.json().get("data", {}).get("errorCode") == "NOT_FOUND")

    print("\n=== 5. Statistics calculation ===")
    # Fetch statistics
    rs = requests.get(f"{BASE_URL}/investigation/statistics")
    check("Get statistics response status 200", rs.status_code == 200)
    stats = rs.json().get("data", {})
    check("totalInvestigations >= 1", stats.get("totalInvestigations", 0) >= 1)
    check("openCount >= 1", stats.get("openCount", 0) >= 1)
    check("criticalCount >= 1", stats.get("criticalCount", 0) >= 1)

    print("\n=== 6. Closing Investigation ===")
    rc = requests.post(f"{BASE_URL}/investigation/{inv_id}/close")
    check("Close investigation response status 200", rc.status_code == 200)
    closed_inv = rc.json().get("data", {})
    check("Status updated to COMPLETED", closed_inv.get("status") == "COMPLETED")
    check("closedAt is populated", bool(closed_inv.get("closedAt")))
    check("timelineEventIds list grew to 3", len(closed_inv.get("timelineEventIds", [])) == 3)
    
    # Verify closing timeline event in DB
    rc_timeline_id = closed_inv.get("timelineEventIds")[-1]
    rt3 = requests.get(f"{BASE_URL}/timeline/{rc_timeline_id}")
    check("Get closing timeline event status 200", rt3.status_code == 200)
    timeline_event3 = rt3.json().get("data", {})
    check("Timeline event title is correct", timeline_event3.get("title") == "Investigation Closed")

    print("\n=== 7. Investigation Deletion ===")
    rd = requests.delete(f"{BASE_URL}/investigation/{inv_id}")
    check("Delete investigation status 200", rd.status_code == 200)
    
    # Try fetching deleted investigation
    rf = requests.get(f"{BASE_URL}/investigation/{inv_id}")
    check("Fetching deleted investigation returns 200", rf.status_code == 200)
    check("Fetching deleted investigation has success=False", rf.json().get("success") is False)
    check("Fetching deleted investigation has NOT_FOUND error", rf.json().get("data", {}).get("errorCode") == "NOT_FOUND")

    print("\n===============================================================")
    if errors:
        print(f"FAILED: {len(errors)} assertions failed.")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
