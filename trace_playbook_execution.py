"""
Playbook Execution Lifecycle Tracer
=====================================
Verifies, in order:
  1. WorkflowExecutionsStore.create() persists a new execution record.
  2. Every WorkflowExecutionsStore.update() actually modifies the persisted execution.
  3. Execution status transitions RUNNING → COMPLETED (or FAILED) in the repository.
  4. Execution can be retrieved via GET /playbooks/{playbookId}/executions.
  5. Execution history endpoint returns the updated execution after completion.

Instruments each step with explicit debug logging:
  - execution ID
  - status before each update
  - status after each update
  - progress after each update
  - final persisted execution record
"""

from __future__ import annotations

import json
import sys
import uuid
import logging
from datetime import datetime

# ---------------------------------------------------------------------------
# Logging — structured output to stdout
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
log = logging.getLogger("playbook_execution_tracer")

# ---------------------------------------------------------------------------
# Patch WorkflowExecutionsStore to intercept every create / update call
# ---------------------------------------------------------------------------
from api.persistence import WorkflowExecutionsStore

_original_create = WorkflowExecutionsStore.create
_original_update = WorkflowExecutionsStore.update
_original_get_by_id = WorkflowExecutionsStore.get_by_id
_original_get_by_playbook = WorkflowExecutionsStore.get_by_playbook

_call_log: list[dict] = []   # stores every intercepted call for post-run audit

def _patched_create(self, execution: dict) -> dict:
    log.info("[STORE.create] CALLED")
    log.info("  execution_id  : %s", execution.get("executionId"))
    log.info("  playbookId    : %s", execution.get("playbookId"))
    log.info("  status        : %s", execution.get("status"))
    log.info("  progress      : %s", execution.get("progress"))
    log.info("  totalSteps    : %s", execution.get("totalSteps"))

    result = _original_create(self, execution)

    log.info("[STORE.create] RETURNED  result=%r", result)
    _call_log.append({"method": "create", "input": dict(execution), "output": result})
    return result

def _patched_update(self, execution_id: str, updates: dict) -> bool:
    # Fetch the CURRENT record before the update so we can log status-before
    before = _original_get_by_id(self, execution_id)
    status_before   = before.get("status")   if before else "<not found>"
    progress_before = before.get("progress") if before else "<not found>"

    log.info("[STORE.update] CALLED  executionId=%s", execution_id)
    log.info("  status_before  : %s", status_before)
    log.info("  progress_before: %s", progress_before)
    log.info("  update_payload : %s",
             json.dumps({k: v for k, v in updates.items() if k != "logs"},
                        default=str))

    result = _original_update(self, execution_id, updates)

    # Fetch AFTER to confirm the DB row changed
    after = _original_get_by_id(self, execution_id)
    status_after   = after.get("status")   if after else "<not found>"
    progress_after = after.get("progress") if after else "<not found>"

    log.info("[STORE.update] RETURNED  success=%r", result)
    log.info("  status_after   : %s", status_after)
    log.info("  progress_after : %s", progress_after)

    _call_log.append({
        "method": "update",
        "execution_id": execution_id,
        "payload_keys": list(updates.keys()),
        "status_before": status_before,
        "progress_before": progress_before,
        "status_after": status_after,
        "progress_after": progress_after,
        "call_returned": result,
    })
    return result

WorkflowExecutionsStore.create      = _patched_create
WorkflowExecutionsStore.update      = _patched_update

# ---------------------------------------------------------------------------
# Bootstrap the FastAPI app (registers all routers, incl. playbook_router)
# ---------------------------------------------------------------------------
log.info("=" * 70)
log.info("Importing FastAPI app …")

# Import only the router pieces we need — avoids loading all of main.py
from fastapi.testclient import TestClient
from fastapi import FastAPI
from api.router import root_router

app = FastAPI()
app.include_router(root_router)
client = TestClient(app, raise_server_exceptions=False)

log.info("App ready.")

# ---------------------------------------------------------------------------
# Helper: pretty-print a section header
# ---------------------------------------------------------------------------
def _h(title: str) -> None:
    width = 66
    log.info("")
    log.info("=" * width)
    log.info("  %s", title)
    log.info("=" * width)

# ---------------------------------------------------------------------------
# STEP 0 — Create a playbook to execute
# ---------------------------------------------------------------------------
_h("STEP 0: Create a test playbook")

ts = datetime.utcnow().isoformat() + "Z"
create_body = {
    "name": "Tracer Playbook",
    "description": "Lifecycle tracer test playbook",
    "severity": "HIGH",
    "status": "ACTIVE",
    "projectId": "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001",
    "createdAt": ts,
    "confidence": 90.0,
    "enabled": True,
    "priority": 1,
    "category": "test",
    "author": "tracer",
    "steps": [
        {
            "stepNumber": 1,
            "title": "Identify Affected Systems",
            "description": "Enumerate all potentially compromised hosts.",
            "stepType": "MANUAL",
            "expectedOutcome": "List of affected assets.",
            "relatedTechniques": ["T1046"],
            "relatedCVEs": [],
            "relatedIOCs": [],
            "createdAt": ts,
        },
        {
            "stepNumber": 2,
            "title": "Isolate Network Segment",
            "description": "Quarantine the affected VLAN.",
            "stepType": "CONTAINMENT",
            "expectedOutcome": "Lateral movement stopped.",
            "relatedTechniques": ["T1021"],
            "relatedCVEs": [],
            "relatedIOCs": [],
            "createdAt": ts,
        },
        {
            "stepNumber": 3,
            "title": "Deploy EDR Signatures",
            "description": "Push new detection rules to endpoint agents.",
            "stepType": "AUTOMATED",
            "expectedOutcome": "All agents updated.",
            "relatedTechniques": [],
            "relatedCVEs": ["CVE-2023-44487"],
            "relatedIOCs": [],
            "createdAt": ts,
        },
    ],
}

resp = client.post("/api/v2/workflow/playbooks/", json=create_body)
log.info("POST /api/v2/workflow/playbooks/ → HTTP %d", resp.status_code)

if resp.status_code not in (200, 201):
    log.error("Playbook creation FAILED — body: %s", resp.text)
    sys.exit(1)

created_pb = resp.json().get("data", {})
playbook_id = created_pb.get("playbookId")
playbook_name = created_pb.get("name")
log.info("Created playbook  id=%s  name=%r  steps=%d",
         playbook_id, playbook_name, len(created_pb.get("steps", [])))

assert playbook_id, "playbookId must not be empty after creation"

# ---------------------------------------------------------------------------
# STEP 1+2+3 — Execute the playbook (triggers create + N updates + final update)
# ---------------------------------------------------------------------------
_h("STEP 1-3: POST /execute → RUNNING → COMPLETED")

log.info("Calling POST /api/v2/workflow/playbooks/%s/execute …", playbook_id)
exec_resp = client.post(f"/api/v2/workflow/playbooks/{playbook_id}/execute")
log.info("HTTP %d returned", exec_resp.status_code)

exec_body = exec_resp.json()
if exec_resp.status_code not in (200, 201):
    log.error("Execute FAILED — body: %s", exec_resp.text)
    sys.exit(1)

exec_data = exec_body.get("data", {})
execution_id    = exec_data.get("executionId")
final_status    = exec_data.get("status")
final_progress  = exec_data.get("progress")
total_steps     = exec_data.get("totalSteps")
completed_steps = exec_data.get("completedSteps")
failed_steps    = exec_data.get("failedSteps")

log.info("")
log.info("=== RETURNED EXECUTION RECORD ===")
log.info("  executionId    : %s", execution_id)
log.info("  playbookId     : %s", exec_data.get('playbookId'))
log.info("  status         : %s", final_status)
log.info("  progress       : %s%%", final_progress)
log.info("  totalSteps     : %s", total_steps)
log.info("  completedSteps : %s", completed_steps)
log.info("  failedSteps    : %s", failed_steps)
log.info("  startedAt      : %s", exec_data.get('startedAt'))
log.info("  finishedAt     : %s", exec_data.get('finishedAt'))
log.info("  logs count     : %d", len(exec_data.get('logs') or []))

assert execution_id, "executionId must be present in response"

# ---------------------------------------------------------------------------
# STEP 1 verification — was create() called?
# ---------------------------------------------------------------------------
_h("VERIFY STEP 1: WorkflowExecutionsStore.create() called?")

create_calls = [c for c in _call_log if c["method"] == "create"]
log.info("create() call count: %d", len(create_calls))
if create_calls:
    c0 = create_calls[0]
    log.info("  execution_id in payload  : %s", c0["input"].get("executionId"))
    log.info("  status in payload        : %s", c0["input"].get("status"))
    log.info("  progress in payload      : %s", c0["input"].get("progress"))
    log.info("  create() returned        : %r", c0["output"])
else:
    log.warning("create() was NEVER called — execution record was NOT persisted via create()")

# ---------------------------------------------------------------------------
# STEP 2 verification — was update() called, and did it change the record?
# ---------------------------------------------------------------------------
_h("VERIFY STEP 2: WorkflowExecutionsStore.update() called and effective?")

update_calls = [c for c in _call_log if c["method"] == "update"]
log.info("update() call count: %d", len(update_calls))

updates_with_status_change = []
for i, uc in enumerate(update_calls):
    log.info("  update[%d]: payload_keys=%s  status_before=%s  status_after=%s  progress_before=%s  progress_after=%s  returned=%s",
             i,
             uc["payload_keys"],
             uc["status_before"],
             uc["status_after"],
             uc["progress_before"],
             uc["progress_after"],
             uc["call_returned"],
             )
    if uc["status_before"] != uc["status_after"] or uc["progress_before"] != uc["progress_after"]:
        updates_with_status_change.append(i)

if updates_with_status_change:
    log.info("Updates that actually modified the DB record: %s", updates_with_status_change)
else:
    log.warning("NO update() call produced a detectable change in the persisted record — "
                "this means update() calls are silently failing or the DB read-back is returning stale data.")

# ---------------------------------------------------------------------------
# STEP 3 verification — status transitioned RUNNING → COMPLETED (or FAILED)?
# ---------------------------------------------------------------------------
_h("VERIFY STEP 3: Status transition RUNNING → COMPLETED/FAILED?")

# Find the create call (should show RUNNING)
if create_calls:
    initial_status = create_calls[0]["input"].get("status")
    log.info("Initial status at create()  : %s", initial_status)
else:
    log.warning("Cannot determine initial status — create() was not called")
    initial_status = None

# Find the final update call (should transition to COMPLETED or FAILED)
final_update = None
for uc in reversed(update_calls):
    if "status" in uc.get("payload_keys", []):
        final_update = uc
        break

if final_update:
    log.info("Final status-bearing update  : status_before=%s  status_after=%s",
             final_update["status_before"], final_update["status_after"])
else:
    log.warning("No update() call included a 'status' field — status was never persisted as COMPLETED/FAILED")

log.info("Status in API response       : %s", final_status)

# ---------------------------------------------------------------------------
# STEP 4 — GET executions listing
# ---------------------------------------------------------------------------
_h("VERIFY STEP 4: GET /playbooks/{playbookId}/executions returns the execution")

list_resp = client.get(f"/api/v2/workflow/playbooks/{playbook_id}/executions")
log.info("GET /executions → HTTP %d", list_resp.status_code)

if list_resp.status_code != 200:
    log.error("Listing executions FAILED — body: %s", list_resp.text)
else:
    list_data = list_resp.json().get("data", [])
    log.info("Executions returned: %d", len(list_data))
    found_in_list = any(e.get("executionId") == execution_id for e in list_data)
    log.info("Our execution present in list: %s", found_in_list)
    for i, e in enumerate(list_data):
        log.info("  [%d] executionId=%s  status=%s  progress=%s  playbookId=%s",
                 i, e.get("executionId"), e.get("status"),
                 e.get("progress"), e.get("playbookId"))
    if not found_in_list:
        log.warning("Execution %s NOT FOUND in listing — persistence to DB may have failed", execution_id)

# ---------------------------------------------------------------------------
# STEP 5 — GET single execution by ID (history endpoint)
# ---------------------------------------------------------------------------
_h("VERIFY STEP 5: GET /playbooks/{playbookId}/executions/{executionId} returns final state")

hist_resp = client.get(
    f"/api/v2/workflow/playbooks/{playbook_id}/executions/{execution_id}"
)
log.info("GET /executions/%s → HTTP %d", execution_id, hist_resp.status_code)

if hist_resp.status_code != 200:
    log.error("History endpoint FAILED — body: %s", hist_resp.text)
else:
    hist_data = hist_resp.json().get("data", {})
    log.info("")
    log.info("=== FINAL PERSISTED EXECUTION RECORD (from history endpoint) ===")
    log.info("  executionId    : %s", hist_data.get("executionId"))
    log.info("  playbookId     : %s", hist_data.get("playbookId"))
    log.info("  status         : %s", hist_data.get("status"))
    log.info("  progress       : %s%%", hist_data.get("progress"))
    log.info("  totalSteps     : %s", hist_data.get("totalSteps"))
    log.info("  completedSteps : %s", hist_data.get("completedSteps"))
    log.info("  failedSteps    : %s", hist_data.get("failedSteps"))
    log.info("  startedAt      : %s", hist_data.get("startedAt"))
    log.info("  finishedAt     : %s", hist_data.get("finishedAt"))
    log.info("  logs count     : %d", len(hist_data.get("logs") or []))

    if hist_data.get("status") in ("COMPLETED", "FAILED"):
        log.info("  ✓ Status is terminal — lifecycle completed successfully")
    else:
        log.warning("  ✗ Status is %r — execution did not reach a terminal state in the DB",
                    hist_data.get("status"))

# ---------------------------------------------------------------------------
# DIAGNOSIS — Where does the lifecycle stop?
# ---------------------------------------------------------------------------
_h("DIAGNOSIS: Where does the lifecycle stop?")

issues_found = []

if not create_calls:
    issues_found.append(
        "CRITICAL: WorkflowExecutionsStore.create() was never called. "
        "No execution record was created in the DB."
    )

if not update_calls:
    issues_found.append(
        "CRITICAL: WorkflowExecutionsStore.update() was never called. "
        "No incremental progress or final status was persisted."
    )

# Count updates where the DB record actually changed
effective_updates = len(updates_with_status_change)
if update_calls and effective_updates == 0:
    issues_found.append(
        f"CRITICAL: update() was called {len(update_calls)} time(s) but NO call "
        "produced a detectable change in the DB record. "
        "The update HTTP call is likely failing (HTTP 4xx/5xx) or the findMany "
        "read-back is returning stale/wrong data."
    )

# Check status transition
if create_calls and not final_update:
    issues_found.append(
        "CRITICAL: No update() call included 'status' in its payload. "
        "The final COMPLETED/FAILED status was never written back to the DB."
    )

if create_calls and final_update:
    if final_update["status_after"] not in ("COMPLETED", "FAILED"):
        issues_found.append(
            f"CRITICAL: Final DB status is {final_update['status_after']!r} "
            "instead of COMPLETED or FAILED. The status update was sent but not "
            "reflected in the DB read-back."
        )

# Check listing
if list_resp.status_code == 200:
    list_data = list_resp.json().get("data", [])
    if not any(e.get("executionId") == execution_id for e in list_data):
        issues_found.append(
            "CRITICAL: The execution was NOT returned by GET /executions. "
            "WorkflowExecutionsStore.get_by_playbook() is either querying with "
            "the wrong playbookId UUID or the DB row was never committed."
        )

# Check history
if hist_resp.status_code == 200:
    hist_data = hist_resp.json().get("data", {})
    if hist_data.get("status") not in ("COMPLETED", "FAILED"):
        issues_found.append(
            f"CRITICAL: History endpoint returned status={hist_data.get('status')!r}. "
            "The execution record in the DB was never updated to a terminal state."
        )
elif hist_resp.status_code == 404:
    issues_found.append(
        "CRITICAL: History endpoint returned 404 — the execution ID could not be "
        "found in the DB. WorkflowExecutionsStore.create() either failed silently "
        "or the DB row is keyed differently than what get_by_id() queries."
    )

log.info("")
if issues_found:
    log.error("LIFECYCLE ISSUES FOUND (%d):", len(issues_found))
    for i, issue in enumerate(issues_found, 1):
        log.error("  [%d] %s", i, issue)
else:
    log.info("ALL CHECKS PASSED — execution lifecycle is end-to-end functional.")

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
_h("SUMMARY")
log.info("create() calls             : %d", len(create_calls))
log.info("update() calls             : %d", len(update_calls))
log.info("effective update() calls   : %d  (actually changed DB record)", effective_updates)
log.info("API response status        : %s", final_status)
log.info("DB final status            : %s",
         (hist_resp.json().get("data", {}).get("status") if hist_resp.status_code == 200 else "N/A"))
log.info("Listing endpoint           : HTTP %d, found=%s",
         list_resp.status_code,
         any(e.get("executionId") == execution_id
             for e in (list_resp.json().get("data", []) if list_resp.status_code == 200 else [])))
log.info("History endpoint           : HTTP %d", hist_resp.status_code)
log.info("")
log.info("Exit status: %s", "FAIL" if issues_found else "PASS")
sys.exit(1 if issues_found else 0)
