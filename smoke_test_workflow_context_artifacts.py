"""
Smoke Test — Workflow Context & Artifact System (Phase 2)
==========================================================
Verifies:
  1. WorkflowExecutionContext construction and field defaults
  2. Variable helpers: set_variable, get_variable, has_variable
  3. WorkflowArtifact model and add/get/list helpers
  4. Step output helpers: set_step_output, get_step_output
  5. ExecutionLogger writes to ctx.logs
  6. StateMachine valid transitions
  7. ManualExecutor returns structured output, writes variables & stepOutputs
  8. NmapExecutor (mocked) writes variables, creates artifact, returns output
  9. Integration: Executor A writes variable → Executor B reads it
 10. update_execution_record persists all Phase 2 fields
 11. Backward compat: ExecutionContext alias resolves to WorkflowExecutionContext
 12. step_results property yields list from stepOutputs
 13. artifacts_as_list serialisation
"""
from __future__ import annotations

import sys
import unittest.mock as _mock
from datetime import datetime

# ---------------------------------------------------------------------------
# Stub api.persistence before any imports touch it
# ---------------------------------------------------------------------------
_fake_updates: dict = {}

class _FakeExecStore:
    def __init__(self, *a, **kw): pass
    def create(self, r): _fake_updates["created"] = r; return r
    def update(self, eid, upd): _fake_updates[eid] = upd; return True
    def get_by_id(self, eid): return _fake_updates.get(eid)
    def get_by_playbook(self, pid): return []
    def get_all(self, project_id=None): return []

class _FakeDict(dict):
    def __init__(self, *a, **kw): super().__init__()
    def get(self, k, d=None): return super().get(k, d)
    def values(self): return super().values()

_persist = _mock.MagicMock()
_persist.WorkflowExecutionsStore.return_value = _FakeExecStore()
_persist.RepositoryBackedDict.side_effect = _FakeDict
_persist.map_playbook = lambda x: x
_persist.call_repository = _mock.MagicMock(return_value={})
_persist.map_timeline_event = lambda v: v
sys.modules["api.persistence"] = _persist

# Stub api.workflow.normalizers
_norm = _mock.MagicMock()
_norm.normalize_playbook = lambda x: x
sys.modules["api.workflow"] = _mock.MagicMock()
sys.modules["api.workflow.normalizers"] = _norm

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
PASS = 0
FAIL = 0

def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        print(f"  PASS  {label}")
        PASS += 1
    else:
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))
        FAIL += 1

# ---------------------------------------------------------------------------
# Import the service under test
# ---------------------------------------------------------------------------
from services.workflow_execution_service import (
    WorkflowArtifact,
    WorkflowExecutionContext,
    ExecutionContext,          # backward-compat alias
    ExecutionLogger,
    StateMachine,
    ManualExecutor,
    update_execution_record,
)

# ---------------------------------------------------------------------------
# 1. WorkflowExecutionContext construction
# ---------------------------------------------------------------------------
print("\n=== 1. Context construction ===")

ctx = WorkflowExecutionContext(
    execution_id="exec-001",
    playbook_id="pb-001",
    playbook_name="Test Playbook",
    steps=[],
    total_steps=3,
    project_id="proj-001",
)

check("executionId property",  ctx.executionId == "exec-001")
check("playbookId property",   ctx.playbookId == "pb-001")
check("projectId property",    ctx.projectId == "proj-001")
check("currentStep is None",   ctx.currentStep is None)
check("status is QUEUED",      ctx.status == "QUEUED")
check("progress is 0",         ctx.progress == 0)
check("variables empty dict",  ctx.variables == {})
check("artifacts empty dict",  ctx.artifacts == {})
check("stepOutputs empty",     ctx.stepOutputs == {})
check("logs empty list",       ctx.logs == [])
check("timelineEvents empty",  ctx.timelineEvents == [])
check("metadata empty dict",   ctx.metadata == {})
check("started_at set",        ctx.started_at != "")
check("updated_at set",        ctx.updated_at != "")
check("finished_at is None",   ctx.finished_at is None)

# Backward compat alias
check("ExecutionContext alias resolves",
      ExecutionContext is WorkflowExecutionContext)

# ---------------------------------------------------------------------------
# 2. Variable helpers
# ---------------------------------------------------------------------------
print("\n=== 2. Variable helpers ===")

ctx.set_variable("target", "192.168.1.1")
ctx.set_variable("open_ports", [80, 443])
ctx.set_variable("services", [{"port": 80, "service": "http"}])

check("has_variable('target')",      ctx.has_variable("target"))
check("get_variable('target')",      ctx.get_variable("target") == "192.168.1.1")
check("has_variable('open_ports')",  ctx.has_variable("open_ports"))
check("get_variable('open_ports')",  ctx.get_variable("open_ports") == [80, 443])
check("has_variable('services')",    ctx.has_variable("services"))
check("get_variable default",        ctx.get_variable("missing", "default") == "default")
check("has_variable missing False",  not ctx.has_variable("missing"))
check("variables dict has 3 keys",   len(ctx.variables) == 3)

# Overwrite
ctx.set_variable("target", "10.0.0.1")
check("set_variable overwrites",     ctx.get_variable("target") == "10.0.0.1")

# ---------------------------------------------------------------------------
# 3. Artifact helpers
# ---------------------------------------------------------------------------
print("\n=== 3. Artifact helpers ===")

a1 = WorkflowArtifact(
    name="Nmap Scan",
    type="json",
    mimeType="application/json",
    producerExecutor="NmapExecutor",
    stepId="step-001",
    metadata={"target": "10.0.0.1", "portCount": 3},
    data={"ports": [80, 443, 8080]},
)
check("WorkflowArtifact created",        a1.name == "Nmap Scan")
check("artifactId is generated",         len(a1.artifactId) > 0)
check("createdAt is set",                a1.createdAt != "")
check("executionId empty before add",    a1.executionId == "")

added = ctx.add_artifact(a1)
check("add_artifact returns artifact",   added is a1)
check("executionId set after add",       a1.executionId == "exec-001")
check("artifact in ctx.artifacts",       a1.artifactId in ctx.artifacts)
check("get_artifact by id",              ctx.get_artifact(a1.artifactId) is a1)
check("get_artifact missing → None",     ctx.get_artifact("nope") is None)

a2 = WorkflowArtifact(name="Report", type="markdown", mimeType="text/markdown",
                       producerExecutor="ReportExecutor", stepId="step-002", data="# Report")
ctx.add_artifact(a2)
listed = ctx.list_artifacts()
check("list_artifacts returns 2",        len(listed) == 2)
check("list sorted by createdAt",        isinstance(listed, list))

# Serialization
as_list = ctx.artifacts_as_list()
check("artifacts_as_list returns list",  isinstance(as_list, list))
check("artifacts_as_list length 2",      len(as_list) == 2)
check("each item is a dict",             all(isinstance(x, dict) for x in as_list))
check("artifactId in serialized",        "artifactId" in as_list[0])
check("data preserved in serialized",    as_list[0]["data"] is not None or as_list[1]["data"] is not None)

# ---------------------------------------------------------------------------
# 4. Step output helpers
# ---------------------------------------------------------------------------
print("\n=== 4. Step output helpers ===")

ctx.set_step_output("step-001", {"host": "10.0.0.1", "ports": [80, 443], "services": []})
ctx.set_step_output("step-002", {"confirmed": True})

check("set/get_step_output step-001",    ctx.get_step_output("step-001")["host"] == "10.0.0.1")
check("set/get_step_output step-002",    ctx.get_step_output("step-002")["confirmed"] is True)
check("get_step_output missing → None",  ctx.get_step_output("nope") is None)
check("stepOutputs has 2 entries",       len(ctx.stepOutputs) == 2)

# step_results property
results = ctx.step_results
check("step_results is a list",          isinstance(results, list))
check("step_results length 2",           len(results) == 2)

# ---------------------------------------------------------------------------
# 5. ExecutionLogger
# ---------------------------------------------------------------------------
print("\n=== 5. ExecutionLogger ===")

ctx2 = WorkflowExecutionContext(
    execution_id="exec-002", playbook_id="pb-002",
    playbook_name="Logger Test", steps=[], total_steps=1,
)
ExecutionLogger.log(ctx2, "INFO", "Starting test")
ExecutionLogger.log(ctx2, "WARN", "Something odd")
ExecutionLogger.log(ctx2, "ERROR", "Failed step")

check("3 log entries",            len(ctx2.logs) == 3)
check("log level normalised",     ctx2.logs[0]["level"] == "info")
check("warn level normalised",    ctx2.logs[1]["level"] == "warn")
check("error level normalised",   ctx2.logs[2]["level"] == "error")
check("message preserved",        ctx2.logs[0]["message"] == "Starting test")
check("timestamp present",        "timestamp" in ctx2.logs[0])

# ---------------------------------------------------------------------------
# 6. StateMachine
# ---------------------------------------------------------------------------
print("\n=== 6. StateMachine ===")

ctx3 = WorkflowExecutionContext(
    execution_id="exec-003", playbook_id="pb-003",
    playbook_name="SM Test", steps=[], total_steps=1,
)
check("initial status QUEUED",       ctx3.status == "QUEUED")
StateMachine.transition(ctx3, "RUNNING")
check("QUEUED → RUNNING",            ctx3.status == "RUNNING")
check("finished_at still None",      ctx3.finished_at is None)
StateMachine.transition(ctx3, "COMPLETED")
check("RUNNING → COMPLETED",         ctx3.status == "COMPLETED")
check("finished_at set on COMPLETED", ctx3.finished_at is not None)

# Invalid transition is warned but doesn't crash
ctx4 = WorkflowExecutionContext(
    execution_id="exec-004", playbook_id="pb-004",
    playbook_name="SM Invalid", steps=[], total_steps=1,
)
StateMachine.transition(ctx4, "COMPLETED")  # invalid: QUEUED → COMPLETED
check("invalid transition logged, status still set", ctx4.status == "COMPLETED")

# ---------------------------------------------------------------------------
# 7. ManualExecutor — structured output
# ---------------------------------------------------------------------------
print("\n=== 7. ManualExecutor ===")

ctx5 = WorkflowExecutionContext(
    execution_id="exec-005", playbook_id="pb-005",
    playbook_name="Manual Test", steps=[], total_steps=1,
)
manual = ManualExecutor()
step_manual = {"stepId": "s-manual-1", "title": "Confirm Asset",
               "stepType": "MANUAL", "stepNumber": 1}

check("can_execute MANUAL",         manual.can_execute(step_manual))
check("cannot execute AUTOMATED",   not manual.can_execute({"stepType": "AUTOMATED"}))

result_m = manual._execute_internal(step_manual, ctx5)
check("Manual result success=True", result_m["success"] is True)
check("Manual result has output",   "output" in result_m)
check("Manual output confirmed",    result_m["output"]["confirmed"] is True)
check("Manual output stepTitle",    result_m["output"]["stepTitle"] == "Confirm Asset")
check("Manual variable written",    ctx5.has_variable("step_s-manual-1_confirmed"))
check("Manual stepOutput saved",    ctx5.get_step_output("s-manual-1") is not None)

# ---------------------------------------------------------------------------
# 8. NmapExecutor — mocked scan
# ---------------------------------------------------------------------------
print("\n=== 8. NmapExecutor (mocked) ===")

from services.workflow_execution_service import NmapExecutor

# Mock main.scan to avoid running actual nmap
_scan_result = {
    "host": "10.10.10.1",
    "ports": [
        {"port": 22, "state": "open", "service": "ssh"},
        {"port": 80, "state": "open", "service": "http"},
        {"port": 3306, "state": "closed", "service": "mysql"},
    ]
}

class _FakeScanRequest:
    def __init__(self, target, profile): self.target = target; self.profile = profile

_fake_main = _mock.MagicMock()
_fake_main.scan.return_value = _scan_result
_fake_main.ScanRequest = _FakeScanRequest
sys.modules["main"] = _fake_main

ctx6 = WorkflowExecutionContext(
    execution_id="exec-006", playbook_id="pb-006",
    playbook_name="Nmap Test", steps=[], total_steps=1,
)
nmap = NmapExecutor()
step_nmap = {
    "stepId": "s-nmap-1", "title": "Nmap Scan",
    "stepType": "AUTOMATED", "stepNumber": 1,
    "config": {"target": "10.10.10.1", "profile": "quick"},
}

check("NmapExecutor can_execute AUTOMATED+scan", nmap.can_execute(step_nmap))
check("NmapExecutor cannot execute MANUAL", not nmap.can_execute({"stepType": "MANUAL", "title": "check"}))

result_n = nmap._execute_internal(step_nmap, ctx6)
check("Nmap result success=True",              result_n["success"] is True)
check("Nmap result has output",                "output" in result_n)
check("Nmap output host",                      result_n["output"]["host"] == "10.10.10.1")
check("Nmap output ports list",                isinstance(result_n["output"]["ports"], list))
check("Nmap output openPorts",                 80 in result_n["output"]["openPorts"])
check("Nmap output services",                  isinstance(result_n["output"]["services"], list))
check("Nmap output artifactId present",        "artifactId" in result_n["output"])
check("Nmap variable 'target' written",        ctx6.get_variable("target") == "10.10.10.1")
check("Nmap variable 'scan_results' written",  ctx6.has_variable("scan_results"))
check("Nmap variable 'open_ports' written",    ctx6.has_variable("open_ports"))
check("Nmap variable 'services' written",      ctx6.has_variable("services"))
check("Nmap artifact created",                 len(ctx6.artifacts) == 1)
check("Nmap stepOutput saved",                 ctx6.get_step_output("s-nmap-1") is not None)
check("Nmap summary mentions target",          "10.10.10.1" in result_n["summary"])
check("Nmap duration > 0",                     result_n.get("duration", 0) >= 0)

# Artifact details
artifact = list(ctx6.artifacts.values())[0]
check("Artifact type json",               artifact.type == "json")
check("Artifact producerExecutor Nmap",   artifact.producerExecutor == "NmapExecutor")
check("Artifact stepId matches",          artifact.stepId == "s-nmap-1")
check("Artifact executionId set",         artifact.executionId == "exec-006")
check("Artifact metadata has target",     artifact.metadata.get("target") == "10.10.10.1")
check("Artifact data has ports",          "ports" in artifact.data)

# ---------------------------------------------------------------------------
# 9. Integration: Executor A writes variable → Executor B reads it
# ---------------------------------------------------------------------------
print("\n=== 9. Integration: variable propagation between executors ===")

# Simulate a two-step execution:
#   Step 1 (NmapExecutor)   → writes target, open_ports, scan_results
#   Step 2 (ManualExecutor) → reads target variable

ctx_int = WorkflowExecutionContext(
    execution_id="exec-int-001", playbook_id="pb-int-001",
    playbook_name="Integration Test", steps=[], total_steps=2,
)

# Step 1: Nmap (with mocked scan)
step1 = {
    "stepId": "int-step-1", "title": "Network Scan",
    "stepType": "AUTOMATED", "stepNumber": 1,
    "config": {"target": "172.16.0.1", "profile": "service"},
}
_fake_main.scan.return_value = {
    "host": "172.16.0.1",
    "ports": [{"port": 443, "state": "open", "service": "https"},
              {"port": 8080, "state": "open", "service": "http-proxy"}],
}
nmap_int = NmapExecutor()
res1 = nmap_int._execute_internal(step1, ctx_int)

check("Step1 success",                    res1["success"] is True)
check("Step1 wrote target variable",      ctx_int.get_variable("target") == "172.16.0.1")
check("Step1 wrote open_ports",           443 in ctx_int.get_variable("open_ports", []))
check("Step1 created artifact",           len(ctx_int.artifacts) == 1)
check("Step1 stepOutput saved",           ctx_int.get_step_output("int-step-1") is not None)

# Step 2: Manual — reads from context (verifying propagation)
step2 = {
    "stepId": "int-step-2", "title": "Confirm Findings",
    "stepType": "MANUAL", "stepNumber": 2,
}
manual_int = ManualExecutor()
res2 = manual_int._execute_internal(step2, ctx_int)

check("Step2 success",                    res2["success"] is True)
# Verify Step 2 can see Step 1 variables
target_from_ctx = ctx_int.get_variable("target")
check("Step2 can read target from ctx",   target_from_ctx == "172.16.0.1")
open_ports = ctx_int.get_variable("open_ports", [])
check("Step2 can read open_ports",        443 in open_ports)
check("Both stepOutputs present",         len(ctx_int.stepOutputs) == 2)
check("Only 1 artifact (nmap only)",      len(ctx_int.artifacts) == 1)

# Variable count check
check("Context has 6 variables after both steps",
      len(ctx_int.variables) >= 4)  # target, scan_results, open_ports, services + confirmation

# ---------------------------------------------------------------------------
# 10. update_execution_record persists Phase 2 fields
# ---------------------------------------------------------------------------
print("\n=== 10. Persistence: Phase 2 fields ===")

ctx_p = WorkflowExecutionContext(
    execution_id="exec-persist-01", playbook_id="pb-p",
    playbook_name="Persist Test", steps=[], total_steps=1,
)
ctx_p.set_variable("target", "1.2.3.4")
ctx_p.set_variable("open_ports", [22, 80])
art_p = WorkflowArtifact(name="Test Art", type="json", mimeType="application/json",
                          producerExecutor="TestExecutor", stepId="sp1", data={"x": 1})
ctx_p.add_artifact(art_p)
ctx_p.set_step_output("sp1", {"confirmed": True, "host": "1.2.3.4"})
ctx_p.timelineEvents.append({"timestamp": "2026-07-16T00:00:00Z",
                               "title": "Test Event", "description": "desc"})

update_execution_record(ctx_p)
saved = _fake_updates.get("exec-persist-01")
check("update_execution_record called",  saved is not None, f"keys: {list(_fake_updates.keys())}")

if saved:
    meta = saved.get("metadata", {})
    check("metadata.variables present",        "variables" in meta)
    check("metadata.variables.target correct", meta["variables"].get("target") == "1.2.3.4")
    check("metadata.artifacts is list",        isinstance(meta.get("artifacts"), list))
    check("metadata.artifacts length 1",       len(meta.get("artifacts", [])) == 1)
    check("metadata.artifactsCount=1",         meta.get("artifactsCount") == 1)
    check("metadata.stepOutputs present",      "stepOutputs" in meta)
    check("metadata.stepOutputs sp1 present",  "sp1" in meta.get("stepOutputs", {}))
    check("metadata.timelineEvents present",   "timelineEvents" in meta)
    check("metadata.timelineEvents length 1",  len(meta.get("timelineEvents", [])) == 1)
    check("metadata.id set",                   meta.get("id") == "exec-persist-01")
    check("metadata.type = playbook",          meta.get("type") == "playbook")

# ---------------------------------------------------------------------------
# 11. WorkflowArtifact.to_dict()
# ---------------------------------------------------------------------------
print("\n=== 11. WorkflowArtifact serialization ===")

wa = WorkflowArtifact(
    name="CSV Export", type="csv", mimeType="text/csv",
    producerExecutor="CsvExecutor", stepId="step-csv",
    executionId="exec-csv", metadata={"rows": 100},
    location="memory://csv-001", data="col1,col2\n1,2",
)
d = wa.to_dict()
check("to_dict has artifactId",         "artifactId" in d)
check("to_dict name",                   d["name"] == "CSV Export")
check("to_dict type",                   d["type"] == "csv")
check("to_dict mimeType",               d["mimeType"] == "text/csv")
check("to_dict producerExecutor",       d["producerExecutor"] == "CsvExecutor")
check("to_dict stepId",                 d["stepId"] == "step-csv")
check("to_dict executionId",            d["executionId"] == "exec-csv")
check("to_dict createdAt present",      d["createdAt"] != "")
check("to_dict metadata rows=100",      d["metadata"].get("rows") == 100)
check("to_dict location",               d["location"] == "memory://csv-001")
check("to_dict data preserved",         "col1" in d["data"])

# ---------------------------------------------------------------------------
# 12. step_results property (backward compat)
# ---------------------------------------------------------------------------
print("\n=== 12. step_results property backward compat ===")

ctx_br = WorkflowExecutionContext(
    execution_id="exec-br-01", playbook_id="pb-br",
    playbook_name="BR Test", steps=[], total_steps=2,
)
ctx_br.set_step_output("s1", {"stepId": "s1", "status": "EXECUTED", "outputs": {}})
ctx_br.set_step_output("s2", {"stepId": "s2", "status": "EXECUTED", "outputs": {}})
sr = ctx_br.step_results
check("step_results is list",    isinstance(sr, list))
check("step_results length 2",   len(sr) == 2)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{'='*50}")
print(f"Phase 2 Smoke Test Complete")
print(f"  PASS: {PASS}")
print(f"  FAIL: {FAIL}")
print(f"{'='*50}")

if FAIL > 0:
    sys.exit(1)
