import os
import sys
import uuid
import json
import unittest.mock as mock
from datetime import datetime
from typing import Any, Dict, List, Optional

# Setup imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Stub api.persistence and api.workflow.normalizers before import
# ---------------------------------------------------------------------------
_fake_updates: dict = {}

class _FakeExecStore:
    def __init__(self, *a, **kw): pass
    def create(self, r): _fake_updates["created"] = r; return r
    def update(self, eid, upd): _fake_updates[eid] = upd; return True
    def get(self, eid): return _fake_updates.get(eid)
    def get_by_id(self, eid): return _fake_updates.get(eid)
    def get_by_playbook(self, pid): return []
    def get_all(self, project_id=None): return []

class _FakeDict(dict):
    def __init__(self, *a, **kw): super().__init__()
    def get(self, k, d=None): return super().get(k, d)
    def values(self): return super().values()

_persist = mock.MagicMock()
_persist.WorkflowExecutionsStore.return_value = _FakeExecStore()
_persist.RepositoryBackedDict.side_effect = _FakeDict
_persist.map_playbook = lambda x: x
_persist.call_repository = mock.MagicMock(return_value={})
_persist.map_timeline_event = lambda v: v
sys.modules["api.persistence"] = _persist

_norm = mock.MagicMock()
_norm.normalize_playbook = lambda x: x
sys.modules["api.workflow"] = mock.MagicMock()
sys.modules["api.workflow.normalizers"] = _norm

# ---------------------------------------------------------------------------
# Imports from production service
# ---------------------------------------------------------------------------
from services.workflow_execution_service import (
    WorkflowExecutionContext,
    WorkflowExecutionManager,
    StepExecutor,
    _REGISTRY
)

# ---------------------------------------------------------------------------
# Define PCAPAnalysisExecutor
# ---------------------------------------------------------------------------
class PCAPAnalysisExecutor(StepExecutor):
    identifier = "pcap_analysis"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        return step.get("executor") == "pcap_analysis"

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        # Requirement 2 & 3 verification: Verify variables resolution before execution and no unresolved ${var} strings
        config = step.get("config") or {}
        capture_file = config.get("capture_file")

        if not capture_file:
            raise ValueError("capture_file is missing from step config")

        # Assert no unresolved placeholders
        if "${" in str(capture_file):
            raise AssertionError(f"[PCAPAnalysisExecutor] ERROR: Received unresolved variable placeholder in config: {capture_file}")

        # Assert correct value propagation
        expected_file = "C:\\fake\\path\\capture.pcapng"
        if capture_file != expected_file:
            raise AssertionError(f"[PCAPAnalysisExecutor] ERROR: Expected capture_file '{expected_file}', got '{capture_file}'")

        print(f"[PCAPAnalysisExecutor] OK: Variable resolution verified. capture_file = '{capture_file}'")

        # Publish new variables
        protocols = ["TCP", "HTTP", "DNS", "TLS"]
        dns_queries = ["malware-c2.net", "safe-site.com", "phishing-login.com"]
        http_hosts = ["unencrypted-transfer.org", "normal-web.com"]
        conversations = ["192.168.1.10 -> 8.8.8.8 (DNS)", "192.168.1.10 -> 203.0.113.5 (HTTP)"]

        ctx.set_variable("protocols", protocols, "array")
        ctx.set_variable("dns_queries", dns_queries, "array")
        ctx.set_variable("http_hosts", http_hosts, "array")
        ctx.set_variable("conversations", conversations, "array")

        output = {
            "protocols": protocols,
            "dns_queries": dns_queries,
            "http_hosts": http_hosts,
            "conversations": conversations
        }

        return {
            "success": True,
            "summary": "PCAP Analysis completed. Identified 3 DNS queries and 2 HTTP hosts.",
            "output": output
        }

# ---------------------------------------------------------------------------
# Define AIInvestigationExecutor
# ---------------------------------------------------------------------------
class AIInvestigationExecutor(StepExecutor):
    identifier = "ai_investigation"

    def can_execute(self, step: Dict[str, Any]) -> bool:
        return step.get("executor") == "ai_investigation"

    def _execute_internal(self, step: Dict[str, Any], ctx: WorkflowExecutionContext) -> Dict[str, Any]:
        # Requirement 2 & 3 verification: Verify variables resolution before execution and no unresolved ${var} strings
        config = step.get("config") or {}
        dns_queries = config.get("dns_queries")
        http_hosts = config.get("http_hosts")

        if not dns_queries or not http_hosts:
            raise ValueError("dns_queries or http_hosts is missing from step config")

        # Assert no unresolved placeholders
        if "${" in str(dns_queries) or "${" in str(http_hosts):
            raise AssertionError(f"[AIInvestigationExecutor] ERROR: Received unresolved variable placeholder in config. dns_queries: {dns_queries}, http_hosts: {http_hosts}")

        # Requirement 5 verification: Assert correct type preservation
        if not isinstance(dns_queries, list):
            raise AssertionError(f"[AIInvestigationExecutor] ERROR: Expected dns_queries to be list/array, got {type(dns_queries)}")
        if not isinstance(http_hosts, list):
            raise AssertionError(f"[AIInvestigationExecutor] ERROR: Expected http_hosts to be list/array, got {type(http_hosts)}")

        # Assert correct value propagation
        expected_dns = ["malware-c2.net", "safe-site.com", "phishing-login.com"]
        expected_http = ["unencrypted-transfer.org", "normal-web.com"]
        if dns_queries != expected_dns:
            raise AssertionError(f"[AIInvestigationExecutor] ERROR: Expected dns_queries {expected_dns}, got {dns_queries}")
        if http_hosts != expected_http:
            raise AssertionError(f"[AIInvestigationExecutor] ERROR: Expected http_hosts {expected_http}, got {http_hosts}")

        print(f"[AIInvestigationExecutor] OK: Variable resolution and type preservation verified.")
        print(f"  dns_queries: {dns_queries} (type: {type(dns_queries)})")
        print(f"  http_hosts: {http_hosts} (type: {type(http_hosts)})")

        # Requirement 5 verification: Assert backward compatibility at executor level
        if not self.has_variable("capture_file") or not self.hasVariable("capture_file"):
            raise AssertionError("[AIInvestigationExecutor] ERROR: Executor has_variable/hasVariable backward compatibility check failed")
        if self.get_variable("capture_file") != "C:\\fake\\path\\capture.pcapng":
            raise AssertionError("[AIInvestigationExecutor] ERROR: Executor get_variable check failed")
        if self.getVariable("capture_file") != "C:\\fake\\path\\capture.pcapng":
            raise AssertionError("[AIInvestigationExecutor] ERROR: Executor getVariable check failed")
        if not self.list_variables() or not self.listVariables():
            raise AssertionError("[AIInvestigationExecutor] ERROR: Executor list_variables/listVariables check failed")

        print("[AIInvestigationExecutor] OK: Executor-level backward compatibility API verified.")

        # Publish new variables
        ai_summary = "AI analysis detected contact with high-risk domain malware-c2.net."
        risk_score = 85
        recommendations = ["Isolate host 192.168.1.10 immediately.", "Revoke credentials used during session."]

        ctx.set_variable("ai_summary", ai_summary, "string")
        ctx.set_variable("risk_score", risk_score, "number")
        ctx.set_variable("recommendations", recommendations, "array")

        output = {
            "summary": ai_summary,
            "risk_score": risk_score,
            "recommendations": recommendations
        }

        return {
            "success": True,
            "summary": "AI Investigation complete. Risk score: 85.",
            "output": output
        }

# ---------------------------------------------------------------------------
# Setup and Run Verification Workflow
# ---------------------------------------------------------------------------
def run_verification():
    print("================================================================================")
    print("PHASE 4.3 — Final Realistic End-to-End Verification")
    print("================================================================================")

    # 1. Register Executors
    _REGISTRY.register(PCAPAnalysisExecutor())
    _REGISTRY.register(AIInvestigationExecutor())
    print("[INIT] Registered PCAPAnalysisExecutor & AIInvestigationExecutor in registry.")

    # 2. Setup mock capture_service for Step 1
    fake_capture_service = mock.MagicMock()
    fake_capture_service.start_capture.return_value = {"success": True}
    fake_capture_service.stop_capture.return_value = {
        "success": True,
        "file": "C:\\fake\\path\\capture.pcapng"
    }
    fake_capture_service.analyze_latest_capture.return_value = {
        "success": True,
        "total_packets": 150
    }
    sys.modules["services.capture_service"] = fake_capture_service
    print("[INIT] Registered mock capture_service.")

    # 3. Create three-step playbook execution context
    execution_id = str(uuid.uuid4())
    ctx = WorkflowExecutionContext(
        execution_id=execution_id,
        playbook_id="realistic-netfusion-pb",
        playbook_name="Realistic NetFusion Investigation Workflow",
        steps=[
            {
                "stepId": "packet-capture-step-1",
                "title": "Start Network Capture",
                "description": "Capture traffic on Ethernet interface",
                "stepType": "AUTOMATED",
                "stepNumber": 1,
                "executor": "packet_capture",
                "config": {
                    "interface": "Ethernet",
                    "duration": 5
                }
            },
            {
                "stepId": "pcap-analysis-step-2",
                "title": "Analyze Captured PCAP",
                "description": "Extract network conversations, protocols, and indicators from capture",
                "stepType": "AUTOMATED",
                "stepNumber": 2,
                "executor": "pcap_analysis",
                "config": {
                    "capture_file": "${capture_file}"
                }
            },
            {
                "stepId": "ai-investigation-step-3",
                "title": "AI Indicator Threat Analysis",
                "description": "Evaluate dns queries and HTTP hosts using AI model",
                "stepType": "AUTOMATED",
                "stepNumber": 3,
                "executor": "ai_investigation",
                "config": {
                    "dns_queries": "${dns_queries}",
                    "http_hosts": "${http_hosts}"
                }
            }
        ],
        total_steps=3
    )

    # 4. Execute workflow background with mocked sleep for instant verification
    print("[EXEC] Starting Workflow Execution Manager...")
    with mock.patch("time.sleep", return_value=None):
        WorkflowExecutionManager.run_execution_background(ctx)

    # 5. Run Verification Assertions
    print("[ASSERT] Commencing post-execution validation...")
    
    # Assert successful completion
    assert ctx.status == "COMPLETED", f"Expected COMPLETED status, got {ctx.status}"
    assert ctx.completed_steps == 3, f"Expected 3 completed steps, got {ctx.completed_steps}"
    print("  [PASS] Workflow completed successfully.")

    # Assert correct value propagation
    assert ctx.get_variable("capture_file") == "C:\\fake\\path\\capture.pcapng", "capture_file value incorrect"
    assert ctx.get_variable("packet_count") == 150, "packet_count value incorrect"
    assert ctx.get_variable("capture_duration") == 5, "capture_duration value incorrect"
    assert ctx.get_variable("protocols") == ["TCP", "HTTP", "DNS", "TLS"], "protocols value incorrect"
    assert ctx.get_variable("dns_queries") == ["malware-c2.net", "safe-site.com", "phishing-login.com"], "dns_queries value incorrect"
    assert ctx.get_variable("http_hosts") == ["unencrypted-transfer.org", "normal-web.com"], "http_hosts value incorrect"
    assert ctx.get_variable("ai_summary") == "AI analysis detected contact with high-risk domain malware-c2.net.", "ai_summary value incorrect"
    assert ctx.get_variable("risk_score") == 85, "risk_score value incorrect"
    print("  [PASS] Correct value propagation verified across all steps.")

    # Assert type preservation
    assert ctx.variables["capture_file"]["type"] == "file", "capture_file type mismatch"
    assert ctx.variables["packet_count"]["type"] == "number", "packet_count type mismatch"
    assert ctx.variables["capture_duration"]["type"] == "number", "capture_duration type mismatch"
    assert ctx.variables["protocols"]["type"] == "array", "protocols type mismatch"
    assert ctx.variables["dns_queries"]["type"] == "array", "dns_queries type mismatch"
    assert ctx.variables["http_hosts"]["type"] == "array", "http_hosts type mismatch"
    assert ctx.variables["ai_summary"]["type"] == "string", "ai_summary type mismatch"
    assert ctx.variables["risk_score"]["type"] == "number", "risk_score type mismatch"
    
    assert isinstance(ctx.get_variable("protocols"), list), "protocols is not list"
    assert isinstance(ctx.get_variable("dns_queries"), list), "dns_queries is not list"
    assert isinstance(ctx.get_variable("risk_score"), int), "risk_score is not int"
    print("  [PASS] Correct type preservation verified.")

    # Assert metadata completeness (Requirement 4 & 5)
    required_metadata_keys = {"name", "type", "value", "createdBy", "stepNumber", "createdAt"}
    for name, var in ctx.variables.items():
        assert required_metadata_keys.issubset(var.keys()), f"Variable '{name}' lacks required metadata: {required_metadata_keys - var.keys()}"
        for key in required_metadata_keys:
            assert var[key] is not None, f"Variable '{name}' metadata '{key}' is None"
    print("  [PASS] Variable metadata completeness verified.")

    # Assert backward compatibility API
    assert ctx.get_variable("dns_queries") == ["malware-c2.net", "safe-site.com", "phishing-login.com"], "get_variable compatibility check failed"
    assert ctx.getVariable("dns_queries") == ["malware-c2.net", "safe-site.com", "phishing-login.com"], "getVariable compatibility check failed"
    assert ctx.has_variable("dns_queries") is True, "has_variable compatibility check failed"
    assert ctx.hasVariable("dns_queries") is True, "hasVariable compatibility check failed"
    
    list_vars = ctx.list_variables()
    listVars = ctx.listVariables()
    assert list_vars == listVars, "list_variables / listVariables mismatch"
    assert len(list_vars) == len(ctx.variables), "list_variables length mismatch"
    print("  [PASS] Backward compatibility API verified.")

    # 6. Print Variable Registry Table (Requirement 4)
    print("\n" + "=" * 100)
    print(f"{'VARIABLE REGISTRY':^100}")
    print("=" * 100)
    print(f"{'Name':<20} | {'Type':<8} | {'Created By':<23} | {'Step #':<6} | {'Created At':<25} | {'Value'}")
    print("-" * 100)
    for name, var in sorted(ctx.variables.items(), key=lambda x: x[1]["stepNumber"]):
        val_str = str(var["value"])
        if len(val_str) > 30:
            val_str = val_str[:27] + "..."
        print(f"{name:<20} | {var['type']:<8} | {var['createdBy']:<23} | {var['stepNumber']:<6} | {var['createdAt']:<25} | {val_str}")
    print("=" * 100)

    # 7. Print Final Execution Logs (Requirement 6)
    print("\n" + "=" * 100)
    print(f"{'WORKFLOW EXECUTION LOGS':^100}")
    print("=" * 100)
    for log in ctx.logs:
        print(f"[{log['timestamp']}] [{log['level'].upper():<5}] {log['message']}")
    print("=" * 100)

    print("\n[SUCCESS] E2E verification passed successfully! No errors detected.")

if __name__ == "__main__":
    run_verification()
