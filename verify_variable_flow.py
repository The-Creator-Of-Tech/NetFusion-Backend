import os
import sys
import uuid
import json
import unittest.mock as mock

# Setup imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Stub api.persistence before any imports touch it
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

# Stub api.workflow.normalizers
_norm = mock.MagicMock()
_norm.normalize_playbook = lambda x: x
sys.modules["api.workflow"] = mock.MagicMock()
sys.modules["api.workflow.normalizers"] = _norm

from services.workflow_execution_service import (
    WorkflowExecutionContext,
    WorkflowExecutionManager,
    _EXECUTION_STORE
)

def run_e2e_verification():
    print("==================================================")
    print("E2E Integration Verification: Nmap -> Variable Registry -> Packet Capture")
    print("==================================================")

    # 1. Create a playbook execution context with variables binding
    execution_id = str(uuid.uuid4())
    ctx = WorkflowExecutionContext(
        execution_id=execution_id,
        playbook_id="e2e-variables-pb",
        playbook_name="E2E Variables Playbook",
        steps=[
            {
                "stepId": "nmap-step-1",
                "title": "Perform Nmap Reconnaissance",
                "description": "Scan the target host",
                "stepType": "AUTOMATED",
                "stepNumber": 1,
                "executor": "nmap",
                "config": {
                    "target": "10.20.30.40",
                    "profile": "quick"
                }
            },
            {
                "stepId": "pcap-step-2",
                "title": "Start Network Capture",
                "description": "Capture traffic on the host interface",
                "stepType": "AUTOMATED",
                "stepNumber": 2,
                "executor": "packet_capture",
                "config": {
                    "interface": "${host}",  # Dynamic variable binding
                    "duration": 2
                }
            }
        ],
        total_steps=2
    )

    # 2. Setup Mock for main.scan (Nmap)
    mock_scan_result = {
        "host": "10.20.30.40",
        "ports": [
            {"port": 80, "state": "open", "service": "http"},
            {"port": 443, "state": "open", "service": "https"}
        ]
    }
    
    class FakeScanRequest:
        def __init__(self, target, profile):
            self.target = target
            self.profile = profile

    fake_main = mock.MagicMock()
    fake_main.scan.return_value = mock_scan_result
    fake_main.ScanRequest = FakeScanRequest
    sys.modules["main"] = fake_main

    # 3. Setup Mocks for capture_service
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

    # Run sync in this thread for testing
    WorkflowExecutionManager.run_execution_background(ctx)

    # 4. Assertions and Output Verification
    print(f"Workflow Finished Status: {ctx.status}")
    print(f"Completed Steps: {ctx.completed_steps}/{ctx.total_steps}")
    if ctx.status != "COMPLETED":
        print("\nLogs:")
        for log in ctx.logs:
            print(f"  [{log.get('level')}] {log.get('message')}")
    assert ctx.status == "COMPLETED", f"Expected completed, got {ctx.status}"

    # Verify that the variables were written correctly in structured form
    print("\nVariable Registry Contents:")
    for name, var in ctx.variables.items():
        print(f"  - {name}: type={var['type']}, value={var['value']}, createdBy={var['createdBy']}, stepNumber={var['stepNumber']}")

    # Verify Nmap published variables
    assert "host" in ctx.variables
    assert ctx.variables["host"]["value"] == "10.20.30.40"
    assert ctx.variables["host"]["createdBy"] == "NmapExecutor"
    assert ctx.variables["host"]["stepNumber"] == 1
    assert ctx.variables["host"]["type"] == "string"

    assert "open_ports" in ctx.variables
    assert ctx.variables["open_ports"]["value"] == [80, 443]
    assert ctx.variables["open_ports"]["type"] == "array"

    # Verify resolved variable binding
    # The interface in pcap-step-2 config should have resolved from "${host}" to "10.20.30.40"
    # We mock services.capture_service.start_capture, so let's verify it was called with the resolved interface!
    fake_capture_service.start_capture.assert_called_with("10.20.30.40")
    print(f"\n[OK] services.capture_service.start_capture was called with resolved value: '10.20.30.40'")

    # Verify PacketCapture published variables
    assert "capture_file" in ctx.variables
    assert ctx.variables["capture_file"]["value"] == "C:\\fake\\path\\capture.pcapng"
    assert ctx.variables["capture_file"]["type"] == "file"
    assert ctx.variables["capture_file"]["createdBy"] == "PacketCaptureExecutor"
    assert ctx.variables["capture_file"]["stepNumber"] == 2

    assert "packet_count" in ctx.variables
    assert ctx.variables["packet_count"]["value"] == 150
    assert ctx.variables["packet_count"]["type"] == "number"

    assert "capture_interface" in ctx.variables
    assert ctx.variables["capture_interface"]["value"] == "10.20.30.40" # Resolved value was saved!
    
    print("\nE2E verification passed successfully!")
    print("==================================================")

if __name__ == "__main__":
    run_e2e_verification()
