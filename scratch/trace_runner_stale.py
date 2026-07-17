import sys
import os
import json
from datetime import datetime
from uuid import UUID

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from fastapi import FastAPI
from api.router import root_router
from api.persistence import call_repository, ensure_uuid
from services.workflow_execution_service import WorkflowExecutionManager, PacketCaptureExecutor

# Instantiate TestClient
app = FastAPI()
app.include_router(root_router)
client = TestClient(app, raise_server_exceptions=True)

PLAYBOOK_ID = "0c2a6623-7c50-51ff-9084-25d828193688"

# Custom serializer helper
def custom_serializer(obj):
    if isinstance(obj, (datetime, UUID)):
        return str(obj)
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    return repr(obj)

def safe_pretty(title, obj):
    try:
        serialized = json.dumps(obj, indent=2, default=custom_serializer)
        print(f"{title}:\n{serialized}", flush=True)
    except Exception as e:
        print(f"{title} (repr):\n{repr(obj)}\n(Failed to serialize: {e})", flush=True)

# Save original methods
orig_create_execution = WorkflowExecutionManager.create_execution
orig_execute_internal = PacketCaptureExecutor._execute_internal

def patched_create_execution(playbook_id: str):
    print("\n--- [STAGE 3] Inside execute_playbook() / create_execution() ---", flush=True)
    try:
        from api.workflow.playbook_router import _PLAYBOOK_STORE
        from api.workflow.normalizers import normalize_playbook
        
        raw_pb = _PLAYBOOK_STORE.get(playbook_id)
        safe_pretty("Loaded raw_pb from store", raw_pb)
        
        if raw_pb:
            pb = normalize_playbook(raw_pb)
            safe_pretty("Normalized pb steps[0].config", pb.get('steps', [{}])[0].get('config'))
    except Exception as e:
        print(f"Error in STAGE 3 tracing: {e}", flush=True)
        
    ctx = orig_create_execution(playbook_id)
    
    print("\n--- [STAGE 4] Inside WorkflowExecutionManager.create_execution() ---", flush=True)
    try:
        if ctx and ctx.steps:
            safe_pretty("ctx.steps[0].config", ctx.steps[0].get('config'))
        else:
            print("ctx or ctx.steps is empty", flush=True)
    except Exception as e:
        print(f"Error in STAGE 4 tracing: {e}", flush=True)
        
    return ctx

def patched_execute_internal(self, step, ctx):
    print("\n--- [STAGE 5] Inside PacketCaptureExecutor ---", flush=True)
    try:
        safe_pretty("step.config before resolving interface", step.get('config'))
    except Exception as e:
        print(f"Error in STAGE 5 tracing: {e}", flush=True)
    return orig_execute_internal(self, step, ctx)

# Apply patches
WorkflowExecutionManager.create_execution = patched_create_execution
PacketCaptureExecutor._execute_internal = patched_execute_internal

def simulate_nestjs_update():
    print("\nSimulating NestJS-style Playbook update...", flush=True)
    # 1. Update the Playbook table columns, but leave metadata STALE
    # We set metadata to the old/legacy playbook structure without config
    stale_metadata = {
        "playbookId": PLAYBOOK_ID,
        "name": "Wi-Fi Packet Capture Playbook (Stale)",
        "description": "This is a simulated stale metadata",
        "severity": "HIGH",
        "status": "ACTIVE",
        "steps": [
            {
                "stepId": "step-1",
                "stepNumber": 1,
                "title": "Automated Wi-Fi Capture",
                "stepType": "AUTOMATED",
                "executor": "packet_capture",
                "config": {} # NO interface/duration configuration in metadata!
            }
        ]
    }
    
    # Update playbooks table in DB via Express repository
    call_repository("playbook", "update", ensure_uuid(PLAYBOOK_ID), {
        "name": "Wi-Fi Packet Capture Playbook (JS)",
        "severity": "HIGH",
        "status": "ACTIVE",
        "metadata": stale_metadata,
        "steps": []
    })
    
    # 2. Hard delete old steps and create new step with correct config in playbook_steps table
    call_repository("playbookStep", "deleteMany", {
        "where": { "playbookId": ensure_uuid(PLAYBOOK_ID) }
    })
    
    # Create the updated step in playbook_steps table with the correct config
    call_repository("playbookStep", "create", {
        "data": {
            "id": ensure_uuid("step-1"),
            "playbookId": ensure_uuid(PLAYBOOK_ID),
            "stepNumber": 1,
            "stepKey": "automated-wifi-capture",
            "title": "Automated Wi-Fi Capture",
            "stepType": "AUTOMATED",
            "executor": "packet_capture",
            "metadata": {
                "config": {
                    "interface": "Wi-Fi",
                    "duration": 30
                }
            },
            "createdBy": "test-user",
            "updatedBy": "test-user"
        }
    })
    print("Database simulated successfully.", flush=True)

def run_trace():
    print("=== STARTING STALE TRACE ===", flush=True)
    
    # Setup the database to mimic NestJS update
    simulate_nestjs_update()
    
    # --- STAGE 1 ---
    print("\n--- [STAGE 1] Immediately after clicking Save Playbook ---", flush=True)
    get_resp = client.get(f"/api/v2/workflow/playbooks/{PLAYBOOK_ID}")
    print(f"GET response status: {get_resp.status_code}", flush=True)
    if get_resp.status_code == 200:
        data = get_resp.json().get("data", {})
        steps = data.get("steps", [])
        if steps:
            safe_pretty("steps[0].config", steps[0].get('config'))
        else:
            print("No steps returned in GET response", flush=True)
    else:
        print(f"GET failed: {get_resp.text}", flush=True)
        
    # --- STAGE 2 ---
    print("\n--- [STAGE 2] Immediately before POST execute ---", flush=True)
    get_resp_2 = client.get(f"/api/v2/workflow/playbooks/{PLAYBOOK_ID}")
    print(f"GET response status: {get_resp_2.status_code}", flush=True)
    if get_resp_2.status_code == 200:
        data = get_resp_2.json().get("data", {})
        steps = data.get("steps", [])
        if steps:
            safe_pretty("steps[0].config", steps[0].get('config'))
        else:
            print("No steps returned in GET response", flush=True)
            
    # Trigger execution (Stages 3, 4, 5)
    print("\nTriggering execution (POST /api/v2/workflow/playbooks/{id}/execute)...", flush=True)
    exec_resp = client.post(f"/api/v2/workflow/playbooks/{PLAYBOOK_ID}/execute")
    print(f"Execute POST response status: {exec_resp.status_code}", flush=True)
    if exec_resp.status_code >= 400:
        print(f"Execute POST response body: {exec_resp.text}", flush=True)
    
    # Wait a brief moment to allow background execution task to run the executor
    import time
    time.sleep(2)
    print("\n=== TRACE RUN COMPLETED ===", flush=True)

if __name__ == "__main__":
    run_trace()
