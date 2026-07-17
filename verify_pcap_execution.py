import time
import json
import os
import sys
import uuid

# Add path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.workflow_execution_service import WorkflowExecutionContext, WorkflowExecutionManager, _EXECUTION_STORE

def run():
    print("Testing PacketCaptureExecutor integration...")
    
    # Create execution ID
    execution_id = str(uuid.uuid4())
    
    # Create context manually
    ctx = WorkflowExecutionContext(
        execution_id=execution_id,
        playbook_id="test-pcap-pb-123",
        playbook_name="Test PCAP Playbook",
        steps=[
            {
                "stepId": "step-1",
                "title": "Start Network Capture",
                "description": "Capture packets",
                "stepType": "AUTOMATED",
                "stepNumber": 1,
                "config": {
                    "interface": "Ethernet",
                    "duration": 5
                }
            }
        ],
        total_steps=1
    )
    
    # Run sync in this thread for testing
    # Suppress output printing for update failures
    import contextlib
    with contextlib.redirect_stdout(None):
        WorkflowExecutionManager.run_execution_background(ctx)
    
    print(f"\nFinal Status: {ctx.status}")
    
    print("\nVariables:")
    print(json.dumps(ctx.variables, indent=2))
    
    print("\nArtifacts:")
    print(json.dumps(ctx.artifacts_as_list(), indent=2))
    
    print("\nTimeline:")
    for t in ctx.timelineEvents:
        print(f"[{t.get('timestamp')}] {t.get('title')}: {t.get('description')}")
        
    print("\nDone.")

if __name__ == "__main__":
    run()
