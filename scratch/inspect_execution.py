import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.workflow_execution_service import _EXECUTION_STORE

executions = _EXECUTION_STORE.get_by_playbook("0c2a6623-7c50-51ff-9084-25d828193688")
print(f"Found {len(executions)} execution(s) for this playbook:")
for idx, exec_rec in enumerate(executions):
    print(f"\nExecution #{idx+1}:")
    print(f"  executionId: {exec_rec.get('executionId')}")
    print(f"  status: {exec_rec.get('status')}")
    print(f"  progress: {exec_rec.get('progress')}")
    print(f"  failedSteps: {exec_rec.get('failedSteps')}")
    print(f"  completedSteps: {exec_rec.get('completedSteps')}")
    print(f"  logs:")
    for log in exec_rec.get('logs', []):
        print(f"    [{log.get('timestamp')}] {log.get('level').upper()}: {log.get('message')}")
    print(f"  stepResults:")
    for res in exec_rec.get('stepResults', []):
        print(f"    {res.get('stepId')}: status={res.get('status')}, summary={res.get('summary')}, duration={res.get('duration')}")
