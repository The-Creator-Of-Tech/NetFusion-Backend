import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.workflow_execution_service import _EXECUTION_STORE

exec_rec = _EXECUTION_STORE.get_by_id("d0cb778a-b01e-494b-a4c2-9aeaefbe5efe")
if exec_rec:
    print(f"executionId: {exec_rec.get('executionId')}")
    print(f"status: {exec_rec.get('status')}")
    print(f"progress: {exec_rec.get('progress')}")
    print(f"failedSteps: {exec_rec.get('failedSteps')}")
    print(f"completedSteps: {exec_rec.get('completedSteps')}")
    print(f"logs:")
    for log in exec_rec.get('logs', []):
        print(f"    [{log.get('timestamp')}] {log.get('level').upper()}: {log.get('message')}")
    print(f"stepResults:")
    for res in exec_rec.get('stepResults', []):
        print(f"    {res.get('stepId')}: status={res.get('status')}, summary={res.get('summary')}, duration={res.get('duration')}")
else:
    print("Execution not found")
