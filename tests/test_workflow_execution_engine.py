import time
import requests

def test_workflow_execution_lifecycle():
    base_url = "http://localhost:8000/api/v2/workflow"
    
    # 1. Fetch playbooks to get a valid playbookId
    print("[1] Fetching playbooks...")
    r = requests.get(f"{base_url}/playbooks")
    assert r.status_code == 200
    res = r.json()
    playbooks = res.get("data", [])
    if not playbooks:
        print("No playbooks found in database, creating a test playbook...")
        # Create a test playbook
        create_payload = {
            "name": "Test Lifecycle Playbook",
            "severity": "MEDIUM",
            "status": "ACTIVE",
            "confidence": 85,
            "description": "Test execution sequence",
            "steps": [
                {
                    "stepNumber": 1,
                    "title": "Recon Host",
                    "stepType": "MANUAL",
                    "description": "Run preliminary reconnaissance",
                    "expectedOutcome": "Host is up"
                },
                {
                    "stepNumber": 2,
                    "title": "Collect Logs",
                    "stepType": "AUTOMATED",
                    "description": "Fetch system event logs",
                    "expectedOutcome": "Logs retrieved"
                }
            ]
        }
        r = requests.post(f"{base_url}/playbooks", json=create_payload)
        assert r.status_code == 200
        playbook_id = r.json()["data"]["playbookId"]
    else:
        playbook_id = playbooks[0]["playbookId"]
        
    print(f"Selected playbookId: {playbook_id}")
    
    # 2. Trigger playbook execution
    print("[2] Triggering playbook execution...")
    r = requests.post(f"{base_url}/playbooks/{playbook_id}/execute")
    assert r.status_code == 201
    exec_res = r.json()
    assert exec_res["success"] is True
    execution_id = exec_res["data"]["executionId"]
    assert exec_res["data"]["status"] == "QUEUED"
    print(f"Triggered execution successfully! ID: {execution_id}")
    
    # 3. Poll execution status
    print("[3] Polling execution status...")
    status = "QUEUED"
    progress = 0
    current_step = None
    
    for attempt in range(30):
        time.sleep(0.2)
        r = requests.get(f"{base_url}/executions/{execution_id}")
        assert r.status_code == 200
        exec_data = r.json()["data"]
        
        status = exec_data["status"]
        progress = exec_data["progress"]
        current_step = exec_data.get("currentStep")
        logs = exec_data.get("logs") or []
        
        print(f"  Attempt {attempt+1}: Status={status}, Progress={progress}%, CurrentStep={current_step}, LogCount={len(logs)}")
        if status in ["COMPLETED", "FAILED", "ABORTED"]:
            break
            
    print(f"Final state reached: Status={status}, Progress={progress}%")
    assert status == "COMPLETED"
    assert progress == 100
    assert current_step is None
    
    # 4. Fetch logs explicitly
    print("[4] Verifying logs route...")
    r = requests.get(f"{base_url}/executions/{execution_id}/logs")
    assert r.status_code == 200
    logs_res = r.json()
    assert logs_res["success"] is True
    assert len(logs_res["data"]) > 0
    print("Logs route works! Samples:")
    for log in logs_res["data"]:
        print(f"  [{log.get('timestamp')}] [{log['level'].upper()}] {log['message']}")

if __name__ == "__main__":
    test_workflow_execution_lifecycle()
