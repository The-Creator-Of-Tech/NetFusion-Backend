import os
import sys
import asyncio
from prisma import Prisma
import requests

API_URL = "http://127.0.0.1:8000"

async def verify_db_and_api():
    # 1. Create a Playbook via API
    payload = {
        "name": "Live capture verification",
        "projectId": "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001",
        "severity": "HIGH",
        "status": "ACTIVE",
        "createdAt": "2026-07-16T10:00:00Z",
        "steps": [
            {
                "stepNumber": 1,
                "title": "Perform network packet capture",
                "stepType": "AUTOMATED",
                "executor": "packet_capture",
                "createdAt": "2026-07-16T10:00:00Z"
            }
        ]
    }
    
    print("Creating playbook...")
    try:
        r = requests.post(f"{API_URL}/api/v2/workflow/playbooks", json=payload, timeout=10)
    except Exception as e:
        print(f"Failed to connect to API: {e}")
        return
        
    if r.status_code != 200:
        print(f"Failed to create playbook: {r.text}")
        return
    playbook = r.json().get("data", {})
    playbook_id = playbook.get("playbookId")
    print(f"Playbook created: {playbook_id}")

    # 2. Get Playbook via API
    print("Getting playbook via API...")
    r = requests.get(f"{API_URL}/api/v2/workflow/playbooks/{playbook_id}")
    fetched = r.json().get("data", {})
    steps = fetched.get("steps", [])
    if not steps:
        print("No steps found in playbook response")
        return
        
    api_executor = steps[0].get("executor")
    print(f"Executor from GET API: {api_executor}")
    if api_executor != "packet_capture":
        print("API PROOF FAILED: Executor is not 'packet_capture'")
        return

    # 3. Verify DB Raw Column
    print("Verifying database row directly...")
    db = Prisma()
    await db.connect()
    try:
        step_rows = await db.query_raw(f'''
            SELECT "id", "playbookId", "executor" 
            FROM playbook_steps 
            WHERE "playbookId" = '{playbook_id}'
        ''')
        print(f"Raw DB Row: {step_rows}")
        if not step_rows:
            print("No rows found in playbook_steps")
            return
            
        db_executor = step_rows[0].get("executor")
        print(f"Executor from DB Column: {db_executor}")
        if db_executor != "packet_capture":
            print("DB PROOF FAILED")
            return
    finally:
        await db.disconnect()

    print("\n--- ALL VERIFICATIONS PASSED ---")

if __name__ == "__main__":
    asyncio.run(verify_db_and_api())
