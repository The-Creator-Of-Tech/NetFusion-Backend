#!/usr/bin/env python3
"""
Diagnostic test for AI Detective data loading.
Calls /ai/detective endpoint and captures all debug output to identify:
1. Which data sources are being read (in-memory, file, Prisma)
2. What fields are available vs missing
3. Mismatch between UI data and detective context
"""

import requests
import json
import sys

# Test with the known projectId from session file
PROJECT_ID = "6a40c592-1873-4a60-afb7-57abdb51a9d2"
BACKEND_URL = "http://localhost:8000"
DETECTIVE_ENDPOINT = f"{BACKEND_URL}/ai/detective"

def test_detective_endpoint():
    """Call /ai/detective with a simple question and capture debug output"""
    
    payload = {
        "projectId": PROJECT_ID,
        "question": "How many packets were captured in this session?"
    }
    
    print("=" * 80)
    print("TESTING AI DETECTIVE ENDPOINT")
    print("=" * 80)
    print(f"URL: {DETECTIVE_ENDPOINT}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    print("=" * 80)
    
    try:
        response = requests.post(DETECTIVE_ENDPOINT, json=payload, timeout=10)
        print(f"\nHTTP Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print("\n✓ Response received successfully")
            print(f"\nResponse content:")
            print(json.dumps(data, indent=2))
        else:
            print(f"\n✗ Error response: {response.status_code}")
            print(f"Body: {response.text[:500]}")
            
    except requests.exceptions.ConnectionError:
        print(f"\n✗ Failed to connect to {BACKEND_URL}")
        print("  Make sure FastAPI backend is running: python main.py")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"\n✗ Request timed out after 10 seconds")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print(f"Testing AI Detective with projectId: {PROJECT_ID}\n")
    test_detective_endpoint()
    print("\n" + "=" * 80)
    print("Check backend console output (stdout/stderr) for debug trace:")
    print("  STEP A: CHECK LATEST PCAP INVESTIGATION")
    print("  STEP B: CHECK LIVE CAPTURE FALLBACK")
    print("  STEP 1-6: TRACE build_detective_context()")
    print("  STEP A-G: TRACE ai_detective() loading")
    print("=" * 80)
