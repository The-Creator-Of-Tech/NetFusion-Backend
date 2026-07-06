#!/usr/bin/env python3
"""
Deep dive into liveAnalysis structure - where the real data is.
"""

import json
import sys

PROJECT_ID = "6a40c592-1873-4a60-afb7-57abdb51a9d2"
SESSION_FILE = f"session_{PROJECT_ID}.json"

def deep_analyze():
    try:
        with open(SESSION_FILE, "r") as f:
            session = json.load(f)
    except Exception as e:
        print(f"✗ Failed to load session: {e}")
        return
    
    print("=" * 80)
    print("DEEP DIVE: liveAnalysis STRUCTURE")
    print("=" * 80)
    
    live_analysis = session.get("liveAnalysis", {})
    print(f"\nliveAnalysis type: {type(live_analysis)}")
    print(f"liveAnalysis keys: {list(live_analysis.keys())}")
    
    for key in live_analysis.keys():
        value = live_analysis[key]
        if isinstance(value, dict):
            print(f"\n  [{key}] - dict")
            print(f"    Keys: {list(value.keys())}")
            if len(str(value)) < 500:
                print(f"    Content: {value}")
        elif isinstance(value, list):
            print(f"\n  [{key}] - list")
            print(f"    Length: {len(value)}")
            if value:
                print(f"    First item: {value[0] if len(str(value[0])) < 200 else str(value[0])[:200]}")
        else:
            print(f"\n  [{key}] - {type(value).__name__}")
            print(f"    Value: {value}")
    
    # Focus on trafficIntelligence
    print("\n" + "=" * 80)
    print("TRAFFIC INTELLIGENCE IN liveAnalysis")
    print("=" * 80)
    
    ti = live_analysis.get("trafficIntelligence", {})
    print(f"\ntrafficIntelligence type: {type(ti)}")
    print(f"trafficIntelligence keys: {list(ti.keys())}")
    
    for key in ti.keys():
        value = ti[key]
        if isinstance(value, dict):
            print(f"\n  [{key}] - dict with {len(value)} keys")
            print(f"    Keys: {list(value.keys())[:5]}...")
        elif isinstance(value, list):
            print(f"\n  [{key}] - list with {len(value)} items")
            if value:
                first = value[0]
                if isinstance(first, dict):
                    print(f"    First item keys: {list(first.keys())}")
                    print(f"    First item: {json.dumps(first, indent=6)[:300]}")
                else:
                    print(f"    First item: {first}")
        else:
            print(f"\n  [{key}] - {type(value).__name__}")
            print(f"    Value: {value}")
    
    # What build_detective_context is actually getting
    print("\n" + "=" * 80)
    print("WHAT build_detective_context() SHOULD BE USING")
    print("=" * 80)
    
    print("\n[CRITICAL FINDING]")
    print("Session root has NO 'analysis' key - it has 'liveAnalysis'")
    print("Session root has NO 'trafficIntelligence' key - it's in liveAnalysis.trafficIntelligence")
    print("Session root has NO 'alerts', 'iocs', 'timeline', 'riskRanking', 'mitre' keys")
    print("\nAll analysis data is NESTED inside liveAnalysis!")
    
    print("\n[AVAILABLE IN liveAnalysis]")
    la_keys = list(live_analysis.keys())
    for key in la_keys:
        val = live_analysis[key]
        if isinstance(val, dict):
            count = len(val)
            print(f"  {key:30} dict with {count} keys")
        elif isinstance(val, list):
            count = len(val)
            print(f"  {key:30} list with {count} items")
        else:
            print(f"  {key:30} {type(val).__name__}")
    
    print("\n[AVAILABLE IN liveAnalysis.trafficIntelligence]")
    for key in ti.keys():
        val = ti[key]
        if isinstance(val, dict):
            count = len(val)
            print(f"  {key:30} dict with {count} keys")
        elif isinstance(val, list):
            count = len(val)
            print(f"  {key:30} list with {count} items")
        else:
            print(f"  {key:30} {type(val).__name__}")

if __name__ == "__main__":
    deep_analyze()
