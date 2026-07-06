#!/usr/bin/env python3
"""
Comprehensive diagnostic for AI Detective data mismatch.
Loads session file, examines what's available vs what's being sent to Groq.
"""

import json
import os
import sys

PROJECT_ID = "6a40c592-1873-4a60-afb7-57abdb51a9d2"
SESSION_FILE = f"session_{PROJECT_ID}.json"
BACKEND_DIR = "C:\\NetFusion-Agent"

def load_session_file():
    """Load session file and return full data"""
    try:
        with open(SESSION_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"✗ Session file not found: {SESSION_FILE}")
        return None
    except json.JSONDecodeError as e:
        print(f"✗ Failed to parse JSON: {e}")
        return None

def analyze_available_data(session):
    """Analyze what data is available in the session"""
    print("\n" + "=" * 80)
    print("AVAILABLE DATA IN SESSION FILE")
    print("=" * 80)
    
    if not session:
        print("✗ No session data to analyze")
        return {}
    
    available = {}
    
    # Root-level keys
    print("\n[SESSION ROOT KEYS]")
    root_keys = list(session.keys())
    print(f"Total root keys: {len(root_keys)}")
    for key in root_keys:
        print(f"  - {key}")
    available["root_keys"] = root_keys
    
    # Analysis object
    print("\n[ANALYSIS OBJECT]")
    analysis = session.get("analysis", {})
    if analysis:
        print(f"  Keys: {list(analysis.keys())}")
        available["analysis_keys"] = list(analysis.keys())
        print(f"  total_packets: {analysis.get('total_packets')}")
        print(f"  total_bytes: {analysis.get('total_bytes')}")
        print(f"  conversation_count: {analysis.get('conversation_count')}")
        print(f"  protocols: {list(analysis.get('protocols', {}).keys())}")
        print(f"  top_sources count: {len(analysis.get('top_sources', []))}")
        print(f"  top_destinations count: {len(analysis.get('top_destinations', []))}")
    else:
        print("  ✗ No analysis object")
    
    # Traffic Intelligence
    print("\n[TRAFFIC INTELLIGENCE]")
    ti = session.get("trafficIntelligence", {})
    if ti:
        print(f"  Keys: {list(ti.keys())}")
        available["ti_keys"] = list(ti.keys())
        print(f"  topTalkers: {len(ti.get('topTalkers', []))} items")
        if ti.get('topTalkers'):
            print(f"    Sample: {ti['topTalkers'][0]}")
        print(f"  topProtocols: {len(ti.get('topProtocols', []))} items")
        print(f"  topExternalDestinations: {len(ti.get('topExternalDestinations', []))} items")
        print(f"  topBandwidthConsumers: {len(ti.get('topBandwidthConsumers', []))} items")
        print(f"  trafficSummary exists: {bool(ti.get('trafficSummary'))}")
        if ti.get('trafficSummary'):
            ts = ti['trafficSummary']
            print(f"    totalPackets: {ts.get('totalPackets')}")
            print(f"    totalBytes: {ts.get('totalBytes')}")
            print(f"    protocols: {list(ts.get('protocols', {}).keys())}")
    else:
        print("  ✗ No trafficIntelligence at root")
    
    # Alerts
    alerts = session.get("alerts", [])
    print(f"\n[ALERTS]")
    print(f"  Count: {len(alerts)}")
    if alerts:
        print(f"  Sample keys: {list(alerts[0].keys())}")
        print(f"  Sample: {alerts[0]}")
    
    # IOCs
    iocs = session.get("iocs", [])
    print(f"\n[IOCs]")
    print(f"  Count: {len(iocs)}")
    if iocs:
        print(f"  Sample: {iocs[0]}")
    
    # Timeline
    timeline = session.get("timeline", [])
    print(f"\n[TIMELINE]")
    print(f"  Count: {len(timeline)}")
    if timeline:
        print(f"  Sample: {timeline[0]}")
    
    # Risk Ranking
    risk_ranking = session.get("riskRanking", [])
    print(f"\n[RISK RANKING]")
    print(f"  Count: {len(risk_ranking)}")
    if risk_ranking:
        print(f"  Sample keys: {list(risk_ranking[0].keys())}")
        print(f"  Sample: {risk_ranking[0]}")
    
    # MITRE
    mitre = session.get("mitre", [])
    print(f"\n[MITRE]")
    print(f"  Count: {len(mitre)}")
    if mitre:
        print(f"  Sample: {mitre[0]}")
    
    # Investigation Plan
    print(f"\n[INVESTIGATION PLAN]")
    plan = session.get("investigationPlan", {})
    if plan:
        print(f"  ✓ Exists")
        print(f"  Keys: {list(plan.keys())}")
    else:
        print(f"  ✗ Missing")
    
    # Attack Story
    print(f"\n[ATTACK STORY]")
    story = session.get("attackStory", {})
    if story:
        print(f"  ✓ Exists")
        print(f"  Keys: {list(story.keys())}")
    else:
        print(f"  ✗ Missing")
    
    # Findings
    findings = session.get("findings", [])
    print(f"\n[FINDINGS]")
    print(f"  Count: {len(findings)}")
    if findings:
        print(f"  Sample: {findings[0]}")
    
    # Live versions
    print(f"\n[LIVE ANALYSIS (if different)]")
    live_analysis = session.get("liveAnalysis") or session.get("live_analysis")
    if live_analysis:
        print(f"  ✓ Exists")
        print(f"  Keys: {list(live_analysis.keys())}")
    else:
        print(f"  ✗ Missing")
    
    # Packets
    packets = session.get("packets", [])
    print(f"\n[PACKETS ARRAY]")
    print(f"  Count: {len(packets)}")
    if packets:
        print(f"  Sample keys: {list(packets[0].keys())}")
        print(f"  Sample: {packets[0]}")
    
    available["alerts_count"] = len(alerts)
    available["iocs_count"] = len(iocs)
    available["timeline_count"] = len(timeline)
    available["risk_ranking_count"] = len(risk_ranking)
    available["mitre_count"] = len(mitre)
    available["findings_count"] = len(findings)
    available["packets_count"] = len(packets)
    available["has_investigation_plan"] = bool(plan)
    available["has_attack_story"] = bool(story)
    
    return available

def print_mismatch_report(session, available):
    """Print field-by-field mismatch report"""
    print("\n" + "=" * 80)
    print("MISMATCH REPORT: WHAT'S IN SESSION vs WHAT DETECTIVE SENDS")
    print("=" * 80)
    
    # What the UI shows (based on available session data)
    ui_visible = {
        "packet_counts": True if available.get("packets_count", 0) > 0 else False,
        "protocols": True if "protocols" in available.get("analysis_keys", []) else False,
        "host_risk_ranking": True if available.get("risk_ranking_count", 0) > 0 else False,
        "alerts": True if available.get("alerts_count", 0) > 0 else False,
        "traffic_intelligence": True if available.get("ti_keys") else False,
        "findings": True if available.get("findings_count", 0) > 0 else False,
    }
    
    print("\n[UI VISIBLE FIELDS]")
    for field, visible in ui_visible.items():
        status = "✓ VISIBLE" if visible else "✗ NOT VISIBLE"
        print(f"  {field}: {status}")
    
    print("\n[FIELD-BY-FIELD ANALYSIS]")
    
    ti = session.get("trafficIntelligence", {})
    analysis = session.get("analysis", {})
    
    fields_to_check = {
        "pcapSummary.totalPackets": {
            "in_session": analysis.get("total_packets") or ti.get("trafficSummary", {}).get("totalPackets"),
            "source": "analysis.total_packets or trafficIntelligence.trafficSummary.totalPackets"
        },
        "pcapSummary.totalBytes": {
            "in_session": analysis.get("total_bytes") or ti.get("trafficSummary", {}).get("totalBytes"),
            "source": "analysis.total_bytes or trafficIntelligence.trafficSummary.totalBytes"
        },
        "pcapSummary.protocols": {
            "in_session": bool(analysis.get("protocols") or ti.get("trafficSummary", {}).get("protocols")),
            "source": "analysis.protocols or trafficIntelligence.trafficSummary.protocols"
        },
        "trafficSummary": {
            "in_session": bool(ti.get("trafficSummary")),
            "source": "trafficIntelligence.trafficSummary"
        },
        "topTalkers": {
            "in_session": len(ti.get("topTalkers", [])),
            "source": "trafficIntelligence.topTalkers"
        },
        "topProtocols": {
            "in_session": len(ti.get("topProtocols", [])),
            "source": "trafficIntelligence.topProtocols"
        },
        "topExternalDestinations": {
            "in_session": len(ti.get("topExternalDestinations", [])),
            "source": "trafficIntelligence.topExternalDestinations"
        },
        "alerts": {
            "in_session": available.get("alerts_count", 0),
            "source": "root.alerts"
        },
        "iocs": {
            "in_session": available.get("iocs_count", 0),
            "source": "root.iocs"
        },
        "findings": {
            "in_session": available.get("findings_count", 0),
            "source": "root.findings"
        },
        "riskRanking": {
            "in_session": available.get("risk_ranking_count", 0),
            "source": "root.riskRanking"
        },
        "timeline": {
            "in_session": available.get("timeline_count", 0),
            "source": "root.timeline"
        },
        "mitre": {
            "in_session": available.get("mitre_count", 0),
            "source": "root.mitre"
        },
        "investigationPlan": {
            "in_session": available.get("has_investigation_plan", False),
            "source": "root.investigationPlan"
        },
        "attackStory": {
            "in_session": available.get("has_attack_story", False),
            "source": "root.attackStory"
        },
    }
    
    for field, info in fields_to_check.items():
        value = info["in_session"]
        source = info["source"]
        
        if isinstance(value, bool):
            status = "✓ PRESENT" if value else "✗ MISSING"
        elif isinstance(value, int):
            if value == 0:
                status = f"✗ EMPTY (0 items)"
            else:
                status = f"✓ {value} items"
        else:
            status = f"✓ {value}"
        
        print(f"  {field:40} {status:30} (from: {source})")
    
    print("\n[WHAT DETECTIVE SENDS TO GROQ] (after pruning to 5/5/10)")
    detective_sends = {
        "pcapSummary.totalPackets": "✓" if analysis.get("total_packets") else "✗",
        "pcapSummary.totalBytes": "✓" if analysis.get("total_bytes") else "✗",
        "pcapSummary.protocols": "✓" if analysis.get("protocols") else "✗",
        "trafficSummary": "✓" if ti.get("trafficSummary") else "✗",
        "topTalkers (max 5)": f"✓ min(5, {len(ti.get('topTalkers', []))})",
        "topProtocols (max 5)": f"✓ min(5, {len(ti.get('topProtocols', []))})",
        "alerts (max 10)": f"✓ min(10, {available.get('alerts_count', 0)})",
        "iocs (max 5)": f"✓ min(5, {available.get('iocs_count', 0)})",
    }
    
    for field, status in detective_sends.items():
        print(f"  {field:40} {status}")
    
    print("\n[WHAT'S AVAILABLE BUT NOT SENT]")
    not_sent = [
        f"findings ({available.get('findings_count', 0)} items) - AVAILABLE but EXCLUDED",
        f"riskRanking ({available.get('risk_ranking_count', 0)} items) - AVAILABLE but EXCLUDED",
        f"timeline ({available.get('timeline_count', 0)} items) - AVAILABLE but EXCLUDED",
        f"mitre ({available.get('mitre_count', 0)} items) - AVAILABLE but EXCLUDED",
        f"investigationPlan - {'AVAILABLE' if available.get('has_investigation_plan') else 'MISSING'}",
        f"attackStory - {'AVAILABLE' if available.get('has_attack_story') else 'MISSING'}",
    ]
    
    for item in not_sent:
        print(f"  ✗ {item}")

if __name__ == "__main__":
    print(f"Analyzing session: {PROJECT_ID}")
    print(f"Session file: {SESSION_FILE}")
    
    session = load_session_file()
    if not session:
        sys.exit(1)
    
    available = analyze_available_data(session)
    print_mismatch_report(session, available)
    
    print("\n" + "=" * 80)
    print("END OF DIAGNOSTIC REPORT")
    print("=" * 80)
