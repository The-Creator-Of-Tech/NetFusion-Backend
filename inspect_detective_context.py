import os
import sys
import json

sys.path.insert(0, os.getcwd())
import main

project_id = '9ca0e9bc-4208-4f18-aaaa-a38eff6dc7d8'
print('PROJECT_ID', project_id)
print('IN-MEMORY capture_sessions keys:', list(main.capture_sessions.keys()))
print('get_capture_session_data', main.get_capture_session_data(project_id))
ctx = main.build_detective_context(project_id)
print('\n=== DETECTIVE CONTEXT ===')
if ctx is None:
    print('None')
else:
    print('keys=', list(ctx.keys()))
    print('pcapSummary=', json.dumps(ctx.get('pcapSummary'), indent=2))
    print('trafficIntelligence=', json.dumps(ctx.get('trafficIntelligence'), indent=2))
    print('alerts count=', len(ctx.get('alerts', [])))
    print('iocs count=', len(ctx.get('iocs', [])))
    print('timeline count=', len(ctx.get('timeline', [])))
    print('mitre count=', len(ctx.get('mitre', [])))
    print('assets topRiskHosts count=', len(ctx.get('assets', {}).get('topRiskHosts', [])))
    lp = ctx.get('latestPcapInvestigation', {})
    print('latestPcapInvestigation keys=', list(lp.keys()))
    print('latestPcapInvestigation investigationPlan exists=', bool(lp.get('investigationPlan')))
    print('latestPcapInvestigation attackStory exists=', bool(lp.get('attackStory')))
    print('findings count by alerts+iocs=', len(ctx.get('alerts', [])) + len(ctx.get('iocs', [])))

# If running as a script, nothing else
