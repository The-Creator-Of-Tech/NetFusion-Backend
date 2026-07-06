import os, sys, traceback
sys.path.insert(0, os.getcwd())
from main import app, ai_detective, build_detective_context, capture_sessions, get_capture_session, get_latest_pcap_investigation
from fastapi.testclient import TestClient

print('=== env ===')
print('GROQ_API_KEY', os.getenv('GROQ_API_KEY'))
print('PRISMA_API_BASE_URL', os.getenv('PRISMA_API_BASE_URL'))
print('client', type(globals().get('app')))
print('routes', [r.path for r in app.routes if hasattr(r, 'path')])

client = TestClient(app)

try:
    resp = client.post('/ai/detective', json={'projectId': 'test_project', 'question': 'How many packets were captured?'})
    print('TESTCLIENT STATUS', resp.status_code)
    print('TEXT', resp.text)
    print('JSON', resp.json() if resp.text else None)
except Exception:
    traceback.print_exc()

print('=== create dummy session ===')
create_result = create_or_update_capture_session = None
try:
    # use function from module if available
    create_or_update_capture_session = globals().get('create_or_update_capture_session')
except Exception:
    pass

import main as m
m.capture_sessions['test_project'] = {
    'projectId': 'test_project',
    'captureId': 'capture_1',
    'analysis': {},
    'liveAnalysis': {'protocols': {'TCP': 10}, 'total_packets': 10},
    'liveSummary': {'totalPackets': 10, 'totalBytes': 1000, 'protocols': {'TCP': 10}},
    'packets': [{'src':'10.0.0.1','dst':'10.0.0.2','protocol':'TCP','length':'100'}],
    'timeline': [],
    'alerts': [],
    'iocs': [],
    'mitre': [],
    'riskRanking': []
}
try:
    ctx = m.build_detective_context('test_project')
    print('build_detective_context returned', type(ctx))
    print('ctx keys', list(ctx.keys()))
    print('pcapSummary', ctx.get('pcapSummary'))
except Exception:
    traceback.print_exc()

try:
    result = m.ai_detective({'projectId': 'test_project', 'question': 'How many packets were captured?'})
    print('ai_detective result', result)
except Exception:
    traceback.print_exc()
