import traceback
import requests

url = 'http://127.0.0.1:8000/ai/detective'
payload = {
    'projectId': 'test_project',
    'question': 'How many packets were captured?'
}
try:
    r = requests.post(url, json=payload, timeout=30)
    print('STATUS', r.status_code)
    print('HEADERS', r.headers)
    print('BODY', r.text)
except Exception:
    traceback.print_exc()
