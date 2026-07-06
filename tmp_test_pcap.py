import requests
from pathlib import Path
p = Path('capture_1780563662.pcapng')
print('exists', p.exists())
with p.open('rb') as f:
    r = requests.post('http://localhost:8000/pcap/analyze', data={'projectId': 'test-project'}, files={'file': ('capture_1780563662.pcapng', f, 'application/octet-stream')})
print('status', r.status_code)
print(r.text)
