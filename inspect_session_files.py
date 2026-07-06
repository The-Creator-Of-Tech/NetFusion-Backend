import json
import glob

files = glob.glob('session_*.json')
print('FILES', files)
for f in files[:5]:
    print('\n---', f)
    with open(f, 'r', encoding='utf-8') as fh:
        data = json.load(fh)
    print('keys=', sorted(list(data.keys())))
    print('trafficIntelligence', bool(data.get('trafficIntelligence')), type(data.get('trafficIntelligence')))
    if data.get('trafficIntelligence'):
        print('ti keys=', sorted(list(data['trafficIntelligence'].keys())))
        print('topTalkers=', len(data['trafficIntelligence'].get('topTalkers', [])))
        print('topProtocols=', len(data['trafficIntelligence'].get('topProtocols', [])))
    findings = data.get('findings', [])
    print('findings', len(findings) if isinstance(findings, list) else 'NA')
    alerts = data.get('alerts', [])
    print('alerts', len(alerts) if isinstance(alerts, list) else 'NA')
    risk = data.get('riskRanking', [])
    print('riskRanking', len(risk) if isinstance(risk, list) else 'NA')
    print('investigationPlan exists', data.get('investigationPlan') is not None)
    print('attackStory exists', data.get('attackStory') is not None)
