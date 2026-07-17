const { PrismaClient } = require('@prisma/client');

async function main() {
    const prisma = new PrismaClient();
    try {
        const API_URL = 'http://127.0.0.1:8000';
        const payload = {
            'name': 'Live capture verification 4',
            'projectId': '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001',
            'severity': 'HIGH',
            'status': 'ACTIVE',
            'createdAt': '2026-07-16T10:00:00Z',
            'steps': [{
                'stepNumber': 1,
                'title': 'Perform network packet capture',
                'stepType': 'AUTOMATED',
                'executor': 'packet_capture',
                'createdAt': '2026-07-16T10:00:00Z'
            }]
        };
        const response = await fetch(API_URL + '/api/v2/workflow/playbooks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        const playbookId = data.data.playbookId;
        console.log('Playbook created:', playbookId);

        const getRes = await fetch(API_URL + '/api/v2/workflow/playbooks/' + playbookId);
        const getJson = await getRes.json();
        const apiExecutor = getJson.data.steps[0].executor;
        console.log('Executor from GET API:', apiExecutor);
        
        const dbStep = await prisma.playbookStep.findFirst({
            where: { playbookId: playbookId }
        });
        console.log('DB Row Executor:', dbStep.executor);
        if (dbStep.executor === 'packet_capture' && apiExecutor === 'packet_capture') {
            console.log('ALL VERIFICATIONS PASSED');
        } else {
            console.log('SOME VERIFICATIONS FAILED');
        }
    } finally {
        await prisma.$disconnect();
    }
}
main().catch(console.error);
