const { PrismaClient } = require('@prisma/client');

const API_URL = 'http://127.0.0.1:8000';

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function run() {
    console.log('=== STARTING JS PCAP CONFIG VERIFICATION ===');
    const prisma = new PrismaClient();

    try {
        const targetPlaybookId = '0c2a6623-7c50-51ff-9084-25d828193688';
        console.log('Cleaning up any existing playbook...');
        await fetch(API_URL + '/api/v2/workflow/playbooks/' + targetPlaybookId, {
            method: 'DELETE'
        });

        // 1. Create Playbook with step config {"interface": "Wi-Fi", "duration": 3}
        const payload = {
            name: "Wi-Fi Packet Capture Playbook (JS)",
            projectId: "1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001",
            severity: "HIGH",
            status: "ACTIVE",
            createdAt: "2026-07-16T10:00:00Z",
            steps: [{
                stepNumber: 1,
                title: "Automated Wi-Fi Capture",
                stepType: "AUTOMATED",
                executor: "packet_capture",
                createdAt: "2026-07-16T10:00:00Z",
                config: {
                    interface: "Wi-Fi",
                    duration: 3
                }
            }]
        };

        console.log('\n1. Creating playbook via API...');
        const createRes = await fetch(API_URL + '/api/v2/workflow/playbooks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const createData = await createRes.json();
        console.log('POST Response:', JSON.stringify(createData, null, 2));
        if (!createData.data) {
            console.error('Failed to create playbook:', createData);
            return;
        }
        const playbookId = createData.data.playbookId;
        console.log('Playbook created successfully. ID:', playbookId);

        // 2. Reload Playbook via GET and verify config preservation
        console.log('\n2. Reloading playbook via API (GET)...');
        const getRes = await fetch(API_URL + '/api/v2/workflow/playbooks/' + playbookId);
        const getData = await getRes.json();
        console.log('GET Response Data:', JSON.stringify(getData, null, 2));
        const fetchedStep = getData.data.steps[0];
        const fetchedConfig = fetchedStep.config;
        console.log('GET Response Step Config:', JSON.stringify(fetchedConfig, null, 2));

        if (fetchedConfig && fetchedConfig.interface === 'Wi-Fi' && fetchedConfig.duration === 3) {
            console.log('GET CONFIG CHECK: PASSED (Preserved exactly)');
        } else {
            console.log('GET CONFIG CHECK: FAILED!');
            return;
        }

        // 3. Database Proof: query the raw metadata column
        console.log('\n3. Fetching raw database row from database...');
        const dbSteps = await prisma.playbookStep.findMany({
            where: { playbookId: playbookId }
        });
        console.log('Database Query Results:');
        for (const step of dbSteps) {
            console.log('Step ID:', step.id);
            console.log('Step Title:', step.title);
            console.log('Metadata Field:', JSON.stringify(step.metadata, null, 2));
        }

        // 4. Execute Playbook and check interface propagation
        console.log('\n4. Triggering playbook execution via API...');
        const execRes = await fetch(API_URL + `/api/v2/workflow/playbooks/${playbookId}/execute`, {
            method: 'POST'
        });
        const execData = await execRes.json();
        if (!execData.data) {
            console.error('Failed to execute playbook:', execData);
            return;
        }
        const executionId = execData.data.executionId;
        console.log('Execution triggered successfully. Execution ID:', executionId);

        console.log('Waiting 5 seconds for execution to process...');
        await sleep(5000);

        // Check variables
        console.log('\n5. Checking execution runtime variables...');
        const varsRes = await fetch(API_URL + `/api/v2/workflow/executions/${executionId}/variables`);
        const varsData = await varsRes.json();
        const variables = varsData.data || {};
        console.log('Execution Variables:', JSON.stringify(variables, null, 2));
        const capInt = variables.capture_interface;
        console.log('Resolved capture_interface variable:', capInt);
        if (capInt === 'Wi-Fi') {
            console.log('VARIABLE PROPAGATION CHECK: PASSED');
        } else {
            console.log('VARIABLE PROPAGATION CHECK: FAILED!');
        }

        // Check logs
        console.log('\n6. Checking execution logs...');
        const logsRes = await fetch(API_URL + `/api/v2/workflow/executions/${executionId}/logs`);
        const logsData = await logsRes.json();
        const logs = logsData.data || [];
        console.log('Execution Logs:');
        for (const log of logs) {
            console.log(`[${log.level}] ${log.message}`);
        }

        console.log('\n=== VERIFICATION COMPLETE ===');

    } catch (err) {
        console.error('Error during verification:', err);
    } finally {
        await prisma.$disconnect();
    }
}

run();
