"use strict";
/**
 * verify_platform_orchestrator.ts
 * ==================================================
 * E2E & Unit verification suite logic for Platform Orchestration Layer.
 * Exercises: PlatformOrchestrator, InvestigationPipeline, CorrelationPipeline,
 *            ResponsePipeline, ReportingPipeline, MaintenancePipeline.
 *
 * Execution: npx ts-node src/verify_platform_orchestrator.ts
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const prisma_1 = __importDefault(require("./lib/prisma"));
const PlatformOrchestrator_1 = require("./application/platform/PlatformOrchestrator");
const InvestigationPipeline_1 = require("./application/platform/InvestigationPipeline");
const CorrelationPipeline_1 = require("./application/platform/CorrelationPipeline");
const ResponsePipeline_1 = require("./application/platform/ResponsePipeline");
const ReportingPipeline_1 = require("./application/platform/ReportingPipeline");
const MaintenancePipeline_1 = require("./application/platform/MaintenancePipeline");
const core_1 = require("./repositories/core");
// Execution assertion metrics
let passed = 0;
let failed = 0;
const errors = [];
function assert(condition, label, detail) {
    if (condition) {
        passed++;
    }
    else {
        failed++;
        const msg = detail ? `${label} — ${detail}` : label;
        errors.push(msg);
        console.log(`  ✗  ${msg}`);
    }
}
function eq(a, b, label) {
    assert(a === b, label, `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}
function assertDefined(v, label) {
    assert(v !== undefined && v !== null, `${label} is defined`);
}
function assertUuid(v, label) {
    const r = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
    assert(typeof v === 'string' && r.test(v), `${label} is valid UUID`);
}
function assertString(v, label) {
    assert(typeof v === 'string' && v.length > 0, `${label} is non-empty string`);
}
function section(title) {
    console.log(`\n${'═'.repeat(60)}\n  ${title}\n${'═'.repeat(60)}`);
}
const RUN = (0, crypto_1.randomUUID)().slice(0, 8);
async function setup() {
    const user = await core_1.userRepository.create({
        email: `pl-verify-${RUN}@test.local`,
        username: `pl_${RUN}`,
        displayName: `Platform Verify ${RUN}`,
        passwordHash: 'dummy',
        status: 'ACTIVE',
    });
    const project = await core_1.projectRepository.create({
        ownerId: user.id,
        name: `Platform Project ${RUN}`,
        status: 'ACTIVE',
    });
    const defaultUuid = '00000000-0000-4000-8000-000000000000';
    // Pre-cleanup of defaultUuid records built by previous un-teared-down runs
    await prisma_1.default.playbookStep.deleteMany({ where: { playbookId: defaultUuid } });
    await prisma_1.default.playbook.deleteMany({ where: { id: defaultUuid } });
    await prisma_1.default.automationStep.deleteMany({ where: { automationId: defaultUuid } });
    await prisma_1.default.automationExecution.deleteMany({ where: { automationId: defaultUuid } });
    await prisma_1.default.automation.deleteMany({ where: { id: defaultUuid } });
    await prisma_1.default.playbook.create({
        data: {
            id: defaultUuid,
            projectId: project.id,
            name: 'Default Playbook',
            severity: 'HIGH',
            status: 'ACTIVE',
            createdBy: user.id,
            updatedBy: user.id,
        }
    });
    await prisma_1.default.automation.create({
        data: {
            id: defaultUuid,
            projectId: project.id,
            name: 'Default Automation',
            trigger: 'ALERT_CREATED',
            status: 'ACTIVE',
            createdBy: user.id,
            updatedBy: user.id,
        }
    });
    return {
        userId: user.id,
        projectId: project.id,
    };
}
async function teardown(ctx) {
    try {
        // Delete platform records created during run
        await prisma_1.default.caseFlow.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.comment.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.notification.deleteMany({ where: { userId: ctx.userId } });
        // AI executions & sessions
        await prisma_1.default.executionUsage.deleteMany({});
        await prisma_1.default.streamingChunk.deleteMany({});
        await prisma_1.default.streaming.deleteMany({});
        await prisma_1.default.execution.deleteMany({});
        await prisma_1.default.promptSection.deleteMany({});
        await prisma_1.default.promptAssembly.deleteMany({});
        await prisma_1.default.memoryEntry.deleteMany({});
        await prisma_1.default.sessionMemory.deleteMany({});
        await prisma_1.default.contextEntry.deleteMany({});
        await prisma_1.default.contextWindow.deleteMany({});
        await prisma_1.default.conversationMessage.deleteMany({});
        await prisma_1.default.conversation.deleteMany({});
        // AI provider models
        await prisma_1.default.providerModel.deleteMany({});
        await prisma_1.default.provider.deleteMany({});
        // Settings
        await prisma_1.default.systemSetting.deleteMany({ where: { createdBy: ctx.userId } });
        // Automation and playbooks
        await prisma_1.default.automationExecution.deleteMany({ where: { automation: { projectId: ctx.projectId } } });
        await prisma_1.default.automationStep.deleteMany({ where: { automation: { projectId: ctx.projectId } } });
        await prisma_1.default.automation.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.playbookStep.deleteMany({ where: { playbook: { projectId: ctx.projectId } } });
        await prisma_1.default.playbook.deleteMany({ where: { projectId: ctx.projectId } });
        // Investigation relationships
        await prisma_1.default.evidence.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.alert.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.finding.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.asset.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.report.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.timelineEvent.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.investigation.deleteMany({ where: { projectId: ctx.projectId } });
        await prisma_1.default.auditLog.deleteMany({ where: { projectId: ctx.projectId } });
        // Projects and User
        await prisma_1.default.project.deleteMany({ where: { id: ctx.projectId } });
        await prisma_1.default.user.deleteMany({ where: { id: ctx.userId } });
    }
    catch (err) {
        console.error('Teardown warning:', err.message);
    }
}
async function main() {
    console.log('Starting Platform Orchestration verification suite...');
    const ctx = await setup();
    try {
        // ─────────────────────────────────────────────────────────────────────────
        // Phase 1: Investigation Pipeline Verification
        // ─────────────────────────────────────────────────────────────────────────
        section('Phase 1: Investigation Pipeline Workflow Tests');
        const invInput = {
            projectId: ctx.projectId,
            ownerId: ctx.userId,
            title: `Pipeline Test Inv ${RUN}`,
            target: '192.168.1.1',
            actor: ctx.userId,
        };
        console.log('Running successful execution of the end-to-end investigation pipeline...');
        const resultRun = await InvestigationPipeline_1.investigationPipeline.execute(invInput);
        assertUuid(resultRun.runId, 'run.runId generation');
        eq(resultRun.status, 'SUCCEEDED', 'pipeline run.status');
        eq(resultRun.step, 10, 'final pipeline flow steps completed');
        assertUuid(resultRun.investigationId, 'resultRun.investigationId');
        assertDefined(resultRun.captureId, 'resultRun.captureId');
        assertDefined(resultRun.scanResultId, 'resultRun.scanResultId');
        assert(resultRun.assetIds.length > 0, 'asset ids generated');
        assert(resultRun.findingIds.length > 0, 'finding ids generated');
        assert(resultRun.alertIds.length > 0, 'alert ids generated');
        assertUuid(resultRun.reportId, 'report generated in pipeline');
        // Verify database entries
        const dbInv = await prisma_1.default.investigation.findUnique({ where: { id: resultRun.investigationId } });
        assertDefined(dbInv, 'Investigation created inside DB');
        eq(dbInv?.title, invInput.title, 'DB investigation title match');
        const dbAssets = await prisma_1.default.asset.findMany({ where: { investigationId: resultRun.investigationId } });
        assert(dbAssets.length > 0, 'Assets present in database');
        eq(dbAssets[0].currentIp, '192.168.1.1', 'Asset IP saved correctly');
        const dbFindings = await prisma_1.default.finding.findMany({ where: { investigationId: resultRun.investigationId } });
        assert(dbFindings.length > 0, 'Findings present in database');
        eq(dbFindings[0].severity, 'LOW', 'Finding severity auto-saved');
        const dbAlerts = await prisma_1.default.alert.findMany({ where: { investigationId: resultRun.investigationId } });
        assert(dbAlerts.length > 0, 'Alerts present in database');
        eq(dbAlerts[0].status, 'NEW', 'Alert status in db');
        // Pause/Resume Pipelines
        console.log('Testing Pause / Cancel workflow...');
        const cancelInput = { ...invInput, title: `Cancel Run ${RUN}` };
        const cancelRun = await InvestigationPipeline_1.investigationPipeline.execute({ ...cancelInput, target: '10.0.0.1' });
        const paused = await InvestigationPipeline_1.investigationPipeline.cancel(cancelRun.runId, ctx.userId);
        eq(paused.status, 'CANCELLED', 'cancelRun status after cancel() call');
        console.log('Testing Resume workflow...');
        const resumed = await InvestigationPipeline_1.investigationPipeline.resume(cancelRun.runId, ctx.userId);
        eq(resumed.status, 'SUCCEEDED', 'pipeline status after resuming execution');
        // Rollback test
        console.log('Testing LIFO-based compensation rollback details...');
        let rollbackTriggered = false;
        try {
            // Execute pipeline with invalid projectId to trigger failure compensation LIFO stacks
            await InvestigationPipeline_1.investigationPipeline.execute({
                projectId: '00000000-0000-0000-0000-000000000000',
                ownerId: ctx.userId,
                title: 'Failing Pipeline',
                target: 'wrong-target',
                actor: ctx.userId,
            });
        }
        catch (_) {
            rollbackTriggered = true;
        }
        assert(rollbackTriggered, 'failing pipeline properly threw error');
        // ─────────────────────────────────────────────────────────────────────────
        // Phase 2: Correlation Pipeline Verification
        // ─────────────────────────────────────────────────────────────────────────
        section('Phase 2: Correlation Pipeline Tests');
        const sampleFinding = dbFindings[0];
        const correlationRes = await CorrelationPipeline_1.correlationPipeline.correlateFinding({
            findingId: sampleFinding.id,
            findingTitle: sampleFinding.title,
            findingSeverity: sampleFinding.severity,
            projectId: ctx.projectId,
            investigationId: resultRun.investigationId,
            actor: ctx.userId,
        });
        assertUuid(correlationRes.findingId, 'correlation return findingId');
        assertDefined(correlationRes.techniques, 'MITRE techniques array');
        assertDefined(correlationRes.riskScore, 'calculated finding riskScore');
        assertDefined(correlationRes.recommendations, 'threat recommendations compiled');
        console.log('Correlating full investigation...');
        const fullCorrelation = await CorrelationPipeline_1.correlationPipeline.correlateInvestigation(resultRun.investigationId, ctx.projectId, ctx.userId);
        eq(fullCorrelation.investigationId, resultRun.investigationId, 'correlation investigation matches');
        assert(fullCorrelation.findingsCount > 0, 'findingsCount aligned');
        assert(fullCorrelation.overallRisk >= 10, 'calculated overall risk assessment');
        // ─────────────────────────────────────────────────────────────────────────
        // Phase 3: Response Pipeline Verification
        // ─────────────────────────────────────────────────────────────────────────
        section('Phase 3: Response Pipeline Tests');
        const sampleAlert = dbAlerts[0];
        const responsePayload = await ResponsePipeline_1.responsePipeline.respondToAlert({
            alertId: sampleAlert.id,
            projectId: ctx.projectId,
            investigationId: resultRun.investigationId,
            actor: ctx.userId,
        });
        eq(responsePayload.alertId, sampleAlert.id, 'response pipeline alert target matched');
        assertDefined(responsePayload.caseId, 'response pipeline ticket caseId');
        eq(responsePayload.status, 'CONTAINED', 'alert protocol resolution status');
        console.log('Verifying standalone case triggers...');
        const standaloneCase = await ResponsePipeline_1.responsePipeline.createCase({
            title: 'Manual Investigation Incident',
            description: 'Platform verification manual case',
            projectId: ctx.projectId,
            investigationId: resultRun.investigationId,
            actor: ctx.userId,
        });
        assertDefined(standaloneCase.caseId, 'created case ID');
        console.log('Verifying playbook standalones...');
        const startedPlaybook = await ResponsePipeline_1.responsePipeline.executePlaybook({
            playbookId: '00000000-0000-4000-8000-000000000000',
            projectId: ctx.projectId,
            investigationId: resultRun.investigationId,
            actor: ctx.userId,
        });
        eq(startedPlaybook.status, 'STARTED', 'playbook run status');
        // Rollback response
        console.log('Verifying case flow isolation rollback...');
        const rolledBackResponse = await ResponsePipeline_1.responsePipeline.rollback(standaloneCase.caseId, ctx.userId);
        eq(rolledBackResponse.status, 'ROLLED_BACK', 'rolled back case response');
        // ─────────────────────────────────────────────────────────────────────────
        // Phase 4: Reporting Pipeline Verification
        // ─────────────────────────────────────────────────────────────────────────
        section('Phase 4: Reporting Pipeline Tests');
        const execReport = await ReportingPipeline_1.reportingPipeline.generateExecutiveReport({
            investigationId: resultRun.investigationId,
            projectId: ctx.projectId,
            actor: ctx.userId,
            title: 'Platform Suite Executive Review',
        });
        assertUuid(execReport.id, 'ReportingPipeline.generateExecutiveReport.id');
        eq(execReport.title, 'Platform Suite Executive Review', 'report title matched');
        console.log('Generating multi-format compliance alignment...');
        const complianceReport = await ReportingPipeline_1.reportingPipeline.generateComplianceReport({
            investigationId: resultRun.investigationId,
            projectId: ctx.projectId,
            actor: ctx.userId,
        });
        assertUuid(complianceReport.id, 'ReportingPipeline.generateComplianceReport.id');
        assertString(complianceReport.content, 'mitre compliance report content text');
        // ─────────────────────────────────────────────────────────────────────────
        // Phase 5: Maintenance Pipeline Verification
        // ─────────────────────────────────────────────────────────────────────────
        section('Phase 5: Maintenance Pipeline & Health Assessment Tests');
        console.log('Running platform database integrity mapping...');
        const integrityRes = await MaintenancePipeline_1.maintenancePipeline.verifyIntegrity(ctx.userId);
        assertDefined(integrityRes.status, 'Integrity mapping check status');
        assertDefined(integrityRes.orphanFindings, 'Orphaned findings count');
        console.log('Checking platform global service checks...');
        const healthStatus = await MaintenancePipeline_1.maintenancePipeline.healthCheck(ctx.userId);
        assertDefined(healthStatus.status, 'Platform global health status');
        eq(healthStatus.services.database, 'UP', 'Internal database status');
        console.log('Performing platform system settings metadata backup...');
        const backupResult = await MaintenancePipeline_1.maintenancePipeline.backupMetadata(ctx.userId);
        assertDefined(backupResult.backupJson, 'settings backup JSON data');
        console.log('Clearing old platforms audit and logs...');
        const purgedCount = await MaintenancePipeline_1.maintenancePipeline.cleanupSoftDeletes(ctx.userId);
        assert(typeof purgedCount === 'number', 'soft deletion count check');
        // ─────────────────────────────────────────────────────────────────────────
        // Phase 6: Top-Level PlatformOrchestrator Unified API
        // ─────────────────────────────────────────────────────────────────────────
        section('Phase 6: Master PlatformOrchestrator End-To-End Checks');
        console.log('Executing top-level unified master SOC pipeline run...');
        const masterPipelineRun = await PlatformOrchestrator_1.platformOrchestrator.runFullPipeline({
            projectId: ctx.projectId,
            ownerId: ctx.userId,
            title: `Platform Master Flow ${RUN}`,
            target: '8.8.8.8',
            actor: ctx.userId,
        });
        assertUuid(masterPipelineRun.runId, 'master SOC run ID');
        eq(masterPipelineRun.status, 'COMPLETED', 'master SOC final status check');
        assertDefined(masterPipelineRun.correlation, 'master SOC pipeline correlation outputs');
        console.log('Cloning whole investigation...');
        const clonedInv = await PlatformOrchestrator_1.platformOrchestrator.cloneInvestigation({
            id: resultRun.investigationId,
            actor: ctx.userId,
        });
        assertUuid(clonedInv.id, 'cloned investigation ID');
        assert(clonedInv.title.includes('Clone'), 'cloned investigation folder title decoration');
        console.log('Performing global dashboard health check...');
        const orchestratorHealth = await PlatformOrchestrator_1.platformOrchestrator.performHealthCheck({ actor: ctx.userId });
        assertDefined(orchestratorHealth.status, 'orchestrator status flag check');
        console.log('Compiling platform reports via unified platform Orchestrator...');
        const platformReports = await PlatformOrchestrator_1.platformOrchestrator.generatePlatformReport({
            actor: ctx.userId,
            projectId: ctx.projectId,
            investigationId: resultRun.investigationId,
        });
        assertDefined(platformReports.executiveReportId, 'platform combined executive report id');
        assertDefined(platformReports.complianceReportId, 'platform combined compliance report id');
        // ─────────────────────────────────────────────────────────────────────────
        // Diagnostics Output
        // ─────────────────────────────────────────────────────────────────────────
        section('Verification Summary');
        console.log(`Passed assertions: ${passed}`);
        console.log(`Failed assertions: ${failed}`);
        if (failed > 0) {
            console.log('\nDetailed Errors:');
            errors.forEach((err, idx) => console.log(`  ${idx + 1}. [Failed] ${err}`));
            process.exit(1);
        }
        else {
            console.log('\nAll platform orchestration tests passed successfully! Perfect score.');
        }
    }
    catch (err) {
        console.error('Fatal execution error:', err.message);
        console.error(err.stack);
        process.exit(1);
    }
    finally {
        console.log('Performing system sanitization cleanups...');
        await teardown(ctx);
    }
}
main();
