"use strict";
/**
 * InvestigationPipeline.ts — Phase A5.4.6
 * ============================================
 * Coordinates the full investigation lifecycle workflow:
 * Create Investigation → Start Capture → Run Nmap → Create Assets →
 * Generate Findings → Generate Timeline → Raise Alerts → Generate Report → Notify Users
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.investigationPipeline = exports.InvestigationPipeline = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// Orchestrator imports
const InvestigationOrchestrator_1 = require("../investigation/InvestigationOrchestrator");
const CaptureOrchestrator_1 = require("../investigation/CaptureOrchestrator");
const ScanOrchestrator_1 = require("../investigation/ScanOrchestrator");
const ReportOrchestrator_1 = require("../investigation/ReportOrchestrator");
const NotificationOrchestrator_1 = require("../shared/NotificationOrchestrator");
// Services
const investigation_1 = require("../../services/investigation");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const crypto_1 = require("crypto");
const activeRuns = new Map();
class InvestigationPipeline extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('InvestigationPipeline');
    }
    async execute(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Starting investigation pipeline for project ${input.projectId}`);
        this.validateRequired(input, ['projectId', 'ownerId', 'title', 'target'], ctx);
        const runId = (0, crypto_1.randomUUID)();
        const run = {
            runId,
            projectId: input.projectId,
            ownerId: input.ownerId,
            title: input.title,
            target: input.target,
            actor: input.actor,
            status: 'RUNNING',
            step: 1,
            assetIds: [],
            findingIds: [],
            alertIds: [],
            compensationStack: [],
        };
        activeRuns.set(runId, run);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_PIPELINE_STARTED, ctx, {
            runId,
            projectId: input.projectId,
            title: input.title,
        });
        try {
            while (run.step <= 9 && run.status === 'RUNNING') {
                this.checkCancellation(ctx);
                await this.runStep(run, ctx);
                run.step++;
            }
            if (run.status === 'RUNNING') {
                run.status = 'SUCCEEDED';
                await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_PIPELINE_COMPLETED, ctx, {
                    runId,
                    investigationId: run.investigationId,
                    projectId: run.projectId,
                    status: run.status,
                });
            }
        }
        catch (err) {
            run.status = 'FAILED';
            this.logError(ctx, `Investigation pipeline run ${runId} failed at step ${run.step}: ${err.message}`);
            // Auto-trigger rollback
            await this.rollbackRun(run, ctx);
            throw err;
        }
        return run;
    }
    async runStep(run, ctx) {
        this.logInfo(ctx, `Executing Pipeline Step ${run.step}/9 for run ${run.runId}`);
        switch (run.step) {
            case 1: {
                // Step 1: Create Investigation
                const inv = await InvestigationOrchestrator_1.investigationOrchestrator.createInvestigation({
                    projectId: run.projectId,
                    ownerId: run.ownerId,
                    title: run.title,
                    actor: run.actor,
                }, ctx);
                run.investigationId = inv.id;
                run.compensationStack.push({
                    label: `delete-investigation-${inv.id}`,
                    fn: async () => {
                        try {
                            await prisma_1.default.investigation.delete({ where: { id: inv.id } });
                        }
                        catch (_) { }
                    }
                });
                break;
            }
            case 2: {
                // Step 2: Start Capture
                const cap = await CaptureOrchestrator_1.captureOrchestrator.startCapture({
                    investigationId: run.investigationId,
                    projectId: run.projectId,
                    interface: 'eth0',
                    actor: run.actor,
                }, ctx);
                run.captureId = cap.captureId;
                run.compensationStack.push({
                    label: `stop-capture-${cap.captureId}`,
                    fn: async () => {
                        try {
                            CaptureOrchestrator_1.captureOrchestrator.clearSessions();
                        }
                        catch (_) { }
                    }
                });
                break;
            }
            case 3: {
                // Step 3: Run Nmap
                const scan = await ScanOrchestrator_1.scanOrchestrator.startQuickScan({
                    investigationId: run.investigationId,
                    projectId: run.projectId,
                    target: run.target,
                    actor: run.actor,
                }, ctx);
                run.scanResultId = scan.scanId;
                if (scan.assetId)
                    run.assetIds.push(scan.assetId);
                run.findingIds.push(...scan.findingIds);
                run.alertIds.push(...scan.alertIds);
                break;
            }
            case 4: {
                // Step 4: Create Assets
                const asset = await investigation_1.assetService.createAsset({
                    projectId: run.projectId,
                    investigationId: run.investigationId,
                    hostname: `host-${run.target}`,
                    currentIp: run.target,
                    type: 'WORKSTATION',
                    createdBy: run.actor,
                    updatedBy: run.actor,
                });
                run.assetIds.push(asset.id);
                run.compensationStack.push({
                    label: `delete-asset-${asset.id}`,
                    fn: async () => {
                        try {
                            await prisma_1.default.asset.delete({ where: { id: asset.id } });
                        }
                        catch (_) { }
                    }
                });
                break;
            }
            case 5: {
                // Step 5: Generate Findings
                const finding = await investigation_1.findingService.createFinding({
                    projectId: run.projectId,
                    investigationId: run.investigationId,
                    assetId: run.assetIds[run.assetIds.length - 1],
                    title: `Port Scan Finding - ${run.target}`,
                    description: `Analysis detected active mapping ports on ${run.target}`,
                    severity: 'HIGH',
                    status: 'OPEN',
                    category: 'VULNERABILITY',
                    createdBy: run.actor,
                    updatedBy: run.actor,
                });
                run.findingIds.push(finding.id);
                run.compensationStack.push({
                    label: `delete-finding-${finding.id}`,
                    fn: async () => {
                        try {
                            await prisma_1.default.finding.delete({ where: { id: finding.id } });
                        }
                        catch (_) { }
                    }
                });
                break;
            }
            case 6: {
                // Step 6: Generate Timeline
                await investigation_1.timelineService.record({
                    projectId: run.projectId,
                    investigationId: run.investigationId,
                    title: 'Automated Pipeline Review',
                    description: `Orchestrated port scan findings for host host-${run.target}`,
                    type: 'MANUAL_ACTION',
                    createdBy: run.actor,
                });
                break;
            }
            case 7: {
                // Step 7: Raise Alerts
                const alert = await investigation_1.alertService.createAlert({
                    projectId: run.projectId,
                    investigationId: run.investigationId,
                    findingId: run.findingIds[run.findingIds.length - 1],
                    title: `Critical Alert - Pipeline ${run.target}`,
                    description: 'High-severity ports open on network device',
                    severity: 'HIGH',
                    status: 'NEW',
                    source: 'SCAN',
                    createdBy: run.actor,
                    updatedBy: run.actor,
                });
                run.alertIds.push(alert.id);
                run.compensationStack.push({
                    label: `delete-alert-${alert.id}`,
                    fn: async () => {
                        try {
                            await prisma_1.default.alert.delete({ where: { id: alert.id } });
                        }
                        catch (_) { }
                    }
                });
                break;
            }
            case 8: {
                // Step 8: Generate Report
                const report = await ReportOrchestrator_1.reportOrchestrator.generateInvestigationReport({
                    investigationId: run.investigationId,
                    projectId: run.projectId,
                    title: `Pipeline Report - ${run.target}`,
                    includeTimeline: true,
                    includeEvidence: true,
                    actor: run.actor,
                }, ctx);
                run.reportId = report.id;
                run.compensationStack.push({
                    label: `delete-report-${report.id}`,
                    fn: async () => {
                        try {
                            await prisma_1.default.report.delete({ where: { id: report.id } });
                        }
                        catch (_) { }
                    }
                });
                break;
            }
            case 9: {
                // Step 9: Notify Users
                await NotificationOrchestrator_1.notificationOrchestrator.sendNotification({
                    userId: run.ownerId,
                    title: 'Investigation Run Complete',
                    message: `The automated SOC workflow for target: ${run.target} succeeded.`,
                    type: 'SYSTEM',
                    actor: run.actor,
                    projectId: run.projectId,
                    investigationId: run.investigationId,
                }, ctx);
                break;
            }
            default:
                throw new Error(`Invalid step: ${run.step}`);
        }
    }
    async rollback(runId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        const run = activeRuns.get(runId);
        if (!run)
            throw new Error(`Pipeline run ${runId} not found.`);
        this.logInfo(ctx, `Forcing rollback of pipeline run ${runId}`);
        run.status = 'ROLLED_BACK';
        await this.rollbackRun(run, ctx);
        return run;
    }
    async rollbackRun(run, ctx) {
        const reversed = [...run.compensationStack].reverse();
        for (const action of reversed) {
            try {
                this.logInfo(ctx, `Compensating pipeline step: ${action.label}`);
                await action.fn();
            }
            catch (err) {
                this.logWarn(ctx, `Compensating pipeline step "${action.label}" failed: ${err.message}`);
            }
        }
        run.compensationStack = [];
    }
    async resume(runId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        const run = activeRuns.get(runId);
        if (!run)
            throw new Error(`Pipeline run ${runId} not found.`);
        if (run.status !== 'FAILED' && run.status !== 'CANCELLED') {
            throw new Error(`Pipeline run ${runId} is status ${run.status} and cannot be resumed.`);
        }
        this.logInfo(ctx, `Resuming pipeline run ${runId} from step ${run.step}`);
        run.status = 'RUNNING';
        try {
            while (run.step <= 9 && run.status === 'RUNNING') {
                this.checkCancellation(ctx);
                await this.runStep(run, ctx);
                run.step++;
            }
            if (run.status === 'RUNNING') {
                run.status = 'SUCCEEDED';
                await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_PIPELINE_COMPLETED, ctx, {
                    runId,
                    investigationId: run.investigationId,
                    projectId: run.projectId,
                    status: run.status,
                });
            }
        }
        catch (err) {
            run.status = 'FAILED';
            this.logError(ctx, `Investigation pipeline run ${runId} failed at step ${run.step}: ${err.message}`);
            throw err;
        }
        return run;
    }
    async cancel(runId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        const run = activeRuns.get(runId);
        if (!run)
            throw new Error(`Pipeline run ${runId} not found.`);
        this.logInfo(ctx, `Cancelling pipeline run ${runId}`);
        run.status = 'CANCELLED';
        return run;
    }
    async calculateStatistics(investigationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { investigationId });
        return InvestigationOrchestrator_1.investigationOrchestrator.generateStatistics(investigationId, actor, ctx);
    }
    getRun(runId) {
        return activeRuns.get(runId);
    }
    clearRuns() {
        activeRuns.clear();
    }
}
exports.InvestigationPipeline = InvestigationPipeline;
exports.investigationPipeline = new InvestigationPipeline();
