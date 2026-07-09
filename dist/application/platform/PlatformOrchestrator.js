"use strict";
/**
 * PlatformOrchestrator.ts — Phase A5.4.6
 * ===========================================
 * Master platform orchestrator coordinating all domain-specific pipelines:
 * Investigation, Correlation, Response, Reporting, and Maintenance.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.platformOrchestrator = exports.PlatformOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// Pipelines
const InvestigationPipeline_1 = require("./InvestigationPipeline");
const CorrelationPipeline_1 = require("./CorrelationPipeline");
const ResponsePipeline_1 = require("./ResponsePipeline");
const ReportingPipeline_1 = require("./ReportingPipeline");
const MaintenancePipeline_1 = require("./MaintenancePipeline");
// Other Orchestrators
const InvestigationOrchestrator_1 = require("../investigation/InvestigationOrchestrator");
// Services
const core_1 = require("../../services/core");
const investigation_1 = require("../../services/investigation");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class PlatformOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('PlatformOrchestrator');
    }
    async startInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Delegating to InvestigationPipeline to execute startInvestigation`);
        return InvestigationPipeline_1.investigationPipeline.execute(input, ctx);
    }
    async runFullPipeline(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Executing Platform Master SOC Workflow pipeline run`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Start Investigation Pipeline (Steps 1 to 9)
            const invRun = await InvestigationPipeline_1.investigationPipeline.execute(input, ctx);
            compensation.register('rollback-investigation-pipeline', async () => {
                try {
                    await InvestigationPipeline_1.investigationPipeline.rollback(invRun.runId, input.actor, ctx);
                }
                catch (_) { }
            });
            // 2. Correlate the generated findings to CVEs, MITRE ATT&CK, AI summary
            let correlationRes = null;
            if (invRun.findingIds && invRun.findingIds.length > 0) {
                correlationRes = await CorrelationPipeline_1.correlationPipeline.correlateFinding({
                    findingId: invRun.findingIds[invRun.findingIds.length - 1],
                    findingTitle: `${input.title} Port Scanning`,
                    findingSeverity: 'HIGH',
                    projectId: input.projectId,
                    investigationId: invRun.investigationId,
                    actor: input.actor,
                }, ctx);
            }
            // 3. Respond to the alert using containment protocols, automations, and trigger ticket creation
            let responseRes = null;
            if (invRun.alertIds && invRun.alertIds.length > 0) {
                responseRes = await ResponsePipeline_1.responsePipeline.respondToAlert({
                    alertId: invRun.alertIds[invRun.alertIds.length - 1],
                    projectId: input.projectId,
                    investigationId: invRun.investigationId,
                    actor: input.actor,
                }, ctx);
                compensation.register('rollback-response-actions', async () => {
                    try {
                        await ResponsePipeline_1.responsePipeline.rollback(responseRes.caseId, input.actor, ctx);
                    }
                    catch (_) { }
                });
            }
            const summaryPayload = {
                runId: invRun.runId,
                investigationId: invRun.investigationId,
                captureId: invRun.captureId,
                scanResultId: invRun.scanResultId,
                correlation: correlationRes,
                response: responseRes,
                status: 'COMPLETED',
                correlationId: ctx.correlationId,
            };
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.PLATFORM_INITIALIZED, ctx, summaryPayload);
            compensation.clear();
            return summaryPayload;
        });
    }
    async resumeInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Resuming investigation pipeline for runId ${input.runId}`);
        return InvestigationPipeline_1.investigationPipeline.resume(input.runId, input.actor, ctx);
    }
    async pauseInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Pausing investigation pipeline for runId ${input.runId}`);
        return InvestigationPipeline_1.investigationPipeline.cancel(input.runId, input.actor, ctx);
    }
    async closeInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.id });
        this.logInfo(ctx, `Closing investigation ${input.id}`);
        return InvestigationOrchestrator_1.investigationOrchestrator.closeInvestigation(input, ctx);
    }
    async archiveInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.id });
        this.logInfo(ctx, `Archiving investigation ${input.id}`);
        return InvestigationOrchestrator_1.investigationOrchestrator.archiveInvestigation(input, ctx);
    }
    async cloneInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.id });
        this.logInfo(ctx, `Cloning investigation ${input.id}`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Fetch original investigation
            const original = await core_1.investigationService.findInvestigation(input.id);
            if (!original)
                throw new Error(`Source investigation ${input.id} not found.`);
            // 2. Create cloned investigation record
            const clone = await InvestigationOrchestrator_1.investigationOrchestrator.createInvestigation({
                projectId: original.projectId,
                ownerId: original.ownerId,
                title: `${original.title} - Clone`,
                description: original.description ?? undefined,
                priority: original.priority,
                tags: original.tags,
                actor: input.actor,
            }, ctx);
            compensation.register('delete-cloned-investigation', async () => {
                try {
                    await core_1.investigationService.deleteInvestigation(clone.id);
                }
                catch (_) { }
            });
            // 3. Fetch original entities and duplicate them
            const findings = await prisma_1.default.finding.findMany({ where: { investigationId: input.id } });
            for (const f of findings) {
                await investigation_1.findingService.createFinding({
                    projectId: clone.projectId,
                    investigationId: clone.id,
                    title: f.title,
                    description: f.description,
                    severity: f.severity,
                    status: f.status,
                    category: f.category,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            const assets = await prisma_1.default.asset.findMany({ where: { investigationId: input.id } });
            for (const a of assets) {
                await investigation_1.assetService.createAsset({
                    projectId: clone.projectId,
                    investigationId: clone.id,
                    hostname: a.hostname,
                    currentIp: a.currentIp,
                    type: a.type,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            await investigation_1.timelineService.record({
                projectId: clone.projectId,
                investigationId: clone.id,
                title: 'Investigation Cloned',
                description: `Cloned from source investigation ${input.id}`,
                type: 'HISTORY_CREATED',
                createdBy: input.actor,
            });
            compensation.clear();
            return clone;
        });
    }
    async generatePlatformReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Compiling platform multi-format reports`);
        const exeReport = await ReportingPipeline_1.reportingPipeline.generateExecutiveReport({
            investigationId: input.investigationId,
            projectId: input.projectId,
            actor: input.actor,
            title: 'Platform Executive Summary',
        }, ctx);
        const compliance = await ReportingPipeline_1.reportingPipeline.generateComplianceReport({
            investigationId: input.investigationId,
            projectId: input.projectId,
            actor: input.actor,
        }, ctx);
        return {
            executiveReportId: exeReport.id,
            complianceReportId: compliance.id,
            generatedAt: new Date(),
        };
    }
    async performHealthCheck(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        return MaintenancePipeline_1.maintenancePipeline.healthCheck(input.actor, ctx);
    }
}
exports.PlatformOrchestrator = PlatformOrchestrator;
exports.platformOrchestrator = new PlatformOrchestrator();
