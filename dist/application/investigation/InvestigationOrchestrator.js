"use strict";
/**
 * InvestigationOrchestrator.ts — Phase A5.4.1
 * ==============================================
 * Orchestrates complete investigation lifecycle workflows.
 *
 * Every public method:
 *  1. Creates or receives an OperationContext with a correlationId
 *  2. Delegates exclusively to Service Layer singletons
 *  3. Handles cross-service coordination (timeline, activity, notifications)
 *  4. Publishes application-level events after successful completion
 *  5. Uses withCompensation() to roll back partial state on failure
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.investigationOrchestrator = exports.InvestigationOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// Service layer imports
const core_1 = require("../../services/core");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator
// ─────────────────────────────────────────────────────────────────────────────
class InvestigationOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('InvestigationOrchestrator');
    }
    // ── Create Investigation ──────────────────────────────────────────────────
    async createInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
        });
        this.logInfo(ctx, `Creating investigation: "${input.title}"`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Create the investigation via InvestigationService
            //    (already coordinates timeline + activity + notification internally)
            const inv = await core_1.investigationService.createInvestigation({
                projectId: input.projectId,
                ownerId: input.ownerId,
                title: input.title,
                description: input.description,
                priority: input.priority ?? 2,
                tags: input.tags ?? [],
            });
            compensation.register(`delete-investigation-${inv.id}`, async () => {
                try {
                    await core_1.investigationService.deleteInvestigation(inv.id);
                }
                catch (_) { /* best effort */ }
            });
            // 2. Record in timeline (additional orchestration-level event)
            await investigation_1.timelineService.record({
                projectId: inv.projectId,
                investigationId: inv.id,
                title: 'Investigation Orchestrated',
                description: `Investigation "${inv.title}" created through orchestration layer.`,
                type: 'HISTORY_CREATED',
                createdBy: input.actor,
            });
            // 3. Activity log
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logCreate(input.actor, 'INVESTIGATION_CREATED', `Investigation "${inv.title}" created`, input.projectId, inv.id);
            }
            // 4. Publish application event
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_STARTED, ctx, {
                investigationId: inv.id,
                projectId: inv.projectId,
                title: inv.title,
            });
            this.logTiming(ctx, 'createInvestigation');
            return inv;
        });
    }
    // ── Update Investigation ──────────────────────────────────────────────────
    async updateInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.id,
        });
        this.validateUuid(input.id, 'investigationId', ctx);
        this.logInfo(ctx, `Updating investigation: ${input.id}`);
        const updateData = {
            ...(input.title !== undefined && { title: input.title }),
            ...(input.description !== undefined && { description: input.description }),
            ...(input.priority !== undefined && { priority: input.priority }),
            ...(input.status !== undefined && { status: input.status }),
            ...(input.tags !== undefined && { tags: input.tags }),
        };
        const updated = await core_1.investigationService.updateInvestigation(input.id, updateData);
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'INVESTIGATION_UPDATED', `Investigation "${updated.title}" updated`, updated.projectId, updated.id);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_UPDATED, ctx, {
            investigationId: updated.id,
            projectId: updated.projectId,
        });
        this.logTiming(ctx, 'updateInvestigation');
        return updated;
    }
    // ── Close Investigation ───────────────────────────────────────────────────
    async closeInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.id });
        this.validateUuid(input.id, 'investigationId', ctx);
        this.logInfo(ctx, `Closing investigation: ${input.id}`);
        const closed = await core_1.investigationService.closeInvestigation(input.id);
        // Record closure reason in timeline if provided
        if (input.reason) {
            await investigation_1.timelineService.record({
                projectId: closed.projectId,
                investigationId: closed.id,
                title: 'Investigation Closure Reason',
                description: input.reason,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            });
        }
        // Resolve all open alerts
        const openAlerts = await investigation_1.alertService.getOpenAlerts(input.id);
        for (const alert of openAlerts) {
            await investigation_1.alertService.resolveAlert(alert.id, input.actor);
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'INVESTIGATION_CLOSED', `Investigation "${closed.title}" closed`, closed.projectId, closed.id);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_CLOSED, ctx, {
            investigationId: closed.id,
            projectId: closed.projectId,
            title: closed.title,
            closedAt: new Date(),
        });
        this.logTiming(ctx, 'closeInvestigation');
        return closed;
    }
    // ── Archive Investigation ─────────────────────────────────────────────────
    async archiveInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.id });
        this.validateUuid(input.id, 'investigationId', ctx);
        this.logInfo(ctx, `Archiving investigation: ${input.id}`);
        const archived = await core_1.investigationService.updateInvestigation(input.id, {
            status: 'ARCHIVED',
        });
        await investigation_1.timelineService.record({
            projectId: archived.projectId,
            investigationId: archived.id,
            title: 'Investigation Archived',
            description: `Investigation "${archived.title}" archived by ${input.actor}.`,
            type: 'HISTORY_CREATED',
            createdBy: input.actor,
        });
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'INVESTIGATION_ARCHIVED', `Investigation "${archived.title}" archived`, archived.projectId, archived.id);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_ARCHIVED, ctx, {
            investigationId: archived.id,
            projectId: archived.projectId,
        });
        this.logTiming(ctx, 'archiveInvestigation');
        return archived;
    }
    // ── Delete Investigation ──────────────────────────────────────────────────
    async deleteInvestigation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.id });
        this.validateUuid(input.id, 'investigationId', ctx);
        this.logInfo(ctx, `Deleting investigation: ${input.id}`);
        const inv = await core_1.investigationService.findInvestigation(input.id);
        if (!inv)
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Investigation', input.id, ctx.correlationId);
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logDelete(input.actor, 'INVESTIGATION_DELETED', `Investigation "${inv.title}" deleted`, inv.projectId, inv.id);
        }
        await core_1.investigationService.deleteInvestigation(input.id);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_DELETED, ctx, {
            investigationId: input.id,
            projectId: inv.projectId,
        });
        this.logTiming(ctx, 'deleteInvestigation');
    }
    // ── Generate Statistics ───────────────────────────────────────────────────
    async generateStatistics(investigationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { investigationId });
        this.validateUuid(investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Generating statistics for investigation: ${investigationId}`);
        const [coreStats, openAlerts] = await Promise.all([
            core_1.investigationService.calculateStatistics(investigationId),
            investigation_1.alertService.getOpenAlerts(investigationId),
        ]);
        const stats = {
            investigationId,
            assetsCount: coreStats.assetsCount,
            findingsCount: coreStats.findingsCount,
            evidenceCount: coreStats.evidenceCount,
            timelineCount: coreStats.timelineCount,
            openAlertsCount: openAlerts.length,
            criticalFindingsCount: 0, // computed below
            riskScore: 0,
            generatedAt: new Date(),
        };
        // Aggregate risk from open alerts
        for (const a of openAlerts) {
            const weights = { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 8 };
            stats.riskScore += weights[a.severity] ?? 5;
        }
        stats.riskScore = Math.min(stats.riskScore, 100);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_STATS, ctx, { investigationId, stats });
        this.logTiming(ctx, 'generateStatistics');
        return stats;
    }
    // ── Link Asset ────────────────────────────────────────────────────────────
    async linkAsset(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.investigationId });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.validateUuid(input.assetId, 'assetId', ctx);
        this.logInfo(ctx, `Linking asset ${input.assetId} to investigation ${input.investigationId}`);
        // Update asset so it is associated with the investigation
        await investigation_1.assetService.updateAsset(input.assetId, {
            investigationId: input.investigationId,
            updatedBy: input.actor,
        });
        await investigation_1.timelineService.record({
            projectId: (await core_1.investigationService.findInvestigation(input.investigationId)).projectId,
            investigationId: input.investigationId,
            title: 'Asset Linked',
            description: `Asset ${input.assetId} linked to investigation.`,
            type: 'HISTORY_CREATED',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.ASSET_LINKED, ctx, {
            investigationId: input.investigationId,
            assetId: input.assetId,
        });
    }
    // ── Link Finding ──────────────────────────────────────────────────────────
    async linkFinding(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.investigationId });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.validateUuid(input.findingId, 'findingId', ctx);
        this.logInfo(ctx, `Linking finding ${input.findingId} to investigation ${input.investigationId}`);
        await investigation_1.findingService.updateFinding(input.findingId, {
            investigationId: input.investigationId,
            updatedBy: input.actor,
        });
        const inv = await core_1.investigationService.findInvestigation(input.investigationId);
        if (!inv)
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);
        await investigation_1.timelineService.record({
            projectId: inv.projectId,
            investigationId: input.investigationId,
            title: 'Finding Linked',
            description: `Finding ${input.findingId} linked to investigation.`,
            type: 'FINDING_CREATED',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.FINDING_LINKED, ctx, {
            investigationId: input.investigationId,
            findingId: input.findingId,
        });
    }
    // ── Link Evidence ─────────────────────────────────────────────────────────
    async linkEvidence(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { investigationId: input.investigationId });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.validateUuid(input.evidenceId, 'evidenceId', ctx);
        this.logInfo(ctx, `Linking evidence ${input.evidenceId} to investigation ${input.investigationId}`);
        const inv = await core_1.investigationService.findInvestigation(input.investigationId);
        if (!inv)
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);
        await investigation_1.timelineService.record({
            projectId: inv.projectId,
            investigationId: input.investigationId,
            title: 'Evidence Imported',
            description: `Evidence ${input.evidenceId} imported into investigation.`,
            type: 'EVIDENCE_ADDED',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.EVIDENCE_IMPORTED, ctx, {
            evidenceId: input.evidenceId,
            investigationId: input.investigationId,
            projectId: inv.projectId,
            sourceType: 'MANUAL',
        });
    }
    // ── Generate Executive Summary ────────────────────────────────────────────
    async generateExecutiveSummary(investigationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { investigationId });
        this.validateUuid(investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Generating executive summary for: ${investigationId}`);
        // Generate the summary report through ReportService
        const report = await investigation_1.reportService.generateSummary(investigationId, actor);
        const inv = await core_1.investigationService.findInvestigation(investigationId);
        if (inv) {
            await shared_1.notificationService.createNotification({
                userId: inv.ownerId,
                title: 'Executive Summary Ready',
                message: `Executive summary for "${inv.title}" has been generated.`,
                type: 'SYSTEM',
                status: 'UNREAD',
                createdBy: actor,
                updatedBy: actor,
            });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_SUMMARY, ctx, {
            investigationId,
            reportId: report.id,
        });
        this.logTiming(ctx, 'generateExecutiveSummary');
        return report;
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.InvestigationOrchestrator = InvestigationOrchestrator;
exports.investigationOrchestrator = new InvestigationOrchestrator();
