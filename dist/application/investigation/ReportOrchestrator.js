"use strict";
/**
 * ReportOrchestrator.ts — Phase A5.4.1
 * =======================================
 * Orchestrates report-generation workflows.
 *
 * Coordinates: InvestigationService · AssetService · FindingService ·
 *              EvidenceService · TimelineService · ReportService ·
 *              NotificationService · ActivityService
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportOrchestrator = exports.ReportOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const core_1 = require("../../services/core");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// ReportOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class ReportOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ReportOrchestrator');
    }
    // ── Generate Investigation Report (full) ──────────────────────────────────
    async generateInvestigationReport(input, parentCtx) {
        return this.generateReport('INVESTIGATION', input, parentCtx);
    }
    // ── Generate Executive Report ─────────────────────────────────────────────
    async generateExecutiveReport(input, parentCtx) {
        return this.generateReport('EXECUTIVE', input, parentCtx);
    }
    // ── Generate Technical Report ─────────────────────────────────────────────
    async generateTechnicalReport(input, parentCtx) {
        return this.generateReport('TECHNICAL', input, parentCtx);
    }
    // ── Core report generation ────────────────────────────────────────────────
    async generateReport(reportType, input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Generating ${reportType} report for investigation ${input.investigationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Verify investigation exists
            const inv = await core_1.investigationService.findInvestigation(input.investigationId);
            if (!inv)
                throw new BaseApplicationService_1.OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);
            // 2. Gather data from multiple services in parallel
            const [openAlerts, timeline] = await Promise.all([
                investigation_1.alertService.getOpenAlerts(input.investigationId),
                input.includeTimeline
                    ? investigation_1.timelineService.getInvestigationTimeline(input.investigationId)
                    : Promise.resolve([]),
            ]);
            // 3. Use ReportService to generate the base summary
            const report = await investigation_1.reportService.generateSummary(input.investigationId, input.actor);
            compensation.register(`delete-report-${report.id}`, async () => {
                try {
                    await investigation_1.reportService.archiveReport(report.id, 'system');
                }
                catch (_) { /* best effort */ }
            });
            // 4. Enrich with orchestration-level content
            const enrichedContent = this.buildEnrichedContent(reportType, report.content, {
                openAlertsCount: openAlerts.length,
                timelineEventCount: timeline.length,
                actor: input.actor,
                correlationId: ctx.correlationId,
            });
            // Update report with enriched content via createReport
            const finalReport = await investigation_1.reportService.createReport({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: input.title ?? `${reportType} Report — ${inv.title}`,
                content: enrichedContent,
                type: reportType,
                status: 'DRAFT',
                createdBy: input.actor,
                updatedBy: input.actor,
                metadata: {
                    reportType,
                    correlationId: ctx.correlationId,
                    openAlertsCount: openAlerts.length,
                    timelineEventCount: timeline.length,
                    generatedAt: new Date().toISOString(),
                },
            });
            // 5. Activity log
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logCreate(input.actor, 'REPORT_GENERATED', `${reportType} report generated for investigation "${inv.title}"`, input.projectId, input.investigationId);
            }
            // 6. Notify investigation owner
            await shared_1.notificationService.createNotification({
                userId: inv.ownerId,
                title: `${reportType} Report Ready`,
                message: `Your ${reportType.toLowerCase()} report for "${inv.title}" is available.`,
                type: 'SYSTEM',
                status: 'UNREAD',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            // 7. Publish event
            const eventName = reportType === 'EXECUTIVE'
                ? ApplicationEvents_1.APP_EVENTS.EXECUTIVE_REPORT_GENERATED
                : reportType === 'TECHNICAL'
                    ? ApplicationEvents_1.APP_EVENTS.TECHNICAL_REPORT_GENERATED
                    : ApplicationEvents_1.APP_EVENTS.REPORT_GENERATED;
            await this.publishEvent(eventName, ctx, {
                reportId: finalReport.id,
                investigationId: input.investigationId,
                projectId: input.projectId,
                reportType,
            });
            this.logTiming(ctx, `generateReport(${reportType})`);
            compensation.clear();
            return finalReport;
        });
    }
    // ── Publish Report ────────────────────────────────────────────────────────
    async publishReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        this.validateUuid(input.reportId, 'reportId', ctx);
        this.logInfo(ctx, `Publishing report ${input.reportId}`);
        const published = await investigation_1.reportService.publishReport(input.reportId, input.actor);
        const inv = await core_1.investigationService.findInvestigation(input.investigationId);
        if (inv) {
            await shared_1.notificationService.createNotification({
                userId: inv.ownerId,
                title: 'Report Published',
                message: `Report "${published.title}" has been published.`,
                type: 'SYSTEM',
                status: 'UNREAD',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'REPORT_PUBLISHED', `Report "${published.title}" published`, input.projectId, input.investigationId);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORT_PUBLISHED, ctx, {
            reportId: input.reportId,
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        this.logTiming(ctx, 'publishReport');
        return published;
    }
    // ── Archive Report ────────────────────────────────────────────────────────
    async archiveReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
        });
        this.validateUuid(input.reportId, 'reportId', ctx);
        this.logInfo(ctx, `Archiving report ${input.reportId}`);
        const archived = await investigation_1.reportService.archiveReport(input.reportId, input.actor);
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'REPORT_ARCHIVED', `Report "${archived.title}" archived`, input.projectId, input.investigationId);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORT_ARCHIVED, ctx, {
            reportId: input.reportId,
            investigationId: input.investigationId,
        });
        return archived;
    }
    // ── Export PDF ────────────────────────────────────────────────────────────
    async exportPDF(input, parentCtx) {
        return this.exportReport({ ...input, format: 'PDF' }, parentCtx);
    }
    // ── Export Markdown ───────────────────────────────────────────────────────
    async exportMarkdown(input, parentCtx) {
        return this.exportReport({ ...input, format: 'MARKDOWN' }, parentCtx);
    }
    // ── Export JSON ───────────────────────────────────────────────────────────
    async exportJSON(input, parentCtx) {
        return this.exportReport({ ...input, format: 'JSON' }, parentCtx);
    }
    // ── Core export ───────────────────────────────────────────────────────────
    async exportReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
        });
        this.validateUuid(input.reportId, 'reportId', ctx);
        this.logInfo(ctx, `Exporting report ${input.reportId} as ${input.format}`);
        // Retrieve markdown content
        const markdown = await investigation_1.reportService.generateMarkdown(input.reportId);
        // Transform to requested format
        let content;
        switch (input.format) {
            case 'JSON': {
                const meta = await investigation_1.reportService.generateMetadata(input.reportId);
                content = JSON.stringify({ metadata: meta, content: markdown }, null, 2);
                break;
            }
            case 'PDF':
                // In a real system this would call a PDF library; here we annotate the markdown
                content = `%PDF-1.4\n% Generated by NetFusion\n\n${markdown}`;
                break;
            case 'MARKDOWN':
            default:
                content = markdown;
                break;
        }
        const exportResult = {
            reportId: input.reportId,
            format: input.format,
            content,
            exportedAt: new Date(),
        };
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORT_EXPORTED, ctx, {
            reportId: input.reportId,
            format: input.format,
        });
        return exportResult;
    }
    // ── Helpers ───────────────────────────────────────────────────────────────
    buildEnrichedContent(reportType, baseContent, meta) {
        const header = [
            `## Report Type: ${reportType}`,
            `**Generated by:** ${meta.actor}`,
            `**Correlation ID:** ${meta.correlationId}`,
            `**Open Alerts:** ${meta.openAlertsCount}`,
            `**Timeline Events:** ${meta.timelineEventCount}`,
            '',
            '---',
            '',
        ].join('\n');
        return `${header}${baseContent}`;
    }
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.ReportOrchestrator = ReportOrchestrator;
exports.reportOrchestrator = new ReportOrchestrator();
