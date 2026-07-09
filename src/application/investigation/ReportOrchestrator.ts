/**
 * ReportOrchestrator.ts — Phase A5.4.1
 * =======================================
 * Orchestrates report-generation workflows.
 *
 * Coordinates: InvestigationService · AssetService · FindingService ·
 *              EvidenceService · TimelineService · ReportService ·
 *              NotificationService · ActivityService
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationNotFoundError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

import { investigationService } from '../../services/core';
import {
  assetService,
  findingService,
  evidenceService,
  reportService,
  timelineService,
  alertService,
} from '../../services/investigation';
import { activityService, notificationService } from '../../services/shared';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type ReportType = 'INVESTIGATION' | 'EXECUTIVE' | 'TECHNICAL';

export interface GenerateReportInput {
  investigationId: string;
  projectId: string;
  actor: string;
  title?: string;
  includeTimeline?: boolean;
  includeEvidence?: boolean;
}

export interface PublishReportInput {
  reportId: string;
  investigationId: string;
  projectId: string;
  actor: string;
}

export interface ArchiveReportInput {
  reportId: string;
  investigationId: string;
  projectId: string;
  actor: string;
}

export interface ExportReportInput {
  reportId: string;
  investigationId: string;
  projectId: string;
  actor: string;
  format: 'PDF' | 'MARKDOWN' | 'JSON';
}

export interface ReportExport {
  reportId: string;
  format: string;
  content: string;
  exportedAt: Date;
}

// ─────────────────────────────────────────────────────────────────────────────
// ReportOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class ReportOrchestrator extends BaseApplicationService {
  constructor() {
    super('ReportOrchestrator');
  }

  // ── Generate Investigation Report (full) ──────────────────────────────────

  async generateInvestigationReport(input: GenerateReportInput, parentCtx?: OperationContext): Promise<any> {
    return this.generateReport('INVESTIGATION', input, parentCtx);
  }

  // ── Generate Executive Report ─────────────────────────────────────────────

  async generateExecutiveReport(input: GenerateReportInput, parentCtx?: OperationContext): Promise<any> {
    return this.generateReport('EXECUTIVE', input, parentCtx);
  }

  // ── Generate Technical Report ─────────────────────────────────────────────

  async generateTechnicalReport(input: GenerateReportInput, parentCtx?: OperationContext): Promise<any> {
    return this.generateReport('TECHNICAL', input, parentCtx);
  }

  // ── Core report generation ────────────────────────────────────────────────

  private async generateReport(
    reportType: ReportType,
    input: GenerateReportInput,
    parentCtx?: OperationContext,
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Generating ${reportType} report for investigation ${input.investigationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Verify investigation exists
      const inv = await investigationService.findInvestigation(input.investigationId);
      if (!inv) throw new OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);

      // 2. Gather data from multiple services in parallel
      const [openAlerts, timeline] = await Promise.all([
        alertService.getOpenAlerts(input.investigationId),
        input.includeTimeline
          ? timelineService.getInvestigationTimeline(input.investigationId)
          : Promise.resolve([]),
      ]);

      // 3. Use ReportService to generate the base summary
      const report = await reportService.generateSummary(input.investigationId, input.actor);

      compensation.register(`delete-report-${report.id}`, async () => {
        try {
          await reportService.archiveReport(report.id, 'system');
        } catch (_) { /* best effort */ }
      });

      // 4. Enrich with orchestration-level content
      const enrichedContent = this.buildEnrichedContent(
        reportType,
        report.content,
        {
          openAlertsCount: openAlerts.length,
          timelineEventCount: timeline.length,
          actor: input.actor,
          correlationId: ctx.correlationId,
        },
      );

      // Update report with enriched content via createReport
      const finalReport = await reportService.createReport({
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
        } as any,
      } as Prisma.ReportUncheckedCreateInput);

      // 5. Activity log
      if (this.isValidUuid(input.actor)) {
        await activityService.logCreate(
          input.actor,
          'REPORT_GENERATED',
          `${reportType} report generated for investigation "${inv.title}"`,
          input.projectId,
          input.investigationId,
        );
      }

      // 6. Notify investigation owner
      await notificationService.createNotification({
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
        ? APP_EVENTS.EXECUTIVE_REPORT_GENERATED
        : reportType === 'TECHNICAL'
          ? APP_EVENTS.TECHNICAL_REPORT_GENERATED
          : APP_EVENTS.REPORT_GENERATED;

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

  async publishReport(input: PublishReportInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
      projectId: input.projectId,
    });
    this.validateUuid(input.reportId, 'reportId', ctx);
    this.logInfo(ctx, `Publishing report ${input.reportId}`);

    const published = await reportService.publishReport(input.reportId, input.actor);

    const inv = await investigationService.findInvestigation(input.investigationId);
    if (inv) {
      await notificationService.createNotification({
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
      await activityService.logUpdate(
        input.actor,
        'REPORT_PUBLISHED',
        `Report "${published.title}" published`,
        input.projectId,
        input.investigationId,
      );
    }

    await this.publishEvent(APP_EVENTS.REPORT_PUBLISHED, ctx, {
      reportId: input.reportId,
      investigationId: input.investigationId,
      projectId: input.projectId,
    });

    this.logTiming(ctx, 'publishReport');
    return published;
  }

  // ── Archive Report ────────────────────────────────────────────────────────

  async archiveReport(input: ArchiveReportInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
    });
    this.validateUuid(input.reportId, 'reportId', ctx);
    this.logInfo(ctx, `Archiving report ${input.reportId}`);

    const archived = await reportService.archiveReport(input.reportId, input.actor);

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'REPORT_ARCHIVED',
        `Report "${archived.title}" archived`,
        input.projectId,
        input.investigationId,
      );
    }

    await this.publishEvent(APP_EVENTS.REPORT_ARCHIVED, ctx, {
      reportId: input.reportId,
      investigationId: input.investigationId,
    });

    return archived;
  }

  // ── Export PDF ────────────────────────────────────────────────────────────

  async exportPDF(input: ExportReportInput, parentCtx?: OperationContext): Promise<ReportExport> {
    return this.exportReport({ ...input, format: 'PDF' }, parentCtx);
  }

  // ── Export Markdown ───────────────────────────────────────────────────────

  async exportMarkdown(input: ExportReportInput, parentCtx?: OperationContext): Promise<ReportExport> {
    return this.exportReport({ ...input, format: 'MARKDOWN' }, parentCtx);
  }

  // ── Export JSON ───────────────────────────────────────────────────────────

  async exportJSON(input: ExportReportInput, parentCtx?: OperationContext): Promise<ReportExport> {
    return this.exportReport({ ...input, format: 'JSON' }, parentCtx);
  }

  // ── Core export ───────────────────────────────────────────────────────────

  private async exportReport(input: ExportReportInput, parentCtx?: OperationContext): Promise<ReportExport> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
    });
    this.validateUuid(input.reportId, 'reportId', ctx);
    this.logInfo(ctx, `Exporting report ${input.reportId} as ${input.format}`);

    // Retrieve markdown content
    const markdown = await reportService.generateMarkdown(input.reportId);

    // Transform to requested format
    let content: string;
    switch (input.format) {
      case 'JSON': {
        const meta = await reportService.generateMetadata(input.reportId);
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

    const exportResult: ReportExport = {
      reportId: input.reportId,
      format: input.format,
      content,
      exportedAt: new Date(),
    };

    await this.publishEvent(APP_EVENTS.REPORT_EXPORTED, ctx, {
      reportId: input.reportId,
      format: input.format,
    });

    return exportResult;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private buildEnrichedContent(
    reportType: ReportType,
    baseContent: string,
    meta: Record<string, any>,
  ): string {
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

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const reportOrchestrator = new ReportOrchestrator();
