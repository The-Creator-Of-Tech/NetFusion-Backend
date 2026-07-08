/**
 * ReportService — Phase A5.3.3
 * ==============================
 * Business logic for Report lifecycle: generation, markdown rendering,
 * metadata extraction, publishing, and archiving.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { reportRepository, findingRepository, assetRepository, alertRepository } from '../../repositories/investigation';
import { investigationRepository } from '../../repositories/core';
import { TimelineService } from './timeline.service';
import prisma from '../../lib/prisma';
import { Report, ReportStatus, Prisma } from '@prisma/client';

export class ReportService extends BaseService {
  constructor(
    private readonly reportRepo        = reportRepository,
    private readonly findingRepo       = findingRepository,
    private readonly assetRepo         = assetRepository,
    private readonly alertRepo         = alertRepository,
    private readonly investigationRepo = investigationRepository,
    private readonly timelineSvc       = new TimelineService(),
  ) { super(); }

  // ── Generate summary ──────────────────────────────────────────────────────

  async generateSummary(investigationId: string, actor: string, tx?: any): Promise<Report> {
    this.validateUuid(investigationId, 'investigationId');
    const runInTx = async (transaction: any) => {
      const inv = await this.investigationRepo.findById(investigationId, transaction);
      if (!inv || inv.deletedAt) throw new Error(`Investigation "${investigationId}" not found.`);

      const [assets, findings, alerts] = await Promise.all([
        this.assetRepo.findByInvestigation(investigationId, transaction),
        this.findingRepo.findByInvestigation(investigationId, transaction),
        this.alertRepo.findByInvestigation(investigationId, transaction),
      ]);

      const openFindings    = findings.filter(f => f.status === 'OPEN').length;
      const criticalFindings = findings.filter(f => f.severity === 'CRITICAL').length;
      const openAlerts      = alerts.filter(a => a.status === 'OPEN').length;

      const content = [
        `# Investigation Summary: ${inv.title}`,
        '',
        `**Status:** ${inv.status}   **Priority:** ${inv.priority}`,
        `**Created:** ${inv.createdAt.toISOString()}`,
        '',
        '## Statistics',
        `- Total assets:          ${assets.length}`,
        `- Total findings:        ${findings.length}`,
        `- Open findings:         ${openFindings}`,
        `- Critical findings:     ${criticalFindings}`,
        `- Total alerts:          ${alerts.length}`,
        `- Open alerts:           ${openAlerts}`,
        '',
        '## Description',
        inv.description ?? '*(No description provided.)*',
      ].join('\n');

      const report = await this.reportRepo.create({
        projectId:      inv.projectId,
        investigationId: investigationId,
        title:          `Summary — ${inv.title}`,
        content,
        type:           'SUMMARY',
        status:         'DRAFT',
        createdBy:      actor,
        updatedBy:      actor,
        metadata: { generatedAt: new Date().toISOString(), assetCount: assets.length, findingCount: findings.length },
      }, transaction);

      await this.timelineSvc.record({
        projectId: inv.projectId, investigationId,
        title: 'Report Generated',
        description: `Summary report "${report.title}" generated.`,
        type: 'HISTORY_CREATED', createdBy: actor,
      }, transaction);

      await eventPublisher.publish('ReportGenerated', { report });
      return report;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Markdown ──────────────────────────────────────────────────────────────

  async generateMarkdown(reportId: string, tx?: any): Promise<string> {
    this.validateUuid(reportId, 'reportId');
    const report = await this.reportRepo.findById(reportId, tx);
    if (!report || report.deletedAt) throw new Error(`Report "${reportId}" not found.`);
    return report.content; // content is already Markdown
  }

  // ── Metadata ──────────────────────────────────────────────────────────────

  async generateMetadata(reportId: string, tx?: any): Promise<Record<string, any>> {
    this.validateUuid(reportId, 'reportId');
    const report = await this.reportRepo.findById(reportId, tx);
    if (!report || report.deletedAt) throw new Error(`Report "${reportId}" not found.`);
    return {
      id:          report.id,
      title:       report.title,
      type:        report.type,
      status:      report.status,
      createdAt:   report.createdAt,
      updatedAt:   report.updatedAt,
      contentLength: report.content.length,
      ...(report.metadata as any ?? {}),
    };
  }

  // ── Publish ───────────────────────────────────────────────────────────────

  async publishReport(reportId: string, actor: string, tx?: any): Promise<Report> {
    return this._transition(reportId, 'PUBLISHED', actor, 'Report Published', tx);
  }

  // ── Archive ───────────────────────────────────────────────────────────────

  async archiveReport(reportId: string, actor: string, tx?: any): Promise<Report> {
    return this._transition(reportId, 'ARCHIVED', actor, 'Report Archived', tx);
  }

  // ── Custom report ─────────────────────────────────────────────────────────

  async createReport(data: Prisma.ReportUncheckedCreateInput, tx?: any): Promise<Report> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'title', 'content', 'createdBy', 'updatedBy']);
    const runInTx = async (transaction: any) => {
      const report = await this.reportRepo.create(data, transaction);
      await this.timelineSvc.record({
        projectId: report.projectId, investigationId: report.investigationId,
        title: 'Report Created',
        description: `Report "${report.title}" created.`,
        type: 'HISTORY_CREATED', createdBy: data.createdBy as string,
      }, transaction);
      await eventPublisher.publish('ReportGenerated', { report });
      return report;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ──────────────────────────────────────────────────────────

  async getByInvestigation(investigationId: string, tx?: any): Promise<Report[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.reportRepo.findByInvestigation(investigationId, tx);
  }

  async getDrafts(tx?: any): Promise<Report[]> {
    return this.reportRepo.findDrafts(tx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  private async _transition(id: string, status: ReportStatus, actor: string, label: string, tx?: any): Promise<Report> {
    this.validateUuid(id, 'reportId');
    const runInTx = async (transaction: any) => {
      const existing = await this.reportRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Report "${id}" not found.`);
      const updated = await this.reportRepo.update(id, { status, updatedBy: actor }, transaction);
      await this.timelineSvc.record({
        projectId: updated.projectId, investigationId: updated.investigationId,
        title: label,
        description: `Report "${updated.title}" ${status.toLowerCase()}.`,
        type: 'HISTORY_CREATED', createdBy: actor,
      }, transaction);
      await eventPublisher.publish(`Report${status.charAt(0) + status.slice(1).toLowerCase()}`, { report: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
