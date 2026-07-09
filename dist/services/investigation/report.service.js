"use strict";
/**
 * ReportService — Phase A5.3.3
 * ==============================
 * Business logic for Report lifecycle: generation, markdown rendering,
 * metadata extraction, publishing, and archiving.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReportService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const core_1 = require("../../repositories/core");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ReportService extends BaseService_1.BaseService {
    constructor(reportRepo = investigation_1.reportRepository, findingRepo = investigation_1.findingRepository, assetRepo = investigation_1.assetRepository, alertRepo = investigation_1.alertRepository, investigationRepo = core_1.investigationRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.reportRepo = reportRepo;
        this.findingRepo = findingRepo;
        this.assetRepo = assetRepo;
        this.alertRepo = alertRepo;
        this.investigationRepo = investigationRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Generate summary ──────────────────────────────────────────────────────
    async generateSummary(investigationId, actor, tx) {
        this.validateUuid(investigationId, 'investigationId');
        const runInTx = async (transaction) => {
            const inv = await this.investigationRepo.findById(investigationId, transaction);
            if (!inv || inv.deletedAt)
                throw new Error(`Investigation "${investigationId}" not found.`);
            const [assets, findings, alerts] = await Promise.all([
                this.assetRepo.findByInvestigation(investigationId, transaction),
                this.findingRepo.findByInvestigation(investigationId, transaction),
                this.alertRepo.findByInvestigation(investigationId, transaction),
            ]);
            const openFindings = findings.filter(f => f.status === 'OPEN').length;
            const criticalFindings = findings.filter(f => f.severity === 'CRITICAL').length;
            const openAlerts = alerts.filter(a => a.status === 'OPEN').length;
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
                projectId: inv.projectId,
                investigationId: investigationId,
                title: `Summary — ${inv.title}`,
                content,
                type: 'SUMMARY',
                status: 'DRAFT',
                createdBy: actor,
                updatedBy: actor,
                metadata: { generatedAt: new Date().toISOString(), assetCount: assets.length, findingCount: findings.length },
            }, transaction);
            await this.timelineSvc.record({
                projectId: inv.projectId, investigationId,
                title: 'Report Generated',
                description: `Summary report "${report.title}" generated.`,
                type: 'HISTORY_CREATED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('ReportGenerated', { report });
            return report;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Markdown ──────────────────────────────────────────────────────────────
    async generateMarkdown(reportId, tx) {
        this.validateUuid(reportId, 'reportId');
        const report = await this.reportRepo.findById(reportId, tx);
        if (!report || report.deletedAt)
            throw new Error(`Report "${reportId}" not found.`);
        return report.content; // content is already Markdown
    }
    // ── Metadata ──────────────────────────────────────────────────────────────
    async generateMetadata(reportId, tx) {
        this.validateUuid(reportId, 'reportId');
        const report = await this.reportRepo.findById(reportId, tx);
        if (!report || report.deletedAt)
            throw new Error(`Report "${reportId}" not found.`);
        return {
            id: report.id,
            title: report.title,
            type: report.type,
            status: report.status,
            createdAt: report.createdAt,
            updatedAt: report.updatedAt,
            contentLength: report.content.length,
            ...(report.metadata ?? {}),
        };
    }
    // ── Publish ───────────────────────────────────────────────────────────────
    async publishReport(reportId, actor, tx) {
        return this._transition(reportId, 'PUBLISHED', actor, 'Report Published', tx);
    }
    // ── Archive ───────────────────────────────────────────────────────────────
    async archiveReport(reportId, actor, tx) {
        return this._transition(reportId, 'ARCHIVED', actor, 'Report Archived', tx);
    }
    // ── Custom report ─────────────────────────────────────────────────────────
    async createReport(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'title', 'content', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const report = await this.reportRepo.create(data, transaction);
            await this.timelineSvc.record({
                projectId: report.projectId, investigationId: report.investigationId,
                title: 'Report Created',
                description: `Report "${report.title}" created.`,
                type: 'HISTORY_CREATED', createdBy: data.createdBy,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('ReportGenerated', { report });
            return report;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ──────────────────────────────────────────────────────────
    async getByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.reportRepo.findByInvestigation(investigationId, tx);
    }
    async getDrafts(tx) {
        return this.reportRepo.findDrafts(tx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────
    async _transition(id, status, actor, label, tx) {
        this.validateUuid(id, 'reportId');
        const runInTx = async (transaction) => {
            const existing = await this.reportRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Report "${id}" not found.`);
            const updated = await this.reportRepo.update(id, { status, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: updated.projectId, investigationId: updated.investigationId,
                title: label,
                description: `Report "${updated.title}" ${status.toLowerCase()}.`,
                type: 'HISTORY_CREATED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish(`Report${status.charAt(0) + status.slice(1).toLowerCase()}`, { report: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ReportService = ReportService;
