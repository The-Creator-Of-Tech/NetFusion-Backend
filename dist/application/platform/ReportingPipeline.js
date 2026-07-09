"use strict";
/**
 * ReportingPipeline.ts — Phase A5.4.6
 * ===========================================
 * Handles multi-format and compliance report generation by coordinating AI, Reports, Investigation, Timelines, and Assets.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportingPipeline = exports.ReportingPipeline = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// Orchestrators
const ReportOrchestrator_1 = require("../investigation/ReportOrchestrator");
const AIOrchestrator_1 = require("../ai/AIOrchestrator");
// Services
const investigation_1 = require("../../services/investigation");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ReportingPipeline extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ReportingPipeline');
    }
    async generateExecutiveReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Generating executive report for ${input.investigationId}`);
        const report = await ReportOrchestrator_1.reportOrchestrator.generateExecutiveReport({
            investigationId: input.investigationId,
            projectId: input.projectId,
            actor: input.actor,
            title: input.title ?? 'Executive Incident Summary',
            includeTimeline: true,
            includeEvidence: true,
        }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORTING_COMPLETED, ctx, {
            reportId: report.id,
            investigationId: input.investigationId,
            type: 'EXECUTIVE',
        });
        return report;
    }
    async generateTechnicalReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Generating technical report for ${input.investigationId}`);
        const report = await ReportOrchestrator_1.reportOrchestrator.generateTechnicalReport({
            investigationId: input.investigationId,
            projectId: input.projectId,
            actor: input.actor,
            title: input.title ?? 'Technical Investigation Log',
            includeTimeline: true,
            includeEvidence: true,
        }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORTING_COMPLETED, ctx, {
            reportId: report.id,
            investigationId: input.investigationId,
            type: 'TECHNICAL',
        });
        return report;
    }
    async generateIncidentSummary(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Generating AI-powered incident summary for ${input.investigationId}`);
        // Fetch findings count to context summary
        const findingsCount = await prisma_1.default.finding.count({ where: { investigationId: input.investigationId } });
        // Call AI conversation / reasoning to compile a smart paragraph
        const aiSummary = await AIOrchestrator_1.aiOrchestrator.runReasoning({
            projectId: input.projectId,
            investigationId: input.investigationId,
            actor: input.actor,
            decision: `Incident compilation for investigation completed successfully. Findings discovered: ${findingsCount}`,
        }, ctx);
        const report = await ReportOrchestrator_1.reportOrchestrator.generateInvestigationReport({
            investigationId: input.investigationId,
            projectId: input.projectId,
            actor: input.actor,
            title: input.title ?? 'AI Incident Summary',
            includeTimeline: false,
            includeEvidence: false,
        }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORTING_COMPLETED, ctx, {
            reportId: report.id,
            investigationId: input.investigationId,
            type: 'AI_INCIDENT_SUMMARY',
        });
        return {
            reportId: report.id,
            aiSummary: aiSummary.decision,
            findingsCount,
        };
    }
    async generateThreatSummary(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Generating threat summary report for ${input.investigationId}`);
        // Count alerts and attacks
        const alertsCount = await prisma_1.default.alert.count({ where: { investigationId: input.investigationId } });
        const report = await ReportOrchestrator_1.reportOrchestrator.generateTechnicalReport({
            investigationId: input.investigationId,
            projectId: input.projectId,
            actor: input.actor,
            title: input.title ?? 'Threat Summary Report',
            includeTimeline: true,
            includeEvidence: false,
        }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORTING_COMPLETED, ctx, {
            reportId: report.id,
            investigationId: input.investigationId,
            type: 'THREAT_SUMMARY',
        });
        return {
            reportId: report.id,
            alertsCount,
        };
    }
    async generateComplianceReport(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Generating compliance mapping report for ${input.investigationId}`);
        // Map targets to framework
        const findings = await prisma_1.default.finding.findMany({ where: { investigationId: input.investigationId } });
        const nistMapped = findings.length > 0 ? 'NIST SP 800-61 Rev 2: Incident Response Lifecycle Map: Containment and Remediation active.' : 'Complies with framework.';
        const report = await investigation_1.reportService.createReport({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: input.title ?? 'Regulatory Compliance Assessment',
            content: `Compliance Mapping: ${nistMapped}`,
            type: 'TECHNICAL',
            status: 'DRAFT',
            createdBy: input.actor,
            updatedBy: input.actor,
            metadata: { compliance: 'NIST/HIPAA' },
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.REPORTING_COMPLETED, ctx, {
            reportId: report.id,
            investigationId: input.investigationId,
            type: 'COMPLIANCE',
        });
        return report;
    }
    async exportJSON(reportId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return ReportOrchestrator_1.reportOrchestrator.exportJSON({
            reportId,
            investigationId: '00000000-0000-4000-a000-000000000000',
            projectId: '00000000-0000-4000-a000-000000000000',
            actor,
            format: 'JSON',
        }, ctx);
    }
    async exportPDF(reportId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return ReportOrchestrator_1.reportOrchestrator.exportPDF({
            reportId,
            investigationId: '00000000-0000-4000-a000-000000000000',
            projectId: '00000000-0000-4000-a000-000000000000',
            actor,
            format: 'PDF',
        }, ctx);
    }
    async exportMarkdown(reportId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return ReportOrchestrator_1.reportOrchestrator.exportMarkdown({
            reportId,
            investigationId: '00000000-0000-4000-a000-000000000000',
            projectId: '00000000-0000-4000-a000-000000000000',
            actor,
            format: 'MARKDOWN',
        }, ctx);
    }
}
exports.ReportingPipeline = ReportingPipeline;
exports.reportingPipeline = new ReportingPipeline();
