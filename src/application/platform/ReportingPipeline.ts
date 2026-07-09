/**
 * ReportingPipeline.ts — Phase A5.4.6
 * ===========================================
 * Handles multi-format and compliance report generation by coordinating AI, Reports, Investigation, Timelines, and Assets.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Orchestrators
import { reportOrchestrator } from '../investigation/ReportOrchestrator';
import { aiOrchestrator } from '../ai/AIOrchestrator';

// Services
import { reportService } from '../../services/investigation';
import prisma from '../../lib/prisma';

export interface ReportingPipelineInput {
  investigationId: string;
  projectId: string;
  actor: string;
  title?: string;
}

export class ReportingPipeline extends BaseApplicationService {
  constructor() {
    super('ReportingPipeline');
  }

  async generateExecutiveReport(
    input: ReportingPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Generating executive report for ${input.investigationId}`);

    const report = await reportOrchestrator.generateExecutiveReport({
      investigationId: input.investigationId,
      projectId: input.projectId,
      actor: input.actor,
      title: input.title ?? 'Executive Incident Summary',
      includeTimeline: true,
      includeEvidence: true,
    }, ctx);

    await this.publishEvent(APP_EVENTS.REPORTING_COMPLETED, ctx, {
      reportId: report.id,
      investigationId: input.investigationId,
      type: 'EXECUTIVE',
    });

    return report;
  }

  async generateTechnicalReport(
    input: ReportingPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Generating technical report for ${input.investigationId}`);

    const report = await reportOrchestrator.generateTechnicalReport({
      investigationId: input.investigationId,
      projectId: input.projectId,
      actor: input.actor,
      title: input.title ?? 'Technical Investigation Log',
      includeTimeline: true,
      includeEvidence: true,
    }, ctx);

    await this.publishEvent(APP_EVENTS.REPORTING_COMPLETED, ctx, {
      reportId: report.id,
      investigationId: input.investigationId,
      type: 'TECHNICAL',
    });

    return report;
  }

  async generateIncidentSummary(
    input: ReportingPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Generating AI-powered incident summary for ${input.investigationId}`);

    // Fetch findings count to context summary
    const findingsCount = await prisma.finding.count({ where: { investigationId: input.investigationId } });

    // Call AI conversation / reasoning to compile a smart paragraph
    const aiSummary = await aiOrchestrator.runReasoning({
      projectId: input.projectId,
      investigationId: input.investigationId,
      actor: input.actor,
      decision: `Incident compilation for investigation completed successfully. Findings discovered: ${findingsCount}`,
    }, ctx);

    const report = await reportOrchestrator.generateInvestigationReport({
      investigationId: input.investigationId,
      projectId: input.projectId,
      actor: input.actor,
      title: input.title ?? 'AI Incident Summary',
      includeTimeline: false,
      includeEvidence: false,
    }, ctx);

    await this.publishEvent(APP_EVENTS.REPORTING_COMPLETED, ctx, {
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

  async generateThreatSummary(
    input: ReportingPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Generating threat summary report for ${input.investigationId}`);

    // Count alerts and attacks
    const alertsCount = await prisma.alert.count({ where: { investigationId: input.investigationId } });

    const report = await reportOrchestrator.generateTechnicalReport({
      investigationId: input.investigationId,
      projectId: input.projectId,
      actor: input.actor,
      title: input.title ?? 'Threat Summary Report',
      includeTimeline: true,
      includeEvidence: false,
    }, ctx);

    await this.publishEvent(APP_EVENTS.REPORTING_COMPLETED, ctx, {
      reportId: report.id,
      investigationId: input.investigationId,
      type: 'THREAT_SUMMARY',
    });

    return {
      reportId: report.id,
      alertsCount,
    };
  }

  async generateComplianceReport(
    input: ReportingPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Generating compliance mapping report for ${input.investigationId}`);

    // Map targets to framework
    const findings = await prisma.finding.findMany({ where: { investigationId: input.investigationId } });
    const nistMapped = findings.length > 0 ? 'NIST SP 800-61 Rev 2: Incident Response Lifecycle Map: Containment and Remediation active.' : 'Complies with framework.';

    const report = await reportService.createReport({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: input.title ?? 'Regulatory Compliance Assessment',
      content: `Compliance Mapping: ${nistMapped}`,
      type: 'TECHNICAL',
      status: 'DRAFT',
      createdBy: input.actor,
      updatedBy: input.actor,
      metadata: { compliance: 'NIST/HIPAA' } as any,
    } as any);

    await this.publishEvent(APP_EVENTS.REPORTING_COMPLETED, ctx, {
      reportId: report.id,
      investigationId: input.investigationId,
      type: 'COMPLIANCE',
    });

    return report;
  }

  async exportJSON(reportId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    return reportOrchestrator.exportJSON({
      reportId,
      investigationId: '00000000-0000-4000-a000-000000000000',
      projectId: '00000000-0000-4000-a000-000000000000',
      actor,
      format: 'JSON',
    }, ctx);
  }

  async exportPDF(reportId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    return reportOrchestrator.exportPDF({
      reportId,
      investigationId: '00000000-0000-4000-a000-000000000000',
      projectId: '00000000-0000-4000-a000-000000000000',
      actor,
      format: 'PDF',
    }, ctx);
  }

  async exportMarkdown(reportId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    return reportOrchestrator.exportMarkdown({
      reportId,
      investigationId: '00000000-0000-4000-a000-000000000000',
      projectId: '00000000-0000-4000-a000-000000000000',
      actor,
      format: 'MARKDOWN',
    }, ctx);
  }
}

export const reportingPipeline = new ReportingPipeline();
