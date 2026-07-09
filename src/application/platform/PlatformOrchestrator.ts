/**
 * PlatformOrchestrator.ts — Phase A5.4.6
 * ===========================================
 * Master platform orchestrator coordinating all domain-specific pipelines:
 * Investigation, Correlation, Response, Reporting, and Maintenance.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Pipelines
import { investigationPipeline, InvestigationPipelineInput } from './InvestigationPipeline';
import { correlationPipeline } from './CorrelationPipeline';
import { responsePipeline } from './ResponsePipeline';
import { reportingPipeline } from './ReportingPipeline';
import { maintenancePipeline } from './MaintenancePipeline';

// Other Orchestrators
import { investigationOrchestrator } from '../investigation/InvestigationOrchestrator';

// Services
import { investigationService } from '../../services/core';
import { assetService, findingService, timelineService } from '../../services/investigation';
import prisma from '../../lib/prisma';
import { Prisma } from '@prisma/client';

export class PlatformOrchestrator extends BaseApplicationService {
  constructor() {
    super('PlatformOrchestrator');
  }

  async startInvestigation(
    input: InvestigationPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Delegating to InvestigationPipeline to execute startInvestigation`);
    return investigationPipeline.execute(input, ctx);
  }

  async runFullPipeline(
    input: InvestigationPipelineInput,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Executing Platform Master SOC Workflow pipeline run`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Start Investigation Pipeline (Steps 1 to 9)
      const invRun = await investigationPipeline.execute(input, ctx);
      
      compensation.register('rollback-investigation-pipeline', async () => {
        try {
          await investigationPipeline.rollback(invRun.runId, input.actor, ctx);
        } catch (_) {}
      });

      // 2. Correlate the generated findings to CVEs, MITRE ATT&CK, AI summary
      let correlationRes: any = null;
      if (invRun.findingIds && invRun.findingIds.length > 0) {
        correlationRes = await correlationPipeline.correlateFinding({
          findingId: invRun.findingIds[invRun.findingIds.length - 1],
          findingTitle: `${input.title} Port Scanning`,
          findingSeverity: 'HIGH',
          projectId: input.projectId,
          investigationId: invRun.investigationId!,
          actor: input.actor,
        }, ctx);
      }

      // 3. Respond to the alert using containment protocols, automations, and trigger ticket creation
      let responseRes: any = null;
      if (invRun.alertIds && invRun.alertIds.length > 0) {
        responseRes = await responsePipeline.respondToAlert({
          alertId: invRun.alertIds[invRun.alertIds.length - 1],
          projectId: input.projectId,
          investigationId: invRun.investigationId!,
          actor: input.actor,
        }, ctx);

        compensation.register('rollback-response-actions', async () => {
          try {
            await responsePipeline.rollback(responseRes.caseId, input.actor, ctx);
          } catch (_) {}
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

      await this.publishEvent(APP_EVENTS.PLATFORM_INITIALIZED, ctx, summaryPayload);

      compensation.clear();
      return summaryPayload;
    });
  }

  async resumeInvestigation(
    input: { runId: string; actor: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Resuming investigation pipeline for runId ${input.runId}`);
    return investigationPipeline.resume(input.runId, input.actor, ctx);
  }

  async pauseInvestigation(
    input: { runId: string; actor: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Pausing investigation pipeline for runId ${input.runId}`);
    return investigationPipeline.cancel(input.runId, input.actor, ctx);
  }

  async closeInvestigation(
    input: { id: string; actor: string; reason?: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.id });
    this.logInfo(ctx, `Closing investigation ${input.id}`);
    return investigationOrchestrator.closeInvestigation(input, ctx);
  }

  async archiveInvestigation(
    input: { id: string; actor: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.id });
    this.logInfo(ctx, `Archiving investigation ${input.id}`);
    return investigationOrchestrator.archiveInvestigation(input, ctx);
  }

  async cloneInvestigation(
    input: { id: string; actor: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.id });
    this.logInfo(ctx, `Cloning investigation ${input.id}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Fetch original investigation
      const original = await investigationService.findInvestigation(input.id);
      if (!original) throw new Error(`Source investigation ${input.id} not found.`);

      // 2. Create cloned investigation record
      const clone = await investigationOrchestrator.createInvestigation({
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
          await investigationService.deleteInvestigation(clone.id);
        } catch (_) {}
      });

      // 3. Fetch original entities and duplicate them
      const findings = await prisma.finding.findMany({ where: { investigationId: input.id } });
      for (const f of findings) {
        await findingService.createFinding({
          projectId: clone.projectId,
          investigationId: clone.id,
          title: f.title,
          description: f.description,
          severity: f.severity,
          status: f.status,
          category: f.category,
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.FindingUncheckedCreateInput);
      }

      const assets = await prisma.asset.findMany({ where: { investigationId: input.id } });
      for (const a of assets) {
        await assetService.createAsset({
          projectId: clone.projectId,
          investigationId: clone.id,
          hostname: a.hostname,
          currentIp: a.currentIp,
          type: a.type,
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.AssetUncheckedCreateInput);
      }

      await timelineService.record({
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

  async generatePlatformReport(
    input: { actor: string; projectId: string; investigationId: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Compiling platform multi-format reports`);

    const exeReport = await reportingPipeline.generateExecutiveReport({
      investigationId: input.investigationId,
      projectId: input.projectId,
      actor: input.actor,
      title: 'Platform Executive Summary',
    }, ctx);

    const compliance = await reportingPipeline.generateComplianceReport({
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

  async performHealthCheck(
    input: { actor: string },
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    return maintenancePipeline.healthCheck(input.actor, ctx);
  }
}

export const platformOrchestrator = new PlatformOrchestrator();
