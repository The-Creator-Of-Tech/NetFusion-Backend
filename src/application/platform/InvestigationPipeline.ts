/**
 * InvestigationPipeline.ts — Phase A5.4.6
 * ============================================
 * Coordinates the full investigation lifecycle workflow:
 * Create Investigation → Start Capture → Run Nmap → Create Assets →
 * Generate Findings → Generate Timeline → Raise Alerts → Generate Report → Notify Users
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Orchestrator imports
import { investigationOrchestrator } from '../investigation/InvestigationOrchestrator';
import { captureOrchestrator } from '../investigation/CaptureOrchestrator';
import { scanOrchestrator } from '../investigation/ScanOrchestrator';
import { reportOrchestrator } from '../investigation/ReportOrchestrator';
import { notificationOrchestrator } from '../shared/NotificationOrchestrator';

// Services
import { assetService, findingService, alertService, timelineService } from '../../services/investigation';
import prisma from '../../lib/prisma';
import { randomUUID } from 'crypto';
import { Prisma } from '@prisma/client';

export interface InvestigationPipelineInput {
  projectId: string;
  ownerId: string;
  title: string;
  target: string;
  actor: string;
}

export interface InvestigationPipelineRun {
  runId: string;
  projectId: string;
  ownerId: string;
  title: string;
  target: string;
  actor: string;
  status: 'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED' | 'ROLLED_BACK';
  step: number; 
  investigationId?: string;
  captureId?: string;
  scanResultId?: string;
  assetIds: string[];
  findingIds: string[];
  alertIds: string[];
  reportId?: string;
  compensationStack: Array<{ label: string; fn: () => Promise<void> }>;
}

const activeRuns = new Map<string, InvestigationPipelineRun>();

export class InvestigationPipeline extends BaseApplicationService {
  constructor() {
    super('InvestigationPipeline');
  }

  async execute(input: InvestigationPipelineInput, parentCtx?: OperationContext): Promise<InvestigationPipelineRun> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Starting investigation pipeline for project ${input.projectId}`);
    this.validateRequired(input, ['projectId', 'ownerId', 'title', 'target'], ctx);

    const runId = randomUUID();
    const run: InvestigationPipelineRun = {
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

    await this.publishEvent(APP_EVENTS.INVESTIGATION_PIPELINE_STARTED, ctx, {
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
        await this.publishEvent(APP_EVENTS.INVESTIGATION_PIPELINE_COMPLETED, ctx, {
          runId,
          investigationId: run.investigationId,
          projectId: run.projectId,
          status: run.status,
        });
      }
    } catch (err: any) {
      run.status = 'FAILED';
      this.logError(ctx, `Investigation pipeline run ${runId} failed at step ${run.step}: ${err.message}`);
      // Auto-trigger rollback
      await this.rollbackRun(run, ctx);
      throw err;
    }

    return run;
  }

  private async runStep(run: InvestigationPipelineRun, ctx: OperationContext): Promise<void> {
    this.logInfo(ctx, `Executing Pipeline Step ${run.step}/9 for run ${run.runId}`);
    
    switch (run.step) {
      case 1: {
        // Step 1: Create Investigation
        const inv = await investigationOrchestrator.createInvestigation({
          projectId: run.projectId,
          ownerId: run.ownerId,
          title: run.title,
          actor: run.actor,
        }, ctx);
        run.investigationId = inv.id;
        run.compensationStack.push({
          label: `delete-investigation-${inv.id}`,
          fn: async () => {
            try { await prisma.investigation.delete({ where: { id: inv.id } }); } catch (_) {}
          }
        });
        break;
      }
      case 2: {
        // Step 2: Start Capture
        const cap = await captureOrchestrator.startCapture({
          investigationId: run.investigationId!,
          projectId: run.projectId,
          interface: 'eth0',
          actor: run.actor,
        }, ctx);
        run.captureId = cap.captureId;
        run.compensationStack.push({
          label: `stop-capture-${cap.captureId}`,
          fn: async () => {
            try { captureOrchestrator.clearSessions(); } catch (_) {}
          }
        });
        break;
      }
      case 3: {
        // Step 3: Run Nmap
        const scan = await scanOrchestrator.startQuickScan({
          investigationId: run.investigationId!,
          projectId: run.projectId,
          target: run.target,
          actor: run.actor,
        }, ctx);
        run.scanResultId = scan.scanId;
        if (scan.assetId) run.assetIds.push(scan.assetId);
        run.findingIds.push(...scan.findingIds);
        run.alertIds.push(...scan.alertIds);
        break;
      }
      case 4: {
        // Step 4: Create Assets
        const asset = await assetService.createAsset({
          projectId: run.projectId,
          investigationId: run.investigationId!,
          hostname: `host-${run.target}`,
          currentIp: run.target,
          type: 'WORKSTATION',
          createdBy: run.actor,
          updatedBy: run.actor,
        } as Prisma.AssetUncheckedCreateInput);
        run.assetIds.push(asset.id);
        run.compensationStack.push({
          label: `delete-asset-${asset.id}`,
          fn: async () => {
            try { await prisma.asset.delete({ where: { id: asset.id } }); } catch (_) {}
          }
        });
        break;
      }
      case 5: {
        // Step 5: Generate Findings
        const finding = await findingService.createFinding({
          projectId: run.projectId,
          investigationId: run.investigationId!,
          assetId: run.assetIds[run.assetIds.length - 1],
          title: `Port Scan Finding - ${run.target}`,
          description: `Analysis detected active mapping ports on ${run.target}`,
          severity: 'HIGH',
          status: 'OPEN',
          category: 'VULNERABILITY',
          createdBy: run.actor,
          updatedBy: run.actor,
        } as Prisma.FindingUncheckedCreateInput);
        run.findingIds.push(finding.id);
        run.compensationStack.push({
          label: `delete-finding-${finding.id}`,
          fn: async () => {
            try { await prisma.finding.delete({ where: { id: finding.id } }); } catch (_) {}
          }
        });
        break;
      }
      case 6: {
        // Step 6: Generate Timeline
        await timelineService.record({
          projectId: run.projectId,
          investigationId: run.investigationId!,
          title: 'Automated Pipeline Review',
          description: `Orchestrated port scan findings for host host-${run.target}`,
          type: 'MANUAL_ACTION',
          createdBy: run.actor,
        });
        break;
      }
      case 7: {
        // Step 7: Raise Alerts
        const alert = await alertService.createAlert({
          projectId: run.projectId,
          investigationId: run.investigationId!,
          findingId: run.findingIds[run.findingIds.length - 1],
          title: `Critical Alert - Pipeline ${run.target}`,
          description: 'High-severity ports open on network device',
          severity: 'HIGH',
          status: 'NEW',
          source: 'SCAN',
          createdBy: run.actor,
          updatedBy: run.actor,
        } as Prisma.AlertUncheckedCreateInput);
        run.alertIds.push(alert.id);
        run.compensationStack.push({
          label: `delete-alert-${alert.id}`,
          fn: async () => {
            try { await prisma.alert.delete({ where: { id: alert.id } }); } catch (_) {}
          }
        });
        break;
      }
      case 8: {
        // Step 8: Generate Report
        const report = await reportOrchestrator.generateInvestigationReport({
          investigationId: run.investigationId!,
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
            try { await prisma.report.delete({ where: { id: report.id } }); } catch (_) {}
          }
        });
        break;
      }
      case 9: {
        // Step 9: Notify Users
        await notificationOrchestrator.sendNotification({
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

  async rollback(runId: string, actor: string, parentCtx?: OperationContext): Promise<InvestigationPipelineRun> {
    const ctx = parentCtx ?? createOperationContext(actor);
    const run = activeRuns.get(runId);
    if (!run) throw new Error(`Pipeline run ${runId} not found.`);

    this.logInfo(ctx, `Forcing rollback of pipeline run ${runId}`);
    run.status = 'ROLLED_BACK';
    await this.rollbackRun(run, ctx);
    return run;
  }

  private async rollbackRun(run: InvestigationPipelineRun, ctx: OperationContext): Promise<void> {
    const reversed = [...run.compensationStack].reverse();
    for (const action of reversed) {
      try {
        this.logInfo(ctx, `Compensating pipeline step: ${action.label}`);
        await action.fn();
      } catch (err: any) {
        this.logWarn(ctx, `Compensating pipeline step "${action.label}" failed: ${err.message}`);
      }
    }
    run.compensationStack = [];
  }

  async resume(runId: string, actor: string, parentCtx?: OperationContext): Promise<InvestigationPipelineRun> {
    const ctx = parentCtx ?? createOperationContext(actor);
    const run = activeRuns.get(runId);
    if (!run) throw new Error(`Pipeline run ${runId} not found.`);

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
        await this.publishEvent(APP_EVENTS.INVESTIGATION_PIPELINE_COMPLETED, ctx, {
          runId,
          investigationId: run.investigationId,
          projectId: run.projectId,
          status: run.status,
        });
      }
    } catch (err: any) {
      run.status = 'FAILED';
      this.logError(ctx, `Investigation pipeline run ${runId} failed at step ${run.step}: ${err.message}`);
      throw err;
    }

    return run;
  }

  async cancel(runId: string, actor: string, parentCtx?: OperationContext): Promise<InvestigationPipelineRun> {
    const ctx = parentCtx ?? createOperationContext(actor);
    const run = activeRuns.get(runId);
    if (!run) throw new Error(`Pipeline run ${runId} not found.`);

    this.logInfo(ctx, `Cancelling pipeline run ${runId}`);
    run.status = 'CANCELLED';
    return run;
  }

  async calculateStatistics(investigationId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor, { investigationId });
    return investigationOrchestrator.generateStatistics(investigationId, actor, ctx);
  }

  getRun(runId: string): InvestigationPipelineRun | undefined {
    return activeRuns.get(runId);
  }

  clearRuns(): void {
    activeRuns.clear();
  }
}

export const investigationPipeline = new InvestigationPipeline();
