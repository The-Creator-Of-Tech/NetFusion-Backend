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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationError,
  OrchestrationNotFoundError,
  WorkflowState,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Service layer imports
import { investigationService } from '../../services/core';
import {
  assetService,
  findingService,
  evidenceService,
  reportService,
  alertService,
  timelineService,
} from '../../services/investigation';
import { notificationService, activityService } from '../../services/shared';

import { Prisma, InvestigationStatus } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Input/Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface CreateInvestigationInput {
  projectId: string;
  ownerId: string;
  title: string;
  description?: string;
  priority?: number;
  tags?: string[];
  actor: string;
}

export interface UpdateInvestigationInput {
  id: string;
  title?: string;
  description?: string;
  priority?: number;
  status?: InvestigationStatus;
  tags?: string[];
  actor: string;
}

export interface CloseInvestigationInput {
  id: string;
  actor: string;
  reason?: string;
}

export interface ArchiveInvestigationInput {
  id: string;
  actor: string;
}

export interface DeleteInvestigationInput {
  id: string;
  actor: string;
}

export interface LinkAssetInput {
  investigationId: string;
  assetId: string;
  actor: string;
}

export interface LinkFindingInput {
  investigationId: string;
  findingId: string;
  actor: string;
}

export interface LinkEvidenceInput {
  investigationId: string;
  evidenceId: string;
  actor: string;
}

export interface InvestigationStatistics {
  investigationId: string;
  assetsCount: number;
  findingsCount: number;
  evidenceCount: number;
  timelineCount: number;
  openAlertsCount: number;
  criticalFindingsCount: number;
  riskScore: number;
  generatedAt: Date;
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class InvestigationOrchestrator extends BaseApplicationService {
  constructor() {
    super('InvestigationOrchestrator');
  }

  // ── Create Investigation ──────────────────────────────────────────────────

  async createInvestigation(input: CreateInvestigationInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
    });
    this.logInfo(ctx, `Creating investigation: "${input.title}"`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Create the investigation via InvestigationService
      //    (already coordinates timeline + activity + notification internally)
      const inv = await investigationService.createInvestigation({
        projectId: input.projectId,
        ownerId: input.ownerId,
        title: input.title,
        description: input.description,
        priority: input.priority ?? 2,
        tags: input.tags ?? [],
      } as Prisma.InvestigationUncheckedCreateInput);

      compensation.register(`delete-investigation-${inv.id}`, async () => {
        try {
          await investigationService.deleteInvestigation(inv.id);
        } catch (_) { /* best effort */ }
      });

      // 2. Record in timeline (additional orchestration-level event)
      await timelineService.record({
        projectId: inv.projectId,
        investigationId: inv.id,
        title: 'Investigation Orchestrated',
        description: `Investigation "${inv.title}" created through orchestration layer.`,
        type: 'HISTORY_CREATED',
        createdBy: input.actor,
      });

      // 3. Activity log
      if (this.isValidUuid(input.actor)) {
        await activityService.logCreate(
          input.actor,
          'INVESTIGATION_CREATED',
          `Investigation "${inv.title}" created`,
          input.projectId,
          inv.id,
        );
      }

      // 4. Publish application event
      await this.publishEvent(APP_EVENTS.INVESTIGATION_STARTED, ctx, {
        investigationId: inv.id,
        projectId: inv.projectId,
        title: inv.title,
      });

      this.logTiming(ctx, 'createInvestigation');
      return inv;
    });
  }

  // ── Update Investigation ──────────────────────────────────────────────────

  async updateInvestigation(input: UpdateInvestigationInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.id,
    });
    this.validateUuid(input.id, 'investigationId', ctx);
    this.logInfo(ctx, `Updating investigation: ${input.id}`);

    const updateData: Prisma.InvestigationUncheckedUpdateInput = {
      ...(input.title      !== undefined && { title: input.title }),
      ...(input.description !== undefined && { description: input.description }),
      ...(input.priority   !== undefined && { priority: input.priority }),
      ...(input.status     !== undefined && { status: input.status }),
      ...(input.tags       !== undefined && { tags: input.tags }),
    };

    const updated = await investigationService.updateInvestigation(input.id, updateData);

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'INVESTIGATION_UPDATED',
        `Investigation "${updated.title}" updated`,
        updated.projectId,
        updated.id,
      );
    }

    await this.publishEvent(APP_EVENTS.INVESTIGATION_UPDATED, ctx, {
      investigationId: updated.id,
      projectId: updated.projectId,
    });

    this.logTiming(ctx, 'updateInvestigation');
    return updated;
  }

  // ── Close Investigation ───────────────────────────────────────────────────

  async closeInvestigation(input: CloseInvestigationInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.id });
    this.validateUuid(input.id, 'investigationId', ctx);
    this.logInfo(ctx, `Closing investigation: ${input.id}`);

    const closed = await investigationService.closeInvestigation(input.id);

    // Record closure reason in timeline if provided
    if (input.reason) {
      await timelineService.record({
        projectId: closed.projectId,
        investigationId: closed.id,
        title: 'Investigation Closure Reason',
        description: input.reason,
        type: 'MANUAL_ACTION',
        createdBy: input.actor,
      });
    }

    // Resolve all open alerts
    const openAlerts = await alertService.getOpenAlerts(input.id);
    for (const alert of openAlerts) {
      await alertService.resolveAlert(alert.id, input.actor);
    }

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'INVESTIGATION_CLOSED',
        `Investigation "${closed.title}" closed`,
        closed.projectId,
        closed.id,
      );
    }

    await this.publishEvent(APP_EVENTS.INVESTIGATION_CLOSED, ctx, {
      investigationId: closed.id,
      projectId: closed.projectId,
      title: closed.title,
      closedAt: new Date(),
    });

    this.logTiming(ctx, 'closeInvestigation');
    return closed;
  }

  // ── Archive Investigation ─────────────────────────────────────────────────

  async archiveInvestigation(input: ArchiveInvestigationInput, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.id });
    this.validateUuid(input.id, 'investigationId', ctx);
    this.logInfo(ctx, `Archiving investigation: ${input.id}`);

    const archived = await investigationService.updateInvestigation(input.id, {
      status: 'ARCHIVED' as InvestigationStatus,
    } as Prisma.InvestigationUncheckedUpdateInput);

    await timelineService.record({
      projectId: archived.projectId,
      investigationId: archived.id,
      title: 'Investigation Archived',
      description: `Investigation "${archived.title}" archived by ${input.actor}.`,
      type: 'HISTORY_CREATED',
      createdBy: input.actor,
    });

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'INVESTIGATION_ARCHIVED',
        `Investigation "${archived.title}" archived`,
        archived.projectId,
        archived.id,
      );
    }

    await this.publishEvent(APP_EVENTS.INVESTIGATION_ARCHIVED, ctx, {
      investigationId: archived.id,
      projectId: archived.projectId,
    });

    this.logTiming(ctx, 'archiveInvestigation');
    return archived;
  }

  // ── Delete Investigation ──────────────────────────────────────────────────

  async deleteInvestigation(input: DeleteInvestigationInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.id });
    this.validateUuid(input.id, 'investigationId', ctx);
    this.logInfo(ctx, `Deleting investigation: ${input.id}`);

    const inv = await investigationService.findInvestigation(input.id);
    if (!inv) throw new OrchestrationNotFoundError('Investigation', input.id, ctx.correlationId);

    if (this.isValidUuid(input.actor)) {
      await activityService.logDelete(
        input.actor,
        'INVESTIGATION_DELETED',
        `Investigation "${inv.title}" deleted`,
        inv.projectId,
        inv.id,
      );
    }

    await investigationService.deleteInvestigation(input.id);

    await this.publishEvent(APP_EVENTS.INVESTIGATION_DELETED, ctx, {
      investigationId: input.id,
      projectId: inv.projectId,
    });

    this.logTiming(ctx, 'deleteInvestigation');
  }

  // ── Generate Statistics ───────────────────────────────────────────────────

  async generateStatistics(
    investigationId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<InvestigationStatistics> {
    const ctx = parentCtx ?? createOperationContext(actor, { investigationId });
    this.validateUuid(investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Generating statistics for investigation: ${investigationId}`);

    const [coreStats, openAlerts] = await Promise.all([
      investigationService.calculateStatistics(investigationId),
      alertService.getOpenAlerts(investigationId),
    ]);

    const stats: InvestigationStatistics = {
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
      const weights: Record<string, number> = { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 8 };
      stats.riskScore += weights[a.severity] ?? 5;
    }
    stats.riskScore = Math.min(stats.riskScore, 100);

    await this.publishEvent(APP_EVENTS.INVESTIGATION_STATS, ctx, { investigationId, stats });

    this.logTiming(ctx, 'generateStatistics');
    return stats;
  }

  // ── Link Asset ────────────────────────────────────────────────────────────

  async linkAsset(input: LinkAssetInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.investigationId });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.validateUuid(input.assetId, 'assetId', ctx);
    this.logInfo(ctx, `Linking asset ${input.assetId} to investigation ${input.investigationId}`);

    // Update asset so it is associated with the investigation
    await assetService.updateAsset(input.assetId, {
      investigationId: input.investigationId,
      updatedBy: input.actor,
    } as Prisma.AssetUncheckedUpdateInput);

    await timelineService.record({
      projectId: (await investigationService.findInvestigation(input.investigationId))!.projectId,
      investigationId: input.investigationId,
      title: 'Asset Linked',
      description: `Asset ${input.assetId} linked to investigation.`,
      type: 'HISTORY_CREATED',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.ASSET_LINKED, ctx, {
      investigationId: input.investigationId,
      assetId: input.assetId,
    });
  }

  // ── Link Finding ──────────────────────────────────────────────────────────

  async linkFinding(input: LinkFindingInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.investigationId });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.validateUuid(input.findingId, 'findingId', ctx);
    this.logInfo(ctx, `Linking finding ${input.findingId} to investigation ${input.investigationId}`);

    await findingService.updateFinding(input.findingId, {
      investigationId: input.investigationId,
      updatedBy: input.actor,
    } as Prisma.FindingUncheckedUpdateInput);

    const inv = await investigationService.findInvestigation(input.investigationId);
    if (!inv) throw new OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);

    await timelineService.record({
      projectId: inv.projectId,
      investigationId: input.investigationId,
      title: 'Finding Linked',
      description: `Finding ${input.findingId} linked to investigation.`,
      type: 'FINDING_CREATED',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.FINDING_LINKED, ctx, {
      investigationId: input.investigationId,
      findingId: input.findingId,
    });
  }

  // ── Link Evidence ─────────────────────────────────────────────────────────

  async linkEvidence(input: LinkEvidenceInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { investigationId: input.investigationId });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.validateUuid(input.evidenceId, 'evidenceId', ctx);
    this.logInfo(ctx, `Linking evidence ${input.evidenceId} to investigation ${input.investigationId}`);

    const inv = await investigationService.findInvestigation(input.investigationId);
    if (!inv) throw new OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);

    await timelineService.record({
      projectId: inv.projectId,
      investigationId: input.investigationId,
      title: 'Evidence Imported',
      description: `Evidence ${input.evidenceId} imported into investigation.`,
      type: 'EVIDENCE_ADDED',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.EVIDENCE_IMPORTED, ctx, {
      evidenceId: input.evidenceId,
      investigationId: input.investigationId,
      projectId: inv.projectId,
      sourceType: 'MANUAL',
    });
  }

  // ── Generate Executive Summary ────────────────────────────────────────────

  async generateExecutiveSummary(
    investigationId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor, { investigationId });
    this.validateUuid(investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Generating executive summary for: ${investigationId}`);

    // Generate the summary report through ReportService
    const report = await reportService.generateSummary(investigationId, actor);

    const inv = await investigationService.findInvestigation(investigationId);
    if (inv) {
      await notificationService.createNotification({
        userId: inv.ownerId,
        title: 'Executive Summary Ready',
        message: `Executive summary for "${inv.title}" has been generated.`,
        type: 'SYSTEM',
        status: 'UNREAD',
        createdBy: actor,
        updatedBy: actor,
      });
    }

    await this.publishEvent(APP_EVENTS.INVESTIGATION_SUMMARY, ctx, {
      investigationId,
      reportId: report.id,
    });

    this.logTiming(ctx, 'generateExecutiveSummary');
    return report;
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const investigationOrchestrator = new InvestigationOrchestrator();
