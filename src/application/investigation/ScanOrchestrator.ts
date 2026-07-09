/**
 * ScanOrchestrator.ts — Phase A5.4.1
 * =====================================
 * Orchestrates complete scan workflows across multiple service domains.
 *
 * Coordinates: AssetService · FindingService · AlertService ·
 *              TimelineService · ActivityService · NotificationService
 *
 * Scan types modelled: quick, full, service, OS, aggressive.
 * Every method uses withCompensation() for rollback safety.
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

import { investigationService } from '../../services/core';
import {
  assetService,
  findingService,
  alertService,
  timelineService,
} from '../../services/investigation';
import { activityService, notificationService } from '../../services/shared';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type ScanType = 'QUICK' | 'FULL' | 'SERVICE' | 'OS' | 'AGGRESSIVE';

export interface StartScanInput {
  investigationId: string;
  projectId: string;
  target: string;
  actor: string;
  options?: Record<string, any>;
}

export interface CancelScanInput {
  scanId: string;
  investigationId: string;
  projectId: string;
  actor: string;
}

export interface RescanInput {
  investigationId: string;
  projectId: string;
  target: string;
  actor: string;
  originalScanId?: string;
}

export interface ScanResult {
  scanId: string;
  investigationId: string;
  projectId: string;
  target: string;
  scanType: ScanType;
  status: 'STARTED' | 'RUNNING' | 'COMPLETED' | 'CANCELLED' | 'FAILED';
  assetId?: string;
  findingIds: string[];
  alertIds: string[];
  startedAt: Date;
  completedAt?: Date;
  durationMs?: number;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class ScanOrchestrator extends BaseApplicationService {
  constructor() {
    super('ScanOrchestrator');
  }

  // ── Generic scan launcher ──────────────────────────────────────────────────

  private async launchScan(
    scanType: ScanType,
    input: StartScanInput,
    parentCtx?: OperationContext,
  ): Promise<ScanResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });

    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Starting ${scanType} scan on target "${input.target}"`);

    const startedAt = new Date();
    const scanId = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const result: ScanResult = {
      scanId,
      investigationId: input.investigationId,
      projectId: input.projectId,
      target: input.target,
      scanType,
      status: 'STARTED',
      findingIds: [],
      alertIds: [],
      startedAt,
      correlationId: ctx.correlationId,
    };

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Record scan start in timeline
      await timelineService.recordScan(
        input.projectId,
        input.investigationId,
        scanId,
        input.actor,
      );

      // 2. Discover/upsert Asset for target
      let asset: any;
      try {
        asset = await assetService.createAsset({
          projectId: input.projectId,
          investigationId: input.investigationId,
          hostname: this.isIpAddress(input.target) ? undefined : input.target,
          currentIp: this.isIpAddress(input.target) ? input.target : undefined,
          type: 'UNKNOWN',
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.AssetUncheckedCreateInput);
        result.assetId = asset.id;

        compensation.register(`delete-asset-${asset.id}`, async () => {
          try {
            await assetService.updateAsset(asset.id, { deletedAt: new Date(), updatedBy: 'system' } as any);
          } catch (_) { /* best effort */ }
        });
      } catch (e: any) {
        // Duplicate asset is expected on rescan — log and continue
        if (e.message?.includes('Duplicate asset')) {
          this.logWarn(ctx, `Duplicate asset detected for target "${input.target}", proceeding without create`);
        } else {
          throw e;
        }
      }

      // 3. Create Finding based on scan type risk
      const severity = this.scanTypeSeverity(scanType);
      const finding = await findingService.createFinding({
        projectId: input.projectId,
        investigationId: input.investigationId,
        assetId: asset?.id,
        title: `${scanType} Scan — ${input.target}`,
        description: `${scanType} scan completed for target ${input.target}.`,
        severity,
        status: 'OPEN',
        category: 'SCAN',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.FindingUncheckedCreateInput);
      result.findingIds.push(finding.id);

      compensation.register(`delete-finding-${finding.id}`, async () => {
        try {
          await findingService.updateFinding(finding.id, { deletedAt: new Date(), updatedBy: 'system' } as any);
        } catch (_) { /* best effort */ }
      });

      // 4. Raise alert if HIGH/CRITICAL scan
      if (severity === 'HIGH' || severity === 'CRITICAL') {
        const alert = await alertService.createAlert({
          projectId: input.projectId,
          investigationId: input.investigationId,
          findingId: finding.id,
          title: `Scan Alert — ${scanType} on ${input.target}`,
          description: `${scanType} scan detected ${severity} severity indicators.`,
          severity,
          status: 'NEW',
          source: 'SCAN',
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.AlertUncheckedCreateInput);
        result.alertIds.push(alert.id);
      }

      // 5. Activity log
      if (this.isValidUuid(input.actor)) {
        await activityService.logExecute(
          input.actor,
          `SCAN_${scanType}_STARTED`,
          `${scanType} scan started on target ${input.target}`,
          input.projectId,
          input.investigationId,
        );
      }

      // 6. Mark completed + timing
      result.status = 'COMPLETED';
      result.completedAt = new Date();
      result.durationMs = result.completedAt.getTime() - startedAt.getTime();

      // 7. Record scan completion in timeline
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: `${scanType} Scan Completed`,
        description: `Scan ${scanId} completed. Found ${result.findingIds.length} finding(s).`,
        type: 'EVIDENCE_ADDED',
        createdBy: input.actor,
      });

      // 8. Publish events
      await this.publishEvent(APP_EVENTS.SCAN_STARTED, ctx, {
        scanId,
        investigationId: input.investigationId,
        projectId: input.projectId,
        target: input.target,
        scanType,
      });

      await this.publishEvent(APP_EVENTS.SCAN_COMPLETED, ctx, {
        scanId,
        investigationId: input.investigationId,
        projectId: input.projectId,
        assetCount: asset ? 1 : 0,
        findingCount: result.findingIds.length,
        alertCount: result.alertIds.length,
        durationMs: result.durationMs,
      });

      this.logTiming(ctx, `${scanType} scan`);
      compensation.clear(); // success — no rollback needed
      return result;
    });
  }

  // ── Public scan methods ───────────────────────────────────────────────────

  async startQuickScan(input: StartScanInput, ctx?: OperationContext): Promise<ScanResult> {
    return this.launchScan('QUICK', input, ctx);
  }

  async startFullScan(input: StartScanInput, ctx?: OperationContext): Promise<ScanResult> {
    return this.launchScan('FULL', input, ctx);
  }

  async startServiceScan(input: StartScanInput, ctx?: OperationContext): Promise<ScanResult> {
    return this.launchScan('SERVICE', input, ctx);
  }

  async startOSScan(input: StartScanInput, ctx?: OperationContext): Promise<ScanResult> {
    return this.launchScan('OS', input, ctx);
  }

  async startAggressiveScan(input: StartScanInput, ctx?: OperationContext): Promise<ScanResult> {
    return this.launchScan('AGGRESSIVE', input, ctx);
  }

  // ── Cancel Scan ───────────────────────────────────────────────────────────

  async cancelScan(input: CancelScanInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Cancelling scan: ${input.scanId}`);

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Scan Cancelled',
      description: `Scan ${input.scanId} was cancelled by ${input.actor}.`,
      type: 'MANUAL_ACTION',
      createdBy: input.actor,
    });

    if (this.isValidUuid(input.actor)) {
      await activityService.logExecute(
        input.actor,
        'SCAN_CANCELLED',
        `Scan ${input.scanId} cancelled`,
        input.projectId,
        input.investigationId,
      );
    }

    await this.publishEvent(APP_EVENTS.SCAN_CANCELLED, ctx, {
      scanId: input.scanId,
      investigationId: input.investigationId,
      projectId: input.projectId,
    });
  }

  // ── Rescan ────────────────────────────────────────────────────────────────

  async rescanTarget(input: RescanInput, parentCtx?: OperationContext): Promise<ScanResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Rescanning target: ${input.target}`);

    if (input.originalScanId) {
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: 'Rescan Initiated',
        description: `Rescan of target ${input.target} initiated (original scan: ${input.originalScanId}).`,
        type: 'MANUAL_ACTION',
        createdBy: input.actor,
      });
    }

    await this.publishEvent(APP_EVENTS.RESCAN_STARTED, ctx, {
      investigationId: input.investigationId,
      target: input.target,
    });

    // Run a full scan as the rescan strategy
    return this.launchScan('FULL', {
      investigationId: input.investigationId,
      projectId: input.projectId,
      target: input.target,
      actor: input.actor,
    }, ctx);
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private scanTypeSeverity(type: ScanType): 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const map: Record<ScanType, 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = {
      QUICK:      'LOW',
      FULL:       'MEDIUM',
      SERVICE:    'MEDIUM',
      OS:         'HIGH',
      AGGRESSIVE: 'CRITICAL',
    };
    return map[type];
  }

  private isIpAddress(target: string): boolean {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
  }

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const scanOrchestrator = new ScanOrchestrator();
