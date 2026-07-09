/**
 * CaptureOrchestrator.ts — Phase A5.4.1
 * ========================================
 * Orchestrates packet-capture workflows.
 *
 * Business flow:
 *   Capture → Packet Analysis → Asset Discovery → Timeline
 *           → Evidence Creation → AI Analysis (optional) → Notification
 *
 * Coordinates: AssetService · EvidenceService · TimelineService ·
 *              AlertService · ActivityService · NotificationService
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
  evidenceService,
  findingService,
  alertService,
  timelineService,
} from '../../services/investigation';
import { activityService, notificationService } from '../../services/shared';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface CaptureSession {
  captureId: string;
  investigationId: string;
  projectId: string;
  status: 'ACTIVE' | 'PAUSED' | 'STOPPED' | 'ANALYSED' | 'SAVED' | 'EXPORTED';
  interface?: string;
  packetCount: number;
  startedAt: Date;
  stoppedAt?: Date;
  evidenceId?: string;
  assetIds: string[];
  alertIds: string[];
  durationMs?: number;
  correlationId: string;
}

export interface StartCaptureInput {
  investigationId: string;
  projectId: string;
  actor: string;
  interface?: string;
  options?: Record<string, any>;
}

export interface StopCaptureInput {
  captureId: string;
  investigationId: string;
  projectId: string;
  actor: string;
}

export interface AnalyseCaptureInput {
  captureId: string;
  investigationId: string;
  projectId: string;
  actor: string;
  pcapContent?: string;
  enableAI?: boolean;
}

export interface SaveCaptureInput {
  captureId: string;
  investigationId: string;
  projectId: string;
  actor: string;
  fileName: string;
  content: string;
}

export interface ImportCaptureInput {
  investigationId: string;
  projectId: string;
  actor: string;
  fileName: string;
  content: string;
}

export interface ExportCaptureInput {
  captureId: string;
  investigationId: string;
  projectId: string;
  actor: string;
  format?: 'PCAPNG' | 'JSON' | 'CSV';
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory session store (per-process; replaced by DB in production)
// ─────────────────────────────────────────────────────────────────────────────

const activeSessions = new Map<string, CaptureSession>();

// ─────────────────────────────────────────────────────────────────────────────
// CaptureOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class CaptureOrchestrator extends BaseApplicationService {
  constructor() {
    super('CaptureOrchestrator');
  }

  // ── Start Capture ──────────────────────────────────────────────────────────

  async startCapture(input: StartCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Starting capture for investigation ${input.investigationId}`);

    const inv = await investigationService.findInvestigation(input.investigationId);
    if (!inv) throw new OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);

    const captureId = `cap-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;

    const session: CaptureSession = {
      captureId,
      investigationId: input.investigationId,
      projectId: input.projectId,
      status: 'ACTIVE',
      interface: input.interface,
      packetCount: 0,
      startedAt: new Date(),
      assetIds: [],
      alertIds: [],
      correlationId: ctx.correlationId,
    };

    activeSessions.set(captureId, session);

    await timelineService.recordCapture(
      input.projectId,
      input.investigationId,
      captureId,
      input.actor,
    );

    if (this.isValidUuid(input.actor)) {
      await activityService.logExecute(
        input.actor,
        'CAPTURE_STARTED',
        `Capture ${captureId} started`,
        input.projectId,
        input.investigationId,
      );
    }

    await this.publishEvent(APP_EVENTS.CAPTURE_STARTED, ctx, {
      captureId,
      investigationId: input.investigationId,
      projectId: input.projectId,
      interface: input.interface,
    });

    return session;
  }

  // ── Stop Capture ───────────────────────────────────────────────────────────

  async stopCapture(input: StopCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
      projectId: input.projectId,
    });

    const session = this.requireSession(input.captureId, ctx);
    this.logInfo(ctx, `Stopping capture ${input.captureId}`);

    session.status = 'STOPPED';
    session.stoppedAt = new Date();
    session.durationMs = session.stoppedAt.getTime() - session.startedAt.getTime();

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Capture Stopped',
      description: `Capture ${input.captureId} stopped. Duration: ${session.durationMs}ms.`,
      type: 'EVIDENCE_ADDED',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.CAPTURE_STOPPED, ctx, {
      captureId: input.captureId,
      investigationId: input.investigationId,
      projectId: input.projectId,
    });

    return session;
  }

  // ── Pause Capture ──────────────────────────────────────────────────────────

  async pauseCapture(input: StopCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
    });

    const session = this.requireSession(input.captureId, ctx);
    if (session.status !== 'ACTIVE') {
      throw this.mapError(new Error(`Capture ${input.captureId} is not active.`), ctx);
    }
    session.status = 'PAUSED';

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Capture Paused',
      description: `Capture ${input.captureId} paused.`,
      type: 'MANUAL_ACTION',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.CAPTURE_PAUSED, ctx, { captureId: input.captureId });
    return session;
  }

  // ── Resume Capture ─────────────────────────────────────────────────────────

  async resumeCapture(input: StopCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
    });

    const session = this.requireSession(input.captureId, ctx);
    if (session.status !== 'PAUSED') {
      throw this.mapError(new Error(`Capture ${input.captureId} is not paused.`), ctx);
    }
    session.status = 'ACTIVE';

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Capture Resumed',
      description: `Capture ${input.captureId} resumed.`,
      type: 'MANUAL_ACTION',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.CAPTURE_RESUMED, ctx, { captureId: input.captureId });
    return session;
  }

  // ── Analyse Capture ────────────────────────────────────────────────────────

  async analyseCapture(input: AnalyseCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
      projectId: input.projectId,
    });
    this.logInfo(ctx, `Analysing capture ${input.captureId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const session = activeSessions.get(input.captureId) ?? {
        captureId: input.captureId,
        investigationId: input.investigationId,
        projectId: input.projectId,
        status: 'STOPPED' as const,
        packetCount: 0,
        startedAt: new Date(),
        assetIds: [],
        alertIds: [],
        correlationId: ctx.correlationId,
      };

      // 1. Create evidence record for the capture
      const evidence = await evidenceService.attachPcap({
        projectId: input.projectId,
        investigationId: input.investigationId,
        fieldName: 'pcap_capture',
        fieldValue: input.pcapContent ?? `capture:${input.captureId}`,
        sourceType: 'CAPTURE',
        type: 'PACKET',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.EvidenceUncheckedCreateInput);
      session.evidenceId = evidence.id;

      compensation.register(`delete-evidence-${evidence.id}`, async () => {
        try {
          // soft-delete via update
        } catch (_) { /* best effort */ }
      });

      // 2. Asset discovery from capture metadata
      let discoveredAsset: any;
      try {
        discoveredAsset = await assetService.createAsset({
          projectId: input.projectId,
          investigationId: input.investigationId,
          type: 'UNKNOWN',
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.AssetUncheckedCreateInput);
        session.assetIds.push(discoveredAsset.id);

        // Link evidence to asset
        await evidenceService.associateAsset(evidence.id, discoveredAsset.id, input.actor);
      } catch (e: any) {
        this.logWarn(ctx, `Asset creation skipped: ${e?.message}`);
      }

      // 3. Create a finding from capture analysis
      const finding = await findingService.createFinding({
        projectId: input.projectId,
        investigationId: input.investigationId,
        assetId: discoveredAsset?.id,
        title: `Capture Analysis — ${input.captureId}`,
        description: `Network capture ${input.captureId} analysed.`,
        severity: 'MEDIUM',
        status: 'OPEN',
        category: 'PACKET_ANALYSIS',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.FindingUncheckedCreateInput);

      // Link evidence to finding
      await evidenceService.associateFinding(evidence.id, finding.id, input.actor);

      // 4. Timeline
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: 'Capture Analysed',
        description: `Capture ${input.captureId} analysis complete. Evidence: ${evidence.id}.`,
        type: 'EVIDENCE_ADDED',
        createdBy: input.actor,
      });

      // 5. Optional AI analysis timeline marker
      if (input.enableAI) {
        await timelineService.recordAIAction(
          input.projectId,
          input.investigationId,
          `AI analysis triggered for capture ${input.captureId}.`,
          input.actor,
        );
      }

      session.status = 'ANALYSED';
      session.packetCount = Math.floor(Math.random() * 1000) + 100; // placeholder
      activeSessions.set(input.captureId, session);

      await this.publishEvent(APP_EVENTS.CAPTURE_ANALYSED, ctx, {
        captureId: input.captureId,
        investigationId: input.investigationId,
        projectId: input.projectId,
        evidenceId: evidence.id,
      });

      compensation.clear();
      return session;
    });
  }

  // ── Save Capture ───────────────────────────────────────────────────────────

  async saveCapture(input: SaveCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
      projectId: input.projectId,
    });
    this.logInfo(ctx, `Saving capture ${input.captureId}`);

    // Persist evidence
    const evidence = await evidenceService.attachPcap({
      projectId: input.projectId,
      investigationId: input.investigationId,
      fieldName: 'pcap_file',
      fieldValue: input.content,
      sourceType: 'FILE_UPLOAD',
      type: 'PACKET',
      metadata: { fileName: input.fileName, captureId: input.captureId },
      createdBy: input.actor,
      updatedBy: input.actor,
    } as Prisma.EvidenceUncheckedCreateInput);

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Capture Saved',
      description: `Capture file "${input.fileName}" saved as evidence ${evidence.id}.`,
      type: 'EVIDENCE_ADDED',
      createdBy: input.actor,
    });

    const session = activeSessions.get(input.captureId) ?? {
      captureId: input.captureId,
      investigationId: input.investigationId,
      projectId: input.projectId,
      status: 'SAVED' as const,
      packetCount: 0,
      startedAt: new Date(),
      assetIds: [],
      alertIds: [],
      correlationId: ctx.correlationId,
    };
    session.status = 'SAVED';
    session.evidenceId = evidence.id;
    activeSessions.set(input.captureId, session);

    await this.publishEvent(APP_EVENTS.CAPTURE_SAVED, ctx, {
      captureId: input.captureId,
      evidenceId: evidence.id,
    });

    return session;
  }

  // ── Import Capture ─────────────────────────────────────────────────────────

  async importCapture(input: ImportCaptureInput, parentCtx?: OperationContext): Promise<CaptureSession> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
      projectId: input.projectId,
    });
    this.logInfo(ctx, `Importing capture "${input.fileName}"`);

    const captureId = `cap-import-${Date.now()}`;
    const evidence = await evidenceService.attachPcap({
      projectId: input.projectId,
      investigationId: input.investigationId,
      fieldName: 'imported_pcap',
      fieldValue: input.content,
      sourceType: 'IMPORT',
      type: 'PACKET',
      metadata: { fileName: input.fileName },
      createdBy: input.actor,
      updatedBy: input.actor,
    } as Prisma.EvidenceUncheckedCreateInput);

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Capture Imported',
      description: `PCAP "${input.fileName}" imported as evidence ${evidence.id}.`,
      type: 'EVIDENCE_ADDED',
      createdBy: input.actor,
    });

    const session: CaptureSession = {
      captureId,
      investigationId: input.investigationId,
      projectId: input.projectId,
      status: 'SAVED',
      packetCount: 0,
      startedAt: new Date(),
      assetIds: [],
      alertIds: [],
      evidenceId: evidence.id,
      correlationId: ctx.correlationId,
    };
    activeSessions.set(captureId, session);

    await this.publishEvent(APP_EVENTS.CAPTURE_IMPORTED, ctx, {
      captureId,
      evidenceId: evidence.id,
      investigationId: input.investigationId,
      projectId: input.projectId,
      sourceType: 'IMPORT',
    });

    return session;
  }

  // ── Export Capture ─────────────────────────────────────────────────────────

  async exportCapture(input: ExportCaptureInput, parentCtx?: OperationContext): Promise<{ url: string; format: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Exporting capture ${input.captureId} as ${input.format ?? 'PCAPNG'}`);

    const format = input.format ?? 'PCAPNG';
    const exportUrl = `/exports/${input.captureId}.${format.toLowerCase()}`;

    await timelineService.record({
      projectId: input.projectId,
      investigationId: input.investigationId,
      title: 'Capture Exported',
      description: `Capture ${input.captureId} exported as ${format}.`,
      type: 'MANUAL_ACTION',
      createdBy: input.actor,
    });

    await this.publishEvent(APP_EVENTS.CAPTURE_EXPORTED, ctx, {
      captureId: input.captureId,
      format,
    });

    return { url: exportUrl, format };
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private requireSession(captureId: string, ctx: OperationContext): CaptureSession {
    const session = activeSessions.get(captureId);
    if (!session) {
      throw new OrchestrationNotFoundError('CaptureSession', captureId, ctx.correlationId);
    }
    return session;
  }

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }

  /** Expose session map for testing */
  getSession(captureId: string): CaptureSession | undefined {
    return activeSessions.get(captureId);
  }

  clearSessions(): void {
    activeSessions.clear();
  }
}

export const captureOrchestrator = new CaptureOrchestrator();
