/**
 * TimelineService — Phase A5.3.3
 * ================================
 * Centralised timeline creation. NOTHING else should insert TimelineEvents
 * directly — all callers must go through this service.
 *
 * Every write method wraps its DB operations in a Prisma transaction and
 * publishes a TimelineRecorded event after commit.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { timelineRepository } from '../../repositories/investigation';
import prisma from '../../lib/prisma';
import { TimelineEvent, TimelineEventType } from '@prisma/client';

interface TimelineInput {
  projectId: string;
  investigationId: string;
  title: string;
  description?: string;
  type?: TimelineEventType;
  eventTimestamp?: Date;
  createdBy: string;
  updatedBy?: string;
  metadata?: Record<string, any>;
}

export class TimelineService extends BaseService {
  constructor(private readonly timelineRepo = timelineRepository) {
    super();
  }

  // ── Generic recorder ──────────────────────────────────────────────────────

  async record(input: TimelineInput, tx?: any): Promise<TimelineEvent> {
    const runInTx = async (transaction: any) => {
      const event = await this.timelineRepo.create({
        projectId:      input.projectId,
        investigationId: input.investigationId,
        title:          input.title,
        description:    input.description ?? null,
        type:           input.type ?? 'HISTORY_CREATED',
        eventTimestamp: input.eventTimestamp ?? this.getUtcNow(),
        createdBy:      input.createdBy,
        updatedBy:      input.updatedBy ?? input.createdBy,
        metadata:       (input.metadata as any) ?? null,
      }, transaction);
      await eventPublisher.publish('TimelineRecorded', { event });
      return event;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Semantic helpers (each maps to a TimelineEventType) ───────────────────

  async recordCreation(projectId: string, investigationId: string, entity: string,
      entityId: string, createdBy: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: `${entity} Created`,
      description: `${entity} ${entityId} was created.`,
      type: 'HISTORY_CREATED', createdBy,
    }, tx);
  }

  async recordUpdate(projectId: string, investigationId: string, entity: string,
      entityId: string, changes: string, updatedBy: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: `${entity} Updated`,
      description: `${entity} ${entityId} updated: ${changes}.`,
      type: 'HISTORY_CREATED', createdBy: updatedBy,
    }, tx);
  }

  async recordStatusChange(projectId: string, investigationId: string, entity: string,
      entityId: string, from: string, to: string, actor: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: `${entity} Status Changed`,
      description: `${entity} ${entityId} status changed from ${from} to ${to}.`,
      type: 'HISTORY_CREATED', createdBy: actor,
    }, tx);
  }

  async recordCapture(projectId: string, investigationId: string, captureId: string,
      actor: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: 'Capture Recorded',
      description: `Packet capture ${captureId} associated with investigation.`,
      type: 'EVIDENCE_ADDED', createdBy: actor,
    }, tx);
  }

  async recordScan(projectId: string, investigationId: string, scanId: string,
      actor: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: 'Scan Recorded',
      description: `Scan ${scanId} results linked to investigation.`,
      type: 'EVIDENCE_ADDED', createdBy: actor,
    }, tx);
  }

  async recordAlert(projectId: string, investigationId: string, alertId: string,
      severity: string, actor: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: 'Alert Generated',
      description: `Alert ${alertId} raised with severity ${severity}.`,
      type: 'ALERT_GENERATED', createdBy: actor,
    }, tx);
  }

  async recordAIAction(projectId: string, investigationId: string, action: string,
      actor: string, tx?: any): Promise<TimelineEvent> {
    return this.record({
      projectId, investigationId,
      title: 'AI Action',
      description: action,
      type: 'MANUAL_ACTION', createdBy: actor,
    }, tx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────

  async getInvestigationTimeline(investigationId: string, tx?: any): Promise<TimelineEvent[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.timelineRepo.findByInvestigation(investigationId, tx);
  }

  async getLatest(investigationId: string, limit = 20, tx?: any): Promise<TimelineEvent[]> {
    return this.timelineRepo.findLatest(limit, { investigationId }, tx);
  }
}
