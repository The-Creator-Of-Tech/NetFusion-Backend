/**
 * AlertService — Phase A5.3.3
 * =============================
 * Business logic for Alert lifecycle management.
 * Handles creation, acknowledgement, resolution, suppression, and scoring.
 * Every state transition records a timeline event and publishes a domain event.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { alertRepository } from '../../repositories/investigation';
import { activityLogRepository } from '../../repositories/core';
import { TimelineService } from './timeline.service';
import prisma from '../../lib/prisma';
import { Alert, AlertSeverity, AlertStatus, Prisma } from '@prisma/client';

const SEVERITY_SCORES: Record<string, number> = {
  CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 10,
};

export class AlertService extends BaseService {
  constructor(
    private readonly alertRepo     = alertRepository,
    private readonly activityRepo  = activityLogRepository,
    private readonly timelineSvc   = new TimelineService(),
  ) { super(); }

  // ── Create ─────────────────────────────────────────────────────────────────

  async createAlert(data: Prisma.AlertUncheckedCreateInput, tx?: any): Promise<Alert> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'title', 'createdBy', 'updatedBy']);
    this.validateUuid(data.projectId, 'projectId');
    this.validateUuid(data.investigationId, 'investigationId');

    const runInTx = async (transaction: any) => {
      const riskScore = SEVERITY_SCORES[(data.severity as string) ?? 'MEDIUM'] ?? 50;
      const alert = await this.alertRepo.create({ ...data, riskScore }, transaction);

      await this.timelineSvc.recordAlert(
        alert.projectId, alert.investigationId, alert.id,
        alert.severity, data.createdBy as string, transaction,
      );
      // Only create ActivityLog if createdBy is a valid UUID
      const actorId = data.createdBy as string;
      if (actorId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actorId)) {
        await this.activityRepo.create({
          userId: actorId, projectId: alert.projectId, investigationId: alert.investigationId,
          action: 'CREATE', type: 'CREATE', details: `Alert "${alert.title}" created`,
          createdBy: actorId, updatedBy: actorId,
        }, transaction);
      }

      await eventPublisher.publish('AlertRaised', { alert });
      return alert;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ─────────────────────────────────────────────────

  async acknowledgeAlert(id: string, actor: string, tx?: any): Promise<Alert> {
    return this._transition(id, 'ACKNOWLEDGED', actor, 'Alert Acknowledged', tx);
  }

  async resolveAlert(id: string, actor: string, tx?: any): Promise<Alert> {
    return this._transition(id, 'RESOLVED', actor, 'Alert Resolved', tx);
  }

  async suppressAlert(id: string, actor: string, reason?: string, tx?: any): Promise<Alert> {
    return this._transition(id, 'SUPPRESSED', actor, `Alert Suppressed${reason ? ': ' + reason : ''}`, tx);
  }

  async reopenAlert(id: string, actor: string, tx?: any): Promise<Alert> {
    return this._transition(id, 'OPEN', actor, 'Alert Reopened', tx);
  }

  // ── Severity escalation ───────────────────────────────────────────────────

  async escalate(id: string, severity: AlertSeverity, actor: string, tx?: any): Promise<Alert> {
    this.validateUuid(id, 'alertId');
    const runInTx = async (transaction: any) => {
      const existing = await this.alertRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Alert "${id}" not found.`);
      const newScore = SEVERITY_SCORES[severity] ?? existing.riskScore;
      const updated  = await this.alertRepo.update(id, { severity, riskScore: newScore, updatedBy: actor }, transaction);
      await this.timelineSvc.record({
        projectId: updated.projectId, investigationId: updated.investigationId,
        title: 'Alert Escalated',
        description: `Alert severity escalated from ${existing.severity} to ${severity}.`,
        type: 'ALERT_GENERATED', createdBy: actor,
      }, transaction);
      await eventPublisher.publish('AlertEscalated', { alert: updated, from: existing.severity, to: severity });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Score ─────────────────────────────────────────────────────────────────

  async calculateAlertScore(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'alertId');
    const alert = await this.alertRepo.findById(id, tx);
    if (!alert || alert.deletedAt) throw new Error(`Alert "${id}" not found.`);
    const base   = SEVERITY_SCORES[alert.severity] ?? 50;
    const conf   = (alert.confidence / 100) * 20; // confidence bonus, max 20
    const score  = Math.min(Math.round(base + conf), 100);
    await this.alertRepo.update(id, { riskScore: score, updatedBy: 'system' }, tx);
    return score;
  }

  // ── Read helpers ──────────────────────────────────────────────────────────

  async getOpenAlerts(investigationId: string, tx?: any): Promise<Alert[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.alertRepo.findByStatus('OPEN', tx);
  }

  async getByInvestigation(investigationId: string, tx?: any): Promise<Alert[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.alertRepo.findByInvestigation(investigationId, tx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  private async _transition(id: string, status: AlertStatus, actor: string, label: string, tx?: any): Promise<Alert> {
    this.validateUuid(id, 'alertId');
    const runInTx = async (transaction: any) => {
      const existing = await this.alertRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Alert "${id}" not found.`);
      const updated  = await this.alertRepo.update(id, { status, updatedBy: actor }, transaction);
      await this.timelineSvc.recordStatusChange(
        updated.projectId, updated.investigationId, 'Alert', id,
        existing.status, status, actor, transaction,
      );
      await eventPublisher.publish(`Alert${status.charAt(0) + status.slice(1).toLowerCase()}`, { alert: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
