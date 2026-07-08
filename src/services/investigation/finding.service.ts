/**
 * FindingService — Phase A5.3.3
 * ===============================
 * Business logic for Finding lifecycle management.
 * All multi-repository writes run inside Prisma transactions.
 * Automatically raises Alerts when severity is HIGH or CRITICAL.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  findingRepository,
  alertRepository,
  evidenceRepository,
} from '../../repositories/investigation';
import { activityLogRepository } from '../../repositories/core';
import { TimelineService } from './timeline.service';
import prisma from '../../lib/prisma';
import { Finding, FindingSeverity, FindingStatus, Prisma } from '@prisma/client';

const HIGH_SEVERITY: FindingSeverity[] = ['HIGH', 'CRITICAL'];

export class FindingService extends BaseService {
  constructor(
    private readonly findingRepo   = findingRepository,
    private readonly alertRepo     = alertRepository,
    private readonly evidenceRepo  = evidenceRepository,
    private readonly activityRepo  = activityLogRepository,
    private readonly timelineSvc   = new TimelineService(),
  ) { super(); }

  // ── Create ─────────────────────────────────────────────────────────────────

  async createFinding(data: Prisma.FindingUncheckedCreateInput, tx?: any): Promise<Finding> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'title', 'createdBy', 'updatedBy']);
    this.validateUuid(data.projectId, 'projectId');
    this.validateUuid(data.investigationId, 'investigationId');

    const runInTx = async (transaction: any) => {
      const finding = await this.findingRepo.create(data, transaction);

      await this.timelineSvc.record({
        projectId: finding.projectId, investigationId: finding.investigationId,
        title: 'Finding Created',
        description: `Finding "${finding.title}" (${finding.severity}) created.`,
        type: 'FINDING_CREATED', createdBy: data.createdBy as string,
      }, transaction);

      // Only create ActivityLog if createdBy is a valid UUID
      const actorId = data.createdBy as string;
      if (actorId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actorId)) {
        await this.activityRepo.create({
          userId: actorId, projectId: finding.projectId, investigationId: finding.investigationId,
          action: 'CREATE', type: 'CREATE', details: `Finding "${finding.title}" created`,
          createdBy: actorId, updatedBy: actorId,
        }, transaction);
      }

      // Auto-raise alert for HIGH/CRITICAL findings
      if (HIGH_SEVERITY.includes(finding.severity)) {
        await this._raiseAlert(finding, data.createdBy as string, transaction);
      }

      await eventPublisher.publish('FindingCreated', { finding });
      return finding;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ─────────────────────────────────────────────────────────────────

  async updateFinding(id: string, data: Prisma.FindingUncheckedUpdateInput, tx?: any): Promise<Finding> {
    this.validateUuid(id, 'findingId');
    const runInTx = async (transaction: any) => {
      const existing = await this.findingRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Finding "${id}" not found.`);

      const updated = await this.findingRepo.update(id, data, transaction);

      // Auto-alert on severity escalation to HIGH/CRITICAL
      const prevSev = existing.severity;
      const newSev  = (data.severity as FindingSeverity) ?? existing.severity;
      if (!HIGH_SEVERITY.includes(prevSev) && HIGH_SEVERITY.includes(newSev)) {
        await this._raiseAlert(updated, (data.updatedBy as string) ?? 'system', transaction);
      }

      await this.timelineSvc.recordUpdate(
        updated.projectId, updated.investigationId, 'Finding', id,
        'fields updated', (data.updatedBy as string) ?? 'system', transaction,
      );
      await eventPublisher.publish('FindingUpdated', { finding: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Severity / Status ──────────────────────────────────────────────────────

  async changeSeverity(id: string, severity: FindingSeverity, actor: string, tx?: any): Promise<Finding> {
    this.validateUuid(id, 'findingId');
    const runInTx = async (transaction: any) => {
      const existing = await this.findingRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Finding "${id}" not found.`);
      const updated = await this.findingRepo.update(id, { severity, updatedBy: actor }, transaction);
      await this.timelineSvc.recordStatusChange(
        updated.projectId, updated.investigationId, 'Finding', id,
        existing.severity, severity, actor, transaction,
      );
      if (!HIGH_SEVERITY.includes(existing.severity) && HIGH_SEVERITY.includes(severity)) {
        await this._raiseAlert(updated, actor, transaction);
      }
      await eventPublisher.publish('FindingSeverityChanged', { finding: updated, from: existing.severity, to: severity });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async changeStatus(id: string, status: FindingStatus, actor: string, tx?: any): Promise<Finding> {
    this.validateUuid(id, 'findingId');
    const runInTx = async (transaction: any) => {
      const existing = await this.findingRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Finding "${id}" not found.`);
      const updated = await this.findingRepo.update(id, { status, updatedBy: actor }, transaction);
      await this.timelineSvc.recordStatusChange(
        updated.projectId, updated.investigationId, 'Finding', id,
        existing.status, status, actor, transaction,
      );
      await eventPublisher.publish('FindingStatusChanged', { finding: updated, from: existing.status, to: status });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Asset / Evidence / MITRE ───────────────────────────────────────────────

  async assignAsset(findingId: string, assetId: string, actor: string, tx?: any): Promise<Finding> {
    this.validateUuid(findingId, 'findingId');
    this.validateUuid(assetId, 'assetId');
    const runInTx = async (transaction: any) => {
      const f = await this.findingRepo.findById(findingId, transaction);
      if (!f || f.deletedAt) throw new Error(`Finding "${findingId}" not found.`);
      const updated = await this.findingRepo.update(findingId, { assetId, updatedBy: actor }, transaction);
      await this.timelineSvc.record({
        projectId: updated.projectId, investigationId: updated.investigationId,
        title: 'Asset Assigned to Finding',
        description: `Asset ${assetId} linked to finding "${updated.title}".`,
        type: 'HISTORY_CREATED', createdBy: actor,
      }, transaction);
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async attachEvidence(findingId: string, evidenceId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(findingId, 'findingId');
    this.validateUuid(evidenceId, 'evidenceId');
    const runInTx = async (transaction: any) => {
      await prisma.evidence.update({ where: { id: evidenceId }, data: { findingId, updatedBy: actor } });
      const f = await this.findingRepo.findById(findingId, transaction);
      if (!f) throw new Error(`Finding "${findingId}" not found.`);
      await this.timelineSvc.record({
        projectId: f.projectId, investigationId: f.investigationId,
        title: 'Evidence Attached to Finding',
        description: `Evidence ${evidenceId} attached to finding "${f.title}".`,
        type: 'EVIDENCE_ADDED', createdBy: actor,
      }, transaction);
      await eventPublisher.publish('EvidenceAttached', { findingId, evidenceId });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async mapMitreTechnique(findingId: string, techniqueId: string, actor: string, tx?: any): Promise<Finding> {
    this.validateUuid(findingId, 'findingId');
    const runInTx = async (transaction: any) => {
      const f = await this.findingRepo.findById(findingId, transaction);
      if (!f || f.deletedAt) throw new Error(`Finding "${findingId}" not found.`);
      const meta = { ...(f.metadata as any ?? {}), mitreTechniques: [...((f.metadata as any)?.mitreTechniques ?? []), techniqueId] };
      const updated = await this.findingRepo.update(findingId, { metadata: meta, updatedBy: actor }, transaction);
      await this.timelineSvc.record({
        projectId: updated.projectId, investigationId: updated.investigationId,
        title: 'MITRE Technique Mapped', description: `Technique ${techniqueId} mapped to finding.`,
        type: 'MITRE_MAPPED', createdBy: actor,
      }, transaction);
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Priority ───────────────────────────────────────────────────────────────

  async calculatePriority(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'findingId');
    const f = await this.findingRepo.findById(id, tx);
    if (!f || f.deletedAt) throw new Error(`Finding "${id}" not found.`);
    const sevScore: Record<string, number> = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 10 };
    const statusBonus: Record<string, number> = { OPEN: 20, CONFIRMED: 15, SUPPRESSED: 0, FALSE_POSITIVE: 0, RESOLVED: 0, CLOSED: 0 };
    return Math.min((sevScore[f.severity] ?? 50) + (statusBonus[f.status] ?? 0), 100);
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private async _raiseAlert(finding: Finding, actor: string, tx: any): Promise<void> {
    const alert = await this.alertRepo.create({
      projectId:      finding.projectId,
      investigationId: finding.investigationId,
      findingId:      finding.id,
      title:          `Alert: ${finding.title}`,
      description:    `Auto-generated from ${finding.severity} finding.`,
      severity:       finding.severity as any,
      status:         'NEW',
      source:         'FINDING',
      riskScore:      finding.riskScore,
      confidence:     finding.confidence,
      createdBy:      actor,
      updatedBy:      actor,
    }, tx);
    await this.timelineSvc.recordAlert(
      finding.projectId, finding.investigationId, alert.id, finding.severity, actor, tx,
    );
    await eventPublisher.publish('AlertRaised', { alert, finding });
  }
}
