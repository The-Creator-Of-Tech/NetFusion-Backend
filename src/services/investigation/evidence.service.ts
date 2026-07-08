/**
 * EvidenceService — Phase A5.3.3
 * ================================
 * Business logic for Evidence lifecycle: integrity checks, duplicate
 * detection via hash, metadata extraction, and cross-entity association.
 */

import * as crypto from 'crypto';
import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { evidenceRepository } from '../../repositories/investigation';
import { TimelineService } from './timeline.service';
import prisma from '../../lib/prisma';
import { Evidence, EvidenceType, Prisma } from '@prisma/client';

export class EvidenceService extends BaseService {
  constructor(
    private readonly evidenceRepo  = evidenceRepository,
    private readonly timelineSvc   = new TimelineService(),
  ) { super(); }

  // ── Attach file / PCAP ────────────────────────────────────────────────────

  async attachFile(data: Prisma.EvidenceUncheckedCreateInput & { rawContent?: Buffer }, tx?: any): Promise<Evidence> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'fieldName', 'fieldValue', 'sourceType', 'createdBy']);
    const runInTx = async (transaction: any) => {
      const hash = await this.calculateHash(data.fieldValue as string);
      const dup  = await this.isDuplicate(hash, data.investigationId, transaction);
      if (dup) throw new Error(`Duplicate evidence: identical content hash already recorded.`);
      const evidence = await this.evidenceRepo.create({
        ...data,
        type: data.type ?? 'FILE',
        metadata: { ...(data.metadata as any ?? {}), hash },
      }, transaction);
      await this.timelineSvc.record({
        projectId: evidence.projectId, investigationId: evidence.investigationId,
        title: 'Evidence File Attached', description: `File evidence "${evidence.fieldName}" added.`,
        type: 'EVIDENCE_ADDED', createdBy: data.createdBy as string,
      }, transaction);
      await eventPublisher.publish('EvidenceAttached', { evidence });
      return evidence;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async attachPcap(data: Prisma.EvidenceUncheckedCreateInput, tx?: any): Promise<Evidence> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'fieldName', 'fieldValue', 'sourceType', 'createdBy']);
    const runInTx = async (transaction: any) => {
      const hash = await this.calculateHash(data.fieldValue as string);
      const dup  = await this.isDuplicate(hash, data.investigationId, transaction);
      if (dup) throw new Error(`Duplicate PCAP evidence: same capture already recorded.`);
      const evidence = await this.evidenceRepo.create({
        ...data, type: 'PACKET',
        metadata: { ...(data.metadata as any ?? {}), hash },
      }, transaction);
      await this.timelineSvc.recordCapture(
        evidence.projectId, evidence.investigationId, evidence.id, data.createdBy as string, transaction,
      );
      await eventPublisher.publish('EvidenceAttached', { evidence });
      return evidence;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Hash helpers ──────────────────────────────────────────────────────────

  async calculateHash(content: string): Promise<string> {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

  async verifyHash(evidenceId: string, expectedHash: string, tx?: any): Promise<boolean> {
    this.validateUuid(evidenceId, 'evidenceId');
    const ev = await this.evidenceRepo.findById(evidenceId, tx);
    if (!ev || ev.deletedAt) throw new Error(`Evidence "${evidenceId}" not found.`);
    const storedHash = (ev.metadata as any)?.hash as string | undefined;
    if (!storedHash) return false;
    return storedHash === expectedHash;
  }

  private async isDuplicate(hash: string, investigationId: string, tx?: any): Promise<boolean> {
    const results = await this.evidenceRepo.findByHash(hash, tx);
    return results.some(e => e.investigationId === investigationId && !e.deletedAt);
  }

  // ── Associations ──────────────────────────────────────────────────────────

  async associateAsset(evidenceId: string, assetId: string, actor: string, tx?: any): Promise<Evidence> {
    this.validateUuid(evidenceId, 'evidenceId');
    this.validateUuid(assetId, 'assetId');
    const runInTx = async (transaction: any) => {
      const ev = await this.evidenceRepo.findById(evidenceId, transaction);
      if (!ev || ev.deletedAt) throw new Error(`Evidence "${evidenceId}" not found.`);
      const updated = await this.evidenceRepo.update(evidenceId, { assetId, updatedBy: actor }, transaction);
      await this.timelineSvc.record({
        projectId: ev.projectId, investigationId: ev.investigationId,
        title: 'Evidence Linked to Asset', description: `Evidence ${evidenceId} linked to asset ${assetId}.`,
        type: 'EVIDENCE_ADDED', createdBy: actor,
      }, transaction);
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async associateFinding(evidenceId: string, findingId: string, actor: string, tx?: any): Promise<Evidence> {
    this.validateUuid(evidenceId, 'evidenceId');
    this.validateUuid(findingId, 'findingId');
    const runInTx = async (transaction: any) => {
      const ev = await this.evidenceRepo.findById(evidenceId, transaction);
      if (!ev || ev.deletedAt) throw new Error(`Evidence "${evidenceId}" not found.`);
      const updated = await this.evidenceRepo.update(evidenceId, { findingId, updatedBy: actor }, transaction);
      await this.timelineSvc.record({
        projectId: ev.projectId, investigationId: ev.investigationId,
        title: 'Evidence Linked to Finding', description: `Evidence ${evidenceId} linked to finding ${findingId}.`,
        type: 'EVIDENCE_ADDED', createdBy: actor,
      }, transaction);
      await eventPublisher.publish('EvidenceAttached', { evidenceId, findingId });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read ─────────────────────────────────────────────────────────────────

  async getByInvestigation(investigationId: string, tx?: any): Promise<Evidence[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.evidenceRepo.findByInvestigation(investigationId, tx);
  }

  async getByAsset(assetId: string, tx?: any): Promise<Evidence[]> {
    this.validateUuid(assetId, 'assetId');
    return this.evidenceRepo.findByAsset(assetId, tx);
  }
}
