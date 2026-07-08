/**
 * IocService — Phase A5.3.5
 * ==========================
 * Business logic for IOC (Indicator of Compromise) lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for IOC records, relationships, and enrichment
 * - IOC enrichment (reputation score, malicious flag, categories)
 * - IOC relationship management (CVE, ThreatActor, Campaign linkage)
 * - IOC type/severity/confidence filtering
 * - IOC correlation with MITRE techniques and CVEs
 * - Risk scoring and threat scoring
 * - Event publishing after every state change
 * - Transaction support (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { iocRepository } from '../../repositories/knowledge';
import prisma from '../../lib/prisma';
import {
  IOC,
  IOCRelationship,
  IOCEnrichment,
  IOCType,
  IOCStatus,
  CVESeverity,
  RelationshipType,
  Prisma,
} from '@prisma/client';

// ── IOC confidence weight map ─────────────────────────────────────────────────
const CONFIDENCE_WEIGHT: Record<string, number> = {
  VERIFIED: 100,
  HIGH: 75,
  MEDIUM: 50,
  LOW: 25,
};

// ── Severity score map ────────────────────────────────────────────────────────
const SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 100,
  HIGH: 75,
  MEDIUM: 50,
  LOW: 25,
};

export class IocService extends BaseService {
  constructor(private readonly iocRepo = iocRepository) {
    super();
  }

  // ── Create ─────────────────────────────────────────────────────────────────

  /**
   * Create a new IOC. Validates iocType and value presence.
   * Publishes IocCreated.
   */
  async createIoc(
    data: Prisma.IOCUncheckedCreateInput,
    tx?: any,
  ): Promise<IOC> {
    this.validateRequired(data as any, ['iocId', 'value', 'iocType', 'createdBy', 'updatedBy']);
    if (!data.value || !String(data.value).trim()) {
      throw new Error('Validation failed: value must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.iocRepo.findByValue(String(data.value).trim(), transaction);
      if (existing) {
        throw new Error(`Conflict: IOC with value "${data.value}" already exists.`);
      }

      const ioc = await this.iocRepo.create(
        { ...data, value: String(data.value).trim() } as any,
        transaction,
      );
      await eventPublisher.publish('IocCreated', { ioc });
      return ioc;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ─────────────────────────────────────────────────────────────────

  /**
   * Update an IOC by UUID.
   * Publishes IocUpdated.
   */
  async updateIoc(
    id: string,
    data: Prisma.IOCUncheckedUpdateInput,
    tx?: any,
  ): Promise<IOC> {
    this.validateUuid(id, 'iocId');

    const runInTx = async (transaction: any) => {
      const existing = await this.iocRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`IOC "${id}" not found.`);
      }
      const updated = await this.iocRepo.update(id, data, transaction);
      await eventPublisher.publish('IocUpdated', { ioc: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ─────────────────────────────────────────────────────────────────

  /**
   * Soft-delete an IOC.
   * Publishes IocDeleted.
   */
  async deleteIoc(id: string, actor: string, tx?: any): Promise<IOC> {
    this.validateUuid(id, 'iocId');

    const runInTx = async (transaction: any) => {
      const existing = await this.iocRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`IOC "${id}" not found.`);
      }
      const deleted = await this.iocRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('IocDeleted', { ioc: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookup ─────────────────────────────────────────────────────────────────

  /** Find an IOC by its indicator value. */
  async findByValue(value: string, tx?: any): Promise<IOC | null> {
    if (!value || !value.trim()) {
      throw new Error('Validation failed: value must not be empty.');
    }
    return this.iocRepo.findByValue(value.trim(), tx);
  }

  /** Find IOCs by type. */
  async findByType(iocType: IOCType, tx?: any): Promise<IOC[]> {
    return this.iocRepo.findByType(iocType, tx);
  }

  /** Find IOCs by status. */
  async findByStatus(status: IOCStatus, tx?: any): Promise<IOC[]> {
    return this.iocRepo.findByStatus(status, tx);
  }

  /** Find all malicious IOCs. */
  async findMalicious(tx?: any): Promise<IOC[]> {
    return this.iocRepo.findMalicious(tx);
  }

  /** Find all revoked IOCs. */
  async findRevoked(tx?: any): Promise<IOC[]> {
    return this.iocRepo.findRevoked(tx);
  }

  /** Find IOCs by confidence classification or numeric range. */
  async findByConfidence(
    min: string | number,
    max?: string | number,
    tx?: any,
  ): Promise<IOC[]> {
    return this.iocRepo.findByConfidence(min, max, tx);
  }

  /** Find IOCs by source. */
  async findBySource(source: string, tx?: any): Promise<IOC[]> {
    if (!source || !source.trim()) {
      throw new Error('Validation failed: source must not be empty.');
    }
    return this.iocRepo.findBySource(source.trim(), tx);
  }

  // ── Enrichment ─────────────────────────────────────────────────────────────

  /** Get enrichment record for an IOC. */
  async getEnrichment(iocId: string, tx?: any): Promise<IOCEnrichment | null> {
    this.validateUuid(iocId, 'iocId');
    return this.iocRepo.findEnrichment(iocId, tx);
  }

  /**
   * Upsert enrichment data for an IOC.
   * Reputation score must be 0–100.
   * Publishes IocEnriched.
   */
  async enrichIoc(
    iocId: string,
    data: {
      reputationScore: number;
      malicious: boolean;
      categories?: string[];
      firstSeen?: string;
      lastSeen?: string;
      provider?: string;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<IOCEnrichment> {
    this.validateUuid(iocId, 'iocId');
    if (
      typeof data.reputationScore !== 'number' ||
      data.reputationScore < 0 ||
      data.reputationScore > 100
    ) {
      throw new Error(
        `Validation failed: reputationScore ${data.reputationScore} must be in [0, 100].`,
      );
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const ioc = await this.iocRepo.findById(iocId, transaction);
      if (!ioc || ioc.deletedAt) {
        throw new Error(`IOC "${iocId}" not found.`);
      }

      const existing = await this.iocRepo.findEnrichment(iocId, transaction);
      let enrichment: IOCEnrichment;

      if (existing) {
        enrichment = await client.iOCEnrichment.update({
          where: { id: existing.id },
          data: {
            reputationScore: data.reputationScore,
            malicious: data.malicious,
            categories: data.categories ?? existing.categories,
            firstSeen: data.firstSeen ?? existing.firstSeen,
            lastSeen: data.lastSeen ?? existing.lastSeen,
            provider: data.provider ?? existing.provider,
            updatedBy: data.updatedBy,
          },
        });
      } else {
        enrichment = await client.iOCEnrichment.create({
          data: {
            iocId,
            reputationScore: data.reputationScore,
            malicious: data.malicious,
            categories: data.categories ?? [],
            firstSeen: data.firstSeen ?? '',
            lastSeen: data.lastSeen ?? '',
            provider: data.provider ?? '',
            createdBy: data.createdBy,
            updatedBy: data.updatedBy,
          },
        });
      }

      await eventPublisher.publish('IocEnriched', { iocId, enrichment });
      return enrichment;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Relationships ──────────────────────────────────────────────────────────

  /** Get relationships for an IOC. */
  async getRelationships(iocId: string, tx?: any): Promise<IOCRelationship[]> {
    this.validateUuid(iocId, 'iocId');
    return this.iocRepo.findRelationships(iocId, tx);
  }

  /**
   * Add a relationship between an IOC and another entity.
   * Publishes IocRelationshipAdded.
   */
  async addRelationship(
    iocId: string,
    data: {
      targetId: string;
      targetType: string;
      relationType: RelationshipType;
      confidence?: number;
      cveId?: string;
      threatId?: string;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<IOCRelationship> {
    this.validateUuid(iocId, 'iocId');
    if (!data.targetType || !data.targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const ioc = await this.iocRepo.findById(iocId, transaction);
      if (!ioc || ioc.deletedAt) {
        throw new Error(`IOC "${iocId}" not found.`);
      }

      const relationship = await client.iOCRelationship.create({
        data: {
          iocId,
          cveId: data.cveId ?? null,
          threatId: data.threatId ?? null,
          targetType: data.targetType.trim(),
          relationType: data.relationType,
          confidence: data.confidence ?? 0,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      await eventPublisher.publish('IocRelationshipAdded', { iocId, relationship });
      return relationship;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Remove a relationship by its UUID.
   * Publishes IocRelationshipRemoved.
   */
  async removeRelationship(relationshipId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(relationshipId, 'relationshipId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const rel = await client.iOCRelationship.findUnique({
        where: { id: relationshipId },
      });
      if (!rel || rel.deletedAt) {
        throw new Error(`IOCRelationship "${relationshipId}" not found.`);
      }
      await client.iOCRelationship.update({
        where: { id: relationshipId },
        data: { deletedAt: new Date(), updatedBy: actor },
      });
      await eventPublisher.publish('IocRelationshipRemoved', { relationshipId });
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Correlation ────────────────────────────────────────────────────────────

  /**
   * Find IOCs associated with a specific CVE.
   */
  async findByCve(cveId: string, tx?: any): Promise<IOC[]> {
    this.validateUuid(cveId, 'cveId');
    const client = tx || prisma;
    return client.iOC.findMany({
      where: {
        deletedAt: null,
        cves: { some: { id: cveId } },
      },
    });
  }

  /**
   * Find IOCs linked to a MITRE technique.
   */
  async findByTechnique(techniqueId: string, tx?: any): Promise<IOC[]> {
    this.validateUuid(techniqueId, 'techniqueId');
    const client = tx || prisma;
    return client.iOC.findMany({
      where: {
        deletedAt: null,
        techniques: { some: { id: techniqueId } },
      },
    });
  }

  /**
   * Find IOCs linked to a threat actor.
   */
  async findByThreatActor(threatActorId: string, tx?: any): Promise<IOC[]> {
    this.validateUuid(threatActorId, 'threatActorId');
    const client = tx || prisma;
    return client.iOC.findMany({
      where: {
        deletedAt: null,
        threatActors: { some: { id: threatActorId } },
      },
    });
  }

  // ── Revocation ─────────────────────────────────────────────────────────────

  /**
   * Mark an IOC as revoked.
   * Publishes IocRevoked.
   */
  async revokeIoc(id: string, actor: string, tx?: any): Promise<IOC> {
    this.validateUuid(id, 'iocId');

    const runInTx = async (transaction: any) => {
      const existing = await this.iocRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`IOC "${id}" not found.`);
      }
      const updated = await this.iocRepo.update(
        id,
        { revoked: true, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('IocRevoked', { ioc: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Scoring ────────────────────────────────────────────────────────────────

  /**
   * Calculate a threat score for an IOC (0–100) based on severity,
   * confidence, malicious flag, and revocation status.
   */
  async calculateThreatScore(iocId: string, tx?: any): Promise<number> {
    this.validateUuid(iocId, 'iocId');
    const ioc = await this.iocRepo.findById(iocId, tx);
    if (!ioc || ioc.deletedAt) {
      throw new Error(`IOC "${iocId}" not found.`);
    }

    if (ioc.revoked) return 0;

    const sevScore = SEVERITY_SCORE[String(ioc.severity ?? 'MEDIUM')] ?? 50;
    const confWeight = CONFIDENCE_WEIGHT[String(ioc.confidence ?? 'MEDIUM').toUpperCase()] ?? 50;
    const maliciousBonus = ioc.malicious ? 10 : 0;

    const score = Math.round((sevScore * confWeight) / 100) + maliciousBonus;
    return Math.min(100, score);
  }

  /**
   * Aggregate threat score across multiple IOC IDs (0–100, mean).
   */
  async aggregateThreatScore(iocIds: string[], tx?: any): Promise<number> {
    if (!iocIds || iocIds.length === 0) return 0;
    const scores = await Promise.all(iocIds.map((id) => this.calculateThreatScore(id, tx)));
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  }

  // ── Statistics ─────────────────────────────────────────────────────────────

  /**
   * Compute IOC statistics across the knowledge base.
   */
  async getStatistics(tx?: any): Promise<{
    totalIOCs: number;
    maliciousIOCs: number;
    revokedIOCs: number;
    averageConfidence: number;
    typeCounts: Record<string, number>;
    sourceCounts: Record<string, number>;
  }> {
    const client = tx || prisma;

    const [total, malicious, revoked, all] = await Promise.all([
      client.iOC.count({ where: { deletedAt: null } }),
      client.iOC.count({ where: { deletedAt: null, malicious: true } }),
      client.iOC.count({ where: { deletedAt: null, revoked: true } }),
      client.iOC.findMany({ where: { deletedAt: null } }),
    ]);

    const typeCounts: Record<string, number> = {};
    const sourceCounts: Record<string, number> = {};
    let confSum = 0;

    for (const ioc of all) {
      const t = String(ioc.iocType ?? 'UNKNOWN');
      typeCounts[t] = (typeCounts[t] ?? 0) + 1;
      if (ioc.source) {
        sourceCounts[ioc.source] = (sourceCounts[ioc.source] ?? 0) + 1;
      }
      confSum += CONFIDENCE_WEIGHT[String(ioc.confidence ?? 'MEDIUM').toUpperCase()] ?? 50;
    }

    return {
      totalIOCs: total,
      maliciousIOCs: malicious,
      revokedIOCs: revoked,
      averageConfidence: total > 0 ? Math.round(confSum / total) : 0,
      typeCounts,
      sourceCounts,
    };
  }

  // ── Bulk Operations ────────────────────────────────────────────────────────

  /**
   * Bulk-create IOCs. Returns succeeded IDs and failed entries.
   */
  async bulkCreateIocs(
    items: Prisma.IOCUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { value: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { value: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const ioc = await this.createIoc({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(ioc.id);
      } catch (e: any) {
        failed.push({ value: String(item.value ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('IocsBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  /**
   * Bulk soft-delete IOCs by IDs.
   */
  async bulkDeleteIocs(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteIoc(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('IocsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const iocService = new IocService();
