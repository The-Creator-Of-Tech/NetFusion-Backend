/**
 * CveService — Phase A5.3.5
 * ==========================
 * Business logic for CVE lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for CVE records, CVSS details, and AffectedProduct entries
 * - CVE correlation with MITRE techniques
 * - CVSS score calculations and severity derivation
 * - Exploitation / patch status tracking
 * - Risk aggregation and threat scoring
 * - Event publishing after every state change
 * - Transaction support (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { cveRepository } from '../../repositories/knowledge';
import prisma from '../../lib/prisma';
import {
  CVE,
  CVSS,
  AffectedProduct,
  CVESeverity,
  Prisma,
} from '@prisma/client';

// ── CVSS severity thresholds (CVSS v3.1) ────────────────────────────────────
const CVSS_SEVERITY_MAP: { threshold: number; severity: CVESeverity }[] = [
  { threshold: 9.0, severity: 'CRITICAL' },
  { threshold: 7.0, severity: 'HIGH' },
  { threshold: 4.0, severity: 'MEDIUM' },
  { threshold: 0.1, severity: 'LOW' },
];

/** Derive CVSS v3.1 severity label from a numeric base score. */
export function cvssScoreToSeverity(score: number): CVESeverity {
  for (const { threshold, severity } of CVSS_SEVERITY_MAP) {
    if (score >= threshold) return severity;
  }
  return 'LOW';
}

/** Validate that a CVSS score is within [0.0, 10.0]. */
export function validateCvssScore(score: number): void {
  if (typeof score !== 'number' || score < 0.0 || score > 10.0) {
    throw new Error(`Validation failed: cvssScore ${score} must be a number in [0.0, 10.0].`);
  }
}

/** Validate CVE ID format: CVE-YYYY-NNNN (4+ digits). */
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;
export function validateCveId(cveId: string): void {
  if (!CVE_ID_RE.test((cveId ?? '').trim())) {
    throw new Error(
      `Validation failed: cveId "${cveId}" must match CVE-YYYY-NNNN format (e.g. CVE-2021-44228).`,
    );
  }
}

export class CveService extends BaseService {
  constructor(private readonly cveRepo = cveRepository) {
    super();
  }

  // ── Create ─────────────────────────────────────────────────────────────────

  /**
   * Create a new CVE record. Validates format and CVSS range.
   * Publishes CveCreated.
   */
  async createCve(
    data: Prisma.CVEUncheckedCreateInput,
    tx?: any,
  ): Promise<CVE> {
    this.validateRequired(data as any, ['cveId', 'severity', 'createdBy', 'updatedBy']);
    validateCveId(String(data.cveId));
    if (data.cvssScore !== undefined && data.cvssScore !== null) {
      validateCvssScore(Number(data.cvssScore));
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.cveRepo.findByCveId(
        String(data.cveId).trim().toUpperCase(),
        transaction,
      );
      if (existing) {
        throw new Error(`Conflict: CVE "${data.cveId}" already exists.`);
      }

      const cve = await this.cveRepo.create(
        { ...data, cveId: String(data.cveId).trim().toUpperCase() } as any,
        transaction,
      );
      await eventPublisher.publish('CveCreated', { cve });
      return cve;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ─────────────────────────────────────────────────────────────────

  /**
   * Update a CVE record by UUID.
   * Publishes CveUpdated.
   */
  async updateCve(
    id: string,
    data: Prisma.CVEUncheckedUpdateInput,
    tx?: any,
  ): Promise<CVE> {
    this.validateUuid(id, 'cveId');
    if (data.cvssScore !== undefined && data.cvssScore !== null) {
      validateCvssScore(Number(data.cvssScore));
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.cveRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CVE "${id}" not found.`);
      }
      const updated = await this.cveRepo.update(id, data, transaction);
      await eventPublisher.publish('CveUpdated', { cve: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ─────────────────────────────────────────────────────────────────

  /**
   * Soft-delete a CVE record.
   * Publishes CveDeleted.
   */
  async deleteCve(id: string, actor: string, tx?: any): Promise<CVE> {
    this.validateUuid(id, 'cveId');

    const runInTx = async (transaction: any) => {
      const existing = await this.cveRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CVE "${id}" not found.`);
      }
      const deleted = await this.cveRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('CveDeleted', { cve: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookup ─────────────────────────────────────────────────────────────────

  /** Find a CVE by its canonical cveId string (e.g. "CVE-2021-44228"). */
  async findByCveId(cveId: string, tx?: any): Promise<CVE | null> {
    validateCveId(cveId);
    return this.cveRepo.findByCveId(cveId.trim().toUpperCase(), tx);
  }

  /** Find CVEs by severity level. */
  async findBySeverity(severity: CVESeverity, tx?: any): Promise<CVE[]> {
    return this.cveRepo.findBySeverity(severity, tx);
  }

  /** Find CVEs by vendor (direct field or through AffectedProduct). */
  async findByVendor(vendor: string, tx?: any): Promise<CVE[]> {
    if (!vendor || !vendor.trim()) {
      throw new Error('Validation failed: vendor must not be empty.');
    }
    return this.cveRepo.findByVendor(vendor.trim(), tx);
  }

  /** Find CVEs by product (direct field or through AffectedProduct). */
  async findByProduct(product: string, tx?: any): Promise<CVE[]> {
    if (!product || !product.trim()) {
      throw new Error('Validation failed: product must not be empty.');
    }
    return this.cveRepo.findByProduct(product.trim(), tx);
  }

  /** Find CVEs with CVSS base score within [min, max]. */
  async findByCvssRange(min: number, max: number, tx?: any): Promise<CVE[]> {
    validateCvssScore(min);
    validateCvssScore(max);
    if (min > max) {
      throw new Error(`Validation failed: min ${min} must be <= max ${max}.`);
    }
    return this.cveRepo.findByCvssRange(min, max, tx);
  }

  /** Find all patched CVEs. */
  async findPatched(tx?: any): Promise<CVE[]> {
    return this.cveRepo.findPatched(tx);
  }

  /** Find all unpatched CVEs. */
  async findUnpatched(tx?: any): Promise<CVE[]> {
    return this.cveRepo.findUnpatched(tx);
  }

  /** Find all exploited CVEs. */
  async findExploited(tx?: any): Promise<CVE[]> {
    return this.cveRepo.findExploited(tx);
  }

  // ── Sub-entities ───────────────────────────────────────────────────────────

  /** Get CVSS detail record for a CVE (by UUID). */
  async getCvssDetails(cveId: string, tx?: any): Promise<CVSS | null> {
    this.validateUuid(cveId, 'cveId');
    return this.cveRepo.findCvss(cveId, tx);
  }

  /** Get AffectedProduct entries for a CVE (by UUID). */
  async getAffectedProducts(cveId: string, tx?: any): Promise<AffectedProduct[]> {
    this.validateUuid(cveId, 'cveId');
    return this.cveRepo.findAffectedProducts(cveId, tx);
  }

  /**
   * Upsert CVSS record for a CVE. Derives severity from score if not provided.
   * Publishes CvssUpdated.
   */
  async upsertCvss(
    cveId: string,
    data: {
      baseScore: number;
      severity?: CVESeverity;
      vectorString?: string;
      exploitabilityScore?: number;
      impactScore?: number;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<CVSS> {
    this.validateUuid(cveId, 'cveId');
    validateCvssScore(data.baseScore);

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const cve = await this.cveRepo.findById(cveId, transaction);
      if (!cve || cve.deletedAt) {
        throw new Error(`CVE "${cveId}" not found.`);
      }

      const derivedSeverity = data.severity ?? cvssScoreToSeverity(data.baseScore);
      const existing = await this.cveRepo.findCvss(cveId, transaction);

      let cvss: CVSS;
      if (existing) {
        cvss = await client.cVSS.update({
          where: { id: existing.id },
          data: {
            baseScore: data.baseScore,
            severity: derivedSeverity,
            vectorString: data.vectorString ?? existing.vectorString,
            exploitabilityScore: data.exploitabilityScore ?? existing.exploitabilityScore,
            impactScore: data.impactScore ?? existing.impactScore,
            updatedBy: data.updatedBy,
          },
        });
      } else {
        cvss = await client.cVSS.create({
          data: {
            cveId,
            baseScore: data.baseScore,
            severity: derivedSeverity,
            vectorString: data.vectorString ?? '',
            exploitabilityScore: data.exploitabilityScore ?? 0,
            impactScore: data.impactScore ?? 0,
            createdBy: data.createdBy,
            updatedBy: data.updatedBy,
          },
        });
      }

      await eventPublisher.publish('CvssUpdated', { cveId, cvss });
      return cvss;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Add an affected product entry to a CVE.
   * Publishes AffectedProductAdded.
   */
  async addAffectedProduct(
    cveId: string,
    data: {
      vendor: string;
      product: string;
      productVersion?: string;
      patched?: boolean;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<AffectedProduct> {
    this.validateUuid(cveId, 'cveId');
    if (!data.vendor || !data.vendor.trim()) {
      throw new Error('Validation failed: vendor must not be empty.');
    }
    if (!data.product || !data.product.trim()) {
      throw new Error('Validation failed: product must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const cve = await this.cveRepo.findById(cveId, transaction);
      if (!cve || cve.deletedAt) {
        throw new Error(`CVE "${cveId}" not found.`);
      }

      const product = await client.affectedProduct.create({
        data: {
          cveId,
          vendor: data.vendor.trim(),
          product: data.product.trim(),
          productVersion: data.productVersion ?? '',
          patched: data.patched ?? false,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });
      await eventPublisher.publish('AffectedProductAdded', { cveId, product });
      return product;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Correlation ────────────────────────────────────────────────────────────

  /**
   * Correlate a CVE to a set of MITRE technique IDs.
   * Connects techniques to the CVE in the DB. Publishes CveCorrelated.
   */
  async correlateToTechniques(
    cveId: string,
    techniqueIds: string[],
    actor: string,
    tx?: any,
  ): Promise<CVE> {
    this.validateUuid(cveId, 'cveId');
    if (!techniqueIds || techniqueIds.length === 0) {
      throw new Error('Validation failed: techniqueIds must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const cve = await this.cveRepo.findById(cveId, transaction);
      if (!cve || cve.deletedAt) {
        throw new Error(`CVE "${cveId}" not found.`);
      }
      const updated = await client.cVE.update({
        where: { id: cveId },
        data: {
          techniques: { connect: techniqueIds.map((id) => ({ id })) },
          updatedBy: actor,
        },
      });
      await eventPublisher.publish('CveCorrelated', { cveId, techniqueIds });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Find CVEs correlated to a specific MITRE technique ID (UUID).
   */
  async findByTechnique(techniqueId: string, tx?: any): Promise<CVE[]> {
    this.validateUuid(techniqueId, 'techniqueId');
    const client = tx || prisma;
    return client.cVE.findMany({
      where: {
        deletedAt: null,
        techniques: { some: { id: techniqueId } },
      },
    });
  }

  /**
   * Find CVEs correlated to a ThreatActor via ThreatRelationship.
   */
  async findByThreatActor(threatActorId: string, tx?: any): Promise<CVE[]> {
    this.validateUuid(threatActorId, 'threatActorId');
    const client = tx || prisma;
    const rels = await client.threatRelationship.findMany({
      where: { threatId: threatActorId, cveId: { not: null }, deletedAt: null },
      select: { cveId: true },
    });
    const ids = rels.map((r: { cveId: string | null }) => r.cveId as string).filter(Boolean);
    if (ids.length === 0) return [];
    return client.cVE.findMany({ where: { id: { in: ids }, deletedAt: null } });
  }

  // ── CVSS Calculations ──────────────────────────────────────────────────────

  /**
   * Calculate the composite risk score for a CVE (0–100) factoring
   * CVSS base score, exploitation status, and patch availability.
   */
  async calculateCveRisk(cveId: string, tx?: any): Promise<number> {
    this.validateUuid(cveId, 'cveId');
    const cve = await this.cveRepo.findById(cveId, tx);
    if (!cve || cve.deletedAt) {
      throw new Error(`CVE "${cveId}" not found.`);
    }

    const cvssScore = Number(cve.cvssScore ?? 0);
    const baseRisk = (cvssScore / 10) * 80; // max 80 from CVSS

    const exploitBonus = cve.exploited ? 15 : 0;
    const patchBonus = cve.patched ? -10 : 0;

    return Math.max(0, Math.min(100, Math.round(baseRisk + exploitBonus + patchBonus)));
  }

  /**
   * Derives CVESeverity from a raw CVSS numeric score (pure function, no DB).
   */
  deriveSeverity(score: number): CVESeverity {
    validateCvssScore(score);
    return cvssScoreToSeverity(score);
  }

  // ── Patch Status ───────────────────────────────────────────────────────────

  /**
   * Mark a CVE as patched.
   * Publishes CvePatched.
   */
  async markPatched(id: string, actor: string, tx?: any): Promise<CVE> {
    this.validateUuid(id, 'cveId');

    const runInTx = async (transaction: any) => {
      const existing = await this.cveRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CVE "${id}" not found.`);
      }
      const updated = await this.cveRepo.update(
        id,
        { patched: true, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('CvePatched', { cve: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Mark a CVE as exploited.
   * Publishes CveExploited.
   */
  async markExploited(id: string, actor: string, tx?: any): Promise<CVE> {
    this.validateUuid(id, 'cveId');

    const runInTx = async (transaction: any) => {
      const existing = await this.cveRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CVE "${id}" not found.`);
      }
      const updated = await this.cveRepo.update(
        id,
        { exploited: true, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('CveExploited', { cve: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Statistics ─────────────────────────────────────────────────────────────

  /**
   * Compute CVE statistics across the knowledge base.
   */
  async getStatistics(tx?: any): Promise<{
    totalCVEs: number;
    exploitedCVEs: number;
    patchedCVEs: number;
    averageCVSS: number;
    severityCounts: Record<string, number>;
    vendorCounts: Record<string, number>;
  }> {
    const client = tx || prisma;

    const [total, exploited, patched, all] = await Promise.all([
      client.cVE.count({ where: { deletedAt: null } }),
      client.cVE.count({ where: { deletedAt: null, exploited: true } }),
      client.cVE.count({ where: { deletedAt: null, patched: true } }),
      client.cVE.findMany({ where: { deletedAt: null } }),
    ]);

    const severityCounts: Record<string, number> = {};
    const vendorCounts: Record<string, number> = {};
    let cvssSum = 0;

    for (const c of all) {
      const sev = String(c.severity ?? 'UNKNOWN');
      severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
      cvssSum += Number(c.cvssScore ?? 0);
      if (c.vendor) {
        vendorCounts[c.vendor] = (vendorCounts[c.vendor] ?? 0) + 1;
      }
    }

    return {
      totalCVEs: total,
      exploitedCVEs: exploited,
      patchedCVEs: patched,
      averageCVSS: total > 0 ? Math.round((cvssSum / total) * 100) / 100 : 0,
      severityCounts,
      vendorCounts,
    };
  }

  // ── Bulk Operations ────────────────────────────────────────────────────────

  /**
   * Bulk-create CVEs. Returns succeeded IDs and failed entries.
   */
  async bulkCreateCves(
    items: Prisma.CVEUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { cveId: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { cveId: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const cve = await this.createCve({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(cve.id);
      } catch (e: any) {
        failed.push({ cveId: String(item.cveId ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('CvesBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  /**
   * Bulk soft-delete CVEs by IDs.
   */
  async bulkDeleteCves(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteCve(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('CvesBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const cveService = new CveService();
