import { BaseRepository } from '../base/BaseRepository';
import { CVE, AffectedProduct, CVSS, CVESeverity, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class CveRepository extends BaseRepository<CVE, Prisma.CVEUncheckedCreateInput, Prisma.CVEUncheckedUpdateInput> {
  constructor() {
    super('cVE');
  }

  /**
   * Finds a CVE by its cveId where not deleted.
   */
  async findByCveId(cveId: string, tx?: any): Promise<CVE | null> {
    return this.findOne({ cveId, deletedAt: null }, tx);
  }

  /**
   * Finds CVEs by severity where not deleted.
   */
  async findBySeverity(severity: CVESeverity, tx?: any): Promise<CVE[]> {
    return this.findMany({ filter: { severity, deletedAt: null } }, tx);
  }

  /**
   * Finds CVEs by vendor where not deleted.
   */
  async findByVendor(vendor: string, tx?: any): Promise<CVE[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        OR: [
          { vendor },
          { affectedProducts: { some: { vendor, deletedAt: null } } },
        ],
      },
    });
  }

  /**
   * Finds CVEs by product where not deleted.
   */
  async findByProduct(product: string, tx?: any): Promise<CVE[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        OR: [
          { product },
          { affectedProducts: { some: { product, deletedAt: null } } },
        ],
      },
    });
  }

  /**
   * Finds CVEs within a CVSS base score range where not deleted.
   */
  async findByCvssRange(min: number, max: number, tx?: any): Promise<CVE[]> {
    return this.findMany(
      {
        filter: {
          cvssScore: { gte: min, lte: max },
          deletedAt: null,
        },
      },
      tx
    );
  }

  /**
   * Finds patched CVEs where not deleted.
   */
  async findPatched(tx?: any): Promise<CVE[]> {
    return this.findMany({ filter: { patched: true, deletedAt: null } }, tx);
  }

  /**
   * Finds unpatched CVEs where not deleted.
   */
  async findUnpatched(tx?: any): Promise<CVE[]> {
    return this.findMany({ filter: { patched: false, deletedAt: null } }, tx);
  }

  /**
   * Finds exploited CVEs where not deleted.
   */
  async findExploited(tx?: any): Promise<CVE[]> {
    return this.findMany({ filter: { exploited: true, deletedAt: null } }, tx);
  }

  /**
   * Finds affected products associated with a specific CVE ID where not deleted.
   */
  async findAffectedProducts(cveId: string, tx?: any): Promise<AffectedProduct[]> {
    const client = tx || prisma;
    return client.affectedProduct.findMany({
      where: { cveId, deletedAt: null },
    });
  }

  /**
   * Finds CVSS details associated with a specific CVE ID where not deleted.
   */
  async findCvss(cveId: string, tx?: any): Promise<CVSS | null> {
    const client = tx || prisma;
    return client.cVSS.findFirst({
      where: { cveId, deletedAt: null },
    });
  }
}
