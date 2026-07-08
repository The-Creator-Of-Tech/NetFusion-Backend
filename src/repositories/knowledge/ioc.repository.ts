import { BaseRepository } from '../base/BaseRepository';
import { IOC, IOCRelationship, IOCEnrichment, IOCType, IOCStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class IocRepository extends BaseRepository<IOC, Prisma.IOCUncheckedCreateInput, Prisma.IOCUncheckedUpdateInput> {
  constructor() {
    super('iOC');
  }

  /**
   * Finds an IOC by its indicator value where not deleted.
   */
  async findByValue(value: string, tx?: any): Promise<IOC | null> {
    return this.findOne({ value, deletedAt: null }, tx);
  }

  /**
   * Finds IOCs by type where not deleted.
   */
  async findByType(iocType: IOCType, tx?: any): Promise<IOC[]> {
    return this.findMany({ filter: { iocType, deletedAt: null } }, tx);
  }

  /**
   * Finds IOCs by status where not deleted.
   */
  async findByStatus(status: IOCStatus, tx?: any): Promise<IOC[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds malicious IOCs where not deleted.
   */
  async findMalicious(tx?: any): Promise<IOC[]> {
    return this.findMany({ filter: { malicious: true, deletedAt: null } }, tx);
  }

  /**
   * Finds revoked IOCs where not deleted.
   */
  async findRevoked(tx?: any): Promise<IOC[]> {
    return this.findMany({ filter: { revoked: true, deletedAt: null } }, tx);
  }

  /**
   * Finds relationships associated with a specific IOC ID where not deleted.
   */
  async findRelationships(iocId: string, tx?: any): Promise<IOCRelationship[]> {
    const client = tx || prisma;
    return client.iOCRelationship.findMany({
      where: { iocId, deletedAt: null },
    });
  }

  /**
   * Finds enrichment details associated with a specific IOC ID where not deleted.
   */
  async findEnrichment(iocId: string, tx?: any): Promise<IOCEnrichment | null> {
    const client = tx || prisma;
    return client.iOCEnrichment.findFirst({
      where: { iocId, deletedAt: null },
    });
  }

  /**
   * Finds IOCs by confidence classification (e.g. 'HIGH') or numeric range.
   */
  async findByConfidence(min: string | number, max?: string | number, tx?: any): Promise<IOC[]> {
    const minStr = String(min);
    const delegate = this.getDelegate(tx);

    if (isNaN(Number(minStr))) {
      return delegate.findMany({
        where: {
          confidence: minStr,
          deletedAt: null,
        },
      });
    } else {
      const allIocs = await delegate.findMany({ where: { deletedAt: null } });
      return allIocs.filter((ioc: IOC) => {
        const confNum = Number(ioc.confidence);
        if (isNaN(confNum)) return false;
        if (confNum < Number(min)) return false;
        if (max !== undefined && confNum > Number(max)) return false;
        return true;
      });
    }
  }

  /**
   * Finds IOCs by source where not deleted.
   */
  async findBySource(source: string, tx?: any): Promise<IOC[]> {
    return this.findMany({ filter: { source, deletedAt: null } }, tx);
  }
}
