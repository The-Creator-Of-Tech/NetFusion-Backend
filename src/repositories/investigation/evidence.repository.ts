import { BaseRepository } from '../base/BaseRepository';
import { Evidence, EvidenceType, Prisma } from '@prisma/client';

export class EvidenceRepository extends BaseRepository<Evidence, Prisma.EvidenceUncheckedCreateInput, Prisma.EvidenceUncheckedUpdateInput> {
  constructor() {
    super('evidence');
  }

  /**
   * Finds evidence associated with a specific investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Evidence[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds evidence associated with a specific asset where not deleted.
   */
  async findByAsset(assetId: string, tx?: any): Promise<Evidence[]> {
    return this.findMany({ filter: { assetId, deletedAt: null } }, tx);
  }

  /**
   * Finds evidence associated with a specific finding where not deleted.
   */
  async findByFinding(findingId: string, tx?: any): Promise<Evidence[]> {
    return this.findMany({ filter: { findingId, deletedAt: null } }, tx);
  }

  /**
   * Finds evidence by type where not deleted.
   */
  async findByType(type: EvidenceType, tx?: any): Promise<Evidence[]> {
    return this.findMany({ filter: { type, deletedAt: null } }, tx);
  }

  /**
   * Finds evidence by matching hash in fieldValue, rawValue, or JSON metadata (hash, sha256, md5) where not deleted.
   */
  async findByHash(hash: string, tx?: any): Promise<Evidence[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        OR: [
          { fieldValue: hash },
          { rawValue: hash },
          { metadata: { path: ['hash'], equals: hash } },
          { metadata: { path: ['sha256'], equals: hash } },
          { metadata: { path: ['md5'], equals: hash } }
        ]
      }
    });
  }

  /**
   * Finds evidence of type PACKET (Packet Capture) where not deleted.
   */
  async findPacketCaptures(tx?: any): Promise<Evidence[]> {
    return this.findMany({ filter: { type: 'PACKET', deletedAt: null } }, tx);
  }

  /**
   * Finds evidence of type LOG where not deleted.
   */
  async findLogs(tx?: any): Promise<Evidence[]> {
    return this.findMany({ filter: { type: 'LOG', deletedAt: null } }, tx);
  }
}
