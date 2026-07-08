import { BaseRepository } from '../base/BaseRepository';
import { Asset, AssetType, Prisma } from '@prisma/client';

export class AssetRepository extends BaseRepository<Asset, Prisma.AssetUncheckedCreateInput, Prisma.AssetUncheckedUpdateInput> {
  constructor() {
    super('asset');
  }

  /**
   * Finds assets associated with a specific investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Asset[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds assets by type where not deleted.
   */
  async findByType(type: AssetType, tx?: any): Promise<Asset[]> {
    return this.findMany({ filter: { type, deletedAt: null } }, tx);
  }

  /**
   * Finds assets by hostname where not deleted.
   */
  async findByHostname(hostname: string, tx?: any): Promise<Asset[]> {
    return this.findMany({ filter: { hostname, deletedAt: null } }, tx);
  }

  /**
   * Finds assets by IP address where not deleted.
   */
  async findByIpAddress(ipAddress: string, tx?: any): Promise<Asset[]> {
    return this.findMany({ filter: { currentIp: ipAddress, deletedAt: null } }, tx);
  }

  /**
   * Finds assets with high risk score where not deleted.
   * Default threshold is 70.0.
   */
  async findCriticalAssets(threshold: number = 70.0, tx?: any): Promise<Asset[]> {
    return this.findMany({ filter: { riskScore: { gte: threshold }, deletedAt: null } }, tx);
  }

  /**
   * Finds an asset by ID and includes its associated findings.
   */
  async findWithFindings(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        findings: true,
      },
    });
  }

  /**
   * Finds an asset by ID and includes its associated evidence.
   */
  async findWithEvidence(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        evidence: true,
      },
    });
  }
}
