import { BaseRepository } from '../base/BaseRepository';
import { Finding, FindingSeverity, FindingStatus, Prisma } from '@prisma/client';

export class FindingRepository extends BaseRepository<Finding, Prisma.FindingUncheckedCreateInput, Prisma.FindingUncheckedUpdateInput> {
  constructor() {
    super('finding');
  }

  /**
   * Finds findings associated with an investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds findings associated with a specific asset where not deleted.
   */
  async findByAsset(assetId: string, tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { assetId, deletedAt: null } }, tx);
  }

  /**
   * Finds findings by severity where not deleted.
   */
  async findBySeverity(severity: FindingSeverity, tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { severity, deletedAt: null } }, tx);
  }

  /**
   * Finds findings by status where not deleted.
   */
  async findByStatus(status: FindingStatus, tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds critical findings (severity is CRITICAL and not deleted).
   */
  async findCriticalFindings(tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { severity: 'CRITICAL', deletedAt: null } }, tx);
  }

  /**
   * Finds open findings (status is OPEN and not deleted).
   */
  async findOpenFindings(tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
  }

  /**
   * Finds resolved findings (status is RESOLVED and not deleted).
   */
  async findResolvedFindings(tx?: any): Promise<Finding[]> {
    return this.findMany({ filter: { status: 'RESOLVED', deletedAt: null } }, tx);
  }

  /**
   * Finds a finding by ID and includes its associated evidence.
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
