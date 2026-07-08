import { BaseRepository } from '../base/BaseRepository';
import { Report, ReportStatus, Prisma } from '@prisma/client';

export class ReportRepository extends BaseRepository<Report, Prisma.ReportUncheckedCreateInput, Prisma.ReportUncheckedUpdateInput> {
  constructor() {
    super('report');
  }

  /**
   * Finds reports associated with a specific investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Report[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds reports by status where not deleted.
   */
  async findByStatus(status: ReportStatus, tx?: any): Promise<Report[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds draft reports (status: DRAFT and not deleted).
   */
  async findDrafts(tx?: any): Promise<Report[]> {
    return this.findMany({ filter: { status: 'DRAFT', deletedAt: null } }, tx);
  }

  /**
   * Finds published reports (status: PUBLISHED and not deleted).
   */
  async findPublished(tx?: any): Promise<Report[]> {
    return this.findMany({ filter: { status: 'PUBLISHED', deletedAt: null } }, tx);
  }
}
