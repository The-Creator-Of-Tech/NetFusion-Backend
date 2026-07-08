import { BaseRepository } from '../base/BaseRepository';
import { Investigation, InvestigationStatus, Prisma } from '@prisma/client';

export class InvestigationRepository extends BaseRepository<Investigation, Prisma.InvestigationUncheckedCreateInput, Prisma.InvestigationUncheckedUpdateInput> {
  constructor() {
    super('investigation');
  }

  /**
   * Finds investigations by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<Investigation[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds investigations by status where not deleted.
   */
  async findByStatus(status: InvestigationStatus, tx?: any): Promise<Investigation[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds open investigations (status: OPEN and not deleted).
   */
  async findOpen(tx?: any): Promise<Investigation[]> {
    return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
  }

  /**
   * Finds an investigation by ID and includes its assets.
   */
  async findWithAssets(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        assets: true,
      },
    });
  }

  /**
   * Finds an investigation by ID and includes its findings.
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
   * Finds completed investigations (status: RESOLVED or CLOSED, and not deleted).
   */
  async findComplete(tx?: any): Promise<Investigation[]> {
    return this.findMany(
      {
        filter: {
          status: { in: ['RESOLVED', 'CLOSED'] },
          deletedAt: null,
        },
      },
      tx
    );
  }
}
