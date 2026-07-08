import { BaseRepository } from '../base/BaseRepository';
import { CaseFlow, CaseFlowExecution, CaseFlowStep, CaseStatus, CasePriority, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class CaseFlowRepository extends BaseRepository<CaseFlow, Prisma.CaseFlowUncheckedCreateInput, Prisma.CaseFlowUncheckedUpdateInput> {
  constructor() {
    super('caseFlow');
  }

  /**
   * Finds case flows by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds case flows by investigation ID where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds case flows by owner where not deleted.
   */
  async findByOwner(owner: string, tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { owner, deletedAt: null } }, tx);
  }

  /**
   * Finds case flows by priority where not deleted.
   */
  async findByPriority(priority: CasePriority, tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { priority, deletedAt: null } }, tx);
  }

  /**
   * Finds case flows by status where not deleted.
   */
  async findByStatus(status: CaseStatus, tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds open case flows where not deleted.
   */
  async findOpen(tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { status: 'OPEN' as CaseStatus, deletedAt: null } }, tx);
  }

  /**
   * Finds in-progress case flows where not deleted.
   */
  async findInProgress(tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { status: 'IN_PROGRESS' as CaseStatus, deletedAt: null } }, tx);
  }

  /**
   * Finds resolved case flows where not deleted.
   */
  async findResolved(tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { status: 'RESOLVED' as CaseStatus, deletedAt: null } }, tx);
  }

  /**
   * Finds closed case flows where not deleted.
   */
  async findClosed(tx?: any): Promise<CaseFlow[]> {
    return this.findMany({ filter: { status: 'CLOSED' as CaseStatus, deletedAt: null } }, tx);
  }

  /**
   * Finds executions associated with a specific case flow ID where not deleted.
   */
  async findExecutions(caseFlowId: string, tx?: any): Promise<CaseFlowExecution[]> {
    const client = tx || prisma;
    return client.caseFlowExecution.findMany({
      where: { caseFlowId, deletedAt: null },
      orderBy: { startedAt: 'desc' },
    });
  }

  /**
   * Finds steps associated with a specific case flow ID where not deleted.
   */
  async findSteps(caseFlowId: string, tx?: any): Promise<CaseFlowStep[]> {
    const client = tx || prisma;
    return client.caseFlowStep.findMany({
      where: { caseFlowId, deletedAt: null },
      orderBy: { stepNumber: 'asc' },
    });
  }

  /**
   * Searches case flow steps for a query string case-insensitively in title or description where not deleted.
   */
  async searchSteps(query: string, tx?: any): Promise<CaseFlowStep[]> {
    const client = tx || prisma;
    return client.caseFlowStep.findMany({
      where: {
        deletedAt: null,
        OR: [
          { title: { contains: query, mode: 'insensitive' } },
          { description: { contains: query, mode: 'insensitive' } },
        ],
      },
      orderBy: { stepNumber: 'asc' },
    });
  }

  /**
   * Computes statistics for case flows.
   */
  async calculateStatistics(tx?: any): Promise<{
    total: number;
    open: number;
    inProgress: number;
    resolved: number;
    closed: number;
    priorityCounts: Record<CasePriority, number>;
  }> {
    const cases = await this.findMany({ filter: { deletedAt: null } }, tx);
    const priorityCounts: Record<CasePriority, number> = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };
    for (const c of cases) {
      priorityCounts[c.priority] = (priorityCounts[c.priority] || 0) + 1;
    }
    return {
      total: cases.length,
      open: cases.filter((c) => c.status === 'OPEN').length,
      inProgress: cases.filter((c) => c.status === 'IN_PROGRESS').length,
      resolved: cases.filter((c) => c.status === 'RESOLVED').length,
      closed: cases.filter((c) => c.status === 'CLOSED').length,
      priorityCounts,
    };
  }
}
