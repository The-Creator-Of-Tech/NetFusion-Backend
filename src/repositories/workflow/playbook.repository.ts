import { BaseRepository } from '../base/BaseRepository';
import { Playbook, PlaybookStep, PlaybookStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class PlaybookRepository extends BaseRepository<Playbook, Prisma.PlaybookUncheckedCreateInput, Prisma.PlaybookUncheckedUpdateInput> {
  constructor() {
    super('playbook');
  }

  /**
   * Finds playbooks by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds playbooks by investigation ID where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds playbooks by category where not deleted.
   */
  async findByCategory(category: string, tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { category, deletedAt: null } }, tx);
  }

  /**
   * Finds playbooks by author where not deleted.
   */
  async findByAuthor(author: string, tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { author, deletedAt: null } }, tx);
  }

  /**
   * Finds playbooks by priority where not deleted.
   */
  async findByPriority(priority: number, tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { priority, deletedAt: null } }, tx);
  }

  /**
   * Finds enabled playbooks where not deleted.
   */
  async findEnabled(tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
  }

  /**
   * Finds disabled playbooks where not deleted.
   */
  async findDisabled(tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
  }

  /**
   * Finds draft playbooks where not deleted.
   */
  async findDrafts(tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { status: 'DRAFT' as PlaybookStatus, deletedAt: null } }, tx);
  }

  /**
   * Finds archived playbooks where not deleted.
   */
  async findArchived(tx?: any): Promise<Playbook[]> {
    return this.findMany({ filter: { status: 'ARCHIVED' as PlaybookStatus, deletedAt: null } }, tx);
  }

  /**
   * Finds a playbook by ID and includes its associated steps where not deleted.
   */
  async findWithSteps(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findFirst({
      where: { id, deletedAt: null },
      include: {
        steps: {
          where: { deletedAt: null },
          orderBy: { stepNumber: 'asc' },
        },
      },
    });
  }

  /**
   * Searches playbook steps for a query string case-insensitively in title or description where not deleted.
   */
  async searchSteps(query: string, tx?: any): Promise<PlaybookStep[]> {
    const client = tx || prisma;
    return client.playbookStep.findMany({
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
   * Finds a playbook step by ID where not deleted.
   */
  async findStep(stepId: string, tx?: any): Promise<PlaybookStep | null> {
    const client = tx || prisma;
    return client.playbookStep.findFirst({
      where: { id: stepId, deletedAt: null },
    });
  }

  /**
   * Computes statistics for playbooks.
   */
  async calculateStatistics(tx?: any): Promise<{
    total: number;
    enabled: number;
    disabled: number;
    draft: number;
    active: number;
    archived: number;
  }> {
    const playbooks = await this.findMany({ filter: { deletedAt: null } }, tx);
    return {
      total: playbooks.length,
      enabled: playbooks.filter((p) => p.enabled).length,
      disabled: playbooks.filter((p) => !p.enabled).length,
      draft: playbooks.filter((p) => p.status === 'DRAFT').length,
      active: playbooks.filter((p) => p.status === 'ACTIVE').length,
      archived: playbooks.filter((p) => p.status === 'ARCHIVED').length,
    };
  }
}
