import { BaseRepository } from '../base/BaseRepository';
import { PromptAssembly, PromptSection, PromptStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class PromptAssemblyRepository extends BaseRepository<PromptAssembly, Prisma.PromptAssemblyUncheckedCreateInput, Prisma.PromptAssemblyUncheckedUpdateInput> {
  constructor() {
    super('promptAssembly');
  }

  /**
   * Finds draft prompt assemblies (status: DRAFT and not deleted).
   */
  async findDrafts(tx?: any): Promise<PromptAssembly[]> {
    return this.findMany({ filter: { status: 'DRAFT', deletedAt: null } }, tx);
  }

  /**
   * Finds published/active prompt assemblies (status: ACTIVE and not deleted).
   */
  async findPublished(tx?: any): Promise<PromptAssembly[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }

  /**
   * Finds archived prompt assemblies (status: ARCHIVED and not deleted).
   */
  async findArchived(tx?: any): Promise<PromptAssembly[]> {
    return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
  }

  /**
   * Finds prompt assemblies by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<PromptAssembly[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds prompt sections associated with a specific prompt assembly ID where not deleted.
   */
  async findSections(promptId: string, tx?: any): Promise<PromptSection[]> {
    const client = tx || prisma;
    return client.promptSection.findMany({
      where: { promptId, deletedAt: null },
    });
  }

  /**
   * Searches for prompt sections containing a query string case-insensitively in title or content where not deleted.
   */
  async searchSections(query: string, tx?: any): Promise<PromptSection[]> {
    const client = tx || prisma;
    return client.promptSection.findMany({
      where: {
        deletedAt: null,
        OR: [
          { title: { contains: query, mode: 'insensitive' } },
          { content: { contains: query, mode: 'insensitive' } },
        ],
      },
    });
  }
}
