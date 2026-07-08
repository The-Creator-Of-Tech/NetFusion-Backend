import { BaseRepository } from '../base/BaseRepository';
import { SessionMemory, MemoryEntry, MemoryStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class SessionMemoryRepository extends BaseRepository<SessionMemory, Prisma.SessionMemoryUncheckedCreateInput, Prisma.SessionMemoryUncheckedUpdateInput> {
  constructor() {
    super('sessionMemory');
  }

  /**
   * Finds session memories by user ID where not deleted.
   */
  async findByUser(userId: string, tx?: any): Promise<SessionMemory[]> {
    return this.findMany({ filter: { userId, deletedAt: null } }, tx);
  }

  /**
   * Finds session memories by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<SessionMemory[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds session memories by investigation ID where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<SessionMemory[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds active session memories (status: ACTIVE and not deleted).
   */
  async findActive(tx?: any): Promise<SessionMemory[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }

  /**
   * Finds archived session memories (status: ARCHIVED and not deleted).
   */
  async findArchived(tx?: any): Promise<SessionMemory[]> {
    return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
  }

  /**
   * Finds memory entries associated with a specific session memory ID where not deleted.
   */
  async findEntries(memoryId: string, tx?: any): Promise<MemoryEntry[]> {
    const client = tx || prisma;
    return client.memoryEntry.findMany({
      where: { memoryId, deletedAt: null },
    });
  }

  /**
   * Searches for memory entries containing a query string case-insensitively in title or content where not deleted.
   */
  async searchEntries(query: string, tx?: any): Promise<MemoryEntry[]> {
    const client = tx || prisma;
    return client.memoryEntry.findMany({
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
