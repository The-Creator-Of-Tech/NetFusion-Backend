import { BaseRepository } from '../base/BaseRepository';
import { ContextWindow, ContextEntry, ContextStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class ContextWindowRepository extends BaseRepository<ContextWindow, Prisma.ContextWindowUncheckedCreateInput, Prisma.ContextWindowUncheckedUpdateInput> {
  constructor() {
    super('contextWindow');
  }

  /**
   * Finds context windows by user ID where not deleted.
   */
  async findByUser(userId: string, tx?: any): Promise<ContextWindow[]> {
    return this.findMany({ filter: { userId, deletedAt: null } }, tx);
  }

  /**
   * Finds context windows by conversation ID where not deleted.
   */
  async findByConversation(conversationId: string, tx?: any): Promise<ContextWindow[]> {
    return this.findMany({ filter: { conversationId, deletedAt: null } }, tx);
  }

  /**
   * Finds active context windows (status: ACTIVE and not deleted).
   */
  async findActive(tx?: any): Promise<ContextWindow[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }

  /**
   * Finds archived context windows (status: ARCHIVED and not deleted).
   */
  async findArchived(tx?: any): Promise<ContextWindow[]> {
    return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
  }

  /**
   * Finds context entries associated with a specific context window ID where not deleted.
   */
  async findEntries(contextId: string, tx?: any): Promise<ContextEntry[]> {
    const client = tx || prisma;
    return client.contextEntry.findMany({
      where: { contextId, deletedAt: null },
    });
  }

  /**
   * Calculates the total size of characters inside all context entries of a context window.
   */
  async calculateContextSize(id: string, tx?: any): Promise<number> {
    const entries = await this.findEntries(id, tx);
    return entries.reduce((sum, entry) => sum + (entry.content?.length || 0), 0);
  }
}
