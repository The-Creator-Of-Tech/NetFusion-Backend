import { BaseRepository } from '../base/BaseRepository';
import { Conversation, ConversationMessage, ConversationStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class ConversationRepository extends BaseRepository<Conversation, Prisma.ConversationUncheckedCreateInput, Prisma.ConversationUncheckedUpdateInput> {
  constructor() {
    super('conversation');
  }

  /**
   * Finds conversations by user ID where not deleted.
   */
  async findByUser(userId: string, tx?: any): Promise<Conversation[]> {
    return this.findMany({ filter: { userId, deletedAt: null } }, tx);
  }

  /**
   * Finds conversations by project ID where not deleted.
   */
  async findByProject(projectId: string, tx?: any): Promise<Conversation[]> {
    return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
  }

  /**
   * Finds conversations by investigation ID where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Conversation[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds active conversations (status: ACTIVE and not deleted).
   */
  async findActive(tx?: any): Promise<Conversation[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }

  /**
   * Finds archived conversations (status: ARCHIVED and not deleted).
   */
  async findArchived(tx?: any): Promise<Conversation[]> {
    return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
  }

  /**
   * Finds completed conversations (status: COMPLETED and not deleted).
   */
  async findCompleted(tx?: any): Promise<Conversation[]> {
    return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
  }

  /**
   * Finds a conversation by ID and includes its associated messages.
   */
  async findWithMessages(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        messages: true,
      },
    });
  }

  /**
   * Searches for conversation messages containing a query string case-insensitively where not deleted.
   */
  async searchMessages(query: string, tx?: any): Promise<ConversationMessage[]> {
    const client = tx || prisma;
    return client.conversationMessage.findMany({
      where: {
        content: { contains: query, mode: 'insensitive' },
        deletedAt: null,
      },
    });
  }
}
