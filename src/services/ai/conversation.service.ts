/**
 * ConversationService — Phase A5.3.4
 * =====================================
 * Manages conversation lifecycle: creation, archiving, completion, messaging,
 * summary updates, tag management, and context-size accounting.
 * Publishes domain events on every meaningful state transition.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  conversationRepository,
  sessionMemoryRepository,
  contextWindowRepository,
} from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  Conversation,
  ConversationMessage,
  ConversationStatus,
  Prisma,
} from '@prisma/client';

export class ConversationService extends BaseService {
  constructor(
    private readonly conversationRepo    = conversationRepository,
    private readonly sessionMemoryRepo   = sessionMemoryRepository,
    private readonly contextWindowRepo   = contextWindowRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createConversation(
    data: Prisma.ConversationUncheckedCreateInput,
    tx?: any,
  ): Promise<Conversation> {
    this.validateRequired(data as any, ['title', 'projectId', 'createdBy', 'updatedBy']);
    this.validateUuid(data.projectId, 'projectId');
    if (data.investigationId) this.validateUuid(data.investigationId as string, 'investigationId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      const conversation = await this.conversationRepo.create(data, transaction);
      await eventPublisher.publish('ConversationCreated', { conversation });
      return conversation;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async archiveConversation(id: string, actor: string, tx?: any): Promise<Conversation> {
    return this._transition(id, 'ARCHIVED', actor, 'ConversationArchived', tx);
  }

  async completeConversation(id: string, actor: string, tx?: any): Promise<Conversation> {
    return this._transition(id, 'COMPLETED', actor, 'ConversationCompleted', tx);
  }

  async reactivateConversation(id: string, actor: string, tx?: any): Promise<Conversation> {
    return this._transition(id, 'ACTIVE', actor, 'ConversationReactivated', tx);
  }

  // ── Messaging ────────────────────────────────────────────────────────────────

  async addMessage(
    conversationId: string,
    data: { role: string; content: string; parentMessageId?: string; metadata?: any; createdBy: string; updatedBy: string },
    tx?: any,
  ): Promise<ConversationMessage> {
    this.validateUuid(conversationId, 'conversationId');
    if (!data.role || !data.content) {
      throw new Error('Validation failed: role and content are required.');
    }

    const runInTx = async (transaction: any) => {
      const conversation = await this.conversationRepo.findById(conversationId, transaction);
      if (!conversation || conversation.deletedAt) {
        throw new Error(`Conversation "${conversationId}" not found.`);
      }

      const client = transaction || prisma;
      const message: ConversationMessage = await client.conversationMessage.create({
        data: {
          conversationId,
          role: data.role,
          content: data.content,
          parentMessageId: data.parentMessageId ?? null,
          metadata: data.metadata ?? null,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      // Update context size accounting
      const newContextSize = (conversation.contextSize ?? 0) + data.content.length;
      await this.conversationRepo.update(
        conversationId,
        { contextSize: newContextSize, updatedBy: data.updatedBy },
        transaction,
      );

      await eventPublisher.publish('ConversationMessageAdded', { conversationId, message });
      return message;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async searchMessages(query: string, tx?: any): Promise<ConversationMessage[]> {
    if (!query || query.trim().length === 0) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.conversationRepo.searchMessages(query, tx);
  }

  // ── Summary / Tags ───────────────────────────────────────────────────────────

  async updateSummary(id: string, summary: string, actor: string, tx?: any): Promise<Conversation> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const existing = await this.conversationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      const updated = await this.conversationRepo.update(id, { summary, updatedBy: actor }, transaction);
      await eventPublisher.publish('ConversationSummaryUpdated', { conversation: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async addTag(id: string, tag: string, actor: string, tx?: any): Promise<Conversation> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const existing = await this.conversationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      const tags = Array.from(new Set([...(existing.tags ?? []), tag]));
      const updated = await this.conversationRepo.update(id, { tags, updatedBy: actor }, transaction);
      await eventPublisher.publish('ConversationTagged', { conversation: updated, tag });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async removeTag(id: string, tag: string, actor: string, tx?: any): Promise<Conversation> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const existing = await this.conversationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      const tags = (existing.tags ?? []).filter((t) => t !== tag);
      const updated = await this.conversationRepo.update(id, { tags, updatedBy: actor }, transaction);
      await eventPublisher.publish('ConversationUntagged', { conversation: updated, tag });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Token accounting ─────────────────────────────────────────────────────────

  async recalculateContextSize(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const conversation = await this.conversationRepo.findWithMessages(id, transaction);
      if (!conversation || conversation.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      const size = (conversation.messages as ConversationMessage[]).reduce(
        (sum: number, m: ConversationMessage) => sum + (m.content?.length ?? 0),
        0,
      );
      await this.conversationRepo.update(id, { contextSize: size, updatedBy: 'system' }, transaction);
      return size;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Statistics ───────────────────────────────────────────────────────────────

  async getConversationStats(id: string, tx?: any): Promise<{
    messageCount: number;
    contextSize: number;
    memoryCount: number;
    windowCount: number;
  }> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const conversation = await this.conversationRepo.findWithMessages(id, transaction);
      if (!conversation || conversation.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      const memories = await this.sessionMemoryRepo.findMany(
        { filter: { conversationId: id, deletedAt: null } },
        transaction,
      );
      const windows = await this.contextWindowRepo.findByConversation(id, transaction);

      return {
        messageCount: (conversation.messages as ConversationMessage[]).length,
        contextSize: conversation.contextSize ?? 0,
        memoryCount: memories.length,
        windowCount: windows.length,
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findConversation(id: string, tx?: any): Promise<Conversation | null> {
    this.validateUuid(id, 'conversationId');
    return this.conversationRepo.findById(id, tx);
  }

  async findByProject(projectId: string, tx?: any): Promise<Conversation[]> {
    this.validateUuid(projectId, 'projectId');
    return this.conversationRepo.findByProject(projectId, tx);
  }

  async findByUser(userId: string, tx?: any): Promise<Conversation[]> {
    this.validateUuid(userId, 'userId');
    return this.conversationRepo.findByUser(userId, tx);
  }

  async findByInvestigation(investigationId: string, tx?: any): Promise<Conversation[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.conversationRepo.findByInvestigation(investigationId, tx);
  }

  async findActive(tx?: any): Promise<Conversation[]> {
    return this.conversationRepo.findActive(tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteConversation(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const existing = await this.conversationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      await this.conversationRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('ConversationDeleted', { conversationId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: ConversationStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<Conversation> {
    this.validateUuid(id, 'conversationId');
    const runInTx = async (transaction: any) => {
      const existing = await this.conversationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Conversation "${id}" not found.`);
      }
      const updated = await this.conversationRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { conversation: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
