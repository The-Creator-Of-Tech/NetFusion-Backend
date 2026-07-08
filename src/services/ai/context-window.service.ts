/**
 * ContextWindowService — Phase A5.3.4
 * ======================================
 * Manages context window lifecycle: creation, archiving, entry management,
 * priority-based ranking, importance/confidence scoring, and size accounting.
 * Publishes events on window mutations and content changes.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { contextWindowRepository } from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  ContextWindow,
  ContextEntry,
  ContextStatus,
  Prisma,
} from '@prisma/client';

export class ContextWindowService extends BaseService {
  constructor(
    private readonly contextRepo = contextWindowRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createWindow(
    data: Prisma.ContextWindowUncheckedCreateInput,
    tx?: any,
  ): Promise<ContextWindow> {
    this.validateRequired(data as any, ['projectId', 'createdBy', 'updatedBy']);
    this.validateUuid(data.projectId, 'projectId');
    if (data.investigationId) this.validateUuid(data.investigationId as string, 'investigationId');
    if (data.conversationId) this.validateUuid(data.conversationId as string, 'conversationId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      const window = await this.contextRepo.create(data, transaction);
      await eventPublisher.publish('ContextWindowCreated', { window });
      return window;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async archiveWindow(id: string, actor: string, tx?: any): Promise<ContextWindow> {
    return this._transition(id, 'ARCHIVED', actor, 'ContextWindowArchived', tx);
  }

  async activateWindow(id: string, actor: string, tx?: any): Promise<ContextWindow> {
    return this._transition(id, 'ACTIVE', actor, 'ContextWindowActivated', tx);
  }

  // ── Entry management ─────────────────────────────────────────────────────────

  async addEntry(
    contextId: string,
    data: {
      source: string;
      priority: string;
      title: string;
      content: string;
      referenceId: string;
      importanceScore: number;
      confidence: number;
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<ContextEntry> {
    this.validateUuid(contextId, 'contextId');
    this.validateRequired(data as any, ['source', 'priority', 'title', 'content', 'referenceId', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const window = await this.contextRepo.findById(contextId, transaction);
      if (!window || window.deletedAt) {
        throw new Error(`ContextWindow "${contextId}" not found.`);
      }

      const client = transaction || prisma;
      const entry: ContextEntry = await client.contextEntry.create({
        data: {
          contextId,
          source: data.source,
          priority: data.priority,
          title: data.title,
          content: data.content,
          referenceId: data.referenceId,
          importanceScore: data.importanceScore ?? 50.0,
          confidence: data.confidence ?? 0.0,
          metadata: data.metadata ?? null,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      // Recalculate context size
      const newSize = await this.contextRepo.calculateContextSize(contextId, transaction);
      await this.contextRepo.update(
        contextId,
        { contextSize: newSize, updatedBy: data.updatedBy },
        transaction,
      );

      await eventPublisher.publish('ContextEntryAdded', { contextId, entry });
      return entry;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateEntry(
    entryId: string,
    data: Partial<Prisma.ContextEntryUncheckedUpdateInput>,
    tx?: any,
  ): Promise<ContextEntry> {
    this.validateUuid(entryId, 'entryId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: ContextEntry | null = await client.contextEntry.findUnique({ where: { id: entryId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`ContextEntry "${entryId}" not found.`);
      }

      const updated: ContextEntry = await client.contextEntry.update({
        where: { id: entryId },
        data: {
          ...data,
          updatedAt: new Date(),
          version: (existing.version ?? 1) + 1,
        },
      });

      // Recalculate parent window context size
      const newSize = await this.contextRepo.calculateContextSize(existing.contextId, transaction);
      await this.contextRepo.update(
        existing.contextId,
        { contextSize: newSize, updatedBy: (data.updatedBy as string) ?? 'system' },
        transaction,
      );

      await eventPublisher.publish('ContextEntryUpdated', { entry: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async deleteEntry(entryId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(entryId, 'entryId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: ContextEntry | null = await client.contextEntry.findUnique({ where: { id: entryId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`ContextEntry "${entryId}" not found.`);
      }

      await client.contextEntry.update({
        where: { id: entryId },
        data: {
          deletedAt: new Date(),
          updatedBy: actor,
          version: (existing.version ?? 1) + 1,
        },
      });

      // Recalculate parent window context size
      const newSize = await this.contextRepo.calculateContextSize(existing.contextId, transaction);
      await this.contextRepo.update(existing.contextId, { contextSize: newSize, updatedBy: actor }, transaction);

      await eventPublisher.publish('ContextEntryDeleted', { entryId });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Priority ranking ─────────────────────────────────────────────────────────

  async rankEntriesByImportance(contextId: string, tx?: any): Promise<ContextEntry[]> {
    this.validateUuid(contextId, 'contextId');
    const runInTx = async (transaction: any) => {
      const entries = await this.contextRepo.findEntries(contextId, transaction);
      return entries.sort((a, b) => (b.importanceScore ?? 0) - (a.importanceScore ?? 0));
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async rankEntriesByConfidence(contextId: string, tx?: any): Promise<ContextEntry[]> {
    this.validateUuid(contextId, 'contextId');
    const runInTx = async (transaction: any) => {
      const entries = await this.contextRepo.findEntries(contextId, transaction);
      return entries.sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0));
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Statistics ───────────────────────────────────────────────────────────────

  async getWindowStats(contextId: string, tx?: any): Promise<{
    entryCount: number;
    contextSize: number;
    averageImportance: number;
    averageConfidence: number;
  }> {
    this.validateUuid(contextId, 'contextId');
    const runInTx = async (transaction: any) => {
      const window = await this.contextRepo.findById(contextId, transaction);
      if (!window || window.deletedAt) {
        throw new Error(`ContextWindow "${contextId}" not found.`);
      }
      const entries = await this.contextRepo.findEntries(contextId, transaction);

      const avgImportance =
        entries.length > 0
          ? entries.reduce((sum, e) => sum + (e.importanceScore ?? 0.0), 0.0) / entries.length
          : 0.0;
      const avgConfidence =
        entries.length > 0
          ? entries.reduce((sum, e) => sum + (e.confidence ?? 0.0), 0.0) / entries.length
          : 0.0;

      return {
        entryCount: entries.length,
        contextSize: window.contextSize ?? 0,
        averageImportance: avgImportance,
        averageConfidence: avgConfidence,
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findWindow(id: string, tx?: any): Promise<ContextWindow | null> {
    this.validateUuid(id, 'contextId');
    return this.contextRepo.findById(id, tx);
  }

  async findByUser(userId: string, tx?: any): Promise<ContextWindow[]> {
    this.validateUuid(userId, 'userId');
    return this.contextRepo.findByUser(userId, tx);
  }

  async findByConversation(conversationId: string, tx?: any): Promise<ContextWindow[]> {
    this.validateUuid(conversationId, 'conversationId');
    return this.contextRepo.findByConversation(conversationId, tx);
  }

  async findActive(tx?: any): Promise<ContextWindow[]> {
    return this.contextRepo.findActive(tx);
  }

  async findEntries(contextId: string, tx?: any): Promise<ContextEntry[]> {
    this.validateUuid(contextId, 'contextId');
    return this.contextRepo.findEntries(contextId, tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteWindow(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'contextId');
    const runInTx = async (transaction: any) => {
      const existing = await this.contextRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`ContextWindow "${id}" not found.`);
      }
      await this.contextRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('ContextWindowDeleted', { contextId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: ContextStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<ContextWindow> {
    this.validateUuid(id, 'contextId');
    const runInTx = async (transaction: any) => {
      const existing = await this.contextRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`ContextWindow "${id}" not found.`);
      }
      const updated = await this.contextRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { window: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
