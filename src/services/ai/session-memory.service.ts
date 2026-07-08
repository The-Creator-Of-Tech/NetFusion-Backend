/**
 * SessionMemoryService — Phase A5.3.4
 * ======================================
 * Manages session memory lifecycle: creation, archiving, entry management,
 * importance scoring, confidence tracking, and state-based search.
 * Publishes events on memory mutations and threshold events.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { sessionMemoryRepository } from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  SessionMemory,
  MemoryEntry,
  MemoryStatus,
  Prisma,
} from '@prisma/client';

export class SessionMemoryService extends BaseService {
  constructor(
    private readonly memoryRepo = sessionMemoryRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createMemory(
    data: Prisma.SessionMemoryUncheckedCreateInput,
    tx?: any,
  ): Promise<SessionMemory> {
    this.validateRequired(data as any, ['conversationId', 'projectId', 'createdBy', 'updatedBy']);
    this.validateUuid(data.conversationId, 'conversationId');
    this.validateUuid(data.projectId, 'projectId');
    if (data.investigationId) this.validateUuid(data.investigationId as string, 'investigationId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      const memory = await this.memoryRepo.create(data, transaction);
      await eventPublisher.publish('SessionMemoryCreated', { memory });
      return memory;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async archiveMemory(id: string, actor: string, tx?: any): Promise<SessionMemory> {
    return this._transition(id, 'ARCHIVED', actor, 'SessionMemoryArchived', tx);
  }

  async activateMemory(id: string, actor: string, tx?: any): Promise<SessionMemory> {
    return this._transition(id, 'ACTIVE', actor, 'SessionMemoryActivated', tx);
  }

  // ── Entry management ─────────────────────────────────────────────────────────

  async addEntry(
    memoryId: string,
    data: {
      memoryType: string;
      state: string;
      title: string;
      content: string;
      importanceScore: number;
      confidence: number;
      sourceId?: string;
      tags?: string[];
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<MemoryEntry> {
    this.validateUuid(memoryId, 'memoryId');
    this.validateRequired(data as any, ['memoryType', 'state', 'title', 'content', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const memory = await this.memoryRepo.findById(memoryId, transaction);
      if (!memory || memory.deletedAt) {
        throw new Error(`SessionMemory "${memoryId}" not found.`);
      }

      const client = transaction || prisma;
      const entry: MemoryEntry = await client.memoryEntry.create({
        data: {
          memoryId,
          memoryType: data.memoryType,
          state: data.state,
          title: data.title,
          content: data.content,
          importanceScore: data.importanceScore ?? 50.0,
          confidence: data.confidence ?? 0.0,
          sourceId: data.sourceId ?? null,
          tags: data.tags ?? [],
          metadata: data.metadata ?? null,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      // Update memory context size accounting
      const newContextSize = (memory.contextSize ?? 0) + data.content.length;
      await this.memoryRepo.update(
        memoryId,
        { contextSize: newContextSize, updatedBy: data.updatedBy },
        transaction,
      );

      await eventPublisher.publish('MemoryEntryAdded', { memoryId, entry });
      return entry;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateEntry(
    entryId: string,
    data: Partial<Prisma.MemoryEntryUncheckedUpdateInput>,
    tx?: any,
  ): Promise<MemoryEntry> {
    this.validateUuid(entryId, 'entryId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: MemoryEntry | null = await client.memoryEntry.findUnique({ where: { id: entryId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`MemoryEntry "${entryId}" not found.`);
      }

      const updated: MemoryEntry = await client.memoryEntry.update({
        where: { id: entryId },
        data: {
          ...data,
          updatedAt: new Date(),
          version: (existing.version ?? 1) + 1,
        },
      });

      await eventPublisher.publish('MemoryEntryUpdated', { entry: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async deleteEntry(entryId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(entryId, 'entryId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: MemoryEntry | null = await client.memoryEntry.findUnique({ where: { id: entryId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`MemoryEntry "${entryId}" not found.`);
      }

      await client.memoryEntry.update({
        where: { id: entryId },
        data: {
          deletedAt: new Date(),
          updatedBy: actor,
          version: (existing.version ?? 1) + 1,
        },
      });

      await eventPublisher.publish('MemoryEntryDeleted', { entryId });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Search ───────────────────────────────────────────────────────────────────

  async searchEntries(query: string, tx?: any): Promise<MemoryEntry[]> {
    if (!query || query.trim().length === 0) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.memoryRepo.searchEntries(query, tx);
  }

  // ── Importance / Confidence ──────────────────────────────────────────────────

  async calculateAverageImportance(memoryId: string, tx?: any): Promise<number> {
    this.validateUuid(memoryId, 'memoryId');
    const runInTx = async (transaction: any) => {
      const entries = await this.memoryRepo.findEntries(memoryId, transaction);
      if (entries.length === 0) return 0.0;
      const sum = entries.reduce((total, e) => total + (e.importanceScore ?? 0.0), 0.0);
      return sum / entries.length;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async calculateAverageConfidence(memoryId: string, tx?: any): Promise<number> {
    this.validateUuid(memoryId, 'memoryId');
    const runInTx = async (transaction: any) => {
      const entries = await this.memoryRepo.findEntries(memoryId, transaction);
      if (entries.length === 0) return 0.0;
      const sum = entries.reduce((total, e) => total + (e.confidence ?? 0.0), 0.0);
      return sum / entries.length;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Statistics ───────────────────────────────────────────────────────────────

  async getMemoryStats(memoryId: string, tx?: any): Promise<{
    entryCount: number;
    contextSize: number;
    averageImportance: number;
    averageConfidence: number;
  }> {
    this.validateUuid(memoryId, 'memoryId');
    const runInTx = async (transaction: any) => {
      const memory = await this.memoryRepo.findById(memoryId, transaction);
      if (!memory || memory.deletedAt) {
        throw new Error(`SessionMemory "${memoryId}" not found.`);
      }
      const entries = await this.memoryRepo.findEntries(memoryId, transaction);
      const avgImportance = await this.calculateAverageImportance(memoryId, transaction);
      const avgConfidence = await this.calculateAverageConfidence(memoryId, transaction);

      return {
        entryCount: entries.length,
        contextSize: memory.contextSize ?? 0,
        averageImportance: avgImportance,
        averageConfidence: avgConfidence,
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findMemory(id: string, tx?: any): Promise<SessionMemory | null> {
    this.validateUuid(id, 'memoryId');
    return this.memoryRepo.findById(id, tx);
  }

  async findByProject(projectId: string, tx?: any): Promise<SessionMemory[]> {
    this.validateUuid(projectId, 'projectId');
    return this.memoryRepo.findByProject(projectId, tx);
  }

  async findByUser(userId: string, tx?: any): Promise<SessionMemory[]> {
    this.validateUuid(userId, 'userId');
    return this.memoryRepo.findByUser(userId, tx);
  }

  async findByInvestigation(investigationId: string, tx?: any): Promise<SessionMemory[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.memoryRepo.findByInvestigation(investigationId, tx);
  }

  async findActive(tx?: any): Promise<SessionMemory[]> {
    return this.memoryRepo.findActive(tx);
  }

  async findEntries(memoryId: string, tx?: any): Promise<MemoryEntry[]> {
    this.validateUuid(memoryId, 'memoryId');
    return this.memoryRepo.findEntries(memoryId, tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteMemory(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'memoryId');
    const runInTx = async (transaction: any) => {
      const existing = await this.memoryRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`SessionMemory "${id}" not found.`);
      }
      await this.memoryRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('SessionMemoryDeleted', { memoryId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: MemoryStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<SessionMemory> {
    this.validateUuid(id, 'memoryId');
    const runInTx = async (transaction: any) => {
      const existing = await this.memoryRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`SessionMemory "${id}" not found.`);
      }
      const updated = await this.memoryRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { memory: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
