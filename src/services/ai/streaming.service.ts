/**
 * StreamingService — Phase A5.3.4
 * ==================================
 * Manages streaming session lifecycle: session creation, chunk ingestion,
 * progress tracking, completion, and content reconstruction.
 * Publishes events on streaming state changes and data events.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { streamingRepository } from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  Streaming,
  StreamingChunk,
  StreamingStatus,
  Prisma,
} from '@prisma/client';

export class StreamingService extends BaseService {
  constructor(
    private readonly streamingRepo = streamingRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createSession(
    data: Prisma.StreamingUncheckedCreateInput,
    tx?: any,
  ): Promise<Streaming> {
    this.validateRequired(data as any, ['createdBy', 'updatedBy']);
    if (data.executionId) this.validateUuid(data.executionId as string, 'executionId');
    if (data.projectId) this.validateUuid(data.projectId as string, 'projectId');
    if (data.investigationId) this.validateUuid(data.investigationId as string, 'investigationId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      const session = await this.streamingRepo.create(
        { ...data, status: 'ACTIVE' as StreamingStatus },
        transaction,
      );
      await eventPublisher.publish('StreamingSessionCreated', { session });
      return session;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async completeSession(id: string, actor: string, tx?: any): Promise<Streaming> {
    return this._transition(id, 'COMPLETED', actor, 'StreamingSessionCompleted', tx);
  }

  async failSession(id: string, actor: string, tx?: any): Promise<Streaming> {
    return this._transition(id, 'FAILED', actor, 'StreamingSessionFailed', tx);
  }

  async cancelSession(id: string, actor: string, tx?: any): Promise<Streaming> {
    return this._transition(id, 'FAILED', actor, 'StreamingSessionCancelled', tx);
  }

  // ── Chunk management ─────────────────────────────────────────────────────────

  async appendChunk(
    streamingId: string,
    data: {
      sequenceNumber: number;
      content: string;
      finishReason?: string;
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<StreamingChunk> {
    this.validateUuid(streamingId, 'streamingId');
    this.validateRequired(data as any, ['sequenceNumber', 'content', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const session = await this.streamingRepo.findById(streamingId, transaction);
      if (!session || session.deletedAt) {
        throw new Error(`Streaming session "${streamingId}" not found.`);
      }
      if (session.status === 'COMPLETED' || session.status === 'FAILED') {
        throw new Error(`Cannot append chunk to a ${session.status} streaming session.`);
      }

      const client = transaction || prisma;
      const chunk: StreamingChunk = await client.streamingChunk.create({
        data: {
          streamingId,
          sequenceNumber: data.sequenceNumber,
          content: data.content,
          finishReason: data.finishReason ?? null,
          metadata: data.metadata ?? null,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      await eventPublisher.publish('StreamingChunkReceived', { streamingId, chunk });

      // Auto-complete if finishReason is set
      if (data.finishReason) {
        await this.completeSession(streamingId, data.updatedBy, transaction);
      }

      return chunk;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Content reconstruction ───────────────────────────────────────────────────

  async reconstructContent(streamingId: string, tx?: any): Promise<string> {
    this.validateUuid(streamingId, 'streamingId');
    const runInTx = async (transaction: any) => {
      const session = await this.streamingRepo.findById(streamingId, transaction);
      if (!session || session.deletedAt) {
        throw new Error(`Streaming session "${streamingId}" not found.`);
      }
      const chunks = await this.streamingRepo.findChunks(streamingId, transaction);
      return chunks.map((c) => c.content).join('');
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Progress tracking ────────────────────────────────────────────────────────

  async getProgress(streamingId: string, tx?: any): Promise<number> {
    this.validateUuid(streamingId, 'streamingId');
    return this.streamingRepo.calculateProgress(streamingId, tx);
  }

  async getStreamingStats(streamingId: string, tx?: any): Promise<{
    chunkCount: number;
    totalLength: number;
    progress: number;
    status: string;
    isComplete: boolean;
  }> {
    this.validateUuid(streamingId, 'streamingId');
    const runInTx = async (transaction: any) => {
      const session = await this.streamingRepo.findById(streamingId, transaction);
      if (!session || session.deletedAt) {
        throw new Error(`Streaming session "${streamingId}" not found.`);
      }
      const chunks = await this.streamingRepo.findChunks(streamingId, transaction);
      const totalLength = chunks.reduce((sum, c) => sum + (c.content?.length ?? 0), 0);
      const progress = await this.streamingRepo.calculateProgress(streamingId, transaction);

      return {
        chunkCount: chunks.length,
        totalLength,
        progress,
        status: session.status,
        isComplete: session.status === 'COMPLETED',
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findSession(id: string, tx?: any): Promise<Streaming | null> {
    this.validateUuid(id, 'streamingId');
    return this.streamingRepo.findById(id, tx);
  }

  async findByExecution(executionId: string, tx?: any): Promise<Streaming | null> {
    this.validateUuid(executionId, 'executionId');
    return this.streamingRepo.findByExecution(executionId, tx);
  }

  async findActive(tx?: any): Promise<Streaming[]> {
    return this.streamingRepo.findActive(tx);
  }

  async findCompleted(tx?: any): Promise<Streaming[]> {
    return this.streamingRepo.findCompleted(tx);
  }

  async findChunks(streamingId: string, tx?: any): Promise<StreamingChunk[]> {
    this.validateUuid(streamingId, 'streamingId');
    return this.streamingRepo.findChunks(streamingId, tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteSession(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'streamingId');
    const runInTx = async (transaction: any) => {
      const existing = await this.streamingRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Streaming session "${id}" not found.`);
      }
      await this.streamingRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('StreamingSessionDeleted', { streamingId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: StreamingStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<Streaming> {
    this.validateUuid(id, 'streamingId');
    const runInTx = async (transaction: any) => {
      const existing = await this.streamingRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Streaming session "${id}" not found.`);
      }
      const updated = await this.streamingRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { session: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
