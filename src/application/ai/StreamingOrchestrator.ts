/**
 * StreamingOrchestrator.ts — Phase A5.4.2
 * ==========================================
 * Responsible for:
 *  - Stream lifecycle management (start, ingest, complete, cancel)
 *  - Chunk aggregation and content reconstruction
 *  - Progress updates
 *  - Cancellation support (respects AbortSignal via ctx.signal)
 *  - Resume (append more chunks to existing ACTIVE session)
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationError,
  OrchestrationNotFoundError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

import { streamingService, executionService } from '../../services/ai';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface StartStreamInput {
  executionId: string;
  actor: string;
  projectId?: string;
  investigationId?: string;
  userId?: string;
}

export interface IngestChunksInput {
  streamingId: string;
  actor: string;
  chunks: Array<{
    content: string;
    sequenceNumber: number;
    finishReason?: string;
    metadata?: any;
  }>;
  onProgress?: (progress: number) => void;
}

export interface StreamLifecycleResult {
  streamingId: string;
  executionId: string;
  chunkCount: number;
  totalLength: number;
  progress: number;
  status: string;
  reconstructed?: string;
  correlationId: string;
}

export interface CancelStreamInput {
  streamingId: string;
  actor: string;
  executionId?: string;
}

export interface ResumeStreamInput {
  streamingId: string;
  actor: string;
  chunks: Array<{
    content: string;
    sequenceNumber: number;
    finishReason?: string;
  }>;
}

// ─────────────────────────────────────────────────────────────────────────────
// StreamingOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class StreamingOrchestrator extends BaseApplicationService {
  constructor() {
    super('StreamingOrchestrator');
  }

  // ── Start Stream ──────────────────────────────────────────────────────────

  async startStream(
    input: StartStreamInput,
    parentCtx?: OperationContext,
  ): Promise<{ streamingId: string; executionId: string; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.executionId, 'executionId', ctx);
    this.logInfo(ctx, `Starting stream for execution: ${input.executionId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const session = await streamingService.createSession({
        executionId: input.executionId,
        projectId: input.projectId ?? null,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.StreamingUncheckedCreateInput);

      compensation.register(`cancel-stream-${session.id}`, async () => {
        try { await streamingService.cancelSession(session.id, input.actor); } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.AI_STREAMING_STARTED, ctx, {
        streamingId: session.id,
        executionId: input.executionId,
        projectId: input.projectId,
      });

      this.logTiming(ctx, 'startStream');
      compensation.clear();

      return {
        streamingId: session.id,
        executionId: input.executionId,
        correlationId: ctx.correlationId,
      };
    });
  }

  // ── Ingest Chunks ─────────────────────────────────────────────────────────

  async ingestChunks(
    input: IngestChunksInput,
    parentCtx?: OperationContext,
  ): Promise<StreamLifecycleResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.streamingId, 'streamingId', ctx);
    this.logInfo(ctx, `Ingesting ${input.chunks.length} chunk(s) into stream: ${input.streamingId}`);

    const session = await streamingService.findSession(input.streamingId);
    if (!session || session.deletedAt) {
      throw new OrchestrationNotFoundError('StreamingSession', input.streamingId, ctx.correlationId);
    }

    for (const chunk of input.chunks) {
      this.checkCancellation(ctx);

      await streamingService.appendChunk(input.streamingId, {
        sequenceNumber: chunk.sequenceNumber,
        content: chunk.content,
        finishReason: chunk.finishReason,
        metadata: chunk.metadata,
        createdBy: input.actor,
        updatedBy: input.actor,
      });

      // Fire progress callback if provided
      if (input.onProgress) {
        const progress = await streamingService.getProgress(input.streamingId);
        input.onProgress(progress);
      }
    }

    const stats = await streamingService.getStreamingStats(input.streamingId);
    const reconstructed = stats.isComplete
      ? await streamingService.reconstructContent(input.streamingId)
      : undefined;

    if (stats.isComplete) {
      await this.publishEvent(APP_EVENTS.AI_STREAMING_FINISHED, ctx, {
        streamingId: input.streamingId,
        executionId: session.executionId ?? 'unknown',
        projectId: session.projectId ?? undefined,
        chunkCount: stats.chunkCount,
        totalLength: stats.totalLength,
      });
    }

    return {
      streamingId: input.streamingId,
      executionId: session.executionId ?? '',
      chunkCount: stats.chunkCount,
      totalLength: stats.totalLength,
      progress: stats.progress,
      status: stats.status,
      reconstructed,
      correlationId: ctx.correlationId,
    };
  }

  // ── Complete Stream ───────────────────────────────────────────────────────

  async completeStream(
    streamingId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<StreamLifecycleResult> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(streamingId, 'streamingId', ctx);
    this.logInfo(ctx, `Completing stream: ${streamingId}`);

    const session = await streamingService.findSession(streamingId);
    if (!session || session.deletedAt) {
      throw new OrchestrationNotFoundError('StreamingSession', streamingId, ctx.correlationId);
    }

    await streamingService.completeSession(streamingId, actor);
    const stats = await streamingService.getStreamingStats(streamingId);
    const reconstructed = await streamingService.reconstructContent(streamingId);

    await this.publishEvent(APP_EVENTS.AI_STREAMING_FINISHED, ctx, {
      streamingId,
      executionId: session.executionId ?? 'unknown',
      projectId: session.projectId ?? undefined,
      chunkCount: stats.chunkCount,
      totalLength: stats.totalLength,
    });

    this.logTiming(ctx, 'completeStream');

    return {
      streamingId,
      executionId: session.executionId ?? '',
      chunkCount: stats.chunkCount,
      totalLength: stats.totalLength,
      progress: stats.progress,
      status: 'COMPLETED',
      reconstructed,
      correlationId: ctx.correlationId,
    };
  }

  // ── Cancel Stream ─────────────────────────────────────────────────────────

  async cancelStream(
    input: CancelStreamInput,
    parentCtx?: OperationContext,
  ): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.streamingId, 'streamingId', ctx);
    this.logInfo(ctx, `Cancelling stream: ${input.streamingId}`);

    const session = await streamingService.findSession(input.streamingId);
    if (!session || session.deletedAt) {
      throw new OrchestrationNotFoundError('StreamingSession', input.streamingId, ctx.correlationId);
    }

    await streamingService.cancelSession(input.streamingId, input.actor);

    if (input.executionId) {
      this.validateUuid(input.executionId, 'executionId', ctx);
      await executionService.cancelExecution(input.executionId, input.actor);

      await this.publishEvent(APP_EVENTS.AI_EXECUTION_CANCELLED, ctx, {
        executionId: input.executionId,
        projectId: session.projectId ?? undefined,
      });
    }

    await this.publishEvent(APP_EVENTS.AI_STREAMING_CANCELLED, ctx, {
      streamingId: input.streamingId,
      executionId: input.executionId ?? session.executionId ?? 'unknown',
    });

    this.logTiming(ctx, 'cancelStream');
  }

  // ── Resume Stream ─────────────────────────────────────────────────────────

  async resumeStream(
    input: ResumeStreamInput,
    parentCtx?: OperationContext,
  ): Promise<StreamLifecycleResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.streamingId, 'streamingId', ctx);
    this.logInfo(ctx, `Resuming stream: ${input.streamingId}`);

    // Validate session is in a resumable state
    const session = await streamingService.findSession(input.streamingId);
    if (!session || session.deletedAt) {
      throw new OrchestrationNotFoundError('StreamingSession', input.streamingId, ctx.correlationId);
    }
    if (session.status === 'COMPLETED') {
      throw new OrchestrationError(
        `Stream ${input.streamingId} is already COMPLETED and cannot be resumed.`,
        ctx.correlationId,
        'INVALID_STATE',
      );
    }

    // Ingest the resume chunks
    return this.ingestChunks({
      streamingId: input.streamingId,
      actor: input.actor,
      chunks: input.chunks,
    }, ctx);
  }

  // ── Get Progress ──────────────────────────────────────────────────────────

  async getProgress(
    streamingId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<{ streamingId: string; progress: number; status: string; chunkCount: number }> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(streamingId, 'streamingId', ctx);

    const stats = await streamingService.getStreamingStats(streamingId);
    return {
      streamingId,
      progress: stats.progress,
      status: stats.status,
      chunkCount: stats.chunkCount,
    };
  }

  // ── Reconstruct Content ───────────────────────────────────────────────────

  async reconstruct(
    streamingId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<string> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(streamingId, 'streamingId', ctx);
    return streamingService.reconstructContent(streamingId);
  }
}

export const streamingOrchestrator = new StreamingOrchestrator();
