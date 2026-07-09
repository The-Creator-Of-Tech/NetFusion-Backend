"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.streamingOrchestrator = exports.StreamingOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const ai_1 = require("../../services/ai");
// ─────────────────────────────────────────────────────────────────────────────
// StreamingOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class StreamingOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('StreamingOrchestrator');
    }
    // ── Start Stream ──────────────────────────────────────────────────────────
    async startStream(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.executionId, 'executionId', ctx);
        this.logInfo(ctx, `Starting stream for execution: ${input.executionId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const session = await ai_1.streamingService.createSession({
                executionId: input.executionId,
                projectId: input.projectId ?? null,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`cancel-stream-${session.id}`, async () => {
                try {
                    await ai_1.streamingService.cancelSession(session.id, input.actor);
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_STARTED, ctx, {
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
    async ingestChunks(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.streamingId, 'streamingId', ctx);
        this.logInfo(ctx, `Ingesting ${input.chunks.length} chunk(s) into stream: ${input.streamingId}`);
        const session = await ai_1.streamingService.findSession(input.streamingId);
        if (!session || session.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('StreamingSession', input.streamingId, ctx.correlationId);
        }
        for (const chunk of input.chunks) {
            this.checkCancellation(ctx);
            await ai_1.streamingService.appendChunk(input.streamingId, {
                sequenceNumber: chunk.sequenceNumber,
                content: chunk.content,
                finishReason: chunk.finishReason,
                metadata: chunk.metadata,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            // Fire progress callback if provided
            if (input.onProgress) {
                const progress = await ai_1.streamingService.getProgress(input.streamingId);
                input.onProgress(progress);
            }
        }
        const stats = await ai_1.streamingService.getStreamingStats(input.streamingId);
        const reconstructed = stats.isComplete
            ? await ai_1.streamingService.reconstructContent(input.streamingId)
            : undefined;
        if (stats.isComplete) {
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_FINISHED, ctx, {
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
    async completeStream(streamingId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(streamingId, 'streamingId', ctx);
        this.logInfo(ctx, `Completing stream: ${streamingId}`);
        const session = await ai_1.streamingService.findSession(streamingId);
        if (!session || session.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('StreamingSession', streamingId, ctx.correlationId);
        }
        await ai_1.streamingService.completeSession(streamingId, actor);
        const stats = await ai_1.streamingService.getStreamingStats(streamingId);
        const reconstructed = await ai_1.streamingService.reconstructContent(streamingId);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_FINISHED, ctx, {
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
    async cancelStream(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.streamingId, 'streamingId', ctx);
        this.logInfo(ctx, `Cancelling stream: ${input.streamingId}`);
        const session = await ai_1.streamingService.findSession(input.streamingId);
        if (!session || session.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('StreamingSession', input.streamingId, ctx.correlationId);
        }
        await ai_1.streamingService.cancelSession(input.streamingId, input.actor);
        if (input.executionId) {
            this.validateUuid(input.executionId, 'executionId', ctx);
            await ai_1.executionService.cancelExecution(input.executionId, input.actor);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_EXECUTION_CANCELLED, ctx, {
                executionId: input.executionId,
                projectId: session.projectId ?? undefined,
            });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_CANCELLED, ctx, {
            streamingId: input.streamingId,
            executionId: input.executionId ?? session.executionId ?? 'unknown',
        });
        this.logTiming(ctx, 'cancelStream');
    }
    // ── Resume Stream ─────────────────────────────────────────────────────────
    async resumeStream(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.streamingId, 'streamingId', ctx);
        this.logInfo(ctx, `Resuming stream: ${input.streamingId}`);
        // Validate session is in a resumable state
        const session = await ai_1.streamingService.findSession(input.streamingId);
        if (!session || session.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('StreamingSession', input.streamingId, ctx.correlationId);
        }
        if (session.status === 'COMPLETED') {
            throw new BaseApplicationService_1.OrchestrationError(`Stream ${input.streamingId} is already COMPLETED and cannot be resumed.`, ctx.correlationId, 'INVALID_STATE');
        }
        // Ingest the resume chunks
        return this.ingestChunks({
            streamingId: input.streamingId,
            actor: input.actor,
            chunks: input.chunks,
        }, ctx);
    }
    // ── Get Progress ──────────────────────────────────────────────────────────
    async getProgress(streamingId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(streamingId, 'streamingId', ctx);
        const stats = await ai_1.streamingService.getStreamingStats(streamingId);
        return {
            streamingId,
            progress: stats.progress,
            status: stats.status,
            chunkCount: stats.chunkCount,
        };
    }
    // ── Reconstruct Content ───────────────────────────────────────────────────
    async reconstruct(streamingId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(streamingId, 'streamingId', ctx);
        return ai_1.streamingService.reconstructContent(streamingId);
    }
}
exports.StreamingOrchestrator = StreamingOrchestrator;
exports.streamingOrchestrator = new StreamingOrchestrator();
