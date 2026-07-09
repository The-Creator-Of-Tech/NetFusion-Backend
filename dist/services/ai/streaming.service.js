"use strict";
/**
 * StreamingService — Phase A5.3.4
 * ==================================
 * Manages streaming session lifecycle: session creation, chunk ingestion,
 * progress tracking, completion, and content reconstruction.
 * Publishes events on streaming state changes and data events.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StreamingService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class StreamingService extends BaseService_1.BaseService {
    constructor(streamingRepo = ai_1.streamingRepository) {
        super();
        this.streamingRepo = streamingRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createSession(data, tx) {
        this.validateRequired(data, ['createdBy', 'updatedBy']);
        if (data.executionId)
            this.validateUuid(data.executionId, 'executionId');
        if (data.projectId)
            this.validateUuid(data.projectId, 'projectId');
        if (data.investigationId)
            this.validateUuid(data.investigationId, 'investigationId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            const session = await this.streamingRepo.create({ ...data, status: 'ACTIVE' }, transaction);
            await EventPublisher_1.eventPublisher.publish('StreamingSessionCreated', { session });
            return session;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async completeSession(id, actor, tx) {
        return this._transition(id, 'COMPLETED', actor, 'StreamingSessionCompleted', tx);
    }
    async failSession(id, actor, tx) {
        return this._transition(id, 'FAILED', actor, 'StreamingSessionFailed', tx);
    }
    async cancelSession(id, actor, tx) {
        return this._transition(id, 'FAILED', actor, 'StreamingSessionCancelled', tx);
    }
    // ── Chunk management ─────────────────────────────────────────────────────────
    async appendChunk(streamingId, data, tx) {
        this.validateUuid(streamingId, 'streamingId');
        this.validateRequired(data, ['sequenceNumber', 'content', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const session = await this.streamingRepo.findById(streamingId, transaction);
            if (!session || session.deletedAt) {
                throw new Error(`Streaming session "${streamingId}" not found.`);
            }
            if (session.status === 'COMPLETED' || session.status === 'FAILED') {
                throw new Error(`Cannot append chunk to a ${session.status} streaming session.`);
            }
            const client = transaction || prisma_1.default;
            const chunk = await client.streamingChunk.create({
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
            await EventPublisher_1.eventPublisher.publish('StreamingChunkReceived', { streamingId, chunk });
            // Auto-complete if finishReason is set
            if (data.finishReason) {
                await this.completeSession(streamingId, data.updatedBy, transaction);
            }
            return chunk;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Content reconstruction ───────────────────────────────────────────────────
    async reconstructContent(streamingId, tx) {
        this.validateUuid(streamingId, 'streamingId');
        const runInTx = async (transaction) => {
            const session = await this.streamingRepo.findById(streamingId, transaction);
            if (!session || session.deletedAt) {
                throw new Error(`Streaming session "${streamingId}" not found.`);
            }
            const chunks = await this.streamingRepo.findChunks(streamingId, transaction);
            return chunks.map((c) => c.content).join('');
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Progress tracking ────────────────────────────────────────────────────────
    async getProgress(streamingId, tx) {
        this.validateUuid(streamingId, 'streamingId');
        return this.streamingRepo.calculateProgress(streamingId, tx);
    }
    async getStreamingStats(streamingId, tx) {
        this.validateUuid(streamingId, 'streamingId');
        const runInTx = async (transaction) => {
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
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findSession(id, tx) {
        this.validateUuid(id, 'streamingId');
        return this.streamingRepo.findById(id, tx);
    }
    async findByExecution(executionId, tx) {
        this.validateUuid(executionId, 'executionId');
        return this.streamingRepo.findByExecution(executionId, tx);
    }
    async findActive(tx) {
        return this.streamingRepo.findActive(tx);
    }
    async findCompleted(tx) {
        return this.streamingRepo.findCompleted(tx);
    }
    async findChunks(streamingId, tx) {
        this.validateUuid(streamingId, 'streamingId');
        return this.streamingRepo.findChunks(streamingId, tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteSession(id, actor, tx) {
        this.validateUuid(id, 'streamingId');
        const runInTx = async (transaction) => {
            const existing = await this.streamingRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Streaming session "${id}" not found.`);
            }
            await this.streamingRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('StreamingSessionDeleted', { streamingId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'streamingId');
        const runInTx = async (transaction) => {
            const existing = await this.streamingRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Streaming session "${id}" not found.`);
            }
            const updated = await this.streamingRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { session: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.StreamingService = StreamingService;
