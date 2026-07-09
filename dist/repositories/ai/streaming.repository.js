"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StreamingRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class StreamingRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('streaming');
    }
    /**
     * Finds a streaming session associated with a specific execution ID where not deleted.
     */
    async findByExecution(executionId, tx) {
        return this.findOne({ executionId, deletedAt: null }, tx);
    }
    /**
     * Finds active streaming sessions (status: ACTIVE and not deleted).
     */
    async findActive(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
    /**
     * Finds completed streaming sessions (status: COMPLETED and not deleted).
     */
    async findCompleted(tx) {
        return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
    }
    /**
     * Finds streaming chunks associated with a specific streaming ID ordered by sequence number where not deleted.
     */
    async findChunks(streamingId, tx) {
        const client = tx || prisma_1.default;
        return client.streamingChunk.findMany({
            where: { streamingId, deletedAt: null },
            orderBy: { sequenceNumber: 'asc' },
        });
    }
    /**
     * Calculates the streaming progress (returns 100 if completed/failed, otherwise returns the count of chunks).
     */
    async calculateProgress(id, tx) {
        const session = await this.findById(id, tx);
        if (!session)
            return 0;
        if (session.status === 'COMPLETED' || session.status === 'FAILED')
            return 100;
        const chunks = await this.findChunks(id, tx);
        if (chunks.length > 0 && chunks[chunks.length - 1].finishReason) {
            return 100;
        }
        return chunks.length;
    }
}
exports.StreamingRepository = StreamingRepository;
