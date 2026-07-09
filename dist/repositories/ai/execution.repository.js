"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExecutionRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ExecutionRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('execution');
    }
    /**
     * Finds executions by provider ID where not deleted.
     */
    async findByProvider(providerId, tx) {
        return this.findMany({ filter: { providerId, deletedAt: null } }, tx);
    }
    /**
     * Finds executions by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds pending executions (status: PENDING and not deleted).
     */
    async findPending(tx) {
        return this.findMany({ filter: { status: 'PENDING', deletedAt: null } }, tx);
    }
    /**
     * Finds completed executions (status: COMPLETED and not deleted).
     */
    async findCompleted(tx) {
        return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
    }
    /**
     * Finds failed executions (status: FAILED and not deleted).
     */
    async findFailed(tx) {
        return this.findMany({ filter: { status: 'FAILED', deletedAt: null } }, tx);
    }
    /**
     * Finds execution usage details associated with a specific execution ID where not deleted.
     */
    async findUsage(executionId, tx) {
        const client = tx || prisma_1.default;
        return client.executionUsage.findFirst({
            where: { executionId, deletedAt: null },
        });
    }
    /**
     * Calculates the estimated cost of an execution.
     */
    async calculateCost(id, tx) {
        const usage = await this.findUsage(id, tx);
        return usage?.estimatedCost || 0.0;
    }
}
exports.ExecutionRepository = ExecutionRepository;
