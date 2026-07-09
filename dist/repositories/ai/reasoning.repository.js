"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReasoningRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ReasoningRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('reasoning');
    }
    /**
     * Finds reasoning sessions by execution ID using JSON metadata path where not deleted.
     */
    async findByExecution(executionId, tx) {
        const delegate = this.getDelegate(tx);
        return delegate.findMany({
            where: {
                deletedAt: null,
                metadata: {
                    path: ['executionId'],
                    equals: executionId,
                },
            },
        });
    }
    /**
     * Finds reasoning sessions by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds completed reasoning sessions (status: COMPLETED and not deleted).
     */
    async findCompleted(tx) {
        return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
    }
    /**
     * Finds failed reasoning sessions (status: FAILED and not deleted).
     */
    async findFailed(tx) {
        return this.findMany({ filter: { status: 'FAILED', deletedAt: null } }, tx);
    }
    /**
     * Finds reasoning steps associated with a specific reasoning session ID where not deleted.
     */
    async findSteps(reasoningId, tx) {
        const client = tx || prisma_1.default;
        return client.reasoningStep.findMany({
            where: { reasoningId, deletedAt: null },
            orderBy: { stepNumber: 'asc' },
        });
    }
    /**
     * Calculates the average confidence of all steps in a reasoning session.
     */
    async calculateConfidence(id, tx) {
        const steps = await this.findSteps(id, tx);
        if (steps.length === 0)
            return 0.0;
        const sum = steps.reduce((total, step) => total + step.confidence, 0);
        return sum / steps.length;
    }
}
exports.ReasoningRepository = ReasoningRepository;
