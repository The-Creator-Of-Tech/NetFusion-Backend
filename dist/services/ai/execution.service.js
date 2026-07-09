"use strict";
/**
 * ExecutionService — Phase A5.3.4
 * ==================================
 * Manages AI execution lifecycle: submission, status transitions,
 * usage recording, cost calculation, retry logic, and token accounting.
 * Publishes events on execution state changes and usage events.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExecutionService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ExecutionService extends BaseService_1.BaseService {
    constructor(executionRepo = ai_1.executionRepository, providerRepo = ai_1.providerRepository) {
        super();
        this.executionRepo = executionRepo;
        this.providerRepo = providerRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async submitExecution(data, tx) {
        this.validateRequired(data, ['providerId', 'systemPrompt', 'userPrompt', 'createdBy', 'updatedBy']);
        this.validateUuid(data.providerId, 'providerId');
        if (data.projectId)
            this.validateUuid(data.projectId, 'projectId');
        if (data.investigationId)
            this.validateUuid(data.investigationId, 'investigationId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            // Verify provider exists and is active
            const provider = await this.providerRepo.findById(data.providerId, transaction);
            if (!provider || provider.deletedAt) {
                throw new Error(`Provider "${data.providerId}" not found.`);
            }
            if (!provider.enabled) {
                throw new Error(`Provider "${data.providerId}" is disabled.`);
            }
            const execution = await this.executionRepo.create({ ...data, status: 'PENDING' }, transaction);
            await EventPublisher_1.eventPublisher.publish('ExecutionSubmitted', { execution });
            return execution;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async startExecution(id, actor, tx) {
        return this._transition(id, 'ACTIVE', actor, 'ExecutionStarted', tx);
    }
    async completeExecution(id, actor, tx) {
        return this._transition(id, 'COMPLETED', actor, 'ExecutionCompleted', tx);
    }
    async failExecution(id, actor, tx) {
        return this._transition(id, 'FAILED', actor, 'ExecutionFailed', tx);
    }
    async cancelExecution(id, actor, tx) {
        return this._transition(id, 'FAILED', actor, 'ExecutionCancelled', tx);
    }
    // ── Usage recording ──────────────────────────────────────────────────────────
    async recordUsage(executionId, data, tx) {
        this.validateUuid(executionId, 'executionId');
        this.validateRequired(data, ['promptTokens', 'completionTokens', 'totalTokens', 'estimatedCost', 'latencyMs', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const execution = await this.executionRepo.findById(executionId, transaction);
            if (!execution || execution.deletedAt) {
                throw new Error(`Execution "${executionId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const usage = await client.executionUsage.create({
                data: {
                    executionId,
                    promptTokens: data.promptTokens,
                    completionTokens: data.completionTokens,
                    totalTokens: data.totalTokens,
                    estimatedCost: data.estimatedCost,
                    latencyMs: data.latencyMs,
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ExecutionUsageRecorded', { executionId, usage });
            return usage;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Cost / token accounting ──────────────────────────────────────────────────
    async calculateCost(id, tx) {
        this.validateUuid(id, 'executionId');
        return this.executionRepo.calculateCost(id, tx);
    }
    async getUsageStats(id, tx) {
        this.validateUuid(id, 'executionId');
        const usage = await this.executionRepo.findUsage(id, tx);
        if (!usage)
            return null;
        return {
            promptTokens: usage.promptTokens,
            completionTokens: usage.completionTokens,
            totalTokens: usage.totalTokens,
            estimatedCost: usage.estimatedCost,
            latencyMs: usage.latencyMs,
        };
    }
    async aggregateProjectUsage(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        const runInTx = async (transaction) => {
            const executions = await this.executionRepo.findMany({ filter: { projectId, deletedAt: null } }, transaction);
            let totalTokens = 0;
            let totalCost = 0;
            let totalLatency = 0;
            let usageCount = 0;
            for (const exec of executions) {
                const usage = await this.executionRepo.findUsage(exec.id, transaction);
                if (usage) {
                    totalTokens += usage.totalTokens;
                    totalCost += usage.estimatedCost;
                    totalLatency += usage.latencyMs;
                    usageCount++;
                }
            }
            return {
                totalExecutions: executions.length,
                totalTokens,
                totalCost,
                avgLatencyMs: usageCount > 0 ? totalLatency / usageCount : 0,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findExecution(id, tx) {
        this.validateUuid(id, 'executionId');
        return this.executionRepo.findById(id, tx);
    }
    async findByProvider(providerId, tx) {
        this.validateUuid(providerId, 'providerId');
        return this.executionRepo.findByProvider(providerId, tx);
    }
    async findByStatus(status, tx) {
        return this.executionRepo.findByStatus(status, tx);
    }
    async findPending(tx) {
        return this.executionRepo.findPending(tx);
    }
    async findCompleted(tx) {
        return this.executionRepo.findCompleted(tx);
    }
    async findFailed(tx) {
        return this.executionRepo.findFailed(tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteExecution(id, actor, tx) {
        this.validateUuid(id, 'executionId');
        const runInTx = async (transaction) => {
            const existing = await this.executionRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Execution "${id}" not found.`);
            }
            await this.executionRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ExecutionDeleted', { executionId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'executionId');
        const runInTx = async (transaction) => {
            const existing = await this.executionRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Execution "${id}" not found.`);
            }
            const updated = await this.executionRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { execution: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ExecutionService = ExecutionService;
