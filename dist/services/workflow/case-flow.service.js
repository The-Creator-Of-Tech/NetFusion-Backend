"use strict";
/**
 * CaseFlowService — Phase A5.3.6
 * =================================
 * Business logic for Case Flow lifecycle and execution management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for CaseFlows, CaseFlowSteps, and CaseFlowExecutions
 * - Status/priority/owner-based lookups
 * - Case lifecycle transitions (open → in_progress → resolved → closed)
 * - Execution start/complete/fail
 * - Step orchestration and assignment
 * - Confidence scoring and statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.caseFlowService = exports.CaseFlowService = exports.VALID_STATUSES = exports.VALID_PRIORITIES = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const workflow_1 = require("../../repositories/workflow");
const prisma_1 = __importDefault(require("../../lib/prisma"));
// ── Valid status transitions ──────────────────────────────────────────────────
const CASE_STATUS_TRANSITIONS = {
    OPEN: ['IN_PROGRESS', 'CLOSED'],
    IN_PROGRESS: ['RESOLVED', 'CLOSED', 'OPEN'],
    RESOLVED: ['CLOSED', 'IN_PROGRESS'],
    CLOSED: ['OPEN'],
};
// ── Priority score map ────────────────────────────────────────────────────────
const PRIORITY_SCORE = {
    CRITICAL: 100,
    HIGH: 75,
    MEDIUM: 50,
    LOW: 25,
};
// ── Valid priorities ──────────────────────────────────────────────────────────
exports.VALID_PRIORITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
// ── Valid statuses ────────────────────────────────────────────────────────────
exports.VALID_STATUSES = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'];
class CaseFlowService extends BaseService_1.BaseService {
    constructor(caseFlowRepo = workflow_1.caseFlowRepository) {
        super();
        this.caseFlowRepo = caseFlowRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    /**
     * Create a new case flow. CaseFlow requires projectId + investigationId.
     * Publishes CaseFlowCreated.
     */
    async createCaseFlow(data, tx) {
        this.validateRequired(data, ['title', 'createdBy', 'updatedBy']);
        if (!data.projectId) {
            throw new Error('Validation failed: projectId is required.');
        }
        if (!data.investigationId) {
            throw new Error('Validation failed: investigationId is required.');
        }
        if (data.priority !== undefined) {
            if (!exports.VALID_PRIORITIES.includes(String(data.priority))) {
                throw new Error(`Validation failed: priority "${data.priority}" is not valid.`);
            }
        }
        if (data.status !== undefined) {
            if (!exports.VALID_STATUSES.includes(String(data.status))) {
                throw new Error(`Validation failed: status "${data.status}" is not valid.`);
            }
        }
        if (data.confidence !== undefined) {
            const conf = Number(data.confidence);
            if (isNaN(conf) || conf < 0 || conf > 100) {
                throw new Error('Validation failed: confidence must be between 0 and 100.');
            }
        }
        const runInTx = async (transaction) => {
            const caseFlow = await this.caseFlowRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowCreated', { caseFlow });
            return caseFlow;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ──────────────────────────────────────────────────────────────────
    /**
     * Update a case flow by UUID. Validates status transitions. Publishes CaseFlowUpdated.
     */
    async updateCaseFlow(id, data, tx) {
        this.validateUuid(id, 'caseFlowId');
        const runInTx = async (transaction) => {
            const existing = await this.caseFlowRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`CaseFlow "${id}" not found.`);
            }
            if (data.status && data.status !== existing.status) {
                const allowed = CASE_STATUS_TRANSITIONS[existing.status] ?? [];
                if (!allowed.includes(String(data.status))) {
                    throw new Error(`Invalid status transition from "${existing.status}" to "${data.status}".`);
                }
            }
            if (data.priority !== undefined) {
                if (!exports.VALID_PRIORITIES.includes(String(data.priority))) {
                    throw new Error(`Validation failed: priority "${data.priority}" is not valid.`);
                }
            }
            if (data.confidence !== undefined) {
                const conf = Number(data.confidence);
                if (isNaN(conf) || conf < 0 || conf > 100) {
                    throw new Error('Validation failed: confidence must be between 0 and 100.');
                }
            }
            const updated = await this.caseFlowRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowUpdated', { caseFlow: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    /**
     * Soft-delete a case flow by UUID. Publishes CaseFlowDeleted.
     */
    async deleteCaseFlow(id, actor, tx) {
        this.validateUuid(id, 'caseFlowId');
        const runInTx = async (transaction) => {
            const existing = await this.caseFlowRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`CaseFlow "${id}" not found.`);
            }
            const deleted = await this.caseFlowRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowDeleted', { caseFlow: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    /** Find case flows by project UUID. */
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        return this.caseFlowRepo.findByProject(projectId, tx);
    }
    /** Find case flows by investigation UUID. */
    async findByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.caseFlowRepo.findByInvestigation(investigationId, tx);
    }
    /** Find case flows by owner (non-empty string). */
    async findByOwner(owner, tx) {
        if (!owner || !owner.trim()) {
            throw new Error('Validation failed: owner must not be empty.');
        }
        return this.caseFlowRepo.findByOwner(owner.trim(), tx);
    }
    /** Find case flows by priority. */
    async findByPriority(priority, tx) {
        if (!exports.VALID_PRIORITIES.includes(priority)) {
            throw new Error(`Validation failed: priority "${priority}" is not valid.`);
        }
        return this.caseFlowRepo.findByPriority(priority, tx);
    }
    /** Find case flows by status. */
    async findByStatus(status, tx) {
        if (!exports.VALID_STATUSES.includes(status)) {
            throw new Error(`Validation failed: status "${status}" is not valid.`);
        }
        return this.caseFlowRepo.findByStatus(status, tx);
    }
    /** Find all OPEN case flows. */
    async findOpen(tx) {
        return this.caseFlowRepo.findOpen(tx);
    }
    /** Find all IN_PROGRESS case flows. */
    async findInProgress(tx) {
        return this.caseFlowRepo.findInProgress(tx);
    }
    /** Find all RESOLVED case flows. */
    async findResolved(tx) {
        return this.caseFlowRepo.findResolved(tx);
    }
    /** Find all CLOSED case flows. */
    async findClosed(tx) {
        return this.caseFlowRepo.findClosed(tx);
    }
    /** Find executions for a case flow UUID. */
    async findExecutions(caseFlowId, tx) {
        this.validateUuid(caseFlowId, 'caseFlowId');
        return this.caseFlowRepo.findExecutions(caseFlowId, tx);
    }
    /** Find steps for a case flow UUID. */
    async findSteps(caseFlowId, tx) {
        this.validateUuid(caseFlowId, 'caseFlowId');
        return this.caseFlowRepo.findSteps(caseFlowId, tx);
    }
    /** Search case flow steps by keyword. */
    async searchSteps(query, tx) {
        if (!query || !query.trim()) {
            throw new Error('Validation failed: search query must not be empty.');
        }
        return this.caseFlowRepo.searchSteps(query.trim(), tx);
    }
    // ── Lifecycle Transitions ───────────────────────────────────────────────────
    /**
     * Transition a case to IN_PROGRESS. Publishes CaseFlowInProgress.
     */
    async startCase(id, actor, tx) {
        this.validateUuid(id, 'caseFlowId');
        const runInTx = async (transaction) => {
            const existing = await this.caseFlowRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`CaseFlow "${id}" not found.`);
            }
            const allowed = CASE_STATUS_TRANSITIONS[existing.status] ?? [];
            if (!allowed.includes('IN_PROGRESS')) {
                throw new Error(`Cannot transition CaseFlow "${id}" from "${existing.status}" to IN_PROGRESS.`);
            }
            const updated = await this.caseFlowRepo.update(id, { status: 'IN_PROGRESS', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowInProgress', { caseFlow: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Transition a case to RESOLVED. Publishes CaseFlowResolved.
     */
    async resolveCase(id, actor, tx) {
        this.validateUuid(id, 'caseFlowId');
        const runInTx = async (transaction) => {
            const existing = await this.caseFlowRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`CaseFlow "${id}" not found.`);
            }
            const allowed = CASE_STATUS_TRANSITIONS[existing.status] ?? [];
            if (!allowed.includes('RESOLVED')) {
                throw new Error(`Cannot resolve CaseFlow "${id}" from status "${existing.status}".`);
            }
            const updated = await this.caseFlowRepo.update(id, { status: 'RESOLVED', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowResolved', { caseFlow: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Transition a case to CLOSED. Publishes CaseFlowClosed.
     */
    async closeCase(id, actor, tx) {
        this.validateUuid(id, 'caseFlowId');
        const runInTx = async (transaction) => {
            const existing = await this.caseFlowRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`CaseFlow "${id}" not found.`);
            }
            const updated = await this.caseFlowRepo.update(id, { status: 'CLOSED', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowClosed', { caseFlow: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Assign a case to a user. Publishes CaseFlowAssigned.
     */
    async assignCase(id, assignee, actor, tx) {
        this.validateUuid(id, 'caseFlowId');
        if (!assignee || !assignee.trim()) {
            throw new Error('Validation failed: assignee must not be empty.');
        }
        const runInTx = async (transaction) => {
            const existing = await this.caseFlowRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`CaseFlow "${id}" not found.`);
            }
            const updated = await this.caseFlowRepo.update(id, { assignedTo: assignee.trim(), updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('CaseFlowAssigned', { caseFlow: updated, assignee });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Execution Lifecycle ─────────────────────────────────────────────────────
    /**
     * Start a new execution for a case flow. Publishes CaseFlowExecutionStarted.
     */
    async startExecution(caseFlowId, actor, tx) {
        this.validateUuid(caseFlowId, 'caseFlowId');
        const runInTx = async (transaction) => {
            const caseFlow = await this.caseFlowRepo.findById(caseFlowId, transaction);
            if (!caseFlow || caseFlow.deletedAt) {
                throw new Error(`CaseFlow "${caseFlowId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const execution = await client.caseFlowExecution.create({
                data: {
                    caseFlowId,
                    status: 'ACTIVE',
                    startedAt: new Date(),
                    createdBy: actor,
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('CaseFlowExecutionStarted', { execution, caseFlowId });
            return execution;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Complete a case flow execution. Publishes CaseFlowExecutionCompleted.
     */
    async completeExecution(executionId, stepResults, actor, tx) {
        this.validateUuid(executionId, 'executionId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.caseFlowExecution.findFirst({
                where: { id: executionId, deletedAt: null },
            });
            if (!existing) {
                throw new Error(`CaseFlowExecution "${executionId}" not found.`);
            }
            const updated = await client.caseFlowExecution.update({
                where: { id: executionId },
                data: {
                    status: 'COMPLETED',
                    completedAt: new Date(),
                    stepResults: stepResults,
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('CaseFlowExecutionCompleted', { execution: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Scoring ─────────────────────────────────────────────────────────────────
    /**
     * Calculate a score (0–100) for a case flow based on priority and confidence.
     */
    async calculateScore(id, tx) {
        this.validateUuid(id, 'caseFlowId');
        const caseFlow = await this.caseFlowRepo.findById(id, tx);
        if (!caseFlow || caseFlow.deletedAt) {
            throw new Error(`CaseFlow "${id}" not found.`);
        }
        const priorityScore = PRIORITY_SCORE[String(caseFlow.priority ?? 'MEDIUM')] ?? 50;
        const confidenceBonus = Math.round((Number(caseFlow.confidence ?? 100) / 100) * 10);
        const steps = await this.caseFlowRepo.findSteps(id, tx);
        const stepBonus = Math.min(steps.length * 2, 10);
        return Math.min(priorityScore + confidenceBonus + stepBonus, 100);
    }
    /**
     * Pure scoring utility: score a list of case flow IDs (0–100).
     */
    scoreCaseFlows(ids) {
        if (!ids || ids.length === 0)
            return 0;
        return Math.min(ids.length * 10, 100);
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    /**
     * Compute aggregate statistics across all non-deleted case flows.
     */
    async getStatistics(tx) {
        const stats = await this.caseFlowRepo.calculateStatistics(tx);
        const client = tx || prisma_1.default;
        const all = await client.caseFlow.findMany({ where: { deletedAt: null } });
        const confidenceSum = all.reduce((s, c) => s + Number(c.confidence ?? 100), 0);
        const totalExecutions = await client.caseFlowExecution.count({ where: { deletedAt: null } });
        return {
            totalCases: stats.total,
            openCases: stats.open,
            inProgressCases: stats.inProgress,
            resolvedCases: stats.resolved,
            closedCases: stats.closed,
            priorityCounts: stats.priorityCounts,
            averageConfidence: all.length > 0 ? Math.round((confidenceSum / all.length) * 10) / 10 : 0,
            totalExecutions,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    /**
     * Bulk-create case flows. Returns succeeded IDs and failed entries.
     */
    async bulkCreateCaseFlows(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const c = await this.createCaseFlow({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(c.id);
            }
            catch (e) {
                failed.push({ title: String(item.title ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('CaseFlowsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    /**
     * Bulk soft-delete case flows by IDs.
     */
    async bulkDeleteCaseFlows(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteCaseFlow(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('CaseFlowsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.CaseFlowService = CaseFlowService;
exports.caseFlowService = new CaseFlowService();
