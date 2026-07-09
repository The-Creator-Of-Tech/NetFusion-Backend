"use strict";
/**
 * AutomationService — Phase A5.3.6
 * ===================================
 * Business logic for Automation lifecycle and execution management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for Automations, AutomationSteps, and AutomationExecutions
 * - Trigger-based lookups, enable/disable, and category queries
 * - Execution lifecycle (start, complete, fail)
 * - Step orchestration and execution logging
 * - Scoring and statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.automationService = exports.AutomationService = exports.VALID_TRIGGERS = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const workflow_1 = require("../../repositories/workflow");
const prisma_1 = __importDefault(require("../../lib/prisma"));
// ── Severity score map ────────────────────────────────────────────────────────
const PRIORITY_SCORE = {};
const priorityToScore = (priority) => {
    if (priority <= 10)
        return 90;
    if (priority <= 50)
        return 70;
    if (priority <= 100)
        return 50;
    return 30;
};
// ── Valid trigger types ───────────────────────────────────────────────────────
exports.VALID_TRIGGERS = [
    'FINDING_CREATED',
    'ALERT_CREATED',
    'RULE_MATCHED',
    'PLAYBOOK_SELECTED',
    'TIMELINE_EVENT',
    'MANUAL',
];
class AutomationService extends BaseService_1.BaseService {
    constructor(automationRepo = workflow_1.automationRepository) {
        super();
        this.automationRepo = automationRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    /**
     * Create a new automation. Validates required fields and publishes AutomationCreated.
     */
    async createAutomation(data, tx) {
        this.validateRequired(data, ['name', 'trigger', 'createdBy', 'updatedBy']);
        if (!data.projectId) {
            throw new Error('Validation failed: projectId is required.');
        }
        if (!exports.VALID_TRIGGERS.includes(String(data.trigger))) {
            throw new Error(`Validation failed: trigger "${data.trigger}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const automation = await this.automationRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('AutomationCreated', { automation });
            return automation;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ──────────────────────────────────────────────────────────────────
    /**
     * Update an automation by UUID. Validates trigger if provided. Publishes AutomationUpdated.
     */
    async updateAutomation(id, data, tx) {
        this.validateUuid(id, 'automationId');
        const runInTx = async (transaction) => {
            const existing = await this.automationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Automation "${id}" not found.`);
            }
            if (data.trigger !== undefined) {
                if (!exports.VALID_TRIGGERS.includes(String(data.trigger))) {
                    throw new Error(`Validation failed: trigger "${data.trigger}" is not valid.`);
                }
            }
            const updated = await this.automationRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('AutomationUpdated', { automation: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    /**
     * Soft-delete an automation by UUID. Publishes AutomationDeleted.
     */
    async deleteAutomation(id, actor, tx) {
        this.validateUuid(id, 'automationId');
        const runInTx = async (transaction) => {
            const existing = await this.automationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Automation "${id}" not found.`);
            }
            const deleted = await this.automationRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('AutomationDeleted', { automation: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    /** Find automations by project UUID. */
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        return this.automationRepo.findByProject(projectId, tx);
    }
    /** Find automations by investigation UUID. */
    async findByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.automationRepo.findByInvestigation(investigationId, tx);
    }
    /** Find automations by playbook UUID. */
    async findByPlaybook(playbookId, tx) {
        this.validateUuid(playbookId, 'playbookId');
        return this.automationRepo.findByPlaybook(playbookId, tx);
    }
    /** Find automations by rule UUID. */
    async findByRule(ruleId, tx) {
        this.validateUuid(ruleId, 'ruleId');
        return this.automationRepo.findByRule(ruleId, tx);
    }
    /** Find automations by trigger type. */
    async findByTrigger(trigger, tx) {
        if (!exports.VALID_TRIGGERS.includes(trigger)) {
            throw new Error(`Validation failed: trigger "${trigger}" is not valid.`);
        }
        return this.automationRepo.findByTrigger(trigger, tx);
    }
    /** Find all enabled automations. */
    async findEnabled(tx) {
        return this.automationRepo.findEnabled(tx);
    }
    /** Find all disabled automations. */
    async findDisabled(tx) {
        return this.automationRepo.findDisabled(tx);
    }
    /** Find executions for an automation UUID. */
    async findExecutions(automationId, tx) {
        this.validateUuid(automationId, 'automationId');
        return this.automationRepo.findExecutions(automationId, tx);
    }
    /** Find steps for an automation UUID. */
    async findSteps(automationId, tx) {
        this.validateUuid(automationId, 'automationId');
        return this.automationRepo.findSteps(automationId, tx);
    }
    /** Search automation steps by keyword. */
    async searchSteps(query, tx) {
        if (!query || !query.trim()) {
            throw new Error('Validation failed: search query must not be empty.');
        }
        return this.automationRepo.searchSteps(query.trim(), tx);
    }
    // ── Enable / Disable ────────────────────────────────────────────────────────
    /**
     * Enable an automation. Publishes AutomationEnabled.
     */
    async enableAutomation(id, actor, tx) {
        this.validateUuid(id, 'automationId');
        const runInTx = async (transaction) => {
            const existing = await this.automationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Automation "${id}" not found.`);
            }
            const updated = await this.automationRepo.update(id, { enabled: true, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('AutomationEnabled', { automation: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Disable an automation. Publishes AutomationDisabled.
     */
    async disableAutomation(id, actor, tx) {
        this.validateUuid(id, 'automationId');
        const runInTx = async (transaction) => {
            const existing = await this.automationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Automation "${id}" not found.`);
            }
            const updated = await this.automationRepo.update(id, { enabled: false, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('AutomationDisabled', { automation: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Execution Lifecycle ─────────────────────────────────────────────────────
    /**
     * Start a new execution for an automation. Publishes AutomationExecutionStarted.
     */
    async startExecution(automationId, actor, tx) {
        this.validateUuid(automationId, 'automationId');
        const runInTx = async (transaction) => {
            const automation = await this.automationRepo.findById(automationId, transaction);
            if (!automation || automation.deletedAt) {
                throw new Error(`Automation "${automationId}" not found.`);
            }
            if (!automation.enabled) {
                throw new Error(`Cannot start execution for disabled automation "${automationId}".`);
            }
            const client = transaction || prisma_1.default;
            const execution = await client.automationExecution.create({
                data: {
                    automationId,
                    status: 'ACTIVE',
                    startedAt: new Date(),
                    createdBy: actor,
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('AutomationExecutionStarted', { execution, automationId });
            return execution;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Complete an execution. Publishes AutomationExecutionCompleted.
     */
    async completeExecution(executionId, stepResults, actor, tx) {
        this.validateUuid(executionId, 'executionId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.automationExecution.findFirst({
                where: { id: executionId, deletedAt: null },
            });
            if (!existing) {
                throw new Error(`AutomationExecution "${executionId}" not found.`);
            }
            const updated = await client.automationExecution.update({
                where: { id: executionId },
                data: {
                    status: 'COMPLETED',
                    completedAt: new Date(),
                    stepResults: stepResults,
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('AutomationExecutionCompleted', { execution: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Fail an execution. Publishes AutomationExecutionFailed.
     */
    async failExecution(executionId, reason, actor, tx) {
        this.validateUuid(executionId, 'executionId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.automationExecution.findFirst({
                where: { id: executionId, deletedAt: null },
            });
            if (!existing) {
                throw new Error(`AutomationExecution "${executionId}" not found.`);
            }
            const updated = await client.automationExecution.update({
                where: { id: executionId },
                data: {
                    status: 'FAILED',
                    completedAt: new Date(),
                    stepResults: [{ error: reason }],
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('AutomationExecutionFailed', { execution: updated, reason });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Scoring ─────────────────────────────────────────────────────────────────
    /**
     * Calculate a score (0–100) for an automation based on priority and enabled state.
     */
    async calculateScore(id, tx) {
        this.validateUuid(id, 'automationId');
        const automation = await this.automationRepo.findById(id, tx);
        if (!automation || automation.deletedAt) {
            throw new Error(`Automation "${id}" not found.`);
        }
        const priorityScore = priorityToScore(automation.priority ?? 100);
        const steps = await this.automationRepo.findSteps(id, tx);
        const stepBonus = Math.min(steps.length * 2, 10);
        const enabledBonus = automation.enabled ? 5 : 0;
        return Math.min(priorityScore + stepBonus + enabledBonus, 100);
    }
    /**
     * Pure scoring utility: score a list of automation IDs (0–100).
     */
    scoreAutomations(ids) {
        if (!ids || ids.length === 0)
            return 0;
        return Math.min(ids.length * 10, 100);
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    /**
     * Compute aggregate statistics across all non-deleted automations.
     */
    async getStatistics(tx) {
        const stats = await this.automationRepo.calculateStatistics(tx);
        const client = tx || prisma_1.default;
        const all = await client.automation.findMany({ where: { deletedAt: null } });
        const prioritySum = all.reduce((s, a) => s + (a.priority ?? 100), 0);
        const totalExecutions = await client.automationExecution.count({ where: { deletedAt: null } });
        return {
            totalAutomations: stats.total,
            enabledAutomations: stats.enabled,
            disabledAutomations: stats.disabled,
            triggerCounts: stats.triggerCounts,
            averagePriority: all.length > 0 ? Math.round((prioritySum / all.length) * 10) / 10 : 0,
            totalExecutions,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    /**
     * Bulk-create automations. Returns succeeded IDs and failed entries.
     */
    async bulkCreateAutomations(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const a = await this.createAutomation({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(a.id);
            }
            catch (e) {
                failed.push({ name: String(item.name ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('AutomationsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    /**
     * Bulk soft-delete automations by IDs.
     */
    async bulkDeleteAutomations(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteAutomation(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('AutomationsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.AutomationService = AutomationService;
exports.automationService = new AutomationService();
