"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AutomationRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class AutomationRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('automation');
    }
    /**
     * Finds automations by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds automations by investigation ID where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds automations by playbook ID where not deleted.
     */
    async findByPlaybook(playbookId, tx) {
        return this.findMany({ filter: { playbookId, deletedAt: null } }, tx);
    }
    /**
     * Finds automations by rule ID where not deleted.
     */
    async findByRule(ruleId, tx) {
        return this.findMany({ filter: { ruleId, deletedAt: null } }, tx);
    }
    /**
     * Finds automations by trigger type where not deleted.
     */
    async findByTrigger(trigger, tx) {
        return this.findMany({ filter: { trigger, deletedAt: null } }, tx);
    }
    /**
     * Finds enabled automations where not deleted.
     */
    async findEnabled(tx) {
        return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
    }
    /**
     * Finds disabled automations where not deleted.
     */
    async findDisabled(tx) {
        return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
    }
    /**
     * Finds executions associated with a specific automation ID where not deleted.
     */
    async findExecutions(automationId, tx) {
        const client = tx || prisma_1.default;
        return client.automationExecution.findMany({
            where: { automationId, deletedAt: null },
            orderBy: { startedAt: 'desc' },
        });
    }
    /**
     * Finds steps associated with a specific automation ID where not deleted.
     */
    async findSteps(automationId, tx) {
        const client = tx || prisma_1.default;
        return client.automationStep.findMany({
            where: { automationId, deletedAt: null },
            orderBy: { stepNumber: 'asc' },
        });
    }
    /**
     * Searches automation steps for a query string case-insensitively in name or description where not deleted.
     */
    async searchSteps(query, tx) {
        const client = tx || prisma_1.default;
        return client.automationStep.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { name: { contains: query, mode: 'insensitive' } },
                    { description: { contains: query, mode: 'insensitive' } },
                ],
            },
            orderBy: { stepNumber: 'asc' },
        });
    }
    /**
     * Computes statistics for automations.
     */
    async calculateStatistics(tx) {
        const automations = await this.findMany({ filter: { deletedAt: null } }, tx);
        const triggerCounts = {
            FINDING_CREATED: 0,
            ALERT_CREATED: 0,
            RULE_MATCHED: 0,
            PLAYBOOK_SELECTED: 0,
            TIMELINE_EVENT: 0,
            MANUAL: 0,
        };
        for (const a of automations) {
            triggerCounts[a.trigger] = (triggerCounts[a.trigger] || 0) + 1;
        }
        return {
            total: automations.length,
            enabled: automations.filter((a) => a.enabled).length,
            disabled: automations.filter((a) => !a.enabled).length,
            triggerCounts,
        };
    }
}
exports.AutomationRepository = AutomationRepository;
