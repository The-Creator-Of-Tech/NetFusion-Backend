"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RuleRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class RuleRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('rule');
    }
    /**
     * Finds rules by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds rules by investigation ID where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds rules by category where not deleted.
     */
    async findByCategory(category, tx) {
        return this.findMany({ filter: { category, deletedAt: null } }, tx);
    }
    /**
     * Finds rules by severity where not deleted.
     */
    async findBySeverity(severity, tx) {
        return this.findMany({ filter: { severity, deletedAt: null } }, tx);
    }
    /**
     * Finds enabled rules where not deleted.
     */
    async findEnabled(tx) {
        return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
    }
    /**
     * Finds disabled rules where not deleted.
     */
    async findDisabled(tx) {
        return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
    }
    /**
     * Finds conditions associated with a specific rule ID where not deleted.
     */
    async findConditions(ruleId, tx) {
        const client = tx || prisma_1.default;
        return client.ruleCondition.findMany({
            where: { ruleId, deletedAt: null },
        });
    }
    /**
     * Finds actions associated with a specific rule ID where not deleted.
     */
    async findActions(ruleId, tx) {
        const client = tx || prisma_1.default;
        return client.ruleAction.findMany({
            where: { ruleId, deletedAt: null },
        });
    }
    /**
     * Searches rule conditions for a query string case-insensitively in field or value where not deleted.
     */
    async searchConditions(query, tx) {
        const client = tx || prisma_1.default;
        return client.ruleCondition.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { field: { contains: query, mode: 'insensitive' } },
                    { value: { contains: query, mode: 'insensitive' } },
                ],
            },
        });
    }
    /**
     * Searches rule actions for a query string case-insensitively in actionType where not deleted.
     */
    async searchActions(query, tx) {
        const client = tx || prisma_1.default;
        return client.ruleAction.findMany({
            where: {
                actionType: { contains: query, mode: 'insensitive' },
                deletedAt: null,
            },
        });
    }
    /**
     * Finds a rule condition by ID where not deleted.
     */
    async findCondition(conditionId, tx) {
        const client = tx || prisma_1.default;
        return client.ruleCondition.findFirst({
            where: { id: conditionId, deletedAt: null },
        });
    }
    /**
     * Finds a rule action by ID where not deleted.
     */
    async findAction(actionId, tx) {
        const client = tx || prisma_1.default;
        return client.ruleAction.findFirst({
            where: { id: actionId, deletedAt: null },
        });
    }
    /**
     * Computes statistics for rules.
     */
    async calculateStatistics(tx) {
        const rules = await this.findMany({ filter: { deletedAt: null } }, tx);
        const severityCounts = {
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
        };
        for (const r of rules) {
            severityCounts[r.severity] = (severityCounts[r.severity] || 0) + 1;
        }
        return {
            total: rules.length,
            enabled: rules.filter((r) => r.enabled).length,
            disabled: rules.filter((r) => !r.enabled).length,
            severityCounts,
        };
    }
}
exports.RuleRepository = RuleRepository;
