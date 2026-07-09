"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PlaybookRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class PlaybookRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('playbook');
    }
    /**
     * Finds playbooks by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds playbooks by investigation ID where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds playbooks by category where not deleted.
     */
    async findByCategory(category, tx) {
        return this.findMany({ filter: { category, deletedAt: null } }, tx);
    }
    /**
     * Finds playbooks by author where not deleted.
     */
    async findByAuthor(author, tx) {
        return this.findMany({ filter: { author, deletedAt: null } }, tx);
    }
    /**
     * Finds playbooks by priority where not deleted.
     */
    async findByPriority(priority, tx) {
        return this.findMany({ filter: { priority, deletedAt: null } }, tx);
    }
    /**
     * Finds enabled playbooks where not deleted.
     */
    async findEnabled(tx) {
        return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
    }
    /**
     * Finds disabled playbooks where not deleted.
     */
    async findDisabled(tx) {
        return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
    }
    /**
     * Finds draft playbooks where not deleted.
     */
    async findDrafts(tx) {
        return this.findMany({ filter: { status: 'DRAFT', deletedAt: null } }, tx);
    }
    /**
     * Finds archived playbooks where not deleted.
     */
    async findArchived(tx) {
        return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
    }
    /**
     * Finds a playbook by ID and includes its associated steps where not deleted.
     */
    async findWithSteps(id, tx) {
        return this.getDelegate(tx).findFirst({
            where: { id, deletedAt: null },
            include: {
                steps: {
                    where: { deletedAt: null },
                    orderBy: { stepNumber: 'asc' },
                },
            },
        });
    }
    /**
     * Searches playbook steps for a query string case-insensitively in title or description where not deleted.
     */
    async searchSteps(query, tx) {
        const client = tx || prisma_1.default;
        return client.playbookStep.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { title: { contains: query, mode: 'insensitive' } },
                    { description: { contains: query, mode: 'insensitive' } },
                ],
            },
            orderBy: { stepNumber: 'asc' },
        });
    }
    /**
     * Finds a playbook step by ID where not deleted.
     */
    async findStep(stepId, tx) {
        const client = tx || prisma_1.default;
        return client.playbookStep.findFirst({
            where: { id: stepId, deletedAt: null },
        });
    }
    /**
     * Computes statistics for playbooks.
     */
    async calculateStatistics(tx) {
        const playbooks = await this.findMany({ filter: { deletedAt: null } }, tx);
        return {
            total: playbooks.length,
            enabled: playbooks.filter((p) => p.enabled).length,
            disabled: playbooks.filter((p) => !p.enabled).length,
            draft: playbooks.filter((p) => p.status === 'DRAFT').length,
            active: playbooks.filter((p) => p.status === 'ACTIVE').length,
            archived: playbooks.filter((p) => p.status === 'ARCHIVED').length,
        };
    }
}
exports.PlaybookRepository = PlaybookRepository;
