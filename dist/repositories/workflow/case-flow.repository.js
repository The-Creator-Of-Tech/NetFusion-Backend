"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CaseFlowRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class CaseFlowRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('caseFlow');
    }
    /**
     * Finds case flows by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds case flows by investigation ID where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds case flows by owner where not deleted.
     */
    async findByOwner(owner, tx) {
        return this.findMany({ filter: { owner, deletedAt: null } }, tx);
    }
    /**
     * Finds case flows by priority where not deleted.
     */
    async findByPriority(priority, tx) {
        return this.findMany({ filter: { priority, deletedAt: null } }, tx);
    }
    /**
     * Finds case flows by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds open case flows where not deleted.
     */
    async findOpen(tx) {
        return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
    }
    /**
     * Finds in-progress case flows where not deleted.
     */
    async findInProgress(tx) {
        return this.findMany({ filter: { status: 'IN_PROGRESS', deletedAt: null } }, tx);
    }
    /**
     * Finds resolved case flows where not deleted.
     */
    async findResolved(tx) {
        return this.findMany({ filter: { status: 'RESOLVED', deletedAt: null } }, tx);
    }
    /**
     * Finds closed case flows where not deleted.
     */
    async findClosed(tx) {
        return this.findMany({ filter: { status: 'CLOSED', deletedAt: null } }, tx);
    }
    /**
     * Finds executions associated with a specific case flow ID where not deleted.
     */
    async findExecutions(caseFlowId, tx) {
        const client = tx || prisma_1.default;
        return client.caseFlowExecution.findMany({
            where: { caseFlowId, deletedAt: null },
            orderBy: { startedAt: 'desc' },
        });
    }
    /**
     * Finds steps associated with a specific case flow ID where not deleted.
     */
    async findSteps(caseFlowId, tx) {
        const client = tx || prisma_1.default;
        return client.caseFlowStep.findMany({
            where: { caseFlowId, deletedAt: null },
            orderBy: { stepNumber: 'asc' },
        });
    }
    /**
     * Searches case flow steps for a query string case-insensitively in title or description where not deleted.
     */
    async searchSteps(query, tx) {
        const client = tx || prisma_1.default;
        return client.caseFlowStep.findMany({
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
     * Computes statistics for case flows.
     */
    async calculateStatistics(tx) {
        const cases = await this.findMany({ filter: { deletedAt: null } }, tx);
        const priorityCounts = {
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
        };
        for (const c of cases) {
            priorityCounts[c.priority] = (priorityCounts[c.priority] || 0) + 1;
        }
        return {
            total: cases.length,
            open: cases.filter((c) => c.status === 'OPEN').length,
            inProgress: cases.filter((c) => c.status === 'IN_PROGRESS').length,
            resolved: cases.filter((c) => c.status === 'RESOLVED').length,
            closed: cases.filter((c) => c.status === 'CLOSED').length,
            priorityCounts,
        };
    }
}
exports.CaseFlowRepository = CaseFlowRepository;
