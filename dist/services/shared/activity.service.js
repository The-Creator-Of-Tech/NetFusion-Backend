"use strict";
/**
 * ActivityService — Phase A5.3.7
 * =================================
 * Business logic for ActivityLog lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Log activities for any user/project/investigation action
 * - Filter by user, project, investigation, action, type
 * - Pagination support
 * - Statistics and audit trail analysis
 * - Cross-module event logging
 * - Event publication after every log entry
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activityService = exports.ActivityService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const VALID_TYPES = ['CREATE', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'EXECUTE', 'OTHER'];
class ActivityService extends BaseService_1.BaseService {
    constructor(activityRepo = core_1.activityLogRepository) {
        super();
        this.activityRepo = activityRepo;
    }
    // ── Log Activity ────────────────────────────────────────────────────────────
    async logActivity(data, tx) {
        this.validateRequired(data, ['userId', 'action', 'type', 'createdBy', 'updatedBy']);
        if (!String(data.action).trim()) {
            throw new Error('Validation failed: action must not be empty.');
        }
        if (!VALID_TYPES.includes(String(data.type).toUpperCase())) {
            throw new Error(`Validation failed: type "${data.type}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const log = await this.activityRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('ActivityLogged', { log });
            return log;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Convenience Loggers ─────────────────────────────────────────────────────
    async logCreate(userId, action, details, projectId, investigationId, tx) {
        return this.logActivity({
            userId, action, type: 'CREATE',
            details, projectId, investigationId,
            createdBy: userId, updatedBy: userId,
        }, tx);
    }
    async logUpdate(userId, action, details, projectId, investigationId, tx) {
        return this.logActivity({
            userId, action, type: 'UPDATE',
            details, projectId, investigationId,
            createdBy: userId, updatedBy: userId,
        }, tx);
    }
    async logDelete(userId, action, details, projectId, investigationId, tx) {
        return this.logActivity({
            userId, action, type: 'DELETE',
            details, projectId, investigationId,
            createdBy: userId, updatedBy: userId,
        }, tx);
    }
    async logExecute(userId, action, details, projectId, investigationId, tx) {
        return this.logActivity({
            userId, action, type: 'EXECUTE',
            details, projectId, investigationId,
            createdBy: userId, updatedBy: userId,
        }, tx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByUser(userId, limit = 100, tx) {
        this.validateUuid(userId, 'userId');
        if (limit < 1)
            throw new Error('Validation failed: limit must be >= 1.');
        const client = tx || prisma_1.default;
        return client.activityLog.findMany({
            where: { userId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
            take: limit,
        });
    }
    async findByProject(projectId, limit = 100, tx) {
        this.validateUuid(projectId, 'projectId');
        if (limit < 1)
            throw new Error('Validation failed: limit must be >= 1.');
        const client = tx || prisma_1.default;
        return client.activityLog.findMany({
            where: { projectId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
            take: limit,
        });
    }
    async findByInvestigation(investigationId, limit = 100, tx) {
        this.validateUuid(investigationId, 'investigationId');
        if (limit < 1)
            throw new Error('Validation failed: limit must be >= 1.');
        const client = tx || prisma_1.default;
        return client.activityLog.findMany({
            where: { investigationId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
            take: limit,
        });
    }
    async findByType(type, tx) {
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.activityLog.findMany({
            where: { type, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByAction(action, tx) {
        if (!action || !action.trim()) {
            throw new Error('Validation failed: action must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.activityLog.findMany({
            where: {
                action: { contains: action.trim(), mode: 'insensitive' },
                deletedAt: null,
            },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findRecent(limit = 50, tx) {
        if (limit < 1)
            throw new Error('Validation failed: limit must be >= 1.');
        const client = tx || prisma_1.default;
        return client.activityLog.findMany({
            where: { deletedAt: null },
            orderBy: { createdAt: 'desc' },
            take: limit,
        });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.activityLog.findMany({ where: { deletedAt: null } });
        const typeCounts = {};
        const userCounts = {};
        const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
        let recent = 0;
        for (const a of all) {
            const t = String(a.type);
            typeCounts[t] = (typeCounts[t] ?? 0) + 1;
            userCounts[a.userId] = (userCounts[a.userId] ?? 0) + 1;
            if (new Date(a.createdAt) >= cutoff)
                recent++;
        }
        return {
            totalLogs: all.length,
            typeCounts,
            userCounts,
            recentActivity: recent,
        };
    }
    // ── Purge (hard delete old logs) ────────────────────────────────────────────
    async purgeOlderThan(cutoffDate, tx) {
        if (!(cutoffDate instanceof Date) || isNaN(cutoffDate.getTime())) {
            throw new Error('Validation failed: cutoffDate must be a valid Date.');
        }
        const client = tx || prisma_1.default;
        const result = await client.activityLog.deleteMany({
            where: { createdAt: { lt: cutoffDate } },
        });
        await EventPublisher_1.eventPublisher.publish('ActivityLogsPurged', { count: result.count, cutoffDate });
        return result.count;
    }
}
exports.ActivityService = ActivityService;
exports.activityService = new ActivityService();
