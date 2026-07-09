"use strict";
/**
 * ActivityOrchestrator.ts
 * =====================================
 * Orchestrates logging and tracking of user and system activities.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.activityOrchestrator = exports.ActivityOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ActivityOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ActivityOrchestrator');
    }
    async logActivity(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Logging activity for user ${input.userId}: ${input.action}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateRequired(input, ['action', 'type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const log = await shared_1.activityService.logActivity({
                userId: input.userId,
                action: input.action,
                type: input.type,
                details: input.details,
                projectId: input.projectId,
                investigationId: input.investigationId,
                createdBy: input.actor,
                updatedBy: input.actor,
            }, null);
            compensation.register(`delete-activity-${log.id}`, async () => {
                try {
                    await prisma_1.default.activityLog.delete({ where: { id: log.id } });
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.ACTIVITY_LOGGED, ctx, {
                activityId: log.id,
                userId: input.userId,
                action: input.action,
            });
            compensation.clear();
            return log;
        });
    }
    async getAuditTrail(query, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        const limit = query.limit ?? 100;
        this.logInfo(ctx, `Fetching audit trail. Filters: ${JSON.stringify(query)}`);
        if (query.userId) {
            this.validateUuid(query.userId, 'userId', ctx);
            return shared_1.activityService.findByUser(query.userId, limit);
        }
        if (query.projectId) {
            this.validateUuid(query.projectId, 'projectId', ctx);
            return shared_1.activityService.findByProject(query.projectId, limit);
        }
        if (query.investigationId) {
            this.validateUuid(query.investigationId, 'investigationId', ctx);
            return shared_1.activityService.findByInvestigation(query.investigationId, limit);
        }
        return shared_1.activityService.findRecent(limit);
    }
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching activity statistics`);
        return shared_1.activityService.getStatistics();
    }
    async getStats(actor, parentCtx) {
        return this.getStatistics(actor, parentCtx);
    }
    async purgeLogs(cutoffDate, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Purging activity logs older than ${cutoffDate.toISOString()}`);
        if (!(cutoffDate instanceof Date) || isNaN(cutoffDate.getTime())) {
            throw new Error('Validation failed: cutoffDate must be a valid Date.');
        }
        return shared_1.activityService.purgeOlderThan(cutoffDate);
    }
    async purgeActivityLogs(cutoffDate, actor, parentCtx) {
        return this.purgeLogs(cutoffDate, actor, parentCtx);
    }
}
exports.ActivityOrchestrator = ActivityOrchestrator;
exports.activityOrchestrator = new ActivityOrchestrator();
