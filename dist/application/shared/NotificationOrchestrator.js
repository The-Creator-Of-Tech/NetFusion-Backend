"use strict";
/**
 * NotificationOrchestrator.ts
 * =====================================
 * Orchestrates notification workflows across the platform.
 * Delegates to NotificationService.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.notificationOrchestrator = exports.NotificationOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class NotificationOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('NotificationOrchestrator');
    }
    async sendNotification(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Sending notification to user ${input.userId}: ${input.title}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateRequired(input, ['title', 'message', 'type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const notif = await shared_1.notificationService.createNotification({
                userId: input.userId,
                title: input.title,
                message: input.message,
                type: input.type,
                createdBy: input.actor,
                updatedBy: input.actor,
            }, null);
            compensation.register(`delete-notification-${notif.id}`, async () => {
                try {
                    await prisma_1.default.notification.delete({ where: { id: notif.id } });
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_SENT, ctx, {
                notificationId: notif.id,
                userId: input.userId,
                type: input.type,
            });
            this.logTiming(ctx, 'sendNotification');
            compensation.clear();
            return notif;
        });
    }
    async broadcastNotification(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Broadcasting notification to ${input.userIds.length} users: ${input.title}`);
        this.validateRequired(input, ['userIds', 'title', 'message', 'type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const results = [];
            for (const userId of input.userIds) {
                this.validateUuid(userId, 'userId', ctx);
                const notif = await shared_1.notificationService.createNotification({
                    userId,
                    title: input.title,
                    message: input.message,
                    type: input.type,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                }, null);
                results.push(notif);
                compensation.register(`delete-notification-${notif.id}`, async () => {
                    try {
                        await prisma_1.default.notification.delete({ where: { id: notif.id } });
                    }
                    catch (_) { }
                });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_BROADCAST, ctx, {
                userIds: input.userIds,
                count: results.length,
                type: input.type,
            });
            this.logTiming(ctx, 'broadcastNotification');
            compensation.clear();
            return results;
        });
    }
    async scheduleNotification(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Scheduling notification for user ${input.userId} at ${input.scheduledAt}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateRequired(input, ['title', 'message', 'type', 'scheduledAt'], ctx);
        if (input.scheduledAt.getTime() <= Date.now()) {
            throw new Error('Validation failed: scheduledAt must be in the future.');
        }
        const notificationId = `notif-sch-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_SENT, ctx, {
            notificationId,
            userId: input.userId,
            type: input.type,
            scheduledAt: input.scheduledAt,
        });
        return { notificationId, scheduledAt: input.scheduledAt };
    }
    async cancelNotification(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Cancelling notification: ${input.notificationId}`);
        this.validateRequired(input, ['notificationId'], ctx);
        if (input.notificationId.startsWith('notif-sch-')) {
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
                notificationId: input.notificationId,
                cancelled: true,
            });
            return;
        }
        this.validateUuid(input.notificationId, 'notificationId', ctx);
        await shared_1.notificationService.deleteNotification(input.notificationId, input.actor);
    }
    async markAsRead(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Marking notification ${input.notificationId} as read`);
        this.validateRequired(input, ['notificationId'], ctx);
        this.validateUuid(input.notificationId, 'notificationId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const notif = await shared_1.notificationService.markRead(input.notificationId, input.actor, null);
            compensation.register(`mark-unread-${notif.id}`, async () => {
                await shared_1.notificationService.markUnread(notif.id, 'system');
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
                notificationId: notif.id,
                userId: notif.userId,
                status: 'READ',
            });
            compensation.clear();
            return notif;
        });
    }
    async markAllAsRead(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Marking all notifications for user ${input.userId} as read`);
        this.validateRequired(input, ['userId'], ctx);
        this.validateUuid(input.userId, 'userId', ctx);
        const count = await shared_1.notificationService.markAllRead(input.userId, input.actor);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
            userId: input.userId,
            count,
            status: 'READ',
        });
        return count;
    }
    async archiveNotification(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Archiving notification ${input.notificationId}`);
        this.validateRequired(input, ['notificationId'], ctx);
        this.validateUuid(input.notificationId, 'notificationId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const notif = await shared_1.notificationService.archiveNotification(input.notificationId, input.actor, null);
            compensation.register(`restore-unread-${notif.id}`, async () => {
                await shared_1.notificationService.markUnread(notif.id, 'system');
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
                notificationId: notif.id,
                userId: notif.userId,
                status: 'ARCHIVED',
            });
            compensation.clear();
            return notif;
        });
    }
    async archiveNotif(input, parentCtx) {
        return this.archiveNotification(input, parentCtx);
    }
}
exports.NotificationOrchestrator = NotificationOrchestrator;
exports.notificationOrchestrator = new NotificationOrchestrator();
