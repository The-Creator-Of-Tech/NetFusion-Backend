"use strict";
/**
 * NotificationService — Phase A5.3.7
 * =====================================
 * Business logic for Notification lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, update, delete notifications for users
 * - Mark as read / unread / archived
 * - Filter by status, type, user
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.notificationService = exports.NotificationService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class NotificationService extends BaseService_1.BaseService {
    constructor(notifRepo = core_1.notificationRepository) {
        super();
        this.notifRepo = notifRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createNotification(data, tx) {
        this.validateRequired(data, ['userId', 'title', 'message', 'type', 'createdBy', 'updatedBy']);
        if (!data.title || !String(data.title).trim()) {
            throw new Error('Validation failed: title must not be empty.');
        }
        if (!data.message || !String(data.message).trim()) {
            throw new Error('Validation failed: message must not be empty.');
        }
        const validTypes = ['SYSTEM', 'ALERT', 'TASK', 'MENTION', 'COMMENT'];
        if (!validTypes.includes(String(data.type).toUpperCase())) {
            throw new Error(`Validation failed: type "${data.type}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const notification = await this.notifRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('NotificationCreated', { notification });
            return notification;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ──────────────────────────────────────────────────────────────────
    async updateNotification(id, data, tx) {
        this.validateUuid(id, 'notificationId');
        const runInTx = async (transaction) => {
            const existing = await this.notifRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Notification "${id}" not found.`);
            }
            const updated = await this.notifRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('NotificationUpdated', { notification: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    async deleteNotification(id, actor, tx) {
        this.validateUuid(id, 'notificationId');
        const runInTx = async (transaction) => {
            const existing = await this.notifRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Notification "${id}" not found.`);
            }
            const deleted = await this.notifRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('NotificationDeleted', { notification: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Status Transitions ──────────────────────────────────────────────────────
    async markRead(id, actor, tx) {
        this.validateUuid(id, 'notificationId');
        const runInTx = async (transaction) => {
            const existing = await this.notifRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Notification "${id}" not found.`);
            }
            const updated = await this.notifRepo.update(id, { status: 'READ', readAt: new Date(), updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('NotificationRead', { notification: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async markUnread(id, actor, tx) {
        this.validateUuid(id, 'notificationId');
        const runInTx = async (transaction) => {
            const existing = await this.notifRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Notification "${id}" not found.`);
            }
            const updated = await this.notifRepo.update(id, { status: 'UNREAD', readAt: null, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('NotificationUnread', { notification: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async archiveNotification(id, actor, tx) {
        this.validateUuid(id, 'notificationId');
        const runInTx = async (transaction) => {
            const existing = await this.notifRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Notification "${id}" not found.`);
            }
            const updated = await this.notifRepo.update(id, { status: 'ARCHIVED', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('NotificationArchived', { notification: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async markAllRead(userId, actor, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        const result = await client.notification.updateMany({
            where: { userId, status: 'UNREAD', deletedAt: null },
            data: { status: 'READ', readAt: new Date(), updatedBy: actor },
        });
        await EventPublisher_1.eventPublisher.publish('NotificationAllRead', { userId, count: result.count });
        return result.count;
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.notification.findMany({
            where: { userId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByStatus(status, tx) {
        const validStatuses = ['READ', 'UNREAD', 'ARCHIVED'];
        if (!validStatuses.includes(String(status).toUpperCase())) {
            throw new Error(`Validation failed: status "${status}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.notification.findMany({
            where: { status, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByType(type, tx) {
        const validTypes = ['SYSTEM', 'ALERT', 'TASK', 'MENTION', 'COMMENT'];
        if (!validTypes.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.notification.findMany({
            where: { type, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findUnread(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.notification.findMany({
            where: { userId, status: 'UNREAD', deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async countUnread(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.notification.count({
            where: { userId, status: 'UNREAD', deletedAt: null },
        });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.notification.findMany({ where: { deletedAt: null } });
        const typeCounts = {};
        let unread = 0, read = 0, archived = 0;
        for (const n of all) {
            const t = String(n.type);
            typeCounts[t] = (typeCounts[t] ?? 0) + 1;
            if (n.status === 'UNREAD')
                unread++;
            else if (n.status === 'READ')
                read++;
            else if (n.status === 'ARCHIVED')
                archived++;
        }
        return {
            totalNotifications: all.length,
            unreadNotifications: unread,
            readNotifications: read,
            archivedNotifications: archived,
            typeCounts,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkCreate(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const n = await this.createNotification({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(n.id);
            }
            catch (e) {
                failed.push({ title: String(item.title ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('NotificationsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkDelete(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteNotification(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('NotificationsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.NotificationService = NotificationService;
exports.notificationService = new NotificationService();
