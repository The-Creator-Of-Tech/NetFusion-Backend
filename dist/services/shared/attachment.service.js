"use strict";
/**
 * AttachmentService — Phase A5.3.7
 * ===================================
 * Business logic for Attachment lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, update, soft-delete attachments
 * - Filter by project, investigation, target, type, status
 * - File metadata validation (fileName, fileSize, mimeType, storageKey)
 * - Status transitions (ACTIVE → DELETED → PENDING)
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.attachmentService = exports.AttachmentService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const VALID_TYPES = ['FILE', 'IMAGE', 'PDF', 'LOG', 'PCAP', 'OTHER'];
const VALID_STATUSES = ['ACTIVE', 'DELETED', 'PENDING'];
class AttachmentService extends BaseService_1.BaseService {
    // ── Create ──────────────────────────────────────────────────────────────────
    async createAttachment(data, tx) {
        this.validateRequired(data, ['projectId', 'fileName', 'fileSize', 'mimeType', 'storageKey', 'type', 'createdBy', 'updatedBy']);
        if (!String(data.fileName).trim()) {
            throw new Error('Validation failed: fileName must not be empty.');
        }
        if (!String(data.storageKey).trim()) {
            throw new Error('Validation failed: storageKey must not be empty.');
        }
        if (!String(data.mimeType).trim()) {
            throw new Error('Validation failed: mimeType must not be empty.');
        }
        const size = Number(data.fileSize);
        if (isNaN(size) || size < 0) {
            throw new Error('Validation failed: fileSize must be a non-negative number.');
        }
        if (!VALID_TYPES.includes(String(data.type).toUpperCase())) {
            throw new Error(`Validation failed: type "${data.type}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const attachment = await client.attachment.create({ data });
            await EventPublisher_1.eventPublisher.publish('AttachmentCreated', { attachment });
            return attachment;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ──────────────────────────────────────────────────────────────────
    async updateAttachment(id, data, tx) {
        this.validateUuid(id, 'attachmentId');
        if (data.fileSize !== undefined) {
            const size = Number(data.fileSize);
            if (isNaN(size) || size < 0) {
                throw new Error('Validation failed: fileSize must be a non-negative number.');
            }
        }
        if (data.type !== undefined && !VALID_TYPES.includes(String(data.type).toUpperCase())) {
            throw new Error(`Validation failed: type "${data.type}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.attachment.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Attachment "${id}" not found.`);
            }
            const updated = await client.attachment.update({ where: { id }, data });
            await EventPublisher_1.eventPublisher.publish('AttachmentUpdated', { attachment: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    async deleteAttachment(id, actor, tx) {
        this.validateUuid(id, 'attachmentId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.attachment.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Attachment "${id}" not found.`);
            }
            const deleted = await client.attachment.update({
                where: { id },
                data: {
                    deletedAt: new Date(),
                    updatedBy: actor,
                    version: { increment: 1 },
                },
            });
            await EventPublisher_1.eventPublisher.publish('AttachmentDeleted', { attachment: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Status Transitions ──────────────────────────────────────────────────────
    async setStatus(id, status, actor, tx) {
        this.validateUuid(id, 'attachmentId');
        if (!VALID_STATUSES.includes(String(status).toUpperCase())) {
            throw new Error(`Validation failed: status "${status}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.attachment.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Attachment "${id}" not found.`);
            }
            const updated = await client.attachment.update({
                where: { id },
                data: { status, updatedBy: actor },
            });
            await EventPublisher_1.eventPublisher.publish('AttachmentStatusChanged', { attachment: updated, status });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        const client = tx || prisma_1.default;
        return client.attachment.findMany({
            where: { projectId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        const client = tx || prisma_1.default;
        return client.attachment.findMany({
            where: { investigationId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByTarget(targetId, targetType, tx) {
        this.validateUuid(targetId, 'targetId');
        if (!targetType || !targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.attachment.findMany({
            where: { targetId, targetType, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByType(type, tx) {
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.attachment.findMany({
            where: { type, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByStatus(status, tx) {
        if (!VALID_STATUSES.includes(String(status).toUpperCase())) {
            throw new Error(`Validation failed: status "${status}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.attachment.findMany({
            where: { status, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByStorageKey(storageKey, tx) {
        if (!storageKey || !storageKey.trim()) {
            throw new Error('Validation failed: storageKey must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.attachment.findFirst({
            where: { storageKey, deletedAt: null },
        });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.attachment.findMany({ where: { deletedAt: null } });
        const typeCounts = {};
        let active = 0, deleted = 0, pending = 0, totalSize = 0;
        for (const a of all) {
            const t = String(a.type);
            typeCounts[t] = (typeCounts[t] ?? 0) + 1;
            totalSize += Number(a.fileSize ?? 0);
            if (a.status === 'ACTIVE')
                active++;
            else if (a.status === 'DELETED')
                deleted++;
            else if (a.status === 'PENDING')
                pending++;
        }
        return {
            totalAttachments: all.length,
            activeAttachments: active,
            deletedAttachments: deleted,
            pendingAttachments: pending,
            totalFileSize: totalSize,
            averageFileSize: all.length > 0 ? Math.round(totalSize / all.length) : 0,
            typeCounts,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkCreate(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const a = await this.createAttachment({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(a.id);
            }
            catch (e) {
                failed.push({ fileName: String(item.fileName ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('AttachmentsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkDelete(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteAttachment(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('AttachmentsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.AttachmentService = AttachmentService;
exports.attachmentService = new AttachmentService();
