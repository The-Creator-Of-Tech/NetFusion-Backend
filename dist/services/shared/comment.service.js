"use strict";
/**
 * CommentService — Phase A5.3.7
 * ================================
 * Business logic for Comment lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, update, soft-delete comments
 * - Filter by user, project, investigation, target
 * - Visibility management (PUBLIC / PRIVATE / TEAM)
 * - Content validation
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.commentService = exports.CommentService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const VALID_VISIBILITIES = ['PUBLIC', 'PRIVATE', 'TEAM'];
class CommentService extends BaseService_1.BaseService {
    // ── Create ──────────────────────────────────────────────────────────────────
    async createComment(data, tx) {
        this.validateRequired(data, ['userId', 'projectId', 'content', 'createdBy', 'updatedBy']);
        if (!String(data.content).trim()) {
            throw new Error('Validation failed: content must not be empty.');
        }
        if (data.visibility !== undefined && !VALID_VISIBILITIES.includes(String(data.visibility).toUpperCase())) {
            throw new Error(`Validation failed: visibility "${data.visibility}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const comment = await client.comment.create({ data });
            await EventPublisher_1.eventPublisher.publish('CommentCreated', { comment });
            return comment;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ──────────────────────────────────────────────────────────────────
    async updateComment(id, data, tx) {
        this.validateUuid(id, 'commentId');
        if (data.content !== undefined && !String(data.content).trim()) {
            throw new Error('Validation failed: content must not be empty.');
        }
        if (data.visibility !== undefined && !VALID_VISIBILITIES.includes(String(data.visibility).toUpperCase())) {
            throw new Error(`Validation failed: visibility "${data.visibility}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.comment.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Comment "${id}" not found.`);
            }
            const updated = await client.comment.update({ where: { id }, data });
            await EventPublisher_1.eventPublisher.publish('CommentUpdated', { comment: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    async deleteComment(id, actor, tx) {
        this.validateUuid(id, 'commentId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.comment.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Comment "${id}" not found.`);
            }
            const deleted = await client.comment.update({
                where: { id },
                data: {
                    deletedAt: new Date(),
                    updatedBy: actor,
                    version: { increment: 1 },
                },
            });
            await EventPublisher_1.eventPublisher.publish('CommentDeleted', { comment: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Visibility ──────────────────────────────────────────────────────────────
    async setVisibility(id, visibility, actor, tx) {
        this.validateUuid(id, 'commentId');
        if (!VALID_VISIBILITIES.includes(String(visibility).toUpperCase())) {
            throw new Error(`Validation failed: visibility "${visibility}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.comment.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Comment "${id}" not found.`);
            }
            const updated = await client.comment.update({
                where: { id },
                data: { visibility, updatedBy: actor },
            });
            await EventPublisher_1.eventPublisher.publish('CommentVisibilityChanged', { comment: updated, visibility });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.comment.findMany({
            where: { userId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        const client = tx || prisma_1.default;
        return client.comment.findMany({
            where: { projectId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        const client = tx || prisma_1.default;
        return client.comment.findMany({
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
        return client.comment.findMany({
            where: { targetId, targetType, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByVisibility(visibility, tx) {
        if (!VALID_VISIBILITIES.includes(String(visibility).toUpperCase())) {
            throw new Error(`Validation failed: visibility "${visibility}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.comment.findMany({
            where: { visibility, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async searchByContent(query, tx) {
        if (!query || !query.trim()) {
            throw new Error('Validation failed: search query must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.comment.findMany({
            where: {
                content: { contains: query.trim(), mode: 'insensitive' },
                deletedAt: null,
            },
            orderBy: { createdAt: 'desc' },
        });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.comment.findMany({ where: { deletedAt: null } });
        let pub = 0, priv = 0, team = 0, totalLen = 0;
        for (const c of all) {
            totalLen += String(c.content ?? '').length;
            if (c.visibility === 'PUBLIC')
                pub++;
            else if (c.visibility === 'PRIVATE')
                priv++;
            else if (c.visibility === 'TEAM')
                team++;
        }
        return {
            totalComments: all.length,
            publicComments: pub,
            privateComments: priv,
            teamComments: team,
            averageContentLength: all.length > 0 ? Math.round(totalLen / all.length) : 0,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkCreate(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (let i = 0; i < items.length; i++) {
            try {
                const c = await this.createComment({ ...items[i], createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(c.id);
            }
            catch (e) {
                failed.push({ index: i, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('CommentsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkDelete(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteComment(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('CommentsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.CommentService = CommentService;
exports.commentService = new CommentService();
