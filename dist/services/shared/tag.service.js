"use strict";
/**
 * TagService — Phase A5.3.7
 * ============================
 * Business logic for Tag & TagAssignment lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, update, soft-delete Tags scoped to projects
 * - Assign / unassign tags to any target (targetId + targetType)
 * - Color and description management
 * - Bulk tag creation and assignment
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.tagService = exports.TagService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class TagService extends BaseService_1.BaseService {
    // ── Create Tag ──────────────────────────────────────────────────────────────
    async createTag(data, tx) {
        this.validateRequired(data, ['projectId', 'name', 'createdBy', 'updatedBy']);
        if (!String(data.name).trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            // Enforce unique [projectId, name]
            const existing = await client.tag.findFirst({
                where: { projectId: data.projectId, name: String(data.name).trim(), deletedAt: null },
            });
            if (existing) {
                throw new Error(`Tag name "${data.name}" already exists in this project.`);
            }
            const tag = await client.tag.create({
                data: { ...data, name: String(data.name).trim() },
            });
            await EventPublisher_1.eventPublisher.publish('TagCreated', { tag });
            return tag;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update Tag ──────────────────────────────────────────────────────────────
    async updateTag(id, data, tx) {
        this.validateUuid(id, 'tagId');
        if (data.name !== undefined && !String(data.name).trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.tag.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Tag "${id}" not found.`);
            }
            const updated = await client.tag.update({ where: { id }, data });
            await EventPublisher_1.eventPublisher.publish('TagUpdated', { tag: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete Tag ──────────────────────────────────────────────────────────────
    async deleteTag(id, actor, tx) {
        this.validateUuid(id, 'tagId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.tag.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`Tag "${id}" not found.`);
            }
            const deleted = await client.tag.update({
                where: { id },
                data: {
                    deletedAt: new Date(),
                    updatedBy: actor,
                    version: { increment: 1 },
                },
            });
            await EventPublisher_1.eventPublisher.publish('TagDeleted', { tag: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Assignments ─────────────────────────────────────────────────────────────
    async assignTag(tagId, targetId, targetType, actor, investigationId, tx) {
        this.validateUuid(tagId, 'tagId');
        this.validateUuid(targetId, 'targetId');
        if (!targetType || !targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            // Verify tag exists
            const tag = await client.tag.findUnique({ where: { id: tagId } });
            if (!tag || tag.deletedAt) {
                throw new Error(`Tag "${tagId}" not found.`);
            }
            // Idempotent: return existing if already assigned
            const existing = await client.tagAssignment.findFirst({
                where: { tagId, targetId, targetType, deletedAt: null },
            });
            if (existing)
                return existing;
            const assignment = await client.tagAssignment.create({
                data: {
                    tagId,
                    targetId,
                    targetType: targetType.trim(),
                    ...(investigationId && { investigationId }),
                    createdBy: actor,
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('TagAssigned', { assignment, tag });
            return assignment;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async unassignTag(tagId, targetId, targetType, actor, tx) {
        this.validateUuid(tagId, 'tagId');
        this.validateUuid(targetId, 'targetId');
        if (!targetType || !targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const assignment = await client.tagAssignment.findFirst({
                where: { tagId, targetId, targetType, deletedAt: null },
            });
            if (!assignment) {
                throw new Error(`TagAssignment for tag "${tagId}" → target "${targetId}" not found.`);
            }
            await client.tagAssignment.update({
                where: { id: assignment.id },
                data: { deletedAt: new Date(), updatedBy: actor, version: { increment: 1 } },
            });
            await EventPublisher_1.eventPublisher.publish('TagUnassigned', { tagId, targetId, targetType });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async getAssignments(tagId, tx) {
        this.validateUuid(tagId, 'tagId');
        const client = tx || prisma_1.default;
        return client.tagAssignment.findMany({
            where: { tagId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async getTagsForTarget(targetId, targetType, tx) {
        this.validateUuid(targetId, 'targetId');
        if (!targetType || !targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        const client = tx || prisma_1.default;
        const assignments = await client.tagAssignment.findMany({
            where: { targetId, targetType, deletedAt: null },
            include: { tag: true },
        });
        return assignments.map((a) => a.tag).filter((t) => !t.deletedAt);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        const client = tx || prisma_1.default;
        return client.tag.findMany({
            where: { projectId, deletedAt: null },
            orderBy: { name: 'asc' },
        });
    }
    async findByName(name, projectId, tx) {
        if (!name || !name.trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        this.validateUuid(projectId, 'projectId');
        const client = tx || prisma_1.default;
        return client.tag.findFirst({
            where: { name: name.trim(), projectId, deletedAt: null },
        });
    }
    async findByColor(color, tx) {
        if (!color || !color.trim()) {
            throw new Error('Validation failed: color must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.tag.findMany({
            where: { color: color.trim(), deletedAt: null },
            orderBy: { name: 'asc' },
        });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const [tags, assignments] = await Promise.all([
            client.tag.findMany({ where: { deletedAt: null } }),
            client.tagAssignment.findMany({ where: { deletedAt: null } }),
        ]);
        const projectCounts = {};
        for (const t of tags) {
            projectCounts[t.projectId] = (projectCounts[t.projectId] ?? 0) + 1;
        }
        return {
            totalTags: tags.length,
            totalAssignments: assignments.length,
            projectCounts,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkCreate(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const t = await this.createTag({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(t.id);
            }
            catch (e) {
                failed.push({ name: String(item.name ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('TagsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkDelete(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteTag(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('TagsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.TagService = TagService;
exports.tagService = new TagService();
