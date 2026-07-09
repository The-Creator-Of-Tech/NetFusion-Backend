"use strict";
/**
 * FavoriteService — Phase A5.3.7
 * =================================
 * Business logic for Favorite lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Toggle favorites (add / remove) for any supported entity type
 * - List favorites by user and/or type
 * - Check if a target is favorited
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.favoriteService = exports.FavoriteService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const VALID_TYPES = [
    'PROJECT', 'INVESTIGATION', 'PLAYBOOK', 'RULE', 'AUTOMATION', 'CASE_FLOW',
];
class FavoriteService extends BaseService_1.BaseService {
    // ── Add Favorite ────────────────────────────────────────────────────────────
    async addFavorite(data, tx) {
        this.validateRequired(data, ['userId', 'targetId', 'type', 'createdBy', 'updatedBy']);
        if (!VALID_TYPES.includes(String(data.type).toUpperCase())) {
            throw new Error(`Validation failed: type "${data.type}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            // Idempotent: return if already favorited (and not soft-deleted), or restore if soft-deleted
            const existing = await client.favorite.findFirst({
                where: {
                    userId: String(data.userId),
                    targetId: String(data.targetId),
                    type: data.type,
                },
            });
            if (existing) {
                if (existing.deletedAt !== null) {
                    const restored = await client.favorite.update({
                        where: { id: existing.id },
                        data: {
                            deletedAt: null,
                            updatedBy: data.updatedBy,
                            version: { increment: 1 },
                        },
                    });
                    await EventPublisher_1.eventPublisher.publish('FavoriteAdded', { favorite: restored });
                    return restored;
                }
                return existing;
            }
            const favorite = await client.favorite.create({ data });
            await EventPublisher_1.eventPublisher.publish('FavoriteAdded', { favorite });
            return favorite;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Remove Favorite ─────────────────────────────────────────────────────────
    async removeFavorite(userId, targetId, type, actor, tx) {
        this.validateUuid(userId, 'userId');
        this.validateUuid(targetId, 'targetId');
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.favorite.findFirst({
                where: { userId, targetId, type, deletedAt: null },
            });
            if (!existing) {
                throw new Error(`Favorite not found for user "${userId}" → target "${targetId}".`);
            }
            await client.favorite.update({
                where: { id: existing.id },
                data: { deletedAt: new Date(), updatedBy: actor, version: { increment: 1 } },
            });
            await EventPublisher_1.eventPublisher.publish('FavoriteRemoved', { userId, targetId, type });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Toggle ──────────────────────────────────────────────────────────────────
    async toggleFavorite(userId, targetId, type, actor, tx) {
        this.validateUuid(userId, 'userId');
        this.validateUuid(targetId, 'targetId');
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        const existing = await client.favorite.findFirst({
            where: { userId, targetId, type, deletedAt: null },
        });
        if (existing) {
            await this.removeFavorite(userId, targetId, type, actor, tx);
            return { added: false };
        }
        else {
            const favorite = await this.addFavorite({ userId, targetId, type, createdBy: actor, updatedBy: actor }, tx);
            return { added: true, favorite };
        }
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.favorite.findMany({
            where: { userId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByUserAndType(userId, type, tx) {
        this.validateUuid(userId, 'userId');
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.favorite.findMany({
            where: { userId, type, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByType(type, tx) {
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.favorite.findMany({
            where: { type, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async isFavorited(userId, targetId, type, tx) {
        this.validateUuid(userId, 'userId');
        this.validateUuid(targetId, 'targetId');
        if (!VALID_TYPES.includes(String(type).toUpperCase())) {
            throw new Error(`Validation failed: type "${type}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        const record = await client.favorite.findFirst({
            where: { userId, targetId, type, deletedAt: null },
        });
        return record !== null;
    }
    async countByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.favorite.count({ where: { userId, deletedAt: null } });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.favorite.findMany({ where: { deletedAt: null } });
        const typeCounts = {};
        const userCounts = {};
        for (const f of all) {
            const t = String(f.type);
            typeCounts[t] = (typeCounts[t] ?? 0) + 1;
            userCounts[f.userId] = (userCounts[f.userId] ?? 0) + 1;
        }
        return { totalFavorites: all.length, typeCounts, userCounts };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkAdd(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (let i = 0; i < items.length; i++) {
            try {
                const f = await this.addFavorite({ ...items[i], createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(f.id);
            }
            catch (e) {
                failed.push({ index: i, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('FavoritesBulkAdded', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkRemove(items, actor, tx) {
        let succeeded = 0;
        const failed = [];
        for (let i = 0; i < items.length; i++) {
            try {
                await this.removeFavorite(items[i].userId, items[i].targetId, items[i].type, actor, tx);
                succeeded++;
            }
            catch (e) {
                failed.push({ index: i, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('FavoritesBulkRemoved', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.FavoriteService = FavoriteService;
exports.favoriteService = new FavoriteService();
