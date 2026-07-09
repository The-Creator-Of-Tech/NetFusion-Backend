"use strict";
/**
 * FavoriteOrchestrator.ts
 * =====================================
 * Orchestrates creating, deleting, and toggling favorite items.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.favoriteOrchestrator = exports.FavoriteOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class FavoriteOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('FavoriteOrchestrator');
    }
    async addFavorite(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Adding favorite for user ${input.userId} target ${input.targetId}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateUuid(input.targetId, 'targetId', ctx);
        this.validateRequired(input, ['type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.favorite.findFirst({
                where: {
                    userId: input.userId,
                    targetId: input.targetId,
                    type: input.type,
                },
            });
            const favorite = await shared_1.favoriteService.addFavorite({
                userId: input.userId,
                targetId: input.targetId,
                type: input.type,
                createdBy: input.actor,
                updatedBy: input.actor,
            }, null);
            if (existing) {
                compensation.register(`restore-favorite-${favorite.id}`, async () => {
                    await prisma_1.default.favorite.update({
                        where: { id: existing.id },
                        data: {
                            deletedAt: existing.deletedAt,
                            updatedBy: 'system',
                            version: { increment: 1 },
                        },
                    });
                });
            }
            else {
                compensation.register(`delete-favorite-${favorite.id}`, async () => {
                    try {
                        await prisma_1.default.favorite.delete({ where: { id: favorite.id } });
                    }
                    catch (_) { }
                });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.FAVORITE_ADDED, ctx, {
                favoriteId: favorite.id,
                userId: input.userId,
                targetId: input.targetId,
                type: input.type,
            });
            compensation.clear();
            return favorite;
        });
    }
    async removeFavorite(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Removing favorite for user ${input.userId} target ${input.targetId}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateUuid(input.targetId, 'targetId', ctx);
        this.validateRequired(input, ['type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.favorite.findFirst({
                where: {
                    userId: input.userId,
                    targetId: input.targetId,
                    type: input.type,
                    deletedAt: null,
                },
            });
            if (!existing) {
                throw new Error(`Favorite not found for user "${input.userId}" → target "${input.targetId}".`);
            }
            await shared_1.favoriteService.removeFavorite(input.userId, input.targetId, input.type, input.actor, null);
            compensation.register(`restore-favorite-${existing.id}`, async () => {
                await prisma_1.default.favorite.update({
                    where: { id: existing.id },
                    data: {
                        deletedAt: null,
                        updatedBy: 'system',
                        version: { increment: 1 },
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.FAVORITE_REMOVED, ctx, {
                userId: input.userId,
                targetId: input.targetId,
                type: input.type,
            });
            compensation.clear();
        });
    }
    async toggleFavorite(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Toggling favorite for user ${input.userId} target ${input.targetId}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateUuid(input.targetId, 'targetId', ctx);
        this.validateRequired(input, ['type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const isFav = await shared_1.favoriteService.isFavorited(input.userId, input.targetId, input.type);
            const res = await shared_1.favoriteService.toggleFavorite(input.userId, input.targetId, input.type, input.actor, null);
            compensation.register(`toggle-back-${input.targetId}`, async () => {
                await shared_1.favoriteService.toggleFavorite(input.userId, input.targetId, input.type, 'system', null);
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.FAVORITE_TOGGLED, ctx, {
                userId: input.userId,
                targetId: input.targetId,
                type: input.type,
                added: res.added,
            });
            compensation.clear();
            return res;
        });
    }
    async isFavorite(userId, targetId, type, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Checking if target ${targetId} is favorited by user ${userId}`);
        this.validateUuid(userId, 'userId', ctx);
        this.validateUuid(targetId, 'targetId', ctx);
        return shared_1.favoriteService.isFavorited(userId, targetId, type);
    }
    async getFavoritesForUser(userId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching favorites for user ${userId}`);
        this.validateUuid(userId, 'userId', ctx);
        return shared_1.favoriteService.findByUser(userId);
    }
}
exports.FavoriteOrchestrator = FavoriteOrchestrator;
exports.favoriteOrchestrator = new FavoriteOrchestrator();
