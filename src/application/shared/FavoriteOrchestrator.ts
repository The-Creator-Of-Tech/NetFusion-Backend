/**
 * FavoriteOrchestrator.ts
 * =====================================
 * Orchestrates creating, deleting, and toggling favorite items.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { favoriteService } from '../../services/shared';
import { Favorite, FavoriteType, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface AddFavoriteInput {
  userId: string;
  targetId: string;
  type: FavoriteType;
  actor: string;
}

export interface RemoveFavoriteInput {
  userId: string;
  targetId: string;
  type: FavoriteType;
  actor: string;
}

export interface ToggleFavoriteInput {
  userId: string;
  targetId: string;
  type: FavoriteType;
  actor: string;
}

export class FavoriteOrchestrator extends BaseApplicationService {
  constructor() {
    super('FavoriteOrchestrator');
  }

  async addFavorite(input: AddFavoriteInput, parentCtx?: OperationContext): Promise<Favorite> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Adding favorite for user ${input.userId} target ${input.targetId}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateUuid(input.targetId, 'targetId', ctx);
    this.validateRequired(input, ['type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.favorite.findFirst({
        where: {
          userId: input.userId,
          targetId: input.targetId,
          type: input.type,
        },
      });

      const favorite = await favoriteService.addFavorite({
        userId: input.userId,
        targetId: input.targetId,
        type: input.type,
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      if (existing) {
        compensation.register(`restore-favorite-${favorite.id}`, async () => {
          await prisma.favorite.update({
            where: { id: existing.id },
            data: {
              deletedAt: existing.deletedAt,
              updatedBy: 'system',
              version: { increment: 1 },
            },
          });
        });
      } else {
        compensation.register(`delete-favorite-${favorite.id}`, async () => {
          try {
            await prisma.favorite.delete({ where: { id: favorite.id } });
          } catch (_) {}
        });
      }

      await this.publishEvent(APP_EVENTS.FAVORITE_ADDED, ctx, {
        favoriteId: favorite.id,
        userId: input.userId,
        targetId: input.targetId,
        type: input.type,
      });

      compensation.clear();
      return favorite;
    });
  }

  async removeFavorite(input: RemoveFavoriteInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Removing favorite for user ${input.userId} target ${input.targetId}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateUuid(input.targetId, 'targetId', ctx);
    this.validateRequired(input, ['type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.favorite.findFirst({
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

      await favoriteService.removeFavorite(input.userId, input.targetId, input.type, input.actor, null);

      compensation.register(`restore-favorite-${existing.id}`, async () => {
        await prisma.favorite.update({
          where: { id: existing.id },
          data: {
            deletedAt: null,
            updatedBy: 'system',
            version: { increment: 1 },
          },
        });
      });

      await this.publishEvent(APP_EVENTS.FAVORITE_REMOVED, ctx, {
        userId: input.userId,
        targetId: input.targetId,
        type: input.type,
      });

      compensation.clear();
    });
  }

  async toggleFavorite(input: ToggleFavoriteInput, parentCtx?: OperationContext): Promise<{ added: boolean; favorite?: Favorite }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Toggling favorite for user ${input.userId} target ${input.targetId}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateUuid(input.targetId, 'targetId', ctx);
    this.validateRequired(input, ['type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const isFav = await favoriteService.isFavorited(input.userId, input.targetId, input.type);

      const res = await favoriteService.toggleFavorite(input.userId, input.targetId, input.type, input.actor, null);

      compensation.register(`toggle-back-${input.targetId}`, async () => {
        await favoriteService.toggleFavorite(input.userId, input.targetId, input.type, 'system', null);
      });

      await this.publishEvent(APP_EVENTS.FAVORITE_TOGGLED, ctx, {
        userId: input.userId,
        targetId: input.targetId,
        type: input.type,
        added: res.added,
      });

      compensation.clear();
      return res;
    });
  }

  async isFavorite(userId: string, targetId: string, type: FavoriteType, actor: string, parentCtx?: OperationContext): Promise<boolean> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Checking if target ${targetId} is favorited by user ${userId}`);
    this.validateUuid(userId, 'userId', ctx);
    this.validateUuid(targetId, 'targetId', ctx);
    return favoriteService.isFavorited(userId, targetId, type);
  }

  async getFavoritesForUser(userId: string, actor: string, parentCtx?: OperationContext): Promise<Favorite[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching favorites for user ${userId}`);
    this.validateUuid(userId, 'userId', ctx);
    return favoriteService.findByUser(userId);
  }
}

export const favoriteOrchestrator = new FavoriteOrchestrator();
