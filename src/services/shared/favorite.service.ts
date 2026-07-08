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

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import prisma from '../../lib/prisma';
import { Favorite, FavoriteType, Prisma } from '@prisma/client';

const VALID_TYPES: string[] = [
  'PROJECT', 'INVESTIGATION', 'PLAYBOOK', 'RULE', 'AUTOMATION', 'CASE_FLOW',
];

export class FavoriteService extends BaseService {

  // ── Add Favorite ────────────────────────────────────────────────────────────

  async addFavorite(
    data: Prisma.FavoriteUncheckedCreateInput,
    tx?: any,
  ): Promise<Favorite> {
    this.validateRequired(data as any, ['userId', 'targetId', 'type', 'createdBy', 'updatedBy']);
    if (!VALID_TYPES.includes(String(data.type).toUpperCase())) {
      throw new Error(`Validation failed: type "${data.type}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;

      // Idempotent: return if already favorited (and not soft-deleted)
      const existing = await client.favorite.findFirst({
        where: {
          userId: String(data.userId),
          targetId: String(data.targetId),
          type: data.type,
          deletedAt: null,
        },
      });
      if (existing) return existing;

      const favorite = await client.favorite.create({ data });
      await eventPublisher.publish('FavoriteAdded', { favorite });
      return favorite;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Remove Favorite ─────────────────────────────────────────────────────────

  async removeFavorite(
    userId: string,
    targetId: string,
    type: FavoriteType,
    actor: string,
    tx?: any,
  ): Promise<void> {
    this.validateUuid(userId, 'userId');
    this.validateUuid(targetId, 'targetId');
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
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
      await eventPublisher.publish('FavoriteRemoved', { userId, targetId, type });
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Toggle ──────────────────────────────────────────────────────────────────

  async toggleFavorite(
    userId: string,
    targetId: string,
    type: FavoriteType,
    actor: string,
    tx?: any,
  ): Promise<{ added: boolean; favorite?: Favorite }> {
    this.validateUuid(userId, 'userId');
    this.validateUuid(targetId, 'targetId');
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }

    const client = tx || prisma;
    const existing = await client.favorite.findFirst({
      where: { userId, targetId, type, deletedAt: null },
    });

    if (existing) {
      await this.removeFavorite(userId, targetId, type, actor, tx);
      return { added: false };
    } else {
      const favorite = await this.addFavorite(
        { userId, targetId, type, createdBy: actor, updatedBy: actor },
        tx,
      );
      return { added: true, favorite };
    }
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByUser(userId: string, tx?: any): Promise<Favorite[]> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.favorite.findMany({
      where: { userId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByUserAndType(userId: string, type: FavoriteType, tx?: any): Promise<Favorite[]> {
    this.validateUuid(userId, 'userId');
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }
    const client = tx || prisma;
    return client.favorite.findMany({
      where: { userId, type, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByType(type: FavoriteType, tx?: any): Promise<Favorite[]> {
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }
    const client = tx || prisma;
    return client.favorite.findMany({
      where: { type, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async isFavorited(userId: string, targetId: string, type: FavoriteType, tx?: any): Promise<boolean> {
    this.validateUuid(userId, 'userId');
    this.validateUuid(targetId, 'targetId');
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }
    const client = tx || prisma;
    const record = await client.favorite.findFirst({
      where: { userId, targetId, type, deletedAt: null },
    });
    return record !== null;
  }

  async countByUser(userId: string, tx?: any): Promise<number> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.favorite.count({ where: { userId, deletedAt: null } });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalFavorites: number;
    typeCounts: Record<string, number>;
    userCounts: Record<string, number>;
  }> {
    const client = tx || prisma;
    const all = await client.favorite.findMany({ where: { deletedAt: null } });

    const typeCounts: Record<string, number> = {};
    const userCounts: Record<string, number> = {};

    for (const f of all) {
      const t = String(f.type);
      typeCounts[t] = (typeCounts[t] ?? 0) + 1;
      userCounts[f.userId] = (userCounts[f.userId] ?? 0) + 1;
    }

    return { totalFavorites: all.length, typeCounts, userCounts };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  async bulkAdd(
    items: Prisma.FavoriteUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { index: number; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { index: number; reason: string }[] = [];

    for (let i = 0; i < items.length; i++) {
      try {
        const f = await this.addFavorite({ ...items[i], createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(f.id);
      } catch (e: any) {
        failed.push({ index: i, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('FavoritesBulkAdded', { succeeded, failed });
    return { succeeded, failed };
  }

  async bulkRemove(
    items: { userId: string; targetId: string; type: FavoriteType }[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: number; failed: { index: number; reason: string }[] }> {
    let succeeded = 0;
    const failed: { index: number; reason: string }[] = [];

    for (let i = 0; i < items.length; i++) {
      try {
        await this.removeFavorite(items[i].userId, items[i].targetId, items[i].type, actor, tx);
        succeeded++;
      } catch (e: any) {
        failed.push({ index: i, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('FavoritesBulkRemoved', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const favoriteService = new FavoriteService();
