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

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import prisma from '../../lib/prisma';
import {
  Comment,
  CommentVisibility,
  Prisma,
} from '@prisma/client';

const VALID_VISIBILITIES: string[] = ['PUBLIC', 'PRIVATE', 'TEAM'];

export class CommentService extends BaseService {

  // ── Create ──────────────────────────────────────────────────────────────────

  async createComment(
    data: Prisma.CommentUncheckedCreateInput,
    tx?: any,
  ): Promise<Comment> {
    this.validateRequired(data as any, ['userId', 'projectId', 'content', 'createdBy', 'updatedBy']);

    if (!String(data.content).trim()) {
      throw new Error('Validation failed: content must not be empty.');
    }
    if (data.visibility !== undefined && !VALID_VISIBILITIES.includes(String(data.visibility).toUpperCase())) {
      throw new Error(`Validation failed: visibility "${data.visibility}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const comment = await client.comment.create({ data });
      await eventPublisher.publish('CommentCreated', { comment });
      return comment;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  async updateComment(
    id: string,
    data: Prisma.CommentUncheckedUpdateInput,
    tx?: any,
  ): Promise<Comment> {
    this.validateUuid(id, 'commentId');

    if (data.content !== undefined && !String(data.content).trim()) {
      throw new Error('Validation failed: content must not be empty.');
    }
    if (data.visibility !== undefined && !VALID_VISIBILITIES.includes(String(data.visibility).toUpperCase())) {
      throw new Error(`Validation failed: visibility "${data.visibility}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.comment.findUnique({ where: { id } });
      if (!existing || existing.deletedAt) {
        throw new Error(`Comment "${id}" not found.`);
      }
      const updated = await client.comment.update({ where: { id }, data });
      await eventPublisher.publish('CommentUpdated', { comment: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  async deleteComment(id: string, actor: string, tx?: any): Promise<Comment> {
    this.validateUuid(id, 'commentId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
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
      await eventPublisher.publish('CommentDeleted', { comment: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Visibility ──────────────────────────────────────────────────────────────

  async setVisibility(id: string, visibility: CommentVisibility, actor: string, tx?: any): Promise<Comment> {
    this.validateUuid(id, 'commentId');
    if (!VALID_VISIBILITIES.includes(String(visibility).toUpperCase())) {
      throw new Error(`Validation failed: visibility "${visibility}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.comment.findUnique({ where: { id } });
      if (!existing || existing.deletedAt) {
        throw new Error(`Comment "${id}" not found.`);
      }
      const updated = await client.comment.update({
        where: { id },
        data: { visibility, updatedBy: actor },
      });
      await eventPublisher.publish('CommentVisibilityChanged', { comment: updated, visibility });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByUser(userId: string, tx?: any): Promise<Comment[]> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.comment.findMany({
      where: { userId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByProject(projectId: string, tx?: any): Promise<Comment[]> {
    this.validateUuid(projectId, 'projectId');
    const client = tx || prisma;
    return client.comment.findMany({
      where: { projectId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByInvestigation(investigationId: string, tx?: any): Promise<Comment[]> {
    this.validateUuid(investigationId, 'investigationId');
    const client = tx || prisma;
    return client.comment.findMany({
      where: { investigationId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByTarget(targetId: string, targetType: string, tx?: any): Promise<Comment[]> {
    this.validateUuid(targetId, 'targetId');
    if (!targetType || !targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }
    const client = tx || prisma;
    return client.comment.findMany({
      where: { targetId, targetType, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByVisibility(visibility: CommentVisibility, tx?: any): Promise<Comment[]> {
    if (!VALID_VISIBILITIES.includes(String(visibility).toUpperCase())) {
      throw new Error(`Validation failed: visibility "${visibility}" is not valid.`);
    }
    const client = tx || prisma;
    return client.comment.findMany({
      where: { visibility, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async searchByContent(query: string, tx?: any): Promise<Comment[]> {
    if (!query || !query.trim()) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    const client = tx || prisma;
    return client.comment.findMany({
      where: {
        content: { contains: query.trim(), mode: 'insensitive' },
        deletedAt: null,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalComments: number;
    publicComments: number;
    privateComments: number;
    teamComments: number;
    averageContentLength: number;
  }> {
    const client = tx || prisma;
    const all = await client.comment.findMany({ where: { deletedAt: null } });

    let pub = 0, priv = 0, team = 0, totalLen = 0;
    for (const c of all) {
      totalLen += String(c.content ?? '').length;
      if (c.visibility === 'PUBLIC') pub++;
      else if (c.visibility === 'PRIVATE') priv++;
      else if (c.visibility === 'TEAM') team++;
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

  async bulkCreate(
    items: Prisma.CommentUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { index: number; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { index: number; reason: string }[] = [];

    for (let i = 0; i < items.length; i++) {
      try {
        const c = await this.createComment({ ...items[i], createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(c.id);
      } catch (e: any) {
        failed.push({ index: i, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('CommentsBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  async bulkDelete(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteComment(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('CommentsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const commentService = new CommentService();
