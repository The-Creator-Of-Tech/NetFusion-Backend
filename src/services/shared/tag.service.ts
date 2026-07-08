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

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import prisma from '../../lib/prisma';
import { Tag, TagAssignment, Prisma } from '@prisma/client';

export class TagService extends BaseService {

  // ── Create Tag ──────────────────────────────────────────────────────────────

  async createTag(
    data: Prisma.TagUncheckedCreateInput,
    tx?: any,
  ): Promise<Tag> {
    this.validateRequired(data as any, ['projectId', 'name', 'createdBy', 'updatedBy']);
    if (!String(data.name).trim()) {
      throw new Error('Validation failed: name must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;

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
      await eventPublisher.publish('TagCreated', { tag });
      return tag;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update Tag ──────────────────────────────────────────────────────────────

  async updateTag(
    id: string,
    data: Prisma.TagUncheckedUpdateInput,
    tx?: any,
  ): Promise<Tag> {
    this.validateUuid(id, 'tagId');

    if (data.name !== undefined && !String(data.name).trim()) {
      throw new Error('Validation failed: name must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.tag.findUnique({ where: { id } });
      if (!existing || existing.deletedAt) {
        throw new Error(`Tag "${id}" not found.`);
      }
      const updated = await client.tag.update({ where: { id }, data });
      await eventPublisher.publish('TagUpdated', { tag: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete Tag ──────────────────────────────────────────────────────────────

  async deleteTag(id: string, actor: string, tx?: any): Promise<Tag> {
    this.validateUuid(id, 'tagId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
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
      await eventPublisher.publish('TagDeleted', { tag: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Assignments ─────────────────────────────────────────────────────────────

  async assignTag(
    tagId: string,
    targetId: string,
    targetType: string,
    actor: string,
    investigationId?: string,
    tx?: any,
  ): Promise<TagAssignment> {
    this.validateUuid(tagId, 'tagId');
    this.validateUuid(targetId, 'targetId');
    if (!targetType || !targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;

      // Verify tag exists
      const tag = await client.tag.findUnique({ where: { id: tagId } });
      if (!tag || tag.deletedAt) {
        throw new Error(`Tag "${tagId}" not found.`);
      }

      // Idempotent: return existing if already assigned
      const existing = await client.tagAssignment.findFirst({
        where: { tagId, targetId, targetType, deletedAt: null },
      });
      if (existing) return existing;

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
      await eventPublisher.publish('TagAssigned', { assignment, tag });
      return assignment;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async unassignTag(
    tagId: string,
    targetId: string,
    targetType: string,
    actor: string,
    tx?: any,
  ): Promise<void> {
    this.validateUuid(tagId, 'tagId');
    this.validateUuid(targetId, 'targetId');
    if (!targetType || !targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
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
      await eventPublisher.publish('TagUnassigned', { tagId, targetId, targetType });
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async getAssignments(tagId: string, tx?: any): Promise<TagAssignment[]> {
    this.validateUuid(tagId, 'tagId');
    const client = tx || prisma;
    return client.tagAssignment.findMany({
      where: { tagId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async getTagsForTarget(targetId: string, targetType: string, tx?: any): Promise<Tag[]> {
    this.validateUuid(targetId, 'targetId');
    if (!targetType || !targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }
    const client = tx || prisma;
    const assignments = await client.tagAssignment.findMany({
      where: { targetId, targetType, deletedAt: null },
      include: { tag: true },
    });
    return assignments.map((a: any) => a.tag).filter((t: Tag) => !t.deletedAt);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByProject(projectId: string, tx?: any): Promise<Tag[]> {
    this.validateUuid(projectId, 'projectId');
    const client = tx || prisma;
    return client.tag.findMany({
      where: { projectId, deletedAt: null },
      orderBy: { name: 'asc' },
    });
  }

  async findByName(name: string, projectId: string, tx?: any): Promise<Tag | null> {
    if (!name || !name.trim()) {
      throw new Error('Validation failed: name must not be empty.');
    }
    this.validateUuid(projectId, 'projectId');
    const client = tx || prisma;
    return client.tag.findFirst({
      where: { name: name.trim(), projectId, deletedAt: null },
    });
  }

  async findByColor(color: string, tx?: any): Promise<Tag[]> {
    if (!color || !color.trim()) {
      throw new Error('Validation failed: color must not be empty.');
    }
    const client = tx || prisma;
    return client.tag.findMany({
      where: { color: color.trim(), deletedAt: null },
      orderBy: { name: 'asc' },
    });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalTags: number;
    totalAssignments: number;
    projectCounts: Record<string, number>;
  }> {
    const client = tx || prisma;
    const [tags, assignments] = await Promise.all([
      client.tag.findMany({ where: { deletedAt: null } }),
      client.tagAssignment.findMany({ where: { deletedAt: null } }),
    ]);

    const projectCounts: Record<string, number> = {};
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

  async bulkCreate(
    items: Prisma.TagUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { name: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { name: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const t = await this.createTag({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(t.id);
      } catch (e: any) {
        failed.push({ name: String(item.name ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('TagsBulkCreated', { succeeded, failed });
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
        await this.deleteTag(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('TagsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const tagService = new TagService();
