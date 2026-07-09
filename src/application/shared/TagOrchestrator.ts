/**
 * TagOrchestrator.ts
 * =====================================
 * Orchestrates creating, deleting, assigning and removing tags from system objects.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { tagService } from '../../services/shared';
import { Tag, TagAssignment, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface CreateTagInput {
  projectId: string;
  name: string;
  color?: string;
  description?: string;
  actor: string;
}

export interface DeleteTagInput {
  tagId: string;
  actor: string;
}

export interface AssignTagInput {
  tagId: string;
  targetId: string;
  targetType: string;
  investigationId?: string;
  actor: string;
}

export interface RemoveTagInput {
  tagId: string;
  targetId: string;
  targetType: string;
  actor: string;
}

export class TagOrchestrator extends BaseApplicationService {
  constructor() {
    super('TagOrchestrator');
  }

  async createTag(input: CreateTagInput, parentCtx?: OperationContext): Promise<Tag> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
    });
    this.logInfo(ctx, `Creating tag "${input.name}" on project ${input.projectId}`);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateRequired(input, ['name'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const tag = await tagService.createTag({
        projectId: input.projectId,
        name: input.name,
        color: input.color,
        description: input.description,
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      compensation.register(`delete-tag-${tag.id}`, async () => {
        try {
          await prisma.tag.delete({ where: { id: tag.id } });
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.TAG_CREATED, ctx, {
        tagId: tag.id,
        projectId: input.projectId,
        name: input.name,
      });

      compensation.clear();
      return tag;
    });
  }

  async deleteTag(input: DeleteTagInput, parentCtx?: OperationContext): Promise<Tag> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Deleting tag ${input.tagId}`);
    this.validateRequired(input, ['tagId'], ctx);
    this.validateUuid(input.tagId, 'tagId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.tag.findUnique({
        where: { id: input.tagId },
      });
      if (!existing || existing.deletedAt) {
        throw new Error(`Tag "${input.tagId}" not found.`);
      }

      const deleted = await tagService.deleteTag(input.tagId, input.actor, null);

      compensation.register(`restore-tag-${input.tagId}`, async () => {
        await prisma.tag.update({
          where: { id: input.tagId },
          data: {
            deletedAt: null,
            updatedBy: 'system',
            version: { increment: 1 },
          },
        });
      });

      await this.publishEvent(APP_EVENTS.TAG_REMOVED, ctx, {
        tagId: input.tagId,
        projectId: deleted.projectId,
        name: deleted.name,
      });

      compensation.clear();
      return deleted;
    });
  }

  async assignTag(input: AssignTagInput, parentCtx?: OperationContext): Promise<TagAssignment> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Assigning tag ${input.tagId} to ${input.targetType} ${input.targetId}`);
    this.validateRequired(input, ['tagId', 'targetId', 'targetType'], ctx);
    this.validateUuid(input.tagId, 'tagId', ctx);
    this.validateUuid(input.targetId, 'targetId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const assignment = await tagService.assignTag(
        input.tagId,
        input.targetId,
        input.targetType,
        input.actor,
        input.investigationId,
        null
      );

      compensation.register(`unassign-tag-${assignment.id}`, async () => {
        try {
          await tagService.unassignTag(input.tagId, input.targetId, input.targetType, 'system');
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.TAG_ASSIGNED, ctx, {
        assignmentId: assignment.id,
        tagId: input.tagId,
        targetId: input.targetId,
        targetType: input.targetType,
      });

      compensation.clear();
      return assignment;
    });
  }

  async removeTag(input: RemoveTagInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Unassigning tag ${input.tagId} from ${input.targetType} ${input.targetId}`);
    this.validateRequired(input, ['tagId', 'targetId', 'targetType'], ctx);
    this.validateUuid(input.tagId, 'tagId', ctx);
    this.validateUuid(input.targetId, 'targetId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.tagAssignment.findFirst({
        where: {
          tagId: input.tagId,
          targetId: input.targetId,
          targetType: input.targetType,
          deletedAt: null,
        },
      });
      if (!existing) {
        throw new Error(`TagAssignment for tag "${input.tagId}" → target "${input.targetId}" not found.`);
      }

      await tagService.unassignTag(input.tagId, input.targetId, input.targetType, input.actor, null);

      compensation.register(`restore-assignment-${existing.id}`, async () => {
        await prisma.tagAssignment.update({
          where: { id: existing.id },
          data: {
            deletedAt: null,
            updatedBy: 'system',
            version: { increment: 1 },
          },
        });
      });

      await this.publishEvent(APP_EVENTS.TAG_REMOVED, ctx, {
        tagId: input.tagId,
        targetId: input.targetId,
        targetType: input.targetType,
      });

      compensation.clear();
    });
  }

  async removeTagAssignment(input: RemoveTagInput, parentCtx?: OperationContext): Promise<void> {
    return this.removeTag(input, parentCtx);
  }

  async getTagsForObject(
    targetId: string,
    targetType: string,
    actor: string,
    parentCtx?: OperationContext
  ): Promise<Tag[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching tags for ${targetType} ${targetId}`);
    this.validateUuid(targetId, 'targetId', ctx);
    if (!targetType || !targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }

    return tagService.getTagsForTarget(targetId, targetType);
  }
}

export const tagOrchestrator = new TagOrchestrator();
