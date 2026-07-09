/**
 * CommentOrchestrator.ts
 * =====================================
 * Orchestrates team collaboration and conversation tracking via comments.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { commentService } from '../../services/shared';
import { Comment, CommentVisibility, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface AddCommentInput {
  userId: string;
  projectId: string;
  investigationId?: string;
  targetId?: string;
  targetType?: string;
  content: string;
  visibility?: CommentVisibility;
  actor: string;
}

export interface UpdateCommentInput {
  commentId: string;
  content?: string;
  visibility?: CommentVisibility;
  actor: string;
}

export interface DeleteCommentInput {
  commentId: string;
  actor: string;
}

export class CommentOrchestrator extends BaseApplicationService {
  constructor() {
    super('CommentOrchestrator');
  }

  async addComment(input: AddCommentInput, parentCtx?: OperationContext): Promise<Comment> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Adding comment for user ${input.userId} on project ${input.projectId}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateRequired(input, ['content'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const comment = await commentService.createComment({
        userId: input.userId,
        projectId: input.projectId,
        investigationId: input.investigationId,
        targetId: input.targetId,
        targetType: input.targetType,
        content: input.content,
        visibility: input.visibility ?? 'PUBLIC',
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      compensation.register(`delete-comment-${comment.id}`, async () => {
        try {
          await prisma.comment.delete({ where: { id: comment.id } });
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.COMMENT_CREATED, ctx, {
        commentId: comment.id,
        projectId: input.projectId,
        userId: input.userId,
      });

      compensation.clear();
      return comment;
    });
  }

  async updateComment(input: UpdateCommentInput, parentCtx?: OperationContext): Promise<Comment> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Updating comment ${input.commentId}`);
    this.validateRequired(input, ['commentId'], ctx);
    this.validateUuid(input.commentId, 'commentId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.comment.findUnique({
        where: { id: input.commentId },
      });
      if (!existing || existing.deletedAt) {
        throw new Error(`Comment "${input.commentId}" not found.`);
      }

      const updated = await commentService.updateComment(
        input.commentId,
        {
          content: input.content,
          visibility: input.visibility,
          updatedBy: input.actor,
        },
        null
      );

      compensation.register(`restore-comment-${input.commentId}`, async () => {
        await prisma.comment.update({
          where: { id: input.commentId },
          data: {
            content: existing.content,
            visibility: existing.visibility,
            updatedBy: 'system',
          },
        });
      });

      await this.publishEvent(APP_EVENTS.COMMENT_UPDATED, ctx, {
        commentId: input.commentId,
        projectId: updated.projectId,
      });

      compensation.clear();
      return updated;
    });
  }

  async deleteComment(input: DeleteCommentInput, parentCtx?: OperationContext): Promise<Comment> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Deleting comment ${input.commentId}`);
    this.validateRequired(input, ['commentId'], ctx);
    this.validateUuid(input.commentId, 'commentId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.comment.findUnique({
        where: { id: input.commentId },
      });
      if (!existing || existing.deletedAt) {
        throw new Error(`Comment "${input.commentId}" not found.`);
      }

      const deleted = await commentService.deleteComment(input.commentId, input.actor, null);

      compensation.register(`restore-comment-${input.commentId}`, async () => {
        await prisma.comment.update({
          where: { id: input.commentId },
          data: {
            deletedAt: null,
            updatedBy: 'system',
            version: { increment: 1 },
          },
        });
      });

      await this.publishEvent(APP_EVENTS.COMMENT_DELETED, ctx, {
        commentId: input.commentId,
        projectId: deleted.projectId,
      });

      compensation.clear();
      return deleted;
    });
  }

  async getCommentsForObject(
    query: { projectId?: string; investigationId?: string; targetId?: string; targetType?: string },
    actor: string,
    parentCtx?: OperationContext
  ): Promise<Comment[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching comments with query: ${JSON.stringify(query)}`);

    if (query.projectId) {
      this.validateUuid(query.projectId, 'projectId', ctx);
      return commentService.findByProject(query.projectId);
    }
    if (query.investigationId) {
      this.validateUuid(query.investigationId, 'investigationId', ctx);
      return commentService.findByInvestigation(query.investigationId);
    }
    if (query.targetId && query.targetType) {
      this.validateUuid(query.targetId, 'targetId', ctx);
      return commentService.findByTarget(query.targetId, query.targetType);
    }

    throw new Error('Validation failed: either projectId, investigationId, or (targetId and targetType) must be provided.');
  }
}

export const commentOrchestrator = new CommentOrchestrator();
