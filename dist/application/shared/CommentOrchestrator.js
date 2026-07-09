"use strict";
/**
 * CommentOrchestrator.ts
 * =====================================
 * Orchestrates team collaboration and conversation tracking via comments.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.commentOrchestrator = exports.CommentOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class CommentOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('CommentOrchestrator');
    }
    async addComment(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Adding comment for user ${input.userId} on project ${input.projectId}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateRequired(input, ['content'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const comment = await shared_1.commentService.createComment({
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
                    await prisma_1.default.comment.delete({ where: { id: comment.id } });
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.COMMENT_CREATED, ctx, {
                commentId: comment.id,
                projectId: input.projectId,
                userId: input.userId,
            });
            compensation.clear();
            return comment;
        });
    }
    async updateComment(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Updating comment ${input.commentId}`);
        this.validateRequired(input, ['commentId'], ctx);
        this.validateUuid(input.commentId, 'commentId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.comment.findUnique({
                where: { id: input.commentId },
            });
            if (!existing || existing.deletedAt) {
                throw new Error(`Comment "${input.commentId}" not found.`);
            }
            const updated = await shared_1.commentService.updateComment(input.commentId, {
                content: input.content,
                visibility: input.visibility,
                updatedBy: input.actor,
            }, null);
            compensation.register(`restore-comment-${input.commentId}`, async () => {
                await prisma_1.default.comment.update({
                    where: { id: input.commentId },
                    data: {
                        content: existing.content,
                        visibility: existing.visibility,
                        updatedBy: 'system',
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.COMMENT_UPDATED, ctx, {
                commentId: input.commentId,
                projectId: updated.projectId,
            });
            compensation.clear();
            return updated;
        });
    }
    async deleteComment(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Deleting comment ${input.commentId}`);
        this.validateRequired(input, ['commentId'], ctx);
        this.validateUuid(input.commentId, 'commentId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.comment.findUnique({
                where: { id: input.commentId },
            });
            if (!existing || existing.deletedAt) {
                throw new Error(`Comment "${input.commentId}" not found.`);
            }
            const deleted = await shared_1.commentService.deleteComment(input.commentId, input.actor, null);
            compensation.register(`restore-comment-${input.commentId}`, async () => {
                await prisma_1.default.comment.update({
                    where: { id: input.commentId },
                    data: {
                        deletedAt: null,
                        updatedBy: 'system',
                        version: { increment: 1 },
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.COMMENT_DELETED, ctx, {
                commentId: input.commentId,
                projectId: deleted.projectId,
            });
            compensation.clear();
            return deleted;
        });
    }
    async getCommentsForObject(query, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching comments with query: ${JSON.stringify(query)}`);
        if (query.projectId) {
            this.validateUuid(query.projectId, 'projectId', ctx);
            return shared_1.commentService.findByProject(query.projectId);
        }
        if (query.investigationId) {
            this.validateUuid(query.investigationId, 'investigationId', ctx);
            return shared_1.commentService.findByInvestigation(query.investigationId);
        }
        if (query.targetId && query.targetType) {
            this.validateUuid(query.targetId, 'targetId', ctx);
            return shared_1.commentService.findByTarget(query.targetId, query.targetType);
        }
        throw new Error('Validation failed: either projectId, investigationId, or (targetId and targetType) must be provided.');
    }
}
exports.CommentOrchestrator = CommentOrchestrator;
exports.commentOrchestrator = new CommentOrchestrator();
