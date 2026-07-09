"use strict";
/**
 * TagOrchestrator.ts
 * =====================================
 * Orchestrates creating, deleting, assigning and removing tags from system objects.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.tagOrchestrator = exports.TagOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class TagOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('TagOrchestrator');
    }
    async createTag(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
        });
        this.logInfo(ctx, `Creating tag "${input.name}" on project ${input.projectId}`);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateRequired(input, ['name'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const tag = await shared_1.tagService.createTag({
                projectId: input.projectId,
                name: input.name,
                color: input.color,
                description: input.description,
                createdBy: input.actor,
                updatedBy: input.actor,
            }, null);
            compensation.register(`delete-tag-${tag.id}`, async () => {
                try {
                    await prisma_1.default.tag.delete({ where: { id: tag.id } });
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.TAG_CREATED, ctx, {
                tagId: tag.id,
                projectId: input.projectId,
                name: input.name,
            });
            compensation.clear();
            return tag;
        });
    }
    async deleteTag(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Deleting tag ${input.tagId}`);
        this.validateRequired(input, ['tagId'], ctx);
        this.validateUuid(input.tagId, 'tagId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.tag.findUnique({
                where: { id: input.tagId },
            });
            if (!existing || existing.deletedAt) {
                throw new Error(`Tag "${input.tagId}" not found.`);
            }
            const deleted = await shared_1.tagService.deleteTag(input.tagId, input.actor, null);
            compensation.register(`restore-tag-${input.tagId}`, async () => {
                await prisma_1.default.tag.update({
                    where: { id: input.tagId },
                    data: {
                        deletedAt: null,
                        updatedBy: 'system',
                        version: { increment: 1 },
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.TAG_REMOVED, ctx, {
                tagId: input.tagId,
                projectId: deleted.projectId,
                name: deleted.name,
            });
            compensation.clear();
            return deleted;
        });
    }
    async assignTag(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Assigning tag ${input.tagId} to ${input.targetType} ${input.targetId}`);
        this.validateRequired(input, ['tagId', 'targetId', 'targetType'], ctx);
        this.validateUuid(input.tagId, 'tagId', ctx);
        this.validateUuid(input.targetId, 'targetId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const assignment = await shared_1.tagService.assignTag(input.tagId, input.targetId, input.targetType, input.actor, input.investigationId, null);
            compensation.register(`unassign-tag-${assignment.id}`, async () => {
                try {
                    await shared_1.tagService.unassignTag(input.tagId, input.targetId, input.targetType, 'system');
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.TAG_ASSIGNED, ctx, {
                assignmentId: assignment.id,
                tagId: input.tagId,
                targetId: input.targetId,
                targetType: input.targetType,
            });
            compensation.clear();
            return assignment;
        });
    }
    async removeTag(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Unassigning tag ${input.tagId} from ${input.targetType} ${input.targetId}`);
        this.validateRequired(input, ['tagId', 'targetId', 'targetType'], ctx);
        this.validateUuid(input.tagId, 'tagId', ctx);
        this.validateUuid(input.targetId, 'targetId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.tagAssignment.findFirst({
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
            await shared_1.tagService.unassignTag(input.tagId, input.targetId, input.targetType, input.actor, null);
            compensation.register(`restore-assignment-${existing.id}`, async () => {
                await prisma_1.default.tagAssignment.update({
                    where: { id: existing.id },
                    data: {
                        deletedAt: null,
                        updatedBy: 'system',
                        version: { increment: 1 },
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.TAG_REMOVED, ctx, {
                tagId: input.tagId,
                targetId: input.targetId,
                targetType: input.targetType,
            });
            compensation.clear();
        });
    }
    async removeTagAssignment(input, parentCtx) {
        return this.removeTag(input, parentCtx);
    }
    async getTagsForObject(targetId, targetType, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching tags for ${targetType} ${targetId}`);
        this.validateUuid(targetId, 'targetId', ctx);
        if (!targetType || !targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        return shared_1.tagService.getTagsForTarget(targetId, targetType);
    }
}
exports.TagOrchestrator = TagOrchestrator;
exports.tagOrchestrator = new TagOrchestrator();
