"use strict";
/**
 * SharedOrchestrator.ts
 * =====================================
 * Master orchestrator for global platform workflows.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sharedOrchestrator = exports.SharedOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const core_1 = require("../../services/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class SharedOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('SharedOrchestrator');
    }
    async initializeUser(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Initializing new user: ${input.username}`);
        this.validateRequired(input, ['email', 'username', 'passwordHash'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const result = await core_1.userService.createUser({
                email: input.email,
                username: input.username,
                passwordHash: input.passwordHash,
                displayName: input.displayName ?? input.username,
            }, null);
            compensation.register(`delete-user-${result.user.id}`, async () => {
                try {
                    await prisma_1.default.userPreference.deleteMany({ where: { userId: result.user.id } });
                    await prisma_1.default.apiKey.deleteMany({ where: { userId: result.user.id } });
                    await prisma_1.default.notification.deleteMany({ where: { userId: result.user.id } });
                    await prisma_1.default.user.delete({ where: { id: result.user.id } });
                }
                catch (_) { }
            });
            this.logInfo(ctx, `User ${result.user.username} initialized successfully.`);
            compensation.clear();
            return result;
        });
    }
    async initializeProject(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Initializing new project: ${input.name}`);
        this.validateUuid(input.ownerId, 'ownerId', ctx);
        this.validateRequired(input, ['name'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const project = await core_1.projectService.createProject({
                ownerId: input.ownerId,
                name: input.name,
                description: input.description,
            }, null);
            compensation.register(`delete-project-${project.id}`, async () => {
                try {
                    await prisma_1.default.auditLog.deleteMany({ where: { projectId: project.id } });
                    await prisma_1.default.project.delete({ where: { id: project.id } });
                }
                catch (_) { }
            });
            compensation.clear();
            return project;
        });
    }
    async cleanupProject(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Cleaning up project ${input.projectId}`);
        this.validateUuid(input.projectId, 'projectId', ctx);
        return this.withCompensation(ctx, async () => {
            await prisma_1.default.attachment.deleteMany({
                where: { projectId: input.projectId, NOT: { deletedAt: null } },
            });
            await prisma_1.default.comment.deleteMany({
                where: { projectId: input.projectId, NOT: { deletedAt: null } },
            });
            await prisma_1.default.tag.deleteMany({
                where: { projectId: input.projectId, NOT: { deletedAt: null } },
            });
            await prisma_1.default.favorite.deleteMany({
                where: { targetId: input.projectId, type: 'PROJECT', NOT: { deletedAt: null } },
            });
        });
    }
    async archiveProject(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Archiving project ${input.projectId}`);
        this.validateUuid(input.projectId, 'projectId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const project = await prisma_1.default.project.findUnique({
                where: { id: input.projectId },
            });
            if (!project || project.deletedAt) {
                throw new Error(`Project with ID "${input.projectId}" not found.`);
            }
            const archived = await core_1.projectService.archiveProject(input.projectId, null);
            compensation.register(`restore-project-status-${project.id}`, async () => {
                await prisma_1.default.project.update({
                    where: { id: project.id },
                    data: { status: project.status },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.INVESTIGATION_ARCHIVED, ctx, {
                projectId: input.projectId,
            });
            compensation.clear();
            return archived;
        });
    }
    async broadcastNotification(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Broadcasting notification to ${input.userIds.length} users`);
        this.validateRequired(input, ['userIds', 'title', 'message', 'type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const results = [];
            for (const userId of input.userIds) {
                this.validateUuid(userId, 'userId', ctx);
                const notif = await shared_1.notificationService.createNotification({
                    userId,
                    title: input.title,
                    message: input.message,
                    type: input.type,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                }, null);
                results.push(notif);
                compensation.register(`delete-notification-${notif.id}`, async () => {
                    await shared_1.notificationService.deleteNotification(notif.id, 'system');
                });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.NOTIFICATION_BROADCAST, ctx, {
                userIds: input.userIds,
                count: results.length,
                type: input.type,
            });
            compensation.clear();
            return results;
        });
    }
    async synchronizeMetadata(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Synchronizing metadata for project ${input.projectId}`);
        this.validateUuid(input.projectId, 'projectId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const project = await prisma_1.default.project.findUnique({ where: { id: input.projectId } });
            if (!project || project.deletedAt) {
                throw new Error(`Project with ID "${input.projectId}" not found.`);
            }
            const stats = await core_1.projectService.calculateProjectStatistics(input.projectId);
            const updatedMetadata = {
                ...(project.metadata || {}),
                synchronizedAt: new Date().toISOString(),
                investigationStats: stats,
            };
            const updated = await core_1.projectService.updateProject(input.projectId, {
                metadata: updatedMetadata,
            });
            compensation.register(`restore-metadata-${project.id}`, async () => {
                await core_1.projectService.updateProject(project.id, {
                    metadata: project.metadata || {},
                });
            });
            compensation.clear();
            return updated;
        });
    }
    async rebuildSearchIndex(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Rebuilding search index`);
        await shared_1.settingService.upsert({
            key: 'platform:search_index_rebuilt_at',
            value: new Date().toISOString(),
            scope: 'GLOBAL',
            createdBy: input.actor,
            updatedBy: input.actor,
        });
    }
    async generatePlatformStatistics(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Generating global platform statistics`);
        const projectCount = await prisma_1.default.project.count({ where: { deletedAt: null } });
        const userCount = await prisma_1.default.user.count({ where: { deletedAt: null } });
        const notificationStats = await shared_1.notificationService.getStatistics();
        const commentStats = await shared_1.commentService.getStatistics();
        const tagStats = await shared_1.tagService.getStatistics();
        const favoriteStats = await shared_1.favoriteService.getStatistics();
        const apiKeyStats = await shared_1.apiKeyService.getStatistics();
        return {
            projects: projectCount,
            users: userCount,
            notifications: notificationStats,
            comments: commentStats,
            tags: tagStats,
            favorites: favoriteStats,
            apiKeys: apiKeyStats,
            generatedAt: new Date(),
        };
    }
    async performMaintenance(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Performing global platform maintenance`);
        const softDeletesCleaned = await this.cleanupSoftDeletes(input, ctx);
        await this.rebuildSearchIndex(input, ctx);
        return { softDeletesCleaned };
    }
    async cleanupSoftDeletes(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Executing cleanup of soft deletes`);
        let count = 0;
        const notifs = await prisma_1.default.notification.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += notifs.count;
        const attachments = await prisma_1.default.attachment.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += attachments.count;
        const comments = await prisma_1.default.comment.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += comments.count;
        const tags = await prisma_1.default.tag.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += tags.count;
        const tagAssignments = await prisma_1.default.tagAssignment.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += tagAssignments.count;
        const favorites = await prisma_1.default.favorite.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += favorites.count;
        const apiKeys = await prisma_1.default.apiKey.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += apiKeys.count;
        const users = await prisma_1.default.user.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += users.count;
        const projects = await prisma_1.default.project.deleteMany({ where: { NOT: { deletedAt: null } } });
        count += projects.count;
        this.logInfo(ctx, `Deleted ${count} soft-deleted records.`);
        return count;
    }
}
exports.SharedOrchestrator = SharedOrchestrator;
exports.sharedOrchestrator = new SharedOrchestrator();
