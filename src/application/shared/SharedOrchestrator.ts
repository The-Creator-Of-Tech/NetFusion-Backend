/**
 * SharedOrchestrator.ts
 * =====================================
 * Master orchestrator for global platform workflows.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import {
  notificationService,
  settingService,
  activityService,
  attachmentService,
  commentService,
  tagService,
  favoriteService,
  apiKeyService,
} from '../../services/shared';
import { userService, projectService } from '../../services/core';
import { User, Project, Notification, NotificationType, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class SharedOrchestrator extends BaseApplicationService {
  constructor() {
    super('SharedOrchestrator');
  }

  async initializeUser(
    input: { email: string; username: string; passwordHash: string; displayName?: string; actor: string },
    parentCtx?: OperationContext
  ): Promise<{ user: User; apiKey: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Initializing new user: ${input.username}`);
    this.validateRequired(input, ['email', 'username', 'passwordHash'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const result = await userService.createUser({
        email: input.email,
        username: input.username,
        passwordHash: input.passwordHash,
        displayName: input.displayName ?? input.username,
      }, null);

      compensation.register(`delete-user-${result.user.id}`, async () => {
        try {
          await prisma.userPreference.deleteMany({ where: { userId: result.user.id } });
          await prisma.apiKey.deleteMany({ where: { userId: result.user.id } });
          await prisma.notification.deleteMany({ where: { userId: result.user.id } });
          await prisma.user.delete({ where: { id: result.user.id } });
        } catch (_) {}
      });

      this.logInfo(ctx, `User ${result.user.username} initialized successfully.`);
      compensation.clear();
      return result;
    });
  }

  async initializeProject(
    input: { ownerId: string; name: string; description?: string; actor: string },
    parentCtx?: OperationContext
  ): Promise<Project> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Initializing new project: ${input.name}`);
    this.validateUuid(input.ownerId, 'ownerId', ctx);
    this.validateRequired(input, ['name'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const project = await projectService.createProject({
        ownerId: input.ownerId,
        name: input.name,
        description: input.description,
      }, null);

      compensation.register(`delete-project-${project.id}`, async () => {
        try {
          await prisma.auditLog.deleteMany({ where: { projectId: project.id } });
          await prisma.project.delete({ where: { id: project.id } });
        } catch (_) {}
      });

      compensation.clear();
      return project;
    });
  }

  async cleanupProject(input: { projectId: string; actor: string }, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Cleaning up project ${input.projectId}`);
    this.validateUuid(input.projectId, 'projectId', ctx);

    return this.withCompensation(ctx, async () => {
      await prisma.attachment.deleteMany({
        where: { projectId: input.projectId, NOT: { deletedAt: null } },
      });
      await prisma.comment.deleteMany({
        where: { projectId: input.projectId, NOT: { deletedAt: null } },
      });
      await prisma.tag.deleteMany({
        where: { projectId: input.projectId, NOT: { deletedAt: null } },
      });
      await prisma.favorite.deleteMany({
        where: { targetId: input.projectId, type: 'PROJECT', NOT: { deletedAt: null } },
      });
    });
  }

  async archiveProject(input: { projectId: string; actor: string }, parentCtx?: OperationContext): Promise<Project> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Archiving project ${input.projectId}`);
    this.validateUuid(input.projectId, 'projectId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const project = await prisma.project.findUnique({
        where: { id: input.projectId },
      });
      if (!project || project.deletedAt) {
        throw new Error(`Project with ID "${input.projectId}" not found.`);
      }

      const archived = await projectService.archiveProject(input.projectId, null);

      compensation.register(`restore-project-status-${project.id}`, async () => {
        await prisma.project.update({
          where: { id: project.id },
          data: { status: project.status },
        });
      });

      await this.publishEvent(APP_EVENTS.INVESTIGATION_ARCHIVED, ctx, {
        projectId: input.projectId,
      });

      compensation.clear();
      return archived;
    });
  }

  async broadcastNotification(
    input: { userIds: string[]; title: string; message: string; type: NotificationType; actor: string; projectId?: string; investigationId?: string },
    parentCtx?: OperationContext
  ): Promise<Notification[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Broadcasting notification to ${input.userIds.length} users`);
    this.validateRequired(input, ['userIds', 'title', 'message', 'type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const results: Notification[] = [];
      for (const userId of input.userIds) {
        this.validateUuid(userId, 'userId', ctx);
        const notif = await notificationService.createNotification({
          userId,
          title: input.title,
          message: input.message,
          type: input.type,
          createdBy: input.actor,
          updatedBy: input.actor,
        }, null);
        results.push(notif);

        compensation.register(`delete-notification-${notif.id}`, async () => {
          await notificationService.deleteNotification(notif.id, 'system');
        });
      }

      await this.publishEvent(APP_EVENTS.NOTIFICATION_BROADCAST, ctx, {
        userIds: input.userIds,
        count: results.length,
        type: input.type,
      });

      compensation.clear();
      return results;
    });
  }

  async synchronizeMetadata(input: { projectId: string; actor: string }, parentCtx?: OperationContext): Promise<Project> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Synchronizing metadata for project ${input.projectId}`);
    this.validateUuid(input.projectId, 'projectId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const project = await prisma.project.findUnique({ where: { id: input.projectId } });
      if (!project || project.deletedAt) {
        throw new Error(`Project with ID "${input.projectId}" not found.`);
      }

      const stats = await projectService.calculateProjectStatistics(input.projectId);
      const updatedMetadata = {
        ...(project.metadata as any || {}),
        synchronizedAt: new Date().toISOString(),
        investigationStats: stats,
      };

      const updated = await projectService.updateProject(input.projectId, {
        metadata: updatedMetadata,
      });

      compensation.register(`restore-metadata-${project.id}`, async () => {
        await projectService.updateProject(project.id, {
          metadata: project.metadata as any || {},
        });
      });

      compensation.clear();
      return updated;
    });
  }

  async rebuildSearchIndex(input: { actor: string }, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Rebuilding search index`);

    await settingService.upsert({
      key: 'platform:search_index_rebuilt_at',
      value: new Date().toISOString(),
      scope: 'GLOBAL',
      createdBy: input.actor,
      updatedBy: input.actor,
    });
  }

  async generatePlatformStatistics(input: { actor: string }, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Generating global platform statistics`);

    const projectCount = await prisma.project.count({ where: { deletedAt: null } });
    const userCount = await prisma.user.count({ where: { deletedAt: null } });
    const notificationStats = await notificationService.getStatistics();
    const commentStats = await commentService.getStatistics();
    const tagStats = await tagService.getStatistics();
    const favoriteStats = await favoriteService.getStatistics();
    const apiKeyStats = await apiKeyService.getStatistics();

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

  async performMaintenance(input: { actor: string }, parentCtx?: OperationContext): Promise<{ softDeletesCleaned: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Performing global platform maintenance`);

    const softDeletesCleaned = await this.cleanupSoftDeletes(input, ctx);
    await this.rebuildSearchIndex(input, ctx);

    return { softDeletesCleaned };
  }

  async cleanupSoftDeletes(input: { actor: string }, parentCtx?: OperationContext): Promise<number> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Executing cleanup of soft deletes`);

    let count = 0;

    const notifs = await prisma.notification.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += notifs.count;

    const attachments = await prisma.attachment.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += attachments.count;

    const comments = await prisma.comment.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += comments.count;

    const tags = await prisma.tag.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += tags.count;

    const tagAssignments = await prisma.tagAssignment.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += tagAssignments.count;

    const favorites = await prisma.favorite.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += favorites.count;

    const apiKeys = await prisma.apiKey.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += apiKeys.count;

    const users = await prisma.user.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += users.count;

    const projects = await prisma.project.deleteMany({ where: { NOT: { deletedAt: null } } });
    count += projects.count;

    this.logInfo(ctx, `Deleted ${count} soft-deleted records.`);
    return count;
  }
}

export const sharedOrchestrator = new SharedOrchestrator();
