/**
 * NotificationOrchestrator.ts
 * =====================================
 * Orchestrates notification workflows across the platform.
 * Delegates to NotificationService.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { notificationService } from '../../services/shared';
import { Notification, NotificationType, NotificationStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface SendNotificationInput {
  userId: string;
  title: string;
  message: string;
  type: NotificationType;
  actor: string;
  projectId?: string;
  investigationId?: string;
}

export interface BroadcastNotificationInput {
  userIds: string[];
  title: string;
  message: string;
  type: NotificationType;
  actor: string;
  projectId?: string;
  investigationId?: string;
}

export interface ScheduleNotificationInput {
  userId: string;
  title: string;
  message: string;
  type: NotificationType;
  actor: string;
  scheduledAt: Date;
  projectId?: string;
  investigationId?: string;
}

export interface CancelNotificationInput {
  notificationId: string;
  actor: string;
}

export interface MarkReadInput {
  notificationId: string;
  actor: string;
}

export interface MarkAllReadInput {
  userId: string;
  actor: string;
}

export class NotificationOrchestrator extends BaseApplicationService {
  constructor() {
    super('NotificationOrchestrator');
  }

  async sendNotification(input: SendNotificationInput, parentCtx?: OperationContext): Promise<Notification> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Sending notification to user ${input.userId}: ${input.title}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateRequired(input, ['title', 'message', 'type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const notif = await notificationService.createNotification({
        userId: input.userId,
        title: input.title,
        message: input.message,
        type: input.type,
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      compensation.register(`delete-notification-${notif.id}`, async () => {
        try {
          await prisma.notification.delete({ where: { id: notif.id } });
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.NOTIFICATION_SENT, ctx, {
        notificationId: notif.id,
        userId: input.userId,
        type: input.type,
      });

      this.logTiming(ctx, 'sendNotification');
      compensation.clear();
      return notif;
    });
  }

  async broadcastNotification(input: BroadcastNotificationInput, parentCtx?: OperationContext): Promise<Notification[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Broadcasting notification to ${input.userIds.length} users: ${input.title}`);
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
          try {
            await prisma.notification.delete({ where: { id: notif.id } });
          } catch (_) {}
        });
      }

      await this.publishEvent(APP_EVENTS.NOTIFICATION_BROADCAST, ctx, {
        userIds: input.userIds,
        count: results.length,
        type: input.type,
      });

      this.logTiming(ctx, 'broadcastNotification');
      compensation.clear();
      return results;
    });
  }

  async scheduleNotification(input: ScheduleNotificationInput, parentCtx?: OperationContext): Promise<{ notificationId: string; scheduledAt: Date }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Scheduling notification for user ${input.userId} at ${input.scheduledAt}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateRequired(input, ['title', 'message', 'type', 'scheduledAt'], ctx);

    if (input.scheduledAt.getTime() <= Date.now()) {
      throw new Error('Validation failed: scheduledAt must be in the future.');
    }

    const notificationId = `notif-sch-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    await this.publishEvent(APP_EVENTS.NOTIFICATION_SENT, ctx, {
      notificationId,
      userId: input.userId,
      type: input.type,
      scheduledAt: input.scheduledAt,
    });

    return { notificationId, scheduledAt: input.scheduledAt };
  }

  async cancelNotification(input: CancelNotificationInput, parentCtx?: OperationContext): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Cancelling notification: ${input.notificationId}`);
    this.validateRequired(input, ['notificationId'], ctx);

    if (input.notificationId.startsWith('notif-sch-')) {
      await this.publishEvent(APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
        notificationId: input.notificationId,
        cancelled: true,
      });
      return;
    }

    this.validateUuid(input.notificationId, 'notificationId', ctx);
    await notificationService.deleteNotification(input.notificationId, input.actor);
  }

  async markAsRead(input: MarkReadInput, parentCtx?: OperationContext): Promise<Notification> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Marking notification ${input.notificationId} as read`);
    this.validateRequired(input, ['notificationId'], ctx);
    this.validateUuid(input.notificationId, 'notificationId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const notif = await notificationService.markRead(input.notificationId, input.actor, null);

      compensation.register(`mark-unread-${notif.id}`, async () => {
        await notificationService.markUnread(notif.id, 'system');
      });

      await this.publishEvent(APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
        notificationId: notif.id,
        userId: notif.userId,
        status: 'READ' as NotificationStatus,
      });

      compensation.clear();
      return notif;
    });
  }

  async markAllAsRead(input: MarkAllReadInput, parentCtx?: OperationContext): Promise<number> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Marking all notifications for user ${input.userId} as read`);
    this.validateRequired(input, ['userId'], ctx);
    this.validateUuid(input.userId, 'userId', ctx);

    const count = await notificationService.markAllRead(input.userId, input.actor);

    await this.publishEvent(APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
      userId: input.userId,
      count,
      status: 'READ' as NotificationStatus,
    });

    return count;
  }

  async archiveNotification(input: MarkReadInput, parentCtx?: OperationContext): Promise<Notification> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Archiving notification ${input.notificationId}`);
    this.validateRequired(input, ['notificationId'], ctx);
    this.validateUuid(input.notificationId, 'notificationId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const notif = await notificationService.archiveNotification(input.notificationId, input.actor, null);

      compensation.register(`restore-unread-${notif.id}`, async () => {
        await notificationService.markUnread(notif.id, 'system');
      });

      await this.publishEvent(APP_EVENTS.NOTIFICATION_MARKED_READ, ctx, {
        notificationId: notif.id,
        userId: notif.userId,
        status: 'ARCHIVED' as NotificationStatus,
      });

      compensation.clear();
      return notif;
    });
  }

  async archiveNotif(input: MarkReadInput, parentCtx?: OperationContext): Promise<Notification> {
    return this.archiveNotification(input, parentCtx);
  }
}

export const notificationOrchestrator = new NotificationOrchestrator();
