/**
 * NotificationService — Phase A5.3.7
 * =====================================
 * Business logic for Notification lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, update, delete notifications for users
 * - Mark as read / unread / archived
 * - Filter by status, type, user
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { notificationRepository } from '../../repositories/core';
import prisma from '../../lib/prisma';
import {
  Notification,
  NotificationStatus,
  NotificationType,
  Prisma,
} from '@prisma/client';

export class NotificationService extends BaseService {
  constructor(private readonly notifRepo = notificationRepository) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createNotification(
    data: Prisma.NotificationUncheckedCreateInput,
    tx?: any,
  ): Promise<Notification> {
    this.validateRequired(data as any, ['userId', 'title', 'message', 'type', 'createdBy', 'updatedBy']);
    if (!data.title || !String(data.title).trim()) {
      throw new Error('Validation failed: title must not be empty.');
    }
    if (!data.message || !String(data.message).trim()) {
      throw new Error('Validation failed: message must not be empty.');
    }

    const validTypes: string[] = ['SYSTEM', 'ALERT', 'TASK', 'MENTION', 'COMMENT'];
    if (!validTypes.includes(String(data.type).toUpperCase())) {
      throw new Error(`Validation failed: type "${data.type}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const notification = await this.notifRepo.create(data, transaction);
      await eventPublisher.publish('NotificationCreated', { notification });
      return notification;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  async updateNotification(
    id: string,
    data: Prisma.NotificationUncheckedUpdateInput,
    tx?: any,
  ): Promise<Notification> {
    this.validateUuid(id, 'notificationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.notifRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`Notification "${id}" not found.`);
      }
      const updated = await this.notifRepo.update(id, data, transaction);
      await eventPublisher.publish('NotificationUpdated', { notification: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  async deleteNotification(id: string, actor: string, tx?: any): Promise<Notification> {
    this.validateUuid(id, 'notificationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.notifRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`Notification "${id}" not found.`);
      }
      const deleted = await this.notifRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('NotificationDeleted', { notification: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Status Transitions ──────────────────────────────────────────────────────

  async markRead(id: string, actor: string, tx?: any): Promise<Notification> {
    this.validateUuid(id, 'notificationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.notifRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`Notification "${id}" not found.`);
      }
      const updated = await this.notifRepo.update(
        id,
        { status: 'READ' as NotificationStatus, readAt: new Date(), updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('NotificationRead', { notification: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async markUnread(id: string, actor: string, tx?: any): Promise<Notification> {
    this.validateUuid(id, 'notificationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.notifRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`Notification "${id}" not found.`);
      }
      const updated = await this.notifRepo.update(
        id,
        { status: 'UNREAD' as NotificationStatus, readAt: null, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('NotificationUnread', { notification: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async archiveNotification(id: string, actor: string, tx?: any): Promise<Notification> {
    this.validateUuid(id, 'notificationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.notifRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`Notification "${id}" not found.`);
      }
      const updated = await this.notifRepo.update(
        id,
        { status: 'ARCHIVED' as NotificationStatus, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('NotificationArchived', { notification: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async markAllRead(userId: string, actor: string, tx?: any): Promise<number> {
    this.validateUuid(userId, 'userId');

    const client = tx || prisma;
    const result = await client.notification.updateMany({
      where: { userId, status: 'UNREAD', deletedAt: null },
      data: { status: 'READ', readAt: new Date(), updatedBy: actor },
    });
    await eventPublisher.publish('NotificationAllRead', { userId, count: result.count });
    return result.count;
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByUser(userId: string, tx?: any): Promise<Notification[]> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.notification.findMany({
      where: { userId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByStatus(status: NotificationStatus, tx?: any): Promise<Notification[]> {
    const validStatuses: string[] = ['READ', 'UNREAD', 'ARCHIVED'];
    if (!validStatuses.includes(String(status).toUpperCase())) {
      throw new Error(`Validation failed: status "${status}" is not valid.`);
    }
    const client = tx || prisma;
    return client.notification.findMany({
      where: { status, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByType(type: NotificationType, tx?: any): Promise<Notification[]> {
    const validTypes: string[] = ['SYSTEM', 'ALERT', 'TASK', 'MENTION', 'COMMENT'];
    if (!validTypes.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }
    const client = tx || prisma;
    return client.notification.findMany({
      where: { type, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findUnread(userId: string, tx?: any): Promise<Notification[]> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.notification.findMany({
      where: { userId, status: 'UNREAD', deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async countUnread(userId: string, tx?: any): Promise<number> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.notification.count({
      where: { userId, status: 'UNREAD', deletedAt: null },
    });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalNotifications: number;
    unreadNotifications: number;
    readNotifications: number;
    archivedNotifications: number;
    typeCounts: Record<string, number>;
  }> {
    const client = tx || prisma;
    const all = await client.notification.findMany({ where: { deletedAt: null } });

    const typeCounts: Record<string, number> = {};
    let unread = 0, read = 0, archived = 0;

    for (const n of all) {
      const t = String(n.type);
      typeCounts[t] = (typeCounts[t] ?? 0) + 1;
      if (n.status === 'UNREAD') unread++;
      else if (n.status === 'READ') read++;
      else if (n.status === 'ARCHIVED') archived++;
    }

    return {
      totalNotifications: all.length,
      unreadNotifications: unread,
      readNotifications: read,
      archivedNotifications: archived,
      typeCounts,
    };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  async bulkCreate(
    items: Prisma.NotificationUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { title: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { title: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const n = await this.createNotification({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(n.id);
      } catch (e: any) {
        failed.push({ title: String(item.title ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('NotificationsBulkCreated', { succeeded, failed });
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
        await this.deleteNotification(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('NotificationsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const notificationService = new NotificationService();
