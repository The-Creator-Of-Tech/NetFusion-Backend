/**
 * ActivityService — Phase A5.3.7
 * =================================
 * Business logic for ActivityLog lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Log activities for any user/project/investigation action
 * - Filter by user, project, investigation, action, type
 * - Pagination support
 * - Statistics and audit trail analysis
 * - Cross-module event logging
 * - Event publication after every log entry
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { activityLogRepository } from '../../repositories/core';
import prisma from '../../lib/prisma';
import { ActivityLog, ActivityType, Prisma } from '@prisma/client';

const VALID_TYPES: string[] = ['CREATE', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'EXECUTE', 'OTHER'];

export class ActivityService extends BaseService {
  constructor(private readonly activityRepo = activityLogRepository) {
    super();
  }

  // ── Log Activity ────────────────────────────────────────────────────────────

  async logActivity(
    data: Prisma.ActivityLogUncheckedCreateInput,
    tx?: any,
  ): Promise<ActivityLog> {
    this.validateRequired(data as any, ['userId', 'action', 'type', 'createdBy', 'updatedBy']);
    if (!String(data.action).trim()) {
      throw new Error('Validation failed: action must not be empty.');
    }
    if (!VALID_TYPES.includes(String(data.type).toUpperCase())) {
      throw new Error(`Validation failed: type "${data.type}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const log = await this.activityRepo.create(data, transaction);
      await eventPublisher.publish('ActivityLogged', { log });
      return log;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Convenience Loggers ─────────────────────────────────────────────────────

  async logCreate(
    userId: string,
    action: string,
    details?: string,
    projectId?: string,
    investigationId?: string,
    tx?: any,
  ): Promise<ActivityLog> {
    return this.logActivity(
      {
        userId, action, type: 'CREATE' as ActivityType,
        details, projectId, investigationId,
        createdBy: userId, updatedBy: userId,
      },
      tx,
    );
  }

  async logUpdate(
    userId: string,
    action: string,
    details?: string,
    projectId?: string,
    investigationId?: string,
    tx?: any,
  ): Promise<ActivityLog> {
    return this.logActivity(
      {
        userId, action, type: 'UPDATE' as ActivityType,
        details, projectId, investigationId,
        createdBy: userId, updatedBy: userId,
      },
      tx,
    );
  }

  async logDelete(
    userId: string,
    action: string,
    details?: string,
    projectId?: string,
    investigationId?: string,
    tx?: any,
  ): Promise<ActivityLog> {
    return this.logActivity(
      {
        userId, action, type: 'DELETE' as ActivityType,
        details, projectId, investigationId,
        createdBy: userId, updatedBy: userId,
      },
      tx,
    );
  }

  async logExecute(
    userId: string,
    action: string,
    details?: string,
    projectId?: string,
    investigationId?: string,
    tx?: any,
  ): Promise<ActivityLog> {
    return this.logActivity(
      {
        userId, action, type: 'EXECUTE' as ActivityType,
        details, projectId, investigationId,
        createdBy: userId, updatedBy: userId,
      },
      tx,
    );
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByUser(userId: string, limit = 100, tx?: any): Promise<ActivityLog[]> {
    this.validateUuid(userId, 'userId');
    if (limit < 1) throw new Error('Validation failed: limit must be >= 1.');
    const client = tx || prisma;
    return client.activityLog.findMany({
      where: { userId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  async findByProject(projectId: string, limit = 100, tx?: any): Promise<ActivityLog[]> {
    this.validateUuid(projectId, 'projectId');
    if (limit < 1) throw new Error('Validation failed: limit must be >= 1.');
    const client = tx || prisma;
    return client.activityLog.findMany({
      where: { projectId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  async findByInvestigation(investigationId: string, limit = 100, tx?: any): Promise<ActivityLog[]> {
    this.validateUuid(investigationId, 'investigationId');
    if (limit < 1) throw new Error('Validation failed: limit must be >= 1.');
    const client = tx || prisma;
    return client.activityLog.findMany({
      where: { investigationId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  async findByType(type: ActivityType, tx?: any): Promise<ActivityLog[]> {
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }
    const client = tx || prisma;
    return client.activityLog.findMany({
      where: { type, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByAction(action: string, tx?: any): Promise<ActivityLog[]> {
    if (!action || !action.trim()) {
      throw new Error('Validation failed: action must not be empty.');
    }
    const client = tx || prisma;
    return client.activityLog.findMany({
      where: {
        action: { contains: action.trim(), mode: 'insensitive' },
        deletedAt: null,
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findRecent(limit = 50, tx?: any): Promise<ActivityLog[]> {
    if (limit < 1) throw new Error('Validation failed: limit must be >= 1.');
    const client = tx || prisma;
    return client.activityLog.findMany({
      where: { deletedAt: null },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalLogs: number;
    typeCounts: Record<string, number>;
    userCounts: Record<string, number>;
    recentActivity: number;
  }> {
    const client = tx || prisma;
    const all = await client.activityLog.findMany({ where: { deletedAt: null } });

    const typeCounts: Record<string, number> = {};
    const userCounts: Record<string, number> = {};
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let recent = 0;

    for (const a of all) {
      const t = String(a.type);
      typeCounts[t] = (typeCounts[t] ?? 0) + 1;
      userCounts[a.userId] = (userCounts[a.userId] ?? 0) + 1;
      if (new Date(a.createdAt) >= cutoff) recent++;
    }

    return {
      totalLogs: all.length,
      typeCounts,
      userCounts,
      recentActivity: recent,
    };
  }

  // ── Purge (hard delete old logs) ────────────────────────────────────────────

  async purgeOlderThan(cutoffDate: Date, tx?: any): Promise<number> {
    if (!(cutoffDate instanceof Date) || isNaN(cutoffDate.getTime())) {
      throw new Error('Validation failed: cutoffDate must be a valid Date.');
    }
    const client = tx || prisma;
    const result = await client.activityLog.deleteMany({
      where: { createdAt: { lt: cutoffDate } },
    });
    await eventPublisher.publish('ActivityLogsPurged', { count: result.count, cutoffDate });
    return result.count;
  }
}

export const activityService = new ActivityService();
