/**
 * ActivityOrchestrator.ts
 * =====================================
 * Orchestrates logging and tracking of user and system activities.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { activityService } from '../../services/shared';
import { ActivityLog, ActivityType, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface LogActivityInput {
  userId: string;
  action: string;
  type: ActivityType;
  details?: string;
  projectId?: string;
  investigationId?: string;
  actor: string;
}

export interface GetAuditTrailInput {
  userId?: string;
  projectId?: string;
  investigationId?: string;
  limit?: number;
}

export class ActivityOrchestrator extends BaseApplicationService {
  constructor() {
    super('ActivityOrchestrator');
  }

  async logActivity(input: LogActivityInput, parentCtx?: OperationContext): Promise<ActivityLog> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Logging activity for user ${input.userId}: ${input.action}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateRequired(input, ['action', 'type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const log = await activityService.logActivity({
        userId: input.userId,
        action: input.action,
        type: input.type,
        details: input.details,
        projectId: input.projectId,
        investigationId: input.investigationId,
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      compensation.register(`delete-activity-${log.id}`, async () => {
        try {
          await prisma.activityLog.delete({ where: { id: log.id } });
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.ACTIVITY_LOGGED, ctx, {
        activityId: log.id,
        userId: input.userId,
        action: input.action,
      });

      compensation.clear();
      return log;
    });
  }

  async getAuditTrail(query: GetAuditTrailInput, actor: string, parentCtx?: OperationContext): Promise<ActivityLog[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    const limit = query.limit ?? 100;
    this.logInfo(ctx, `Fetching audit trail. Filters: ${JSON.stringify(query)}`);

    if (query.userId) {
      this.validateUuid(query.userId, 'userId', ctx);
      return activityService.findByUser(query.userId, limit);
    }
    if (query.projectId) {
      this.validateUuid(query.projectId, 'projectId', ctx);
      return activityService.findByProject(query.projectId, limit);
    }
    if (query.investigationId) {
      this.validateUuid(query.investigationId, 'investigationId', ctx);
      return activityService.findByInvestigation(query.investigationId, limit);
    }
    return activityService.findRecent(limit);
  }

  async getStatistics(actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching activity statistics`);
    return activityService.getStatistics();
  }

  async getStats(actor: string, parentCtx?: OperationContext): Promise<any> {
    return this.getStatistics(actor, parentCtx);
  }

  async purgeLogs(cutoffDate: Date, actor: string, parentCtx?: OperationContext): Promise<number> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Purging activity logs older than ${cutoffDate.toISOString()}`);
    if (!(cutoffDate instanceof Date) || isNaN(cutoffDate.getTime())) {
      throw new Error('Validation failed: cutoffDate must be a valid Date.');
    }

    return activityService.purgeOlderThan(cutoffDate);
  }

  async purgeActivityLogs(cutoffDate: Date, actor: string, parentCtx?: OperationContext): Promise<number> {
    return this.purgeLogs(cutoffDate, actor, parentCtx);
  }
}

export const activityOrchestrator = new ActivityOrchestrator();
