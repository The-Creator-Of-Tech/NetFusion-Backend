/**
 * MaintenancePipeline.ts — Phase A5.4.6
 * ===========================================
 * Handles platform-wide administrative workflows (cleanup, archive, indexing, integrity, health) by coordinating the Shared domain.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Orchestrators
import { sharedOrchestrator } from '../shared/SharedOrchestrator';

// Services
import { providerService } from '../../services/ai';
import prisma from '../../lib/prisma';

export class MaintenancePipeline extends BaseApplicationService {
  constructor() {
    super('MaintenancePipeline');
  }

  async cleanup(actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Performing MaintenancePipeline cleanup`);

    const result = await sharedOrchestrator.performMaintenance({ actor }, ctx);

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'CLEANUP',
      softDeletesCleaned: result.softDeletesCleaned,
    });

    return result;
  }

  async archive(projectId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId });
    this.logInfo(ctx, `Archiving project ${projectId}`);

    const result = await sharedOrchestrator.archiveProject({ projectId, actor }, ctx);

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'ARCHIVE_PROJECT',
      projectId,
    });

    return result;
  }

  async reindex(actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Rebuilding platform search indexes`);

    await sharedOrchestrator.rebuildSearchIndex({ actor }, ctx);

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'REINDEX',
    });

    return { success: true };
  }

  async recalculateStatistics(projectId: string, actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId });
    this.logInfo(ctx, `Recalculating metadata statistics for projectCode ${projectId}`);

    const result = await sharedOrchestrator.synchronizeMetadata({ projectId, actor }, ctx);

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'RECALCULATE_STATS',
      projectId,
    });

    return result;
  }

  async cleanupSoftDeletes(actor: string, parentCtx?: OperationContext): Promise<number> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Invoking soft delete purging`);
    const cleaned = await sharedOrchestrator.cleanupSoftDeletes({ actor }, ctx);

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'PURGE_SOFT_DELETES',
      count: cleaned,
    });

    return cleaned;
  }

  async verifyIntegrity(actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Checking cross-relation database integrity`);

    // Verify orphan assets/findings/alerts
    const projects = await prisma.project.findMany({ select: { id: true } });
    const projectIds = projects.map(p => p.id);
    const investigations = await prisma.investigation.findMany({ select: { id: true } });
    const investigationIds = investigations.map(i => i.id);

    // Verify orphan assets/findings/alerts referencing non-existent project or investigation IDs
    const [orphanFindings, orphanAssets, orphanAlerts] = await Promise.all([
      prisma.finding.count({
        where: {
          OR: [
            { projectId: { notIn: projectIds } },
            { investigationId: { notIn: investigationIds } },
          ],
        },
      }),
      prisma.asset.count({
        where: {
          OR: [
            { projectId: { notIn: projectIds } },
            { investigationId: { notIn: investigationIds } },
          ],
        },
      }),
      prisma.alert.count({
        where: {
          OR: [
            { projectId: { notIn: projectIds } },
            { investigationId: { notIn: investigationIds } },
          ],
        },
      }),
    ]);

    const status = (orphanFindings + orphanAssets + orphanAlerts) === 0 ? 'HEALTHY' : 'WARNING';

    const result = {
      status,
      orphanFindings,
      orphanAssets,
      orphanAlerts,
      checkedAt: new Date(),
    };

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'INTEGRITY_CHECK',
      status,
    });

    return result;
  }

  async healthCheck(actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Executing platform global health check`);

    let dbHealthy = true;
    try {
      await prisma.$queryRaw`SELECT 1`;
    } catch (_) {
      dbHealthy = false;
    }

    const aiProviders = await providerService.findEnabled().catch(() => []);
    const healthyProviders = aiProviders.filter((p: any) => p.status === 'ACTIVE').length;

    const stats = await sharedOrchestrator.generatePlatformStatistics({ actor }, ctx);

    const overallHealthy = dbHealthy && healthyProviders > 0;

    const result = {
      status: overallHealthy ? 'UP' : 'DOWN',
      services: {
        database: dbHealthy ? 'UP' : 'DOWN',
        aiProviders: healthyProviders > 0 ? 'UP' : 'DOWN',
      },
      stats,
      checkedAt: new Date(),
    };

    if (overallHealthy) {
      await this.publishEvent(APP_EVENTS.PLATFORM_HEALTH_VERIFIED, ctx, {
        status: result.status,
        database: result.services.database,
        aiProviders: healthyProviders,
      });
    }

    return result;
  }

  async backupMetadata(actor: string, parentCtx?: OperationContext): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Backing up platform settings metadata`);

    const settings = await prisma.systemSetting.findMany();
    const backupJson = JSON.stringify(settings, null, 2);

    await this.publishEvent(APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
      type: 'BACKUP_METADATA',
      settingsCount: settings.length,
    });

    return {
      backupJson,
      settingsCount: settings.length,
      timestamp: new Date(),
    };
  }
}

export const maintenancePipeline = new MaintenancePipeline();
