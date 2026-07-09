"use strict";
/**
 * MaintenancePipeline.ts — Phase A5.4.6
 * ===========================================
 * Handles platform-wide administrative workflows (cleanup, archive, indexing, integrity, health) by coordinating the Shared domain.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.maintenancePipeline = exports.MaintenancePipeline = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// Orchestrators
const SharedOrchestrator_1 = require("../shared/SharedOrchestrator");
// Services
const ai_1 = require("../../services/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class MaintenancePipeline extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('MaintenancePipeline');
    }
    async cleanup(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Performing MaintenancePipeline cleanup`);
        const result = await SharedOrchestrator_1.sharedOrchestrator.performMaintenance({ actor }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
            type: 'CLEANUP',
            softDeletesCleaned: result.softDeletesCleaned,
        });
        return result;
    }
    async archive(projectId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId });
        this.logInfo(ctx, `Archiving project ${projectId}`);
        const result = await SharedOrchestrator_1.sharedOrchestrator.archiveProject({ projectId, actor }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
            type: 'ARCHIVE_PROJECT',
            projectId,
        });
        return result;
    }
    async reindex(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Rebuilding platform search indexes`);
        await SharedOrchestrator_1.sharedOrchestrator.rebuildSearchIndex({ actor }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
            type: 'REINDEX',
        });
        return { success: true };
    }
    async recalculateStatistics(projectId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId });
        this.logInfo(ctx, `Recalculating metadata statistics for projectCode ${projectId}`);
        const result = await SharedOrchestrator_1.sharedOrchestrator.synchronizeMetadata({ projectId, actor }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
            type: 'RECALCULATE_STATS',
            projectId,
        });
        return result;
    }
    async cleanupSoftDeletes(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Invoking soft delete purging`);
        const cleaned = await SharedOrchestrator_1.sharedOrchestrator.cleanupSoftDeletes({ actor }, ctx);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
            type: 'PURGE_SOFT_DELETES',
            count: cleaned,
        });
        return cleaned;
    }
    async verifyIntegrity(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Checking cross-relation database integrity`);
        // Verify orphan assets/findings/alerts
        const projects = await prisma_1.default.project.findMany({ select: { id: true } });
        const projectIds = projects.map(p => p.id);
        const investigations = await prisma_1.default.investigation.findMany({ select: { id: true } });
        const investigationIds = investigations.map(i => i.id);
        // Verify orphan assets/findings/alerts referencing non-existent project or investigation IDs
        const [orphanFindings, orphanAssets, orphanAlerts] = await Promise.all([
            prisma_1.default.finding.count({
                where: {
                    OR: [
                        { projectId: { notIn: projectIds } },
                        { investigationId: { notIn: investigationIds } },
                    ],
                },
            }),
            prisma_1.default.asset.count({
                where: {
                    OR: [
                        { projectId: { notIn: projectIds } },
                        { investigationId: { notIn: investigationIds } },
                    ],
                },
            }),
            prisma_1.default.alert.count({
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
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
            type: 'INTEGRITY_CHECK',
            status,
        });
        return result;
    }
    async healthCheck(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Executing platform global health check`);
        let dbHealthy = true;
        try {
            await prisma_1.default.$queryRaw `SELECT 1`;
        }
        catch (_) {
            dbHealthy = false;
        }
        const aiProviders = await ai_1.providerService.findEnabled().catch(() => []);
        const healthyProviders = aiProviders.filter((p) => p.status === 'ACTIVE').length;
        const stats = await SharedOrchestrator_1.sharedOrchestrator.generatePlatformStatistics({ actor }, ctx);
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
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.PLATFORM_HEALTH_VERIFIED, ctx, {
                status: result.status,
                database: result.services.database,
                aiProviders: healthyProviders,
            });
        }
        return result;
    }
    async backupMetadata(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Backing up platform settings metadata`);
        const settings = await prisma_1.default.systemSetting.findMany();
        const backupJson = JSON.stringify(settings, null, 2);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.MAINTENANCE_COMPLETED, ctx, {
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
exports.MaintenancePipeline = MaintenancePipeline;
exports.maintenancePipeline = new MaintenancePipeline();
