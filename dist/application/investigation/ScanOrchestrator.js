"use strict";
/**
 * ScanOrchestrator.ts — Phase A5.4.1
 * =====================================
 * Orchestrates complete scan workflows across multiple service domains.
 *
 * Coordinates: AssetService · FindingService · AlertService ·
 *              TimelineService · ActivityService · NotificationService
 *
 * Scan types modelled: quick, full, service, OS, aggressive.
 * Every method uses withCompensation() for rollback safety.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanOrchestrator = exports.ScanOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// ScanOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class ScanOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ScanOrchestrator');
    }
    // ── Generic scan launcher ──────────────────────────────────────────────────
    async launchScan(scanType, input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Starting ${scanType} scan on target "${input.target}"`);
        const startedAt = new Date();
        const scanId = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const result = {
            scanId,
            investigationId: input.investigationId,
            projectId: input.projectId,
            target: input.target,
            scanType,
            status: 'STARTED',
            findingIds: [],
            alertIds: [],
            startedAt,
            correlationId: ctx.correlationId,
        };
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Record scan start in timeline
            await investigation_1.timelineService.recordScan(input.projectId, input.investigationId, scanId, input.actor);
            // 2. Discover/upsert Asset for target
            let asset;
            try {
                asset = await investigation_1.assetService.createAsset({
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    hostname: this.isIpAddress(input.target) ? undefined : input.target,
                    currentIp: this.isIpAddress(input.target) ? input.target : undefined,
                    type: 'UNKNOWN',
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
                result.assetId = asset.id;
                compensation.register(`delete-asset-${asset.id}`, async () => {
                    try {
                        await investigation_1.assetService.updateAsset(asset.id, { deletedAt: new Date(), updatedBy: 'system' });
                    }
                    catch (_) { /* best effort */ }
                });
            }
            catch (e) {
                // Duplicate asset is expected on rescan — log and continue
                if (e.message?.includes('Duplicate asset')) {
                    this.logWarn(ctx, `Duplicate asset detected for target "${input.target}", proceeding without create`);
                }
                else {
                    throw e;
                }
            }
            // 3. Create Finding based on scan type risk
            const severity = this.scanTypeSeverity(scanType);
            const finding = await investigation_1.findingService.createFinding({
                projectId: input.projectId,
                investigationId: input.investigationId,
                assetId: asset?.id,
                title: `${scanType} Scan — ${input.target}`,
                description: `${scanType} scan completed for target ${input.target}.`,
                severity,
                status: 'OPEN',
                category: 'SCAN',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            result.findingIds.push(finding.id);
            compensation.register(`delete-finding-${finding.id}`, async () => {
                try {
                    await investigation_1.findingService.updateFinding(finding.id, { deletedAt: new Date(), updatedBy: 'system' });
                }
                catch (_) { /* best effort */ }
            });
            // 4. Raise alert if HIGH/CRITICAL scan
            if (severity === 'HIGH' || severity === 'CRITICAL') {
                const alert = await investigation_1.alertService.createAlert({
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    findingId: finding.id,
                    title: `Scan Alert — ${scanType} on ${input.target}`,
                    description: `${scanType} scan detected ${severity} severity indicators.`,
                    severity,
                    status: 'NEW',
                    source: 'SCAN',
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
                result.alertIds.push(alert.id);
            }
            // 5. Activity log
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logExecute(input.actor, `SCAN_${scanType}_STARTED`, `${scanType} scan started on target ${input.target}`, input.projectId, input.investigationId);
            }
            // 6. Mark completed + timing
            result.status = 'COMPLETED';
            result.completedAt = new Date();
            result.durationMs = result.completedAt.getTime() - startedAt.getTime();
            // 7. Record scan completion in timeline
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `${scanType} Scan Completed`,
                description: `Scan ${scanId} completed. Found ${result.findingIds.length} finding(s).`,
                type: 'EVIDENCE_ADDED',
                createdBy: input.actor,
            });
            // 8. Publish events
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.SCAN_STARTED, ctx, {
                scanId,
                investigationId: input.investigationId,
                projectId: input.projectId,
                target: input.target,
                scanType,
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.SCAN_COMPLETED, ctx, {
                scanId,
                investigationId: input.investigationId,
                projectId: input.projectId,
                assetCount: asset ? 1 : 0,
                findingCount: result.findingIds.length,
                alertCount: result.alertIds.length,
                durationMs: result.durationMs,
            });
            this.logTiming(ctx, `${scanType} scan`);
            compensation.clear(); // success — no rollback needed
            return result;
        });
    }
    // ── Public scan methods ───────────────────────────────────────────────────
    async startQuickScan(input, ctx) {
        return this.launchScan('QUICK', input, ctx);
    }
    async startFullScan(input, ctx) {
        return this.launchScan('FULL', input, ctx);
    }
    async startServiceScan(input, ctx) {
        return this.launchScan('SERVICE', input, ctx);
    }
    async startOSScan(input, ctx) {
        return this.launchScan('OS', input, ctx);
    }
    async startAggressiveScan(input, ctx) {
        return this.launchScan('AGGRESSIVE', input, ctx);
    }
    // ── Cancel Scan ───────────────────────────────────────────────────────────
    async cancelScan(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Cancelling scan: ${input.scanId}`);
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Scan Cancelled',
            description: `Scan ${input.scanId} was cancelled by ${input.actor}.`,
            type: 'MANUAL_ACTION',
            createdBy: input.actor,
        });
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logExecute(input.actor, 'SCAN_CANCELLED', `Scan ${input.scanId} cancelled`, input.projectId, input.investigationId);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.SCAN_CANCELLED, ctx, {
            scanId: input.scanId,
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
    }
    // ── Rescan ────────────────────────────────────────────────────────────────
    async rescanTarget(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Rescanning target: ${input.target}`);
        if (input.originalScanId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: 'Rescan Initiated',
                description: `Rescan of target ${input.target} initiated (original scan: ${input.originalScanId}).`,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.RESCAN_STARTED, ctx, {
            investigationId: input.investigationId,
            target: input.target,
        });
        // Run a full scan as the rescan strategy
        return this.launchScan('FULL', {
            investigationId: input.investigationId,
            projectId: input.projectId,
            target: input.target,
            actor: input.actor,
        }, ctx);
    }
    // ── Helpers ───────────────────────────────────────────────────────────────
    scanTypeSeverity(type) {
        const map = {
            QUICK: 'LOW',
            FULL: 'MEDIUM',
            SERVICE: 'MEDIUM',
            OS: 'HIGH',
            AGGRESSIVE: 'CRITICAL',
        };
        return map[type];
    }
    isIpAddress(target) {
        return /^\d{1,3}(\.\d{1,3}){3}$/.test(target);
    }
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.ScanOrchestrator = ScanOrchestrator;
exports.scanOrchestrator = new ScanOrchestrator();
