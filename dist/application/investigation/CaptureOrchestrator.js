"use strict";
/**
 * CaptureOrchestrator.ts — Phase A5.4.1
 * ========================================
 * Orchestrates packet-capture workflows.
 *
 * Business flow:
 *   Capture → Packet Analysis → Asset Discovery → Timeline
 *           → Evidence Creation → AI Analysis (optional) → Notification
 *
 * Coordinates: AssetService · EvidenceService · TimelineService ·
 *              AlertService · ActivityService · NotificationService
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.captureOrchestrator = exports.CaptureOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const core_1 = require("../../services/core");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// In-memory session store (per-process; replaced by DB in production)
// ─────────────────────────────────────────────────────────────────────────────
const activeSessions = new Map();
// ─────────────────────────────────────────────────────────────────────────────
// CaptureOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class CaptureOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('CaptureOrchestrator');
    }
    // ── Start Capture ──────────────────────────────────────────────────────────
    async startCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Starting capture for investigation ${input.investigationId}`);
        const inv = await core_1.investigationService.findInvestigation(input.investigationId);
        if (!inv)
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Investigation', input.investigationId, ctx.correlationId);
        const captureId = `cap-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
        const session = {
            captureId,
            investigationId: input.investigationId,
            projectId: input.projectId,
            status: 'ACTIVE',
            interface: input.interface,
            packetCount: 0,
            startedAt: new Date(),
            assetIds: [],
            alertIds: [],
            correlationId: ctx.correlationId,
        };
        activeSessions.set(captureId, session);
        await investigation_1.timelineService.recordCapture(input.projectId, input.investigationId, captureId, input.actor);
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logExecute(input.actor, 'CAPTURE_STARTED', `Capture ${captureId} started`, input.projectId, input.investigationId);
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_STARTED, ctx, {
            captureId,
            investigationId: input.investigationId,
            projectId: input.projectId,
            interface: input.interface,
        });
        return session;
    }
    // ── Stop Capture ───────────────────────────────────────────────────────────
    async stopCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        const session = this.requireSession(input.captureId, ctx);
        this.logInfo(ctx, `Stopping capture ${input.captureId}`);
        session.status = 'STOPPED';
        session.stoppedAt = new Date();
        session.durationMs = session.stoppedAt.getTime() - session.startedAt.getTime();
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Capture Stopped',
            description: `Capture ${input.captureId} stopped. Duration: ${session.durationMs}ms.`,
            type: 'EVIDENCE_ADDED',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_STOPPED, ctx, {
            captureId: input.captureId,
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        return session;
    }
    // ── Pause Capture ──────────────────────────────────────────────────────────
    async pauseCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
        });
        const session = this.requireSession(input.captureId, ctx);
        if (session.status !== 'ACTIVE') {
            throw this.mapError(new Error(`Capture ${input.captureId} is not active.`), ctx);
        }
        session.status = 'PAUSED';
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Capture Paused',
            description: `Capture ${input.captureId} paused.`,
            type: 'MANUAL_ACTION',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_PAUSED, ctx, { captureId: input.captureId });
        return session;
    }
    // ── Resume Capture ─────────────────────────────────────────────────────────
    async resumeCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
        });
        const session = this.requireSession(input.captureId, ctx);
        if (session.status !== 'PAUSED') {
            throw this.mapError(new Error(`Capture ${input.captureId} is not paused.`), ctx);
        }
        session.status = 'ACTIVE';
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Capture Resumed',
            description: `Capture ${input.captureId} resumed.`,
            type: 'MANUAL_ACTION',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_RESUMED, ctx, { captureId: input.captureId });
        return session;
    }
    // ── Analyse Capture ────────────────────────────────────────────────────────
    async analyseCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        this.logInfo(ctx, `Analysing capture ${input.captureId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const session = activeSessions.get(input.captureId) ?? {
                captureId: input.captureId,
                investigationId: input.investigationId,
                projectId: input.projectId,
                status: 'STOPPED',
                packetCount: 0,
                startedAt: new Date(),
                assetIds: [],
                alertIds: [],
                correlationId: ctx.correlationId,
            };
            // 1. Create evidence record for the capture
            const evidence = await investigation_1.evidenceService.attachPcap({
                projectId: input.projectId,
                investigationId: input.investigationId,
                fieldName: 'pcap_capture',
                fieldValue: input.pcapContent ?? `capture:${input.captureId}`,
                sourceType: 'CAPTURE',
                type: 'PACKET',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            session.evidenceId = evidence.id;
            compensation.register(`delete-evidence-${evidence.id}`, async () => {
                try {
                    // soft-delete via update
                }
                catch (_) { /* best effort */ }
            });
            // 2. Asset discovery from capture metadata
            let discoveredAsset;
            try {
                discoveredAsset = await investigation_1.assetService.createAsset({
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    type: 'UNKNOWN',
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
                session.assetIds.push(discoveredAsset.id);
                // Link evidence to asset
                await investigation_1.evidenceService.associateAsset(evidence.id, discoveredAsset.id, input.actor);
            }
            catch (e) {
                this.logWarn(ctx, `Asset creation skipped: ${e?.message}`);
            }
            // 3. Create a finding from capture analysis
            const finding = await investigation_1.findingService.createFinding({
                projectId: input.projectId,
                investigationId: input.investigationId,
                assetId: discoveredAsset?.id,
                title: `Capture Analysis — ${input.captureId}`,
                description: `Network capture ${input.captureId} analysed.`,
                severity: 'MEDIUM',
                status: 'OPEN',
                category: 'PACKET_ANALYSIS',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            // Link evidence to finding
            await investigation_1.evidenceService.associateFinding(evidence.id, finding.id, input.actor);
            // 4. Timeline
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: 'Capture Analysed',
                description: `Capture ${input.captureId} analysis complete. Evidence: ${evidence.id}.`,
                type: 'EVIDENCE_ADDED',
                createdBy: input.actor,
            });
            // 5. Optional AI analysis timeline marker
            if (input.enableAI) {
                await investigation_1.timelineService.recordAIAction(input.projectId, input.investigationId, `AI analysis triggered for capture ${input.captureId}.`, input.actor);
            }
            session.status = 'ANALYSED';
            session.packetCount = Math.floor(Math.random() * 1000) + 100; // placeholder
            activeSessions.set(input.captureId, session);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_ANALYSED, ctx, {
                captureId: input.captureId,
                investigationId: input.investigationId,
                projectId: input.projectId,
                evidenceId: evidence.id,
            });
            compensation.clear();
            return session;
        });
    }
    // ── Save Capture ───────────────────────────────────────────────────────────
    async saveCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        this.logInfo(ctx, `Saving capture ${input.captureId}`);
        // Persist evidence
        const evidence = await investigation_1.evidenceService.attachPcap({
            projectId: input.projectId,
            investigationId: input.investigationId,
            fieldName: 'pcap_file',
            fieldValue: input.content,
            sourceType: 'FILE_UPLOAD',
            type: 'PACKET',
            metadata: { fileName: input.fileName, captureId: input.captureId },
            createdBy: input.actor,
            updatedBy: input.actor,
        });
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Capture Saved',
            description: `Capture file "${input.fileName}" saved as evidence ${evidence.id}.`,
            type: 'EVIDENCE_ADDED',
            createdBy: input.actor,
        });
        const session = activeSessions.get(input.captureId) ?? {
            captureId: input.captureId,
            investigationId: input.investigationId,
            projectId: input.projectId,
            status: 'SAVED',
            packetCount: 0,
            startedAt: new Date(),
            assetIds: [],
            alertIds: [],
            correlationId: ctx.correlationId,
        };
        session.status = 'SAVED';
        session.evidenceId = evidence.id;
        activeSessions.set(input.captureId, session);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_SAVED, ctx, {
            captureId: input.captureId,
            evidenceId: evidence.id,
        });
        return session;
    }
    // ── Import Capture ─────────────────────────────────────────────────────────
    async importCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
            projectId: input.projectId,
        });
        this.logInfo(ctx, `Importing capture "${input.fileName}"`);
        const captureId = `cap-import-${Date.now()}`;
        const evidence = await investigation_1.evidenceService.attachPcap({
            projectId: input.projectId,
            investigationId: input.investigationId,
            fieldName: 'imported_pcap',
            fieldValue: input.content,
            sourceType: 'IMPORT',
            type: 'PACKET',
            metadata: { fileName: input.fileName },
            createdBy: input.actor,
            updatedBy: input.actor,
        });
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Capture Imported',
            description: `PCAP "${input.fileName}" imported as evidence ${evidence.id}.`,
            type: 'EVIDENCE_ADDED',
            createdBy: input.actor,
        });
        const session = {
            captureId,
            investigationId: input.investigationId,
            projectId: input.projectId,
            status: 'SAVED',
            packetCount: 0,
            startedAt: new Date(),
            assetIds: [],
            alertIds: [],
            evidenceId: evidence.id,
            correlationId: ctx.correlationId,
        };
        activeSessions.set(captureId, session);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_IMPORTED, ctx, {
            captureId,
            evidenceId: evidence.id,
            investigationId: input.investigationId,
            projectId: input.projectId,
            sourceType: 'IMPORT',
        });
        return session;
    }
    // ── Export Capture ─────────────────────────────────────────────────────────
    async exportCapture(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Exporting capture ${input.captureId} as ${input.format ?? 'PCAPNG'}`);
        const format = input.format ?? 'PCAPNG';
        const exportUrl = `/exports/${input.captureId}.${format.toLowerCase()}`;
        await investigation_1.timelineService.record({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: 'Capture Exported',
            description: `Capture ${input.captureId} exported as ${format}.`,
            type: 'MANUAL_ACTION',
            createdBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CAPTURE_EXPORTED, ctx, {
            captureId: input.captureId,
            format,
        });
        return { url: exportUrl, format };
    }
    // ── Helpers ───────────────────────────────────────────────────────────────
    requireSession(captureId, ctx) {
        const session = activeSessions.get(captureId);
        if (!session) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('CaptureSession', captureId, ctx.correlationId);
        }
        return session;
    }
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
    /** Expose session map for testing */
    getSession(captureId) {
        return activeSessions.get(captureId);
    }
    clearSessions() {
        activeSessions.clear();
    }
}
exports.CaptureOrchestrator = CaptureOrchestrator;
exports.captureOrchestrator = new CaptureOrchestrator();
