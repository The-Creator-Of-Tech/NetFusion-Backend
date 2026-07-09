"use strict";
/**
 * TimelineService — Phase A5.3.3
 * ================================
 * Centralised timeline creation. NOTHING else should insert TimelineEvents
 * directly — all callers must go through this service.
 *
 * Every write method wraps its DB operations in a Prisma transaction and
 * publishes a TimelineRecorded event after commit.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TimelineService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class TimelineService extends BaseService_1.BaseService {
    constructor(timelineRepo = investigation_1.timelineRepository) {
        super();
        this.timelineRepo = timelineRepo;
    }
    // ── Generic recorder ──────────────────────────────────────────────────────
    async record(input, tx) {
        const runInTx = async (transaction) => {
            const event = await this.timelineRepo.create({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: input.title,
                description: input.description ?? null,
                type: input.type ?? 'HISTORY_CREATED',
                eventTimestamp: input.eventTimestamp ?? this.getUtcNow(),
                createdBy: input.createdBy,
                updatedBy: input.updatedBy ?? input.createdBy,
                metadata: input.metadata ?? null,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('TimelineRecorded', { event });
            return event;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Semantic helpers (each maps to a TimelineEventType) ───────────────────
    async recordCreation(projectId, investigationId, entity, entityId, createdBy, tx) {
        return this.record({
            projectId, investigationId,
            title: `${entity} Created`,
            description: `${entity} ${entityId} was created.`,
            type: 'HISTORY_CREATED', createdBy,
        }, tx);
    }
    async recordUpdate(projectId, investigationId, entity, entityId, changes, updatedBy, tx) {
        return this.record({
            projectId, investigationId,
            title: `${entity} Updated`,
            description: `${entity} ${entityId} updated: ${changes}.`,
            type: 'HISTORY_CREATED', createdBy: updatedBy,
        }, tx);
    }
    async recordStatusChange(projectId, investigationId, entity, entityId, from, to, actor, tx) {
        return this.record({
            projectId, investigationId,
            title: `${entity} Status Changed`,
            description: `${entity} ${entityId} status changed from ${from} to ${to}.`,
            type: 'HISTORY_CREATED', createdBy: actor,
        }, tx);
    }
    async recordCapture(projectId, investigationId, captureId, actor, tx) {
        return this.record({
            projectId, investigationId,
            title: 'Capture Recorded',
            description: `Packet capture ${captureId} associated with investigation.`,
            type: 'EVIDENCE_ADDED', createdBy: actor,
        }, tx);
    }
    async recordScan(projectId, investigationId, scanId, actor, tx) {
        return this.record({
            projectId, investigationId,
            title: 'Scan Recorded',
            description: `Scan ${scanId} results linked to investigation.`,
            type: 'EVIDENCE_ADDED', createdBy: actor,
        }, tx);
    }
    async recordAlert(projectId, investigationId, alertId, severity, actor, tx) {
        return this.record({
            projectId, investigationId,
            title: 'Alert Generated',
            description: `Alert ${alertId} raised with severity ${severity}.`,
            type: 'ALERT_GENERATED', createdBy: actor,
        }, tx);
    }
    async recordAIAction(projectId, investigationId, action, actor, tx) {
        return this.record({
            projectId, investigationId,
            title: 'AI Action',
            description: action,
            type: 'MANUAL_ACTION', createdBy: actor,
        }, tx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────
    async getInvestigationTimeline(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.timelineRepo.findByInvestigation(investigationId, tx);
    }
    async getLatest(investigationId, limit = 20, tx) {
        return this.timelineRepo.findLatest(limit, { investigationId }, tx);
    }
}
exports.TimelineService = TimelineService;
