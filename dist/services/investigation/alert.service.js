"use strict";
/**
 * AlertService — Phase A5.3.3
 * =============================
 * Business logic for Alert lifecycle management.
 * Handles creation, acknowledgement, resolution, suppression, and scoring.
 * Every state transition records a timeline event and publishes a domain event.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlertService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const core_1 = require("../../repositories/core");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const SEVERITY_SCORES = {
    CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 10,
};
class AlertService extends BaseService_1.BaseService {
    constructor(alertRepo = investigation_1.alertRepository, activityRepo = core_1.activityLogRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.alertRepo = alertRepo;
        this.activityRepo = activityRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Create ─────────────────────────────────────────────────────────────────
    async createAlert(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'title', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        this.validateUuid(data.investigationId, 'investigationId');
        const runInTx = async (transaction) => {
            const riskScore = SEVERITY_SCORES[data.severity ?? 'MEDIUM'] ?? 50;
            const alert = await this.alertRepo.create({ ...data, riskScore }, transaction);
            await this.timelineSvc.recordAlert(alert.projectId, alert.investigationId, alert.id, alert.severity, data.createdBy, transaction);
            // Only create ActivityLog if createdBy is a valid UUID
            const actorId = data.createdBy;
            if (actorId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actorId)) {
                await this.activityRepo.create({
                    userId: actorId, projectId: alert.projectId, investigationId: alert.investigationId,
                    action: 'CREATE', type: 'CREATE', details: `Alert "${alert.title}" created`,
                    createdBy: actorId, updatedBy: actorId,
                }, transaction);
            }
            await EventPublisher_1.eventPublisher.publish('AlertRaised', { alert });
            return alert;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ─────────────────────────────────────────────────
    async acknowledgeAlert(id, actor, tx) {
        return this._transition(id, 'ACKNOWLEDGED', actor, 'Alert Acknowledged', tx);
    }
    async resolveAlert(id, actor, tx) {
        return this._transition(id, 'RESOLVED', actor, 'Alert Resolved', tx);
    }
    async suppressAlert(id, actor, reason, tx) {
        return this._transition(id, 'SUPPRESSED', actor, `Alert Suppressed${reason ? ': ' + reason : ''}`, tx);
    }
    async reopenAlert(id, actor, tx) {
        return this._transition(id, 'OPEN', actor, 'Alert Reopened', tx);
    }
    // ── Severity escalation ───────────────────────────────────────────────────
    async escalate(id, severity, actor, tx) {
        this.validateUuid(id, 'alertId');
        const runInTx = async (transaction) => {
            const existing = await this.alertRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Alert "${id}" not found.`);
            const newScore = SEVERITY_SCORES[severity] ?? existing.riskScore;
            const updated = await this.alertRepo.update(id, { severity, riskScore: newScore, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: updated.projectId, investigationId: updated.investigationId,
                title: 'Alert Escalated',
                description: `Alert severity escalated from ${existing.severity} to ${severity}.`,
                type: 'ALERT_GENERATED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AlertEscalated', { alert: updated, from: existing.severity, to: severity });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Score ─────────────────────────────────────────────────────────────────
    async calculateAlertScore(id, tx) {
        this.validateUuid(id, 'alertId');
        const alert = await this.alertRepo.findById(id, tx);
        if (!alert || alert.deletedAt)
            throw new Error(`Alert "${id}" not found.`);
        const base = SEVERITY_SCORES[alert.severity] ?? 50;
        const conf = (alert.confidence / 100) * 20; // confidence bonus, max 20
        const score = Math.min(Math.round(base + conf), 100);
        await this.alertRepo.update(id, { riskScore: score, updatedBy: 'system' }, tx);
        return score;
    }
    // ── Read helpers ──────────────────────────────────────────────────────────
    async getOpenAlerts(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.alertRepo.findByStatus('OPEN', tx);
    }
    async getByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.alertRepo.findByInvestigation(investigationId, tx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────
    async _transition(id, status, actor, label, tx) {
        this.validateUuid(id, 'alertId');
        const runInTx = async (transaction) => {
            const existing = await this.alertRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Alert "${id}" not found.`);
            const updated = await this.alertRepo.update(id, { status, updatedBy: actor }, transaction);
            await this.timelineSvc.recordStatusChange(updated.projectId, updated.investigationId, 'Alert', id, existing.status, status, actor, transaction);
            await EventPublisher_1.eventPublisher.publish(`Alert${status.charAt(0) + status.slice(1).toLowerCase()}`, { alert: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.AlertService = AlertService;
