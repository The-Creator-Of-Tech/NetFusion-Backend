"use strict";
/**
 * FindingService — Phase A5.3.3
 * ===============================
 * Business logic for Finding lifecycle management.
 * All multi-repository writes run inside Prisma transactions.
 * Automatically raises Alerts when severity is HIGH or CRITICAL.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const core_1 = require("../../repositories/core");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const HIGH_SEVERITY = ['HIGH', 'CRITICAL'];
class FindingService extends BaseService_1.BaseService {
    constructor(findingRepo = investigation_1.findingRepository, alertRepo = investigation_1.alertRepository, evidenceRepo = investigation_1.evidenceRepository, activityRepo = core_1.activityLogRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.findingRepo = findingRepo;
        this.alertRepo = alertRepo;
        this.evidenceRepo = evidenceRepo;
        this.activityRepo = activityRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Create ─────────────────────────────────────────────────────────────────
    async createFinding(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'title', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        this.validateUuid(data.investigationId, 'investigationId');
        const runInTx = async (transaction) => {
            const finding = await this.findingRepo.create(data, transaction);
            await this.timelineSvc.record({
                projectId: finding.projectId, investigationId: finding.investigationId,
                title: 'Finding Created',
                description: `Finding "${finding.title}" (${finding.severity}) created.`,
                type: 'FINDING_CREATED', createdBy: data.createdBy,
            }, transaction);
            // Only create ActivityLog if createdBy is a valid UUID
            const actorId = data.createdBy;
            if (actorId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actorId)) {
                await this.activityRepo.create({
                    userId: actorId, projectId: finding.projectId, investigationId: finding.investigationId,
                    action: 'CREATE', type: 'CREATE', details: `Finding "${finding.title}" created`,
                    createdBy: actorId, updatedBy: actorId,
                }, transaction);
            }
            // Auto-raise alert for HIGH/CRITICAL findings
            if (HIGH_SEVERITY.includes(finding.severity)) {
                await this._raiseAlert(finding, data.createdBy, transaction);
            }
            await EventPublisher_1.eventPublisher.publish('FindingCreated', { finding });
            return finding;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ─────────────────────────────────────────────────────────────────
    async updateFinding(id, data, tx) {
        this.validateUuid(id, 'findingId');
        const runInTx = async (transaction) => {
            const existing = await this.findingRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Finding "${id}" not found.`);
            const updated = await this.findingRepo.update(id, data, transaction);
            // Auto-alert on severity escalation to HIGH/CRITICAL
            const prevSev = existing.severity;
            const newSev = data.severity ?? existing.severity;
            if (!HIGH_SEVERITY.includes(prevSev) && HIGH_SEVERITY.includes(newSev)) {
                await this._raiseAlert(updated, data.updatedBy ?? 'system', transaction);
            }
            await this.timelineSvc.recordUpdate(updated.projectId, updated.investigationId, 'Finding', id, 'fields updated', data.updatedBy ?? 'system', transaction);
            await EventPublisher_1.eventPublisher.publish('FindingUpdated', { finding: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Severity / Status ──────────────────────────────────────────────────────
    async changeSeverity(id, severity, actor, tx) {
        this.validateUuid(id, 'findingId');
        const runInTx = async (transaction) => {
            const existing = await this.findingRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Finding "${id}" not found.`);
            const updated = await this.findingRepo.update(id, { severity, updatedBy: actor }, transaction);
            await this.timelineSvc.recordStatusChange(updated.projectId, updated.investigationId, 'Finding', id, existing.severity, severity, actor, transaction);
            if (!HIGH_SEVERITY.includes(existing.severity) && HIGH_SEVERITY.includes(severity)) {
                await this._raiseAlert(updated, actor, transaction);
            }
            await EventPublisher_1.eventPublisher.publish('FindingSeverityChanged', { finding: updated, from: existing.severity, to: severity });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async changeStatus(id, status, actor, tx) {
        this.validateUuid(id, 'findingId');
        const runInTx = async (transaction) => {
            const existing = await this.findingRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Finding "${id}" not found.`);
            const updated = await this.findingRepo.update(id, { status, updatedBy: actor }, transaction);
            await this.timelineSvc.recordStatusChange(updated.projectId, updated.investigationId, 'Finding', id, existing.status, status, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('FindingStatusChanged', { finding: updated, from: existing.status, to: status });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Asset / Evidence / MITRE ───────────────────────────────────────────────
    async assignAsset(findingId, assetId, actor, tx) {
        this.validateUuid(findingId, 'findingId');
        this.validateUuid(assetId, 'assetId');
        const runInTx = async (transaction) => {
            const f = await this.findingRepo.findById(findingId, transaction);
            if (!f || f.deletedAt)
                throw new Error(`Finding "${findingId}" not found.`);
            const updated = await this.findingRepo.update(findingId, { assetId, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: updated.projectId, investigationId: updated.investigationId,
                title: 'Asset Assigned to Finding',
                description: `Asset ${assetId} linked to finding "${updated.title}".`,
                type: 'HISTORY_CREATED', createdBy: actor,
            }, transaction);
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async attachEvidence(findingId, evidenceId, actor, tx) {
        this.validateUuid(findingId, 'findingId');
        this.validateUuid(evidenceId, 'evidenceId');
        const runInTx = async (transaction) => {
            await prisma_1.default.evidence.update({ where: { id: evidenceId }, data: { findingId, updatedBy: actor } });
            const f = await this.findingRepo.findById(findingId, transaction);
            if (!f)
                throw new Error(`Finding "${findingId}" not found.`);
            await this.timelineSvc.record({
                projectId: f.projectId, investigationId: f.investigationId,
                title: 'Evidence Attached to Finding',
                description: `Evidence ${evidenceId} attached to finding "${f.title}".`,
                type: 'EVIDENCE_ADDED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('EvidenceAttached', { findingId, evidenceId });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async mapMitreTechnique(findingId, techniqueId, actor, tx) {
        this.validateUuid(findingId, 'findingId');
        const runInTx = async (transaction) => {
            const f = await this.findingRepo.findById(findingId, transaction);
            if (!f || f.deletedAt)
                throw new Error(`Finding "${findingId}" not found.`);
            const meta = { ...(f.metadata ?? {}), mitreTechniques: [...(f.metadata?.mitreTechniques ?? []), techniqueId] };
            const updated = await this.findingRepo.update(findingId, { metadata: meta, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: updated.projectId, investigationId: updated.investigationId,
                title: 'MITRE Technique Mapped', description: `Technique ${techniqueId} mapped to finding.`,
                type: 'MITRE_MAPPED', createdBy: actor,
            }, transaction);
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Priority ───────────────────────────────────────────────────────────────
    async calculatePriority(id, tx) {
        this.validateUuid(id, 'findingId');
        const f = await this.findingRepo.findById(id, tx);
        if (!f || f.deletedAt)
            throw new Error(`Finding "${id}" not found.`);
        const sevScore = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 10 };
        const statusBonus = { OPEN: 20, CONFIRMED: 15, SUPPRESSED: 0, FALSE_POSITIVE: 0, RESOLVED: 0, CLOSED: 0 };
        return Math.min((sevScore[f.severity] ?? 50) + (statusBonus[f.status] ?? 0), 100);
    }
    // ── Internal ───────────────────────────────────────────────────────────────
    async _raiseAlert(finding, actor, tx) {
        const alert = await this.alertRepo.create({
            projectId: finding.projectId,
            investigationId: finding.investigationId,
            findingId: finding.id,
            title: `Alert: ${finding.title}`,
            description: `Auto-generated from ${finding.severity} finding.`,
            severity: finding.severity,
            status: 'NEW',
            source: 'FINDING',
            riskScore: finding.riskScore,
            confidence: finding.confidence,
            createdBy: actor,
            updatedBy: actor,
        }, tx);
        await this.timelineSvc.recordAlert(finding.projectId, finding.investigationId, alert.id, finding.severity, actor, tx);
        await EventPublisher_1.eventPublisher.publish('AlertRaised', { alert, finding });
    }
}
exports.FindingService = FindingService;
