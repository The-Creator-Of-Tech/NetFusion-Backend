"use strict";
/**
 * AssetService — Phase A5.3.3
 * ============================
 * Business logic for Asset management. Orchestrates AssetRepository,
 * TimelineService, EvidenceRepository, and FindingRepository.
 * All multi-repository writes execute inside Prisma transactions.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AssetService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const core_1 = require("../../repositories/core");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class AssetService extends BaseService_1.BaseService {
    constructor(assetRepo = investigation_1.assetRepository, evidenceRepo = investigation_1.evidenceRepository, findingRepo = investigation_1.findingRepository, activityRepo = core_1.activityLogRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.assetRepo = assetRepo;
        this.evidenceRepo = evidenceRepo;
        this.findingRepo = findingRepo;
        this.activityRepo = activityRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Create ─────────────────────────────────────────────────────────────────
    async createAsset(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        this.validateUuid(data.investigationId, 'investigationId');
        const runInTx = async (transaction) => {
            // Duplicate detection: same hostname + IP + investigation (normalize before lookup)
            const normalizedHostname = this.normalizeHostname(data.hostname);
            const normalizedIp = this.normalizeIp(data.currentIp);
            if (normalizedHostname || normalizedIp) {
                const filter = { investigationId: data.investigationId, deletedAt: null };
                if (normalizedHostname)
                    filter.hostname = normalizedHostname;
                if (normalizedIp)
                    filter.currentIp = normalizedIp;
                const existing = await this.assetRepo.findOne(filter, transaction);
                if (existing)
                    throw new Error(`Duplicate asset: hostname/IP already exists in this investigation.`);
            }
            const asset = await this.assetRepo.create({
                ...data,
                hostname: normalizedHostname,
                currentIp: normalizedIp,
            }, transaction);
            await this.timelineSvc.recordCreation(asset.projectId, asset.investigationId, 'Asset', asset.id, data.createdBy, transaction);
            // Only create ActivityLog if createdBy is a valid UUID (real actor, not 'system'/'test')
            const actorId = data.createdBy;
            if (actorId && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actorId)) {
                await this.activityRepo.create({
                    userId: actorId, projectId: asset.projectId, investigationId: asset.investigationId,
                    action: 'CREATE', type: 'CREATE', details: `Asset ${asset.id} created`,
                    createdBy: actorId, updatedBy: actorId,
                }, transaction);
            }
            await EventPublisher_1.eventPublisher.publish('AssetCreated', { asset });
            return asset;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ─────────────────────────────────────────────────────────────────
    async updateAsset(id, data, tx) {
        this.validateUuid(id, 'assetId');
        const runInTx = async (transaction) => {
            const existing = await this.assetRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Asset "${id}" not found.`);
            const updated = await this.assetRepo.update(id, {
                ...data,
                hostname: data.hostname != null ? this.normalizeHostname(data.hostname) : undefined,
                currentIp: data.currentIp != null ? this.normalizeIp(data.currentIp) : undefined,
            }, transaction);
            await this.timelineSvc.recordUpdate(updated.projectId, updated.investigationId, 'Asset', id, 'fields updated', data.updatedBy ?? 'system', transaction);
            await EventPublisher_1.eventPublisher.publish('AssetUpdated', { asset: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Merge ──────────────────────────────────────────────────────────────────
    async mergeAssets(sourceId, targetId, actor, tx) {
        this.validateUuid(sourceId, 'sourceId');
        this.validateUuid(targetId, 'targetId');
        const runInTx = async (transaction) => {
            const [source, target] = await Promise.all([
                this.assetRepo.findById(sourceId, transaction),
                this.assetRepo.findById(targetId, transaction),
            ]);
            if (!source || source.deletedAt)
                throw new Error(`Source asset "${sourceId}" not found.`);
            if (!target || target.deletedAt)
                throw new Error(`Target asset "${targetId}" not found.`);
            // Re-point evidence and findings from source → target
            await prisma_1.default.evidence.updateMany({ where: { assetId: sourceId }, data: { assetId: targetId } });
            await prisma_1.default.finding.updateMany({ where: { assetId: sourceId }, data: { assetId: targetId } });
            // Soft-delete source
            await this.assetRepo.softDelete(sourceId, actor, transaction);
            // Merge metadata
            const mergedMeta = { ...(target.metadata ?? {}), ...(source.metadata ?? {}), mergedFrom: sourceId };
            const merged = await this.assetRepo.update(targetId, {
                metadata: mergedMeta, riskScore: Math.max(source.riskScore, target.riskScore),
                updatedBy: actor,
            }, transaction);
            await this.timelineSvc.record({
                projectId: merged.projectId, investigationId: merged.investigationId,
                title: 'Assets Merged', description: `Asset ${sourceId} merged into ${targetId}.`,
                type: 'HISTORY_CREATED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AssetsMerged', { source, target: merged });
            return merged;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Enrich ─────────────────────────────────────────────────────────────────
    async enrichAsset(id, enrichment, actor, tx) {
        this.validateUuid(id, 'assetId');
        const runInTx = async (transaction) => {
            const existing = await this.assetRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Asset "${id}" not found.`);
            const merged = { ...(existing.metadata ?? {}), ...enrichment };
            const enriched = await this.assetRepo.update(id, { metadata: merged, updatedBy: actor }, transaction);
            await this.timelineSvc.record({
                projectId: enriched.projectId, investigationId: enriched.investigationId,
                title: 'Asset Enriched', description: `Enrichment data added to asset ${id}.`,
                type: 'EVIDENCE_ADDED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AssetEnriched', { asset: enriched });
            return enriched;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Risk score ─────────────────────────────────────────────────────────────
    async calculateRiskScore(id, tx) {
        this.validateUuid(id, 'assetId');
        const runInTx = async (transaction) => {
            const [asset, findings, evidence] = await Promise.all([
                this.assetRepo.findById(id, transaction),
                this.findingRepo.findByAsset(id, transaction),
                this.evidenceRepo.findByAsset(id, transaction),
            ]);
            if (!asset || asset.deletedAt)
                throw new Error(`Asset "${id}" not found.`);
            let score = 0;
            const severityWeights = { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 8, INFO: 2 };
            for (const f of findings) {
                score += severityWeights[f.severity] ?? 5;
            }
            score += Math.min(evidence.length * 2, 20); // evidence volume bonus, capped
            score = Math.min(score, 100);
            await this.assetRepo.update(id, { riskScore: score, updatedBy: 'system' }, transaction);
            return score;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Associations ───────────────────────────────────────────────────────────
    async associateEvidence(assetId, evidenceId, actor, tx) {
        this.validateUuid(assetId, 'assetId');
        this.validateUuid(evidenceId, 'evidenceId');
        const runInTx = async (transaction) => {
            await prisma_1.default.evidence.update({ where: { id: evidenceId }, data: { assetId, updatedBy: actor } });
            const asset = await this.assetRepo.findById(assetId, transaction);
            if (!asset)
                throw new Error(`Asset "${assetId}" not found.`);
            await this.timelineSvc.record({
                projectId: asset.projectId, investigationId: asset.investigationId,
                title: 'Evidence Linked to Asset', description: `Evidence ${evidenceId} associated with asset ${assetId}.`,
                type: 'EVIDENCE_ADDED', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AssetEvidenceLinked', { assetId, evidenceId });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async associateFindings(assetId, findingIds, actor, tx) {
        this.validateUuid(assetId, 'assetId');
        const runInTx = async (transaction) => {
            for (const fid of findingIds) {
                await prisma_1.default.finding.update({ where: { id: fid }, data: { assetId, updatedBy: actor } });
            }
            const asset = await this.assetRepo.findById(assetId, transaction);
            if (!asset)
                throw new Error(`Asset "${assetId}" not found.`);
            await this.timelineSvc.record({
                projectId: asset.projectId, investigationId: asset.investigationId,
                title: 'Findings Associated', description: `${findingIds.length} finding(s) linked to asset.`,
                type: 'FINDING_CREATED', createdBy: actor,
            }, transaction);
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Summary ────────────────────────────────────────────────────────────────
    async summarizeAsset(id, tx) {
        this.validateUuid(id, 'assetId');
        const runInTx = async (transaction) => {
            const [asset, findings, evidence] = await Promise.all([
                this.assetRepo.findById(id, transaction),
                this.findingRepo.findByAsset(id, transaction),
                this.evidenceRepo.findByAsset(id, transaction),
            ]);
            if (!asset || asset.deletedAt)
                throw new Error(`Asset "${id}" not found.`);
            const openFindings = findings.filter(f => f.status === 'OPEN');
            const criticalFindings = findings.filter(f => f.severity === 'CRITICAL');
            return {
                id: asset.id, hostname: asset.hostname, currentIp: asset.currentIp,
                type: asset.type, riskScore: asset.riskScore,
                findingsTotal: findings.length, openFindings: openFindings.length,
                criticalFindings: criticalFindings.length, evidenceTotal: evidence.length,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Private helpers ────────────────────────────────────────────────────────
    normalizeHostname(h) {
        return h ? h.trim().toLowerCase() : undefined;
    }
    normalizeIp(ip) {
        return ip ? ip.trim() : undefined;
    }
}
exports.AssetService = AssetService;
