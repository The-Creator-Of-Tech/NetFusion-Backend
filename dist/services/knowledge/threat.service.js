"use strict";
/**
 * ThreatService — Phase A5.3.5
 * =============================
 * Business logic for Threat Actor and Campaign lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for ThreatActor, ThreatCampaign, ThreatRelationship
 * - Threat actor correlation (CVE, IOC, MITRE technique linkage)
 * - Campaign mapping (actor ↔ campaign M2M)
 * - IOC relationship management for threat actors
 * - Risk aggregation and threat scoring
 * - Event publishing after every state change
 * - Transaction support (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.threatService = exports.ThreatService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const knowledge_1 = require("../../repositories/knowledge");
const prisma_1 = __importDefault(require("../../lib/prisma"));
// ── Severity score map ────────────────────────────────────────────────────────
const THREAT_LEVEL_SCORE = {
    CRITICAL: 100,
    HIGH: 75,
    MEDIUM: 50,
    LOW: 25,
};
// ── Confidence weight map ─────────────────────────────────────────────────────
const CONFIDENCE_WEIGHT = {
    VERIFIED: 100,
    HIGH: 75,
    MEDIUM: 50,
    LOW: 25,
};
class ThreatService extends BaseService_1.BaseService {
    constructor(threatRepo = knowledge_1.threatRepository) {
        super();
        this.threatRepo = threatRepo;
    }
    // ── ThreatActor CRUD ───────────────────────────────────────────────────────
    /**
     * Create a new ThreatActor.
     * Publishes ThreatActorCreated.
     */
    async createThreatActor(data, tx) {
        this.validateRequired(data, ['threatId', 'name', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            // Conflict: same threatId
            const existing = await this.threatRepo.findOne({ threatId: String(data.threatId), deletedAt: null }, transaction);
            if (existing) {
                throw new Error(`Conflict: ThreatActor with threatId "${data.threatId}" already exists.`);
            }
            const actor = await this.threatRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('ThreatActorCreated', { actor });
            return actor;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Update a ThreatActor by UUID.
     * Publishes ThreatActorUpdated.
     */
    async updateThreatActor(id, data, tx) {
        this.validateUuid(id, 'threatActorId');
        const runInTx = async (transaction) => {
            const existing = await this.threatRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ThreatActor "${id}" not found.`);
            }
            const updated = await this.threatRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('ThreatActorUpdated', { actor: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Soft-delete a ThreatActor.
     * Publishes ThreatActorDeleted.
     */
    async deleteThreatActor(id, actor, tx) {
        this.validateUuid(id, 'threatActorId');
        const runInTx = async (transaction) => {
            const existing = await this.threatRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ThreatActor "${id}" not found.`);
            }
            const deleted = await this.threatRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ThreatActorDeleted', { actor: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── ThreatActor Lookups ────────────────────────────────────────────────────
    /** Find threat actors by severity level. */
    async findByThreatLevel(severity, tx) {
        return this.threatRepo.findByThreatLevel(severity, tx);
    }
    /** Find threat actors by status. */
    async findByStatus(status, tx) {
        return this.threatRepo.findByStatus(status, tx);
    }
    /** Find threat actors by name or alias. */
    async findByActor(name, tx) {
        if (!name || !name.trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        return this.threatRepo.findByActor(name.trim(), tx);
    }
    /** Find threat actors involved in a campaign (by UUID or campaignId string). */
    async findByCampaign(campaignId, tx) {
        if (!campaignId || !campaignId.trim()) {
            throw new Error('Validation failed: campaignId must not be empty.');
        }
        return this.threatRepo.findByCampaign(campaignId.trim(), tx);
    }
    // ── Campaign CRUD ──────────────────────────────────────────────────────────
    /**
     * Create a new ThreatCampaign.
     * Publishes ThreatCampaignCreated.
     */
    async createCampaign(data, tx) {
        if (!data.campaignId || !data.campaignId.trim()) {
            throw new Error('Validation failed: campaignId must not be empty.');
        }
        if (!data.name || !data.name.trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            // Conflict check
            const existing = await client.threatCampaign.findFirst({
                where: { campaignId: data.campaignId.trim(), deletedAt: null },
            });
            if (existing) {
                throw new Error(`Conflict: ThreatCampaign with campaignId "${data.campaignId}" already exists.`);
            }
            const campaign = await client.threatCampaign.create({
                data: {
                    campaignId: data.campaignId.trim(),
                    name: data.name.trim(),
                    confidence: data.confidence,
                    status: data.status ?? 'ACTIVE',
                    description: data.description ?? '',
                    startDate: data.startDate ? new Date(data.startDate) : null,
                    endDate: data.endDate ? new Date(data.endDate) : null,
                    active: data.active ?? true,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                    ...(data.threatActorIds?.length
                        ? { threatActors: { connect: data.threatActorIds.map((id) => ({ id })) } }
                        : {}),
                },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatCampaignCreated', { campaign });
            return campaign;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Update a ThreatCampaign by UUID.
     * Publishes ThreatCampaignUpdated.
     */
    async updateCampaign(id, data, tx) {
        this.validateUuid(id, 'campaignId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.threatCampaign.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ThreatCampaign "${id}" not found.`);
            }
            const updated = await client.threatCampaign.update({
                where: { id },
                data,
            });
            await EventPublisher_1.eventPublisher.publish('ThreatCampaignUpdated', { campaign: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Soft-delete a ThreatCampaign.
     * Publishes ThreatCampaignDeleted.
     */
    async deleteCampaign(id, actor, tx) {
        this.validateUuid(id, 'campaignId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.threatCampaign.findUnique({ where: { id } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ThreatCampaign "${id}" not found.`);
            }
            const deleted = await client.threatCampaign.update({
                where: { id },
                data: { deletedAt: new Date(), updatedBy: actor },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatCampaignDeleted', { campaign: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Campaign Mapping ───────────────────────────────────────────────────────
    /**
     * Link a ThreatActor to a ThreatCampaign.
     * Publishes ThreatActorCampaignLinked.
     */
    async linkActorToCampaign(actorId, campaignId, actor, tx) {
        this.validateUuid(actorId, 'actorId');
        this.validateUuid(campaignId, 'campaignId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const threatActor = await this.threatRepo.findById(actorId, transaction);
            if (!threatActor || threatActor.deletedAt) {
                throw new Error(`ThreatActor "${actorId}" not found.`);
            }
            const campaign = await client.threatCampaign.findUnique({ where: { id: campaignId } });
            if (!campaign || campaign.deletedAt) {
                throw new Error(`ThreatCampaign "${campaignId}" not found.`);
            }
            const updated = await client.threatCampaign.update({
                where: { id: campaignId },
                data: {
                    threatActors: { connect: { id: actorId } },
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatActorCampaignLinked', { actorId, campaignId });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Unlink a ThreatActor from a ThreatCampaign.
     * Publishes ThreatActorCampaignUnlinked.
     */
    async unlinkActorFromCampaign(actorId, campaignId, actor, tx) {
        this.validateUuid(actorId, 'actorId');
        this.validateUuid(campaignId, 'campaignId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const updated = await client.threatCampaign.update({
                where: { id: campaignId },
                data: {
                    threatActors: { disconnect: { id: actorId } },
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatActorCampaignUnlinked', { actorId, campaignId });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /** Get campaigns for a ThreatActor. */
    async getCampaigns(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        return this.threatRepo.findCampaigns(threatActorId, tx);
    }
    // ── IOC Relationships ──────────────────────────────────────────────────────
    /** Get relationships for a ThreatActor. */
    async getRelationships(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        return this.threatRepo.findRelationships(threatActorId, tx);
    }
    /**
     * Add a ThreatRelationship for a ThreatActor.
     * Publishes ThreatRelationshipAdded.
     */
    async addRelationship(data, tx) {
        if (!data.targetType || !data.targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const relationship = await client.threatRelationship.create({
                data: {
                    threatId: data.threatId ?? null,
                    campaignId: data.campaignId ?? null,
                    cveId: data.cveId ?? null,
                    mitreId: data.mitreId ?? null,
                    targetType: data.targetType.trim(),
                    relationType: data.relationType,
                    confidence: data.confidence ?? 0,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatRelationshipAdded', { relationship });
            return relationship;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Correlation ────────────────────────────────────────────────────────────
    /** Get MITRE techniques used by a ThreatActor. */
    async getTechniques(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        return this.threatRepo.findTechniques(threatActorId, tx);
    }
    /**
     * Link MITRE techniques to a ThreatActor.
     * Publishes ThreatActorTechniquesLinked.
     */
    async linkTechniques(threatActorId, techniqueIds, actor, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        if (!techniqueIds || techniqueIds.length === 0) {
            throw new Error('Validation failed: techniqueIds must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await this.threatRepo.findById(threatActorId, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ThreatActor "${threatActorId}" not found.`);
            }
            const updated = await client.threatActor.update({
                where: { id: threatActorId },
                data: {
                    techniques: { connect: techniqueIds.map((id) => ({ id })) },
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatActorTechniquesLinked', { threatActorId, techniqueIds });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /** Get IOCs associated with a ThreatActor. */
    async getAssociatedIocs(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        return this.threatRepo.findAssociatedIOCs(threatActorId, tx);
    }
    /**
     * Link IOCs to a ThreatActor.
     * Publishes ThreatActorIocsLinked.
     */
    async linkIocs(threatActorId, iocIds, actor, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        if (!iocIds || iocIds.length === 0) {
            throw new Error('Validation failed: iocIds must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await this.threatRepo.findById(threatActorId, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ThreatActor "${threatActorId}" not found.`);
            }
            const updated = await client.threatActor.update({
                where: { id: threatActorId },
                data: {
                    iocs: { connect: iocIds.map((id) => ({ id })) },
                    updatedBy: actor,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ThreatActorIocsLinked', { threatActorId, iocIds });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /** Get CVEs associated with a ThreatActor (via ThreatRelationship). */
    async getAssociatedCves(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        return this.threatRepo.findAssociatedCVEs(threatActorId, tx);
    }
    // ── Scoring ────────────────────────────────────────────────────────────────
    /**
     * Calculate a threat score (0–100) for a ThreatActor based on severity
     * and confidence, optionally weighted by active/inactive status.
     */
    async calculateThreatScore(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        const actor = await this.threatRepo.findById(threatActorId, tx);
        if (!actor || actor.deletedAt) {
            throw new Error(`ThreatActor "${threatActorId}" not found.`);
        }
        const levelScore = THREAT_LEVEL_SCORE[String(actor.severity ?? 'MEDIUM')] ?? 50;
        const confWeight = CONFIDENCE_WEIGHT[String(actor.confidence ?? 'MEDIUM').toUpperCase()] ?? 50;
        const activeBonus = actor.active ? 10 : 0;
        const score = Math.round((levelScore * confWeight) / 100) + activeBonus;
        return Math.min(100, score);
    }
    /**
     * Aggregate threat score across multiple ThreatActor IDs (0–100, mean).
     */
    async aggregateThreatScore(threatActorIds, tx) {
        if (!threatActorIds || threatActorIds.length === 0)
            return 0;
        const scores = await Promise.all(threatActorIds.map((id) => this.calculateThreatScore(id, tx)));
        return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }
    /**
     * Score a campaign (0–100) by the max score across its threat actors.
     */
    async scoreCampaign(campaignId, tx) {
        this.validateUuid(campaignId, 'campaignId');
        const actors = await this.threatRepo.findByCampaign(campaignId, tx);
        if (actors.length === 0)
            return 0;
        const scores = await Promise.all(actors.map((a) => this.calculateThreatScore(a.id, tx)));
        return Math.max(...scores);
    }
    // ── Statistics ─────────────────────────────────────────────────────────────
    /**
     * Compute threat statistics across the knowledge base.
     */
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const [total, active, allActors, allCampaigns] = await Promise.all([
            client.threatActor.count({ where: { deletedAt: null } }),
            client.threatActor.count({ where: { deletedAt: null, active: true } }),
            client.threatActor.findMany({ where: { deletedAt: null } }),
            client.threatCampaign.findMany({ where: { deletedAt: null } }),
        ]);
        const actorCounts = {};
        const countryCounts = {};
        let confSum = 0;
        let sevSum = 0;
        for (const a of allActors) {
            const sev = String(a.severity ?? 'UNKNOWN');
            actorCounts[sev] = (actorCounts[sev] ?? 0) + 1;
            sevSum += THREAT_LEVEL_SCORE[sev] ?? 50;
            confSum += CONFIDENCE_WEIGHT[String(a.confidence ?? 'MEDIUM').toUpperCase()] ?? 50;
            if (a.country) {
                countryCounts[a.country] = (countryCounts[a.country] ?? 0) + 1;
            }
        }
        const campaignCounts = {};
        for (const c of allCampaigns) {
            const status = String(c.status ?? 'UNKNOWN');
            campaignCounts[status] = (campaignCounts[status] ?? 0) + 1;
        }
        return {
            totalThreats: total,
            activeThreats: active,
            averageConfidence: total > 0 ? Math.round(confSum / total) : 0,
            averageSeverityScore: total > 0 ? Math.round(sevSum / total) : 0,
            actorCounts,
            campaignCounts,
            countryCounts,
        };
    }
    // ── Bulk Operations ────────────────────────────────────────────────────────
    /**
     * Bulk-create ThreatActors.
     */
    async bulkCreateActors(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const created = await this.createThreatActor({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(created.id);
            }
            catch (e) {
                failed.push({
                    threatId: String(item.threatId ?? ''),
                    reason: e.message ?? 'Unknown error',
                });
            }
        }
        await EventPublisher_1.eventPublisher.publish('ThreatActorsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    /**
     * Bulk soft-delete ThreatActors.
     */
    async bulkDeleteActors(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteThreatActor(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('ThreatActorsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.ThreatService = ThreatService;
exports.threatService = new ThreatService();
