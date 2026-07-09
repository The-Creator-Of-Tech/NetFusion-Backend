"use strict";
/**
 * IocService — Phase A5.3.5
 * ==========================
 * Business logic for IOC (Indicator of Compromise) lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for IOC records, relationships, and enrichment
 * - IOC enrichment (reputation score, malicious flag, categories)
 * - IOC relationship management (CVE, ThreatActor, Campaign linkage)
 * - IOC type/severity/confidence filtering
 * - IOC correlation with MITRE techniques and CVEs
 * - Risk scoring and threat scoring
 * - Event publishing after every state change
 * - Transaction support (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.iocService = exports.IocService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const knowledge_1 = require("../../repositories/knowledge");
const prisma_1 = __importDefault(require("../../lib/prisma"));
// ── IOC confidence weight map ─────────────────────────────────────────────────
const CONFIDENCE_WEIGHT = {
    VERIFIED: 100,
    HIGH: 75,
    MEDIUM: 50,
    LOW: 25,
};
// ── Severity score map ────────────────────────────────────────────────────────
const SEVERITY_SCORE = {
    CRITICAL: 100,
    HIGH: 75,
    MEDIUM: 50,
    LOW: 25,
};
class IocService extends BaseService_1.BaseService {
    constructor(iocRepo = knowledge_1.iocRepository) {
        super();
        this.iocRepo = iocRepo;
    }
    // ── Create ─────────────────────────────────────────────────────────────────
    /**
     * Create a new IOC. Validates iocType and value presence.
     * Publishes IocCreated.
     */
    async createIoc(data, tx) {
        this.validateRequired(data, ['iocId', 'value', 'iocType', 'createdBy', 'updatedBy']);
        if (!data.value || !String(data.value).trim()) {
            throw new Error('Validation failed: value must not be empty.');
        }
        const runInTx = async (transaction) => {
            const existing = await this.iocRepo.findByValue(String(data.value).trim(), transaction);
            if (existing) {
                throw new Error(`Conflict: IOC with value "${data.value}" already exists.`);
            }
            const ioc = await this.iocRepo.create({ ...data, value: String(data.value).trim() }, transaction);
            await EventPublisher_1.eventPublisher.publish('IocCreated', { ioc });
            return ioc;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ─────────────────────────────────────────────────────────────────
    /**
     * Update an IOC by UUID.
     * Publishes IocUpdated.
     */
    async updateIoc(id, data, tx) {
        this.validateUuid(id, 'iocId');
        const runInTx = async (transaction) => {
            const existing = await this.iocRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`IOC "${id}" not found.`);
            }
            const updated = await this.iocRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('IocUpdated', { ioc: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ─────────────────────────────────────────────────────────────────
    /**
     * Soft-delete an IOC.
     * Publishes IocDeleted.
     */
    async deleteIoc(id, actor, tx) {
        this.validateUuid(id, 'iocId');
        const runInTx = async (transaction) => {
            const existing = await this.iocRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`IOC "${id}" not found.`);
            }
            const deleted = await this.iocRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('IocDeleted', { ioc: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookup ─────────────────────────────────────────────────────────────────
    /** Find an IOC by its indicator value. */
    async findByValue(value, tx) {
        if (!value || !value.trim()) {
            throw new Error('Validation failed: value must not be empty.');
        }
        return this.iocRepo.findByValue(value.trim(), tx);
    }
    /** Find IOCs by type. */
    async findByType(iocType, tx) {
        return this.iocRepo.findByType(iocType, tx);
    }
    /** Find IOCs by status. */
    async findByStatus(status, tx) {
        return this.iocRepo.findByStatus(status, tx);
    }
    /** Find all malicious IOCs. */
    async findMalicious(tx) {
        return this.iocRepo.findMalicious(tx);
    }
    /** Find all revoked IOCs. */
    async findRevoked(tx) {
        return this.iocRepo.findRevoked(tx);
    }
    /** Find IOCs by confidence classification or numeric range. */
    async findByConfidence(min, max, tx) {
        return this.iocRepo.findByConfidence(min, max, tx);
    }
    /** Find IOCs by source. */
    async findBySource(source, tx) {
        if (!source || !source.trim()) {
            throw new Error('Validation failed: source must not be empty.');
        }
        return this.iocRepo.findBySource(source.trim(), tx);
    }
    // ── Enrichment ─────────────────────────────────────────────────────────────
    /** Get enrichment record for an IOC. */
    async getEnrichment(iocId, tx) {
        this.validateUuid(iocId, 'iocId');
        return this.iocRepo.findEnrichment(iocId, tx);
    }
    /**
     * Upsert enrichment data for an IOC.
     * Reputation score must be 0–100.
     * Publishes IocEnriched.
     */
    async enrichIoc(iocId, data, tx) {
        this.validateUuid(iocId, 'iocId');
        if (typeof data.reputationScore !== 'number' ||
            data.reputationScore < 0 ||
            data.reputationScore > 100) {
            throw new Error(`Validation failed: reputationScore ${data.reputationScore} must be in [0, 100].`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const ioc = await this.iocRepo.findById(iocId, transaction);
            if (!ioc || ioc.deletedAt) {
                throw new Error(`IOC "${iocId}" not found.`);
            }
            const existing = await this.iocRepo.findEnrichment(iocId, transaction);
            let enrichment;
            if (existing) {
                enrichment = await client.iOCEnrichment.update({
                    where: { id: existing.id },
                    data: {
                        reputationScore: data.reputationScore,
                        malicious: data.malicious,
                        categories: data.categories ?? existing.categories,
                        firstSeen: data.firstSeen ?? existing.firstSeen,
                        lastSeen: data.lastSeen ?? existing.lastSeen,
                        provider: data.provider ?? existing.provider,
                        updatedBy: data.updatedBy,
                    },
                });
            }
            else {
                enrichment = await client.iOCEnrichment.create({
                    data: {
                        iocId,
                        reputationScore: data.reputationScore,
                        malicious: data.malicious,
                        categories: data.categories ?? [],
                        firstSeen: data.firstSeen ? new Date(data.firstSeen) : null,
                        lastSeen: data.lastSeen ? new Date(data.lastSeen) : null,
                        provider: data.provider ?? '',
                        createdBy: data.createdBy,
                        updatedBy: data.updatedBy,
                    },
                });
            }
            await EventPublisher_1.eventPublisher.publish('IocEnriched', { iocId, enrichment });
            return enrichment;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Relationships ──────────────────────────────────────────────────────────
    /** Get relationships for an IOC. */
    async getRelationships(iocId, tx) {
        this.validateUuid(iocId, 'iocId');
        return this.iocRepo.findRelationships(iocId, tx);
    }
    /**
     * Add a relationship between an IOC and another entity.
     * Publishes IocRelationshipAdded.
     */
    async addRelationship(iocId, data, tx) {
        this.validateUuid(iocId, 'iocId');
        if (!data.targetType || !data.targetType.trim()) {
            throw new Error('Validation failed: targetType must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const ioc = await this.iocRepo.findById(iocId, transaction);
            if (!ioc || ioc.deletedAt) {
                throw new Error(`IOC "${iocId}" not found.`);
            }
            const relationship = await client.iOCRelationship.create({
                data: {
                    iocId,
                    cveId: data.cveId ?? null,
                    threatId: data.threatId ?? null,
                    targetType: data.targetType.trim(),
                    relationType: data.relationType,
                    confidence: data.confidence ?? 0,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            await EventPublisher_1.eventPublisher.publish('IocRelationshipAdded', { iocId, relationship });
            return relationship;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    /**
     * Remove a relationship by its UUID.
     * Publishes IocRelationshipRemoved.
     */
    async removeRelationship(relationshipId, actor, tx) {
        this.validateUuid(relationshipId, 'relationshipId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const rel = await client.iOCRelationship.findUnique({
                where: { id: relationshipId },
            });
            if (!rel || rel.deletedAt) {
                throw new Error(`IOCRelationship "${relationshipId}" not found.`);
            }
            await client.iOCRelationship.update({
                where: { id: relationshipId },
                data: { deletedAt: new Date(), updatedBy: actor },
            });
            await EventPublisher_1.eventPublisher.publish('IocRelationshipRemoved', { relationshipId });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Correlation ────────────────────────────────────────────────────────────
    /**
     * Find IOCs associated with a specific CVE.
     */
    async findByCve(cveId, tx) {
        this.validateUuid(cveId, 'cveId');
        const client = tx || prisma_1.default;
        return client.iOC.findMany({
            where: {
                deletedAt: null,
                cves: { some: { id: cveId } },
            },
        });
    }
    /**
     * Find IOCs linked to a MITRE technique.
     */
    async findByTechnique(techniqueId, tx) {
        this.validateUuid(techniqueId, 'techniqueId');
        const client = tx || prisma_1.default;
        return client.iOC.findMany({
            where: {
                deletedAt: null,
                techniques: { some: { id: techniqueId } },
            },
        });
    }
    /**
     * Find IOCs linked to a threat actor.
     */
    async findByThreatActor(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        const client = tx || prisma_1.default;
        return client.iOC.findMany({
            where: {
                deletedAt: null,
                threatActors: { some: { id: threatActorId } },
            },
        });
    }
    // ── Revocation ─────────────────────────────────────────────────────────────
    /**
     * Mark an IOC as revoked.
     * Publishes IocRevoked.
     */
    async revokeIoc(id, actor, tx) {
        this.validateUuid(id, 'iocId');
        const runInTx = async (transaction) => {
            const existing = await this.iocRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`IOC "${id}" not found.`);
            }
            const updated = await this.iocRepo.update(id, { revoked: true, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('IocRevoked', { ioc: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Scoring ────────────────────────────────────────────────────────────────
    /**
     * Calculate a threat score for an IOC (0–100) based on severity,
     * confidence, malicious flag, and revocation status.
     */
    async calculateThreatScore(iocId, tx) {
        this.validateUuid(iocId, 'iocId');
        const ioc = await this.iocRepo.findById(iocId, tx);
        if (!ioc || ioc.deletedAt) {
            throw new Error(`IOC "${iocId}" not found.`);
        }
        if (ioc.revoked)
            return 0;
        const sevScore = SEVERITY_SCORE[String(ioc.severity ?? 'MEDIUM')] ?? 50;
        const confWeight = CONFIDENCE_WEIGHT[String(ioc.confidence ?? 'MEDIUM').toUpperCase()] ?? 50;
        const maliciousBonus = ioc.malicious ? 10 : 0;
        const score = Math.round((sevScore * confWeight) / 100) + maliciousBonus;
        return Math.min(100, score);
    }
    /**
     * Aggregate threat score across multiple IOC IDs (0–100, mean).
     */
    async aggregateThreatScore(iocIds, tx) {
        if (!iocIds || iocIds.length === 0)
            return 0;
        const scores = await Promise.all(iocIds.map((id) => this.calculateThreatScore(id, tx)));
        return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }
    // ── Statistics ─────────────────────────────────────────────────────────────
    /**
     * Compute IOC statistics across the knowledge base.
     */
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const [total, malicious, revoked, all] = await Promise.all([
            client.iOC.count({ where: { deletedAt: null } }),
            client.iOC.count({ where: { deletedAt: null, malicious: true } }),
            client.iOC.count({ where: { deletedAt: null, revoked: true } }),
            client.iOC.findMany({ where: { deletedAt: null } }),
        ]);
        const typeCounts = {};
        const sourceCounts = {};
        let confSum = 0;
        for (const ioc of all) {
            const t = String(ioc.iocType ?? 'UNKNOWN');
            typeCounts[t] = (typeCounts[t] ?? 0) + 1;
            if (ioc.source) {
                sourceCounts[ioc.source] = (sourceCounts[ioc.source] ?? 0) + 1;
            }
            confSum += CONFIDENCE_WEIGHT[String(ioc.confidence ?? 'MEDIUM').toUpperCase()] ?? 50;
        }
        return {
            totalIOCs: total,
            maliciousIOCs: malicious,
            revokedIOCs: revoked,
            averageConfidence: total > 0 ? Math.round(confSum / total) : 0,
            typeCounts,
            sourceCounts,
        };
    }
    // ── Bulk Operations ────────────────────────────────────────────────────────
    /**
     * Bulk-create IOCs. Returns succeeded IDs and failed entries.
     */
    async bulkCreateIocs(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const ioc = await this.createIoc({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(ioc.id);
            }
            catch (e) {
                failed.push({ value: String(item.value ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('IocsBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    /**
     * Bulk soft-delete IOCs by IDs.
     */
    async bulkDeleteIocs(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteIoc(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('IocsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.IocService = IocService;
exports.iocService = new IocService();
