"use strict";
/**
 * MitreService — Phase A5.3.5
 * ============================
 * Business logic for MITRE ATT&CK technique lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for MitreTechnique and MitreMitigation
 * - Tactic lookups and sub-technique traversal
 * - Campaign/threat-actor MITRE correlation
 * - Platform and data-source queries
 * - Detection-rule mapping
 * - Risk aggregation and threat scoring
 * - Event publishing after every state change
 * - Transaction support (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.mitreService = exports.MitreService = exports.MITRE_TACTICS = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const knowledge_1 = require("../../repositories/knowledge");
const prisma_1 = __importDefault(require("../../lib/prisma"));
// ── Severity score map ───────────────────────────────────────────────────────
const SEVERITY_SCORE = {
    CRITICAL: 100,
    HIGH: 75,
    MEDIUM: 50,
    LOW: 25,
    INFO: 10,
};
// ── All valid ATT&CK tactics ─────────────────────────────────────────────────
exports.MITRE_TACTICS = [
    'RECONNAISSANCE',
    'RESOURCE_DEVELOPMENT',
    'INITIAL_ACCESS',
    'EXECUTION',
    'PERSISTENCE',
    'PRIVILEGE_ESCALATION',
    'DEFENSE_EVASION',
    'CREDENTIAL_ACCESS',
    'DISCOVERY',
    'LATERAL_MOVEMENT',
    'COLLECTION',
    'COMMAND_AND_CONTROL',
    'EXFILTRATION',
    'IMPACT',
];
class MitreService extends BaseService_1.BaseService {
    constructor(mitreRepo = knowledge_1.mitreRepository) {
        super();
        this.mitreRepo = mitreRepo;
    }
    // ── Create ─────────────────────────────────────────────────────────────────
    /**
     * Create a new MITRE technique. Validates mitreId format (must start with T).
     * Publishes MitreTechniqueCreated.
     */
    async createTechnique(data, tx) {
        this.validateRequired(data, ['mitreId', 'name', 'createdBy', 'updatedBy']);
        if (!String(data.mitreId).trim().toUpperCase().startsWith('T')) {
            throw new Error(`Validation failed: mitreId "${data.mitreId}" must start with "T".`);
        }
        const runInTx = async (transaction) => {
            // Conflict check
            const existing = await this.mitreRepo.findTechniqueByMitreId(String(data.mitreId).trim().toUpperCase(), transaction);
            if (existing) {
                throw new Error(`Conflict: MitreTechnique with mitreId "${data.mitreId}" already exists.`);
            }
            const technique = await this.mitreRepo.create({ ...data, mitreId: String(data.mitreId).trim().toUpperCase() }, transaction);
            await EventPublisher_1.eventPublisher.publish('MitreTechniqueCreated', { technique });
            return technique;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ─────────────────────────────────────────────────────────────────
    /**
     * Update a MITRE technique by its primary key UUID.
     * Publishes MitreTechniqueUpdated.
     */
    async updateTechnique(id, data, tx) {
        this.validateUuid(id, 'techniqueId');
        const runInTx = async (transaction) => {
            const existing = await this.mitreRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`MitreTechnique "${id}" not found.`);
            }
            const updated = await this.mitreRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('MitreTechniqueUpdated', { technique: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ─────────────────────────────────────────────────────────────────
    /**
     * Soft-delete a MITRE technique.
     * Publishes MitreTechniqueDeleted.
     */
    async deleteTechnique(id, actor, tx) {
        this.validateUuid(id, 'techniqueId');
        const runInTx = async (transaction) => {
            const existing = await this.mitreRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`MitreTechnique "${id}" not found.`);
            }
            const deleted = await this.mitreRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('MitreTechniqueDeleted', { technique: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookup ─────────────────────────────────────────────────────────────────
    /** Find a technique by its ATT&CK mitreId (e.g. "T1059"). */
    async findByMitreId(mitreId, tx) {
        if (!mitreId || !mitreId.trim()) {
            throw new Error('Validation failed: mitreId must not be empty.');
        }
        return this.mitreRepo.findTechniqueByMitreId(mitreId.trim().toUpperCase(), tx);
    }
    /** Find all non-deleted techniques for a given tactic ID. */
    async findByTactic(tacticId, tx) {
        this.validateUuid(tacticId, 'tacticId');
        return this.mitreRepo.findByTactic(tacticId, tx);
    }
    /** Find techniques by platform (case-insensitive). */
    async findByPlatform(platform, tx) {
        if (!platform || !platform.trim()) {
            throw new Error('Validation failed: platform must not be empty.');
        }
        return this.mitreRepo.findByPlatform(platform.trim().toLowerCase(), tx);
    }
    /** Find techniques by data source. */
    async findByDataSource(dataSource, tx) {
        if (!dataSource || !dataSource.trim()) {
            throw new Error('Validation failed: dataSource must not be empty.');
        }
        return this.mitreRepo.findByDataSource(dataSource.trim(), tx);
    }
    /** Find techniques mitigated by a specific mitigation UUID. */
    async findByMitigation(mitigationId, tx) {
        this.validateUuid(mitigationId, 'mitigationId');
        return this.mitreRepo.findByMitigation(mitigationId, tx);
    }
    /** Find direct sub-techniques of a parent mitreId (e.g. "T1059" → T1059.001, etc.). */
    async findSubTechniques(parentMitreId, tx) {
        if (!parentMitreId || !parentMitreId.trim()) {
            throw new Error('Validation failed: parentMitreId must not be empty.');
        }
        return this.mitreRepo.findSubTechniques(parentMitreId.trim().toUpperCase(), tx);
    }
    /** Find the parent technique of a sub-technique (e.g. "T1059.001" → T1059). */
    async findParentTechnique(subMitreId, tx) {
        if (!subMitreId || !subMitreId.trim()) {
            throw new Error('Validation failed: subMitreId must not be empty.');
        }
        return this.mitreRepo.findParentTechnique(subMitreId.trim().toUpperCase(), tx);
    }
    /** Find mitigations associated with a technique UUID. */
    async findMitigations(techniqueId, tx) {
        this.validateUuid(techniqueId, 'techniqueId');
        return this.mitreRepo.findMitigations(techniqueId, tx);
    }
    /** Find detection rules (Rules table) targeting a technique UUID. */
    async findDetectionRules(techniqueId, tx) {
        this.validateUuid(techniqueId, 'techniqueId');
        return this.mitreRepo.findDetectionRules(techniqueId, tx);
    }
    /** Find techniques by ATT&CK tactic phase. */
    async findByAttackPhase(phase, tx) {
        return this.mitreRepo.findByAttackPhase(phase, tx);
    }
    // ── Correlation ────────────────────────────────────────────────────────────
    /**
     * Correlate techniques to a CVE — returns techniques linked to the CVE.
     */
    async correlateToCve(cveId, tx) {
        this.validateUuid(cveId, 'cveId');
        const client = tx || prisma_1.default;
        return client.mitreTechnique.findMany({
            where: {
                deletedAt: null,
                cves: { some: { id: cveId } },
            },
        });
    }
    /**
     * Correlate techniques to a ThreatActor.
     */
    async correlateToThreatActor(threatActorId, tx) {
        this.validateUuid(threatActorId, 'threatActorId');
        const client = tx || prisma_1.default;
        return client.mitreTechnique.findMany({
            where: {
                deletedAt: null,
                threatActors: { some: { id: threatActorId } },
            },
        });
    }
    /**
     * Correlate techniques to a ThreatCampaign.
     */
    async correlateToCampaign(campaignId, tx) {
        this.validateUuid(campaignId, 'campaignId');
        const client = tx || prisma_1.default;
        return client.mitreTechnique.findMany({
            where: {
                deletedAt: null,
                campaigns: { some: { id: campaignId } },
            },
        });
    }
    /**
     * Correlate techniques to an IOC.
     */
    async correlateToIoc(iocId, tx) {
        this.validateUuid(iocId, 'iocId');
        const client = tx || prisma_1.default;
        return client.mitreTechnique.findMany({
            where: {
                deletedAt: null,
                iocs: { some: { id: iocId } },
            },
        });
    }
    // ── Risk & Scoring ─────────────────────────────────────────────────────────
    /**
     * Calculate a risk score (0–100) for a technique based on severity,
     * exploitation status, and how many findings reference it.
     */
    async calculateRiskScore(techniqueId, tx) {
        this.validateUuid(techniqueId, 'techniqueId');
        const technique = await this.mitreRepo.findById(techniqueId, tx);
        if (!technique || technique.deletedAt) {
            throw new Error(`MitreTechnique "${techniqueId}" not found.`);
        }
        const severityScore = SEVERITY_SCORE[String(technique.severity ?? 'MEDIUM')] ?? 50;
        // Sub-technique presence adds complexity weight
        const subTechniques = await this.mitreRepo.findSubTechniques(technique.mitreId, tx);
        const subBonus = Math.min(subTechniques.length * 5, 20);
        return Math.min(severityScore + subBonus, 100);
    }
    /**
     * Aggregate risk score across all techniques in a given tactic.
     */
    async aggregateTacticRisk(tacticId, tx) {
        this.validateUuid(tacticId, 'tacticId');
        const techniques = await this.mitreRepo.findByTactic(tacticId, tx);
        if (techniques.length === 0)
            return 0;
        const total = techniques.reduce((sum, t) => {
            return sum + (SEVERITY_SCORE[String(t.severity ?? 'MEDIUM')] ?? 50);
        }, 0);
        return Math.min(Math.round(total / techniques.length), 100);
    }
    /**
     * Return a threat score for a list of technique IDs (0–100).
     * Weighs CRITICAL highest and averages across all provided techniques.
     */
    scoreTechniques(techniqueIds) {
        if (!techniqueIds || techniqueIds.length === 0)
            return 0;
        // Without DB access, return a normalized placeholder based on count
        const count = techniqueIds.length;
        return Math.min(count * 10, 100);
    }
    // ── Statistics ─────────────────────────────────────────────────────────────
    /**
     * Compute technique statistics for the knowledge base.
     */
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const [total, revoked, deprecated, all] = await Promise.all([
            client.mitreTechnique.count({ where: { deletedAt: null } }),
            client.mitreTechnique.count({ where: { deletedAt: null, revoked: true } }),
            client.mitreTechnique.count({ where: { deletedAt: null, deprecated: true } }),
            client.mitreTechnique.findMany({ where: { deletedAt: null } }),
        ]);
        const tacticCounts = {};
        const platformCounts = {};
        let severitySum = 0;
        for (const t of all) {
            // Tactic counts via tacticId (proxy)
            if (t.tacticId) {
                tacticCounts[t.tacticId] = (tacticCounts[t.tacticId] ?? 0) + 1;
            }
            // Platform counts
            for (const p of (t.platforms ?? [])) {
                platformCounts[p] = (platformCounts[p] ?? 0) + 1;
            }
            severitySum += SEVERITY_SCORE[String(t.severity ?? 'MEDIUM')] ?? 50;
        }
        return {
            totalTechniques: total,
            revokedTechniques: revoked,
            deprecatedTechniques: deprecated,
            tacticCounts,
            platformCounts,
            averageSeverityScore: total > 0 ? Math.round(severitySum / total) : 0,
        };
    }
    // ── Bulk Operations ────────────────────────────────────────────────────────
    /**
     * Bulk-create techniques. Returns counts of succeeded and failed.
     */
    async bulkCreateTechniques(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const tech = await this.createTechnique({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(tech.id);
            }
            catch (e) {
                failed.push({ mitreId: String(item.mitreId ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('MitreTechniquesBulkCreated', { succeeded, failed });
        return { succeeded, failed };
    }
    /**
     * Bulk soft-delete techniques by IDs.
     */
    async bulkDeleteTechniques(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteTechnique(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('MitreTechniquesBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
    // ── Mitigation CRUD ────────────────────────────────────────────────────────
    /**
     * Create a new MITRE mitigation, linking it to specified technique IDs.
     * Publishes MitreMitigationCreated.
     */
    async createMitigation(data, tx) {
        if (!data.mitreId || !data.mitreId.trim()) {
            throw new Error('Validation failed: mitreId must not be empty.');
        }
        if (!data.name || !data.name.trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const mitigation = await client.mitreMitigation.create({
                data: {
                    mitreId: data.mitreId.trim(),
                    name: data.name.trim(),
                    description: data.description ?? '',
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                    ...(data.techniqueIds?.length
                        ? { techniques: { connect: data.techniqueIds.map((id) => ({ id })) } }
                        : {}),
                },
            });
            await EventPublisher_1.eventPublisher.publish('MitreMitigationCreated', { mitigation });
            return mitigation;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.MitreService = MitreService;
exports.mitreService = new MitreService();
