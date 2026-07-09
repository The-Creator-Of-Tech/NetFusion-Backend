"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MitreRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class MitreRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('mitreTechnique');
    }
    /**
     * Finds a MITRE technique by its mitreId where not deleted.
     */
    async findTechniqueByMitreId(mitreId, tx) {
        return this.findOne({ mitreId, deletedAt: null }, tx);
    }
    /**
     * Finds techniques by tactic ID where not deleted.
     */
    async findByTactic(tacticId, tx) {
        return this.findMany({ filter: { tacticId, deletedAt: null } }, tx);
    }
    /**
     * Finds techniques by platform where not deleted.
     */
    async findByPlatform(platform, tx) {
        return this.findMany({
            filter: {
                platforms: { has: platform },
                deletedAt: null,
            },
        }, tx);
    }
    /**
     * Finds techniques by data source where not deleted.
     */
    async findByDataSource(dataSource, tx) {
        return this.findMany({ filter: { dataSource, deletedAt: null } }, tx);
    }
    /**
     * Finds techniques mitigated by a specific mitigation ID where not deleted.
     */
    async findByMitigation(mitigationId, tx) {
        return this.findMany({
            filter: {
                mitigations: { some: { id: mitigationId } },
                deletedAt: null,
            },
        }, tx);
    }
    /**
     * Finds sub-techniques of a parent technique where not deleted.
     */
    async findSubTechniques(parentMitreId, tx) {
        return this.findMany({
            filter: {
                mitreId: { startsWith: `${parentMitreId}.` },
                deletedAt: null,
            },
        }, tx);
    }
    /**
     * Finds the parent technique of a sub-technique where not deleted.
     */
    async findParentTechnique(subTechniqueMitreId, tx) {
        const parts = subTechniqueMitreId.split('.');
        if (parts.length <= 1)
            return null;
        const parentId = parts[0];
        return this.findTechniqueByMitreId(parentId, tx);
    }
    /**
     * Finds mitigations linked to a specific technique where not deleted.
     */
    async findMitigations(techniqueId, tx) {
        const client = tx || prisma_1.default;
        return client.mitreMitigation.findMany({
            where: {
                techniques: { some: { id: techniqueId } },
                deletedAt: null,
            },
        });
    }
    /**
     * Finds detection rules (from Rules table) associated with a technique where not deleted.
     */
    async findDetectionRules(techniqueId, tx) {
        const technique = await this.findById(techniqueId, tx);
        if (!technique)
            return [];
        const client = tx || prisma_1.default;
        return client.rule.findMany({
            where: {
                deletedAt: null,
                metadata: {
                    path: ['techniques'],
                    equals: [technique.mitreId],
                },
            },
        });
    }
    /**
     * Finds techniques by MITRE attack phase (tacticType) where not deleted.
     */
    async findByAttackPhase(phase, tx) {
        const delegate = this.getDelegate(tx);
        return delegate.findMany({
            where: {
                deletedAt: null,
                tactic: {
                    tacticType: phase,
                    deletedAt: null,
                },
            },
        });
    }
}
exports.MitreRepository = MitreRepository;
