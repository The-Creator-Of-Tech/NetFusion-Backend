"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ThreatRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ThreatRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('threatActor');
    }
    /**
     * Finds threat actors by severity level where not deleted.
     */
    async findByThreatLevel(severity, tx) {
        return this.findMany({ filter: { severity, deletedAt: null } }, tx);
    }
    /**
     * Finds threat actors by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds threat actors by name contains or in aliases where not deleted.
     */
    async findByActor(name, tx) {
        const delegate = this.getDelegate(tx);
        return delegate.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { name: { contains: name, mode: 'insensitive' } },
                    { aliases: { has: name } },
                ],
            },
        });
    }
    /**
     * Finds threat actors involved in a campaign by campaign UUID or string code where not deleted.
     */
    async findByCampaign(campaignId, tx) {
        const delegate = this.getDelegate(tx);
        const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(campaignId);
        return delegate.findMany({
            where: {
                deletedAt: null,
                campaigns: {
                    some: {
                        OR: isUuid
                            ? [{ id: campaignId }, { campaignId: campaignId }]
                            : [{ campaignId: campaignId }],
                        deletedAt: null,
                    },
                },
            },
        });
    }
    /**
     * Finds campaigns associated with a specific threat actor ID where not deleted.
     */
    async findCampaigns(threatActorId, tx) {
        const client = tx || prisma_1.default;
        return client.threatCampaign.findMany({
            where: {
                threatActors: { some: { id: threatActorId } },
                deletedAt: null,
            },
        });
    }
    /**
     * Finds relationships associated with a specific threat actor ID where not deleted.
     */
    async findRelationships(threatActorId, tx) {
        const client = tx || prisma_1.default;
        return client.threatRelationship.findMany({
            where: {
                threatId: threatActorId,
                deletedAt: null,
            },
        });
    }
    /**
     * Finds techniques used by a threat actor where not deleted.
     */
    async findTechniques(threatActorId, tx) {
        const client = tx || prisma_1.default;
        return client.mitreTechnique.findMany({
            where: {
                threatActors: { some: { id: threatActorId } },
                deletedAt: null,
            },
        });
    }
    /**
     * Finds IOCs associated with a threat actor where not deleted.
     */
    async findAssociatedIOCs(threatActorId, tx) {
        const client = tx || prisma_1.default;
        return client.iOC.findMany({
            where: {
                threatActors: { some: { id: threatActorId } },
                deletedAt: null,
            },
        });
    }
    /**
     * Finds CVEs indirectly associated with a threat actor through ThreatRelationship table where not deleted.
     */
    async findAssociatedCVEs(threatActorId, tx) {
        const client = tx || prisma_1.default;
        const relationships = await client.threatRelationship.findMany({
            where: {
                threatId: threatActorId,
                cveId: { not: null },
                deletedAt: null,
            },
            select: { cveId: true },
        });
        const cveIds = relationships.map((r) => r.cveId).filter(Boolean);
        if (cveIds.length === 0)
            return [];
        return client.cVE.findMany({
            where: {
                id: { in: cveIds },
                deletedAt: null,
            },
        });
    }
}
exports.ThreatRepository = ThreatRepository;
