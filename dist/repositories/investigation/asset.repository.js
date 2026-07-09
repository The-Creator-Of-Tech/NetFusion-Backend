"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AssetRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class AssetRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('asset');
    }
    /**
     * Finds assets associated with a specific investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds assets by type where not deleted.
     */
    async findByType(type, tx) {
        return this.findMany({ filter: { type, deletedAt: null } }, tx);
    }
    /**
     * Finds assets by hostname where not deleted.
     */
    async findByHostname(hostname, tx) {
        return this.findMany({ filter: { hostname, deletedAt: null } }, tx);
    }
    /**
     * Finds assets by IP address where not deleted.
     */
    async findByIpAddress(ipAddress, tx) {
        return this.findMany({ filter: { currentIp: ipAddress, deletedAt: null } }, tx);
    }
    /**
     * Finds assets with high risk score where not deleted.
     * Default threshold is 70.0.
     */
    async findCriticalAssets(threshold = 70.0, tx) {
        return this.findMany({ filter: { riskScore: { gte: threshold }, deletedAt: null } }, tx);
    }
    /**
     * Finds an asset by ID and includes its associated findings.
     */
    async findWithFindings(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                findings: true,
            },
        });
    }
    /**
     * Finds an asset by ID and includes its associated evidence.
     */
    async findWithEvidence(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                evidence: true,
            },
        });
    }
}
exports.AssetRepository = AssetRepository;
