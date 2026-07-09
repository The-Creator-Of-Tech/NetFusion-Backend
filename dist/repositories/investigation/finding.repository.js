"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class FindingRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('finding');
    }
    /**
     * Finds findings associated with an investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds findings associated with a specific asset where not deleted.
     */
    async findByAsset(assetId, tx) {
        return this.findMany({ filter: { assetId, deletedAt: null } }, tx);
    }
    /**
     * Finds findings by severity where not deleted.
     */
    async findBySeverity(severity, tx) {
        return this.findMany({ filter: { severity, deletedAt: null } }, tx);
    }
    /**
     * Finds findings by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds critical findings (severity is CRITICAL and not deleted).
     */
    async findCriticalFindings(tx) {
        return this.findMany({ filter: { severity: 'CRITICAL', deletedAt: null } }, tx);
    }
    /**
     * Finds open findings (status is OPEN and not deleted).
     */
    async findOpenFindings(tx) {
        return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
    }
    /**
     * Finds resolved findings (status is RESOLVED and not deleted).
     */
    async findResolvedFindings(tx) {
        return this.findMany({ filter: { status: 'RESOLVED', deletedAt: null } }, tx);
    }
    /**
     * Finds a finding by ID and includes its associated evidence.
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
exports.FindingRepository = FindingRepository;
