"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EvidenceRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class EvidenceRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('evidence');
    }
    /**
     * Finds evidence associated with a specific investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds evidence associated with a specific asset where not deleted.
     */
    async findByAsset(assetId, tx) {
        return this.findMany({ filter: { assetId, deletedAt: null } }, tx);
    }
    /**
     * Finds evidence associated with a specific finding where not deleted.
     */
    async findByFinding(findingId, tx) {
        return this.findMany({ filter: { findingId, deletedAt: null } }, tx);
    }
    /**
     * Finds evidence by type where not deleted.
     */
    async findByType(type, tx) {
        return this.findMany({ filter: { type, deletedAt: null } }, tx);
    }
    /**
     * Finds evidence by matching hash in fieldValue, rawValue, or JSON metadata (hash, sha256, md5) where not deleted.
     */
    async findByHash(hash, tx) {
        const delegate = this.getDelegate(tx);
        return delegate.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { fieldValue: hash },
                    { rawValue: hash },
                    { metadata: { path: ['hash'], equals: hash } },
                    { metadata: { path: ['sha256'], equals: hash } },
                    { metadata: { path: ['md5'], equals: hash } }
                ]
            }
        });
    }
    /**
     * Finds evidence of type PACKET (Packet Capture) where not deleted.
     */
    async findPacketCaptures(tx) {
        return this.findMany({ filter: { type: 'PACKET', deletedAt: null } }, tx);
    }
    /**
     * Finds evidence of type LOG where not deleted.
     */
    async findLogs(tx) {
        return this.findMany({ filter: { type: 'LOG', deletedAt: null } }, tx);
    }
}
exports.EvidenceRepository = EvidenceRepository;
