"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IocRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class IocRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('iOC');
    }
    /**
     * Finds an IOC by its indicator value where not deleted.
     */
    async findByValue(value, tx) {
        return this.findOne({ value, deletedAt: null }, tx);
    }
    /**
     * Finds IOCs by type where not deleted.
     */
    async findByType(iocType, tx) {
        return this.findMany({ filter: { iocType, deletedAt: null } }, tx);
    }
    /**
     * Finds IOCs by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds malicious IOCs where not deleted.
     */
    async findMalicious(tx) {
        return this.findMany({ filter: { malicious: true, deletedAt: null } }, tx);
    }
    /**
     * Finds revoked IOCs where not deleted.
     */
    async findRevoked(tx) {
        return this.findMany({ filter: { revoked: true, deletedAt: null } }, tx);
    }
    /**
     * Finds relationships associated with a specific IOC ID where not deleted.
     */
    async findRelationships(iocId, tx) {
        const client = tx || prisma_1.default;
        return client.iOCRelationship.findMany({
            where: { iocId, deletedAt: null },
        });
    }
    /**
     * Finds enrichment details associated with a specific IOC ID where not deleted.
     */
    async findEnrichment(iocId, tx) {
        const client = tx || prisma_1.default;
        return client.iOCEnrichment.findFirst({
            where: { iocId, deletedAt: null },
        });
    }
    /**
     * Finds IOCs by confidence classification (e.g. 'HIGH') or numeric range.
     */
    async findByConfidence(min, max, tx) {
        const minStr = String(min);
        const delegate = this.getDelegate(tx);
        if (isNaN(Number(minStr))) {
            return delegate.findMany({
                where: {
                    confidence: minStr,
                    deletedAt: null,
                },
            });
        }
        else {
            const allIocs = await delegate.findMany({ where: { deletedAt: null } });
            return allIocs.filter((ioc) => {
                const confNum = Number(ioc.confidence);
                if (isNaN(confNum))
                    return false;
                if (confNum < Number(min))
                    return false;
                if (max !== undefined && confNum > Number(max))
                    return false;
                return true;
            });
        }
    }
    /**
     * Finds IOCs by source where not deleted.
     */
    async findBySource(source, tx) {
        return this.findMany({ filter: { source, deletedAt: null } }, tx);
    }
}
exports.IocRepository = IocRepository;
