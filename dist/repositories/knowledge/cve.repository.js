"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CveRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class CveRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('cVE');
    }
    /**
     * Finds a CVE by its cveId where not deleted.
     */
    async findByCveId(cveId, tx) {
        return this.findOne({ cveId, deletedAt: null }, tx);
    }
    /**
     * Finds CVEs by severity where not deleted.
     */
    async findBySeverity(severity, tx) {
        return this.findMany({ filter: { severity, deletedAt: null } }, tx);
    }
    /**
     * Finds CVEs by vendor where not deleted.
     */
    async findByVendor(vendor, tx) {
        const delegate = this.getDelegate(tx);
        return delegate.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { vendor },
                    { affectedProducts: { some: { vendor, deletedAt: null } } },
                ],
            },
        });
    }
    /**
     * Finds CVEs by product where not deleted.
     */
    async findByProduct(product, tx) {
        const delegate = this.getDelegate(tx);
        return delegate.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { product },
                    { affectedProducts: { some: { product, deletedAt: null } } },
                ],
            },
        });
    }
    /**
     * Finds CVEs within a CVSS base score range where not deleted.
     */
    async findByCvssRange(min, max, tx) {
        return this.findMany({
            filter: {
                cvssScore: { gte: min, lte: max },
                deletedAt: null,
            },
        }, tx);
    }
    /**
     * Finds patched CVEs where not deleted.
     */
    async findPatched(tx) {
        return this.findMany({ filter: { patched: true, deletedAt: null } }, tx);
    }
    /**
     * Finds unpatched CVEs where not deleted.
     */
    async findUnpatched(tx) {
        return this.findMany({ filter: { patched: false, deletedAt: null } }, tx);
    }
    /**
     * Finds exploited CVEs where not deleted.
     */
    async findExploited(tx) {
        return this.findMany({ filter: { exploited: true, deletedAt: null } }, tx);
    }
    /**
     * Finds affected products associated with a specific CVE ID where not deleted.
     */
    async findAffectedProducts(cveId, tx) {
        const client = tx || prisma_1.default;
        return client.affectedProduct.findMany({
            where: { cveId, deletedAt: null },
        });
    }
    /**
     * Finds CVSS details associated with a specific CVE ID where not deleted.
     */
    async findCvss(cveId, tx) {
        const client = tx || prisma_1.default;
        return client.cVSS.findFirst({
            where: { cveId, deletedAt: null },
        });
    }
}
exports.CveRepository = CveRepository;
