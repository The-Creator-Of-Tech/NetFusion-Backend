"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReportRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class ReportRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('report');
    }
    /**
     * Finds reports associated with a specific investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds reports by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds draft reports (status: DRAFT and not deleted).
     */
    async findDrafts(tx) {
        return this.findMany({ filter: { status: 'DRAFT', deletedAt: null } }, tx);
    }
    /**
     * Finds published reports (status: PUBLISHED and not deleted).
     */
    async findPublished(tx) {
        return this.findMany({ filter: { status: 'PUBLISHED', deletedAt: null } }, tx);
    }
}
exports.ReportRepository = ReportRepository;
