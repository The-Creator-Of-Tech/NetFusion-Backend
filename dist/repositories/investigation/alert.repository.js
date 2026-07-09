"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlertRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class AlertRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('alert');
    }
    /**
     * Finds alerts associated with a specific investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds alerts by severity where not deleted.
     */
    async findBySeverity(severity, tx) {
        return this.findMany({ filter: { severity, deletedAt: null } }, tx);
    }
    /**
     * Finds alerts by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds open alerts (status: OPEN and not deleted).
     */
    async findOpenAlerts(tx) {
        return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
    }
    /**
     * Finds acknowledged alerts (status: ACKNOWLEDGED and not deleted).
     */
    async findAcknowledgedAlerts(tx) {
        return this.findMany({ filter: { status: 'ACKNOWLEDGED', deletedAt: null } }, tx);
    }
}
exports.AlertRepository = AlertRepository;
