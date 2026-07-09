"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TimelineRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class TimelineRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('timelineEvent');
    }
    /**
     * Finds timeline events associated with a specific investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds timeline events by type where not deleted.
     */
    async findByEventType(type, tx) {
        return this.findMany({ filter: { type, deletedAt: null } }, tx);
    }
    /**
     * Finds timeline events within a specific event timestamp range where not deleted.
     */
    async findRange(start, end, tx) {
        return this.findMany({
            filter: {
                eventTimestamp: { gte: start, lte: end },
                deletedAt: null,
            },
            sort: [{ field: 'eventTimestamp', direction: 'asc' }],
        }, tx);
    }
    /**
     * Finds the latest timeline events ordered by event timestamp descending where not deleted.
     */
    async findLatest(limit = 10, filter, tx) {
        return this.findMany({
            filter: { ...filter, deletedAt: null },
            sort: [{ field: 'eventTimestamp', direction: 'desc' }],
            limit,
        }, tx);
    }
    /**
     * Finds the oldest timeline events ordered by event timestamp ascending where not deleted.
     */
    async findOldest(limit = 10, filter, tx) {
        return this.findMany({
            filter: { ...filter, deletedAt: null },
            sort: [{ field: 'eventTimestamp', direction: 'asc' }],
            limit,
        }, tx);
    }
}
exports.TimelineRepository = TimelineRepository;
