"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionMemoryRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class SessionMemoryRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('sessionMemory');
    }
    /**
     * Finds session memories by user ID where not deleted.
     */
    async findByUser(userId, tx) {
        return this.findMany({ filter: { userId, deletedAt: null } }, tx);
    }
    /**
     * Finds session memories by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds session memories by investigation ID where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds active session memories (status: ACTIVE and not deleted).
     */
    async findActive(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
    /**
     * Finds archived session memories (status: ARCHIVED and not deleted).
     */
    async findArchived(tx) {
        return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
    }
    /**
     * Finds memory entries associated with a specific session memory ID where not deleted.
     */
    async findEntries(memoryId, tx) {
        const client = tx || prisma_1.default;
        return client.memoryEntry.findMany({
            where: { memoryId, deletedAt: null },
        });
    }
    /**
     * Searches for memory entries containing a query string case-insensitively in title or content where not deleted.
     */
    async searchEntries(query, tx) {
        const client = tx || prisma_1.default;
        return client.memoryEntry.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { title: { contains: query, mode: 'insensitive' } },
                    { content: { contains: query, mode: 'insensitive' } },
                ],
            },
        });
    }
}
exports.SessionMemoryRepository = SessionMemoryRepository;
