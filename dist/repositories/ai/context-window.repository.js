"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContextWindowRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ContextWindowRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('contextWindow');
    }
    /**
     * Finds context windows by user ID where not deleted.
     */
    async findByUser(userId, tx) {
        return this.findMany({ filter: { userId, deletedAt: null } }, tx);
    }
    /**
     * Finds context windows by conversation ID where not deleted.
     */
    async findByConversation(conversationId, tx) {
        return this.findMany({ filter: { conversationId, deletedAt: null } }, tx);
    }
    /**
     * Finds active context windows (status: ACTIVE and not deleted).
     */
    async findActive(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
    /**
     * Finds archived context windows (status: ARCHIVED and not deleted).
     */
    async findArchived(tx) {
        return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
    }
    /**
     * Finds context entries associated with a specific context window ID where not deleted.
     */
    async findEntries(contextId, tx) {
        const client = tx || prisma_1.default;
        return client.contextEntry.findMany({
            where: { contextId, deletedAt: null },
        });
    }
    /**
     * Calculates the total size of characters inside all context entries of a context window.
     */
    async calculateContextSize(id, tx) {
        const entries = await this.findEntries(id, tx);
        return entries.reduce((sum, entry) => sum + (entry.content?.length || 0), 0);
    }
}
exports.ContextWindowRepository = ContextWindowRepository;
