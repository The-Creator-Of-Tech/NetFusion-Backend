"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConversationRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ConversationRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('conversation');
    }
    /**
     * Finds conversations by user ID where not deleted.
     */
    async findByUser(userId, tx) {
        return this.findMany({ filter: { userId, deletedAt: null } }, tx);
    }
    /**
     * Finds conversations by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds conversations by investigation ID where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds active conversations (status: ACTIVE and not deleted).
     */
    async findActive(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
    /**
     * Finds archived conversations (status: ARCHIVED and not deleted).
     */
    async findArchived(tx) {
        return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
    }
    /**
     * Finds completed conversations (status: COMPLETED and not deleted).
     */
    async findCompleted(tx) {
        return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
    }
    /**
     * Finds a conversation by ID and includes its associated messages.
     */
    async findWithMessages(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                messages: true,
            },
        });
    }
    /**
     * Searches for conversation messages containing a query string case-insensitively where not deleted.
     */
    async searchMessages(query, tx) {
        const client = tx || prisma_1.default;
        return client.conversationMessage.findMany({
            where: {
                content: { contains: query, mode: 'insensitive' },
                deletedAt: null,
            },
        });
    }
}
exports.ConversationRepository = ConversationRepository;
