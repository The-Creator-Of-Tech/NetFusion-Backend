"use strict";
/**
 * ConversationService — Phase A5.3.4
 * =====================================
 * Manages conversation lifecycle: creation, archiving, completion, messaging,
 * summary updates, tag management, and context-size accounting.
 * Publishes domain events on every meaningful state transition.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConversationService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ConversationService extends BaseService_1.BaseService {
    constructor(conversationRepo = ai_1.conversationRepository, sessionMemoryRepo = ai_1.sessionMemoryRepository, contextWindowRepo = ai_1.contextWindowRepository) {
        super();
        this.conversationRepo = conversationRepo;
        this.sessionMemoryRepo = sessionMemoryRepo;
        this.contextWindowRepo = contextWindowRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createConversation(data, tx) {
        this.validateRequired(data, ['title', 'projectId', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        if (data.investigationId)
            this.validateUuid(data.investigationId, 'investigationId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            const conversation = await this.conversationRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('ConversationCreated', { conversation });
            return conversation;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async archiveConversation(id, actor, tx) {
        return this._transition(id, 'ARCHIVED', actor, 'ConversationArchived', tx);
    }
    async completeConversation(id, actor, tx) {
        return this._transition(id, 'COMPLETED', actor, 'ConversationCompleted', tx);
    }
    async reactivateConversation(id, actor, tx) {
        return this._transition(id, 'ACTIVE', actor, 'ConversationReactivated', tx);
    }
    // ── Messaging ────────────────────────────────────────────────────────────────
    async addMessage(conversationId, data, tx) {
        this.validateUuid(conversationId, 'conversationId');
        if (!data.role || !data.content) {
            throw new Error('Validation failed: role and content are required.');
        }
        const runInTx = async (transaction) => {
            const conversation = await this.conversationRepo.findById(conversationId, transaction);
            if (!conversation || conversation.deletedAt) {
                throw new Error(`Conversation "${conversationId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const message = await client.conversationMessage.create({
                data: {
                    conversationId,
                    role: data.role,
                    content: data.content,
                    parentMessageId: data.parentMessageId ?? null,
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            // Update context size accounting
            const newContextSize = (conversation.contextSize ?? 0) + data.content.length;
            await this.conversationRepo.update(conversationId, { contextSize: newContextSize, updatedBy: data.updatedBy }, transaction);
            await EventPublisher_1.eventPublisher.publish('ConversationMessageAdded', { conversationId, message });
            return message;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async searchMessages(query, tx) {
        if (!query || query.trim().length === 0) {
            throw new Error('Validation failed: search query must not be empty.');
        }
        return this.conversationRepo.searchMessages(query, tx);
    }
    // ── Summary / Tags ───────────────────────────────────────────────────────────
    async updateSummary(id, summary, actor, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const existing = await this.conversationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            const updated = await this.conversationRepo.update(id, { summary, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ConversationSummaryUpdated', { conversation: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async addTag(id, tag, actor, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const existing = await this.conversationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            const tags = Array.from(new Set([...(existing.tags ?? []), tag]));
            const updated = await this.conversationRepo.update(id, { tags, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ConversationTagged', { conversation: updated, tag });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async removeTag(id, tag, actor, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const existing = await this.conversationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            const tags = (existing.tags ?? []).filter((t) => t !== tag);
            const updated = await this.conversationRepo.update(id, { tags, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ConversationUntagged', { conversation: updated, tag });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Token accounting ─────────────────────────────────────────────────────────
    async recalculateContextSize(id, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const conversation = await this.conversationRepo.findWithMessages(id, transaction);
            if (!conversation || conversation.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            const size = conversation.messages.reduce((sum, m) => sum + (m.content?.length ?? 0), 0);
            await this.conversationRepo.update(id, { contextSize: size, updatedBy: 'system' }, transaction);
            return size;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Statistics ───────────────────────────────────────────────────────────────
    async getConversationStats(id, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const conversation = await this.conversationRepo.findWithMessages(id, transaction);
            if (!conversation || conversation.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            const memories = await this.sessionMemoryRepo.findMany({ filter: { conversationId: id, deletedAt: null } }, transaction);
            const windows = await this.contextWindowRepo.findByConversation(id, transaction);
            return {
                messageCount: conversation.messages.length,
                contextSize: conversation.contextSize ?? 0,
                memoryCount: memories.length,
                windowCount: windows.length,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findConversation(id, tx) {
        this.validateUuid(id, 'conversationId');
        return this.conversationRepo.findById(id, tx);
    }
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        return this.conversationRepo.findByProject(projectId, tx);
    }
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        return this.conversationRepo.findByUser(userId, tx);
    }
    async findByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.conversationRepo.findByInvestigation(investigationId, tx);
    }
    async findActive(tx) {
        return this.conversationRepo.findActive(tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteConversation(id, actor, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const existing = await this.conversationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            await this.conversationRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ConversationDeleted', { conversationId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'conversationId');
        const runInTx = async (transaction) => {
            const existing = await this.conversationRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Conversation "${id}" not found.`);
            }
            const updated = await this.conversationRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { conversation: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ConversationService = ConversationService;
