"use strict";
/**
 * ContextWindowService — Phase A5.3.4
 * ======================================
 * Manages context window lifecycle: creation, archiving, entry management,
 * priority-based ranking, importance/confidence scoring, and size accounting.
 * Publishes events on window mutations and content changes.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContextWindowService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ContextWindowService extends BaseService_1.BaseService {
    constructor(contextRepo = ai_1.contextWindowRepository) {
        super();
        this.contextRepo = contextRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createWindow(data, tx) {
        this.validateRequired(data, ['projectId', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        if (data.investigationId)
            this.validateUuid(data.investigationId, 'investigationId');
        if (data.conversationId)
            this.validateUuid(data.conversationId, 'conversationId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            const window = await this.contextRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('ContextWindowCreated', { window });
            return window;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async archiveWindow(id, actor, tx) {
        return this._transition(id, 'ARCHIVED', actor, 'ContextWindowArchived', tx);
    }
    async activateWindow(id, actor, tx) {
        return this._transition(id, 'ACTIVE', actor, 'ContextWindowActivated', tx);
    }
    // ── Entry management ─────────────────────────────────────────────────────────
    async addEntry(contextId, data, tx) {
        this.validateUuid(contextId, 'contextId');
        this.validateRequired(data, ['source', 'priority', 'title', 'content', 'referenceId', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const window = await this.contextRepo.findById(contextId, transaction);
            if (!window || window.deletedAt) {
                throw new Error(`ContextWindow "${contextId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const entry = await client.contextEntry.create({
                data: {
                    contextId,
                    source: data.source,
                    priority: data.priority,
                    title: data.title,
                    content: data.content,
                    referenceId: data.referenceId,
                    importanceScore: data.importanceScore ?? 50.0,
                    confidence: data.confidence ?? 0.0,
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            // Recalculate context size
            const newSize = await this.contextRepo.calculateContextSize(contextId, transaction);
            await this.contextRepo.update(contextId, { contextSize: newSize, updatedBy: data.updatedBy }, transaction);
            await EventPublisher_1.eventPublisher.publish('ContextEntryAdded', { contextId, entry });
            return entry;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateEntry(entryId, data, tx) {
        this.validateUuid(entryId, 'entryId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.contextEntry.findUnique({ where: { id: entryId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ContextEntry "${entryId}" not found.`);
            }
            const updated = await client.contextEntry.update({
                where: { id: entryId },
                data: {
                    ...data,
                    updatedAt: new Date(),
                    version: (existing.version ?? 1) + 1,
                },
            });
            // Recalculate parent window context size
            const newSize = await this.contextRepo.calculateContextSize(existing.contextId, transaction);
            await this.contextRepo.update(existing.contextId, { contextSize: newSize, updatedBy: data.updatedBy ?? 'system' }, transaction);
            await EventPublisher_1.eventPublisher.publish('ContextEntryUpdated', { entry: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async deleteEntry(entryId, actor, tx) {
        this.validateUuid(entryId, 'entryId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.contextEntry.findUnique({ where: { id: entryId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ContextEntry "${entryId}" not found.`);
            }
            await client.contextEntry.update({
                where: { id: entryId },
                data: {
                    deletedAt: new Date(),
                    updatedBy: actor,
                    version: (existing.version ?? 1) + 1,
                },
            });
            // Recalculate parent window context size
            const newSize = await this.contextRepo.calculateContextSize(existing.contextId, transaction);
            await this.contextRepo.update(existing.contextId, { contextSize: newSize, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ContextEntryDeleted', { entryId });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Priority ranking ─────────────────────────────────────────────────────────
    async rankEntriesByImportance(contextId, tx) {
        this.validateUuid(contextId, 'contextId');
        const runInTx = async (transaction) => {
            const entries = await this.contextRepo.findEntries(contextId, transaction);
            return entries.sort((a, b) => (b.importanceScore ?? 0) - (a.importanceScore ?? 0));
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async rankEntriesByConfidence(contextId, tx) {
        this.validateUuid(contextId, 'contextId');
        const runInTx = async (transaction) => {
            const entries = await this.contextRepo.findEntries(contextId, transaction);
            return entries.sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0));
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Statistics ───────────────────────────────────────────────────────────────
    async getWindowStats(contextId, tx) {
        this.validateUuid(contextId, 'contextId');
        const runInTx = async (transaction) => {
            const window = await this.contextRepo.findById(contextId, transaction);
            if (!window || window.deletedAt) {
                throw new Error(`ContextWindow "${contextId}" not found.`);
            }
            const entries = await this.contextRepo.findEntries(contextId, transaction);
            const avgImportance = entries.length > 0
                ? entries.reduce((sum, e) => sum + (e.importanceScore ?? 0.0), 0.0) / entries.length
                : 0.0;
            const avgConfidence = entries.length > 0
                ? entries.reduce((sum, e) => sum + (e.confidence ?? 0.0), 0.0) / entries.length
                : 0.0;
            return {
                entryCount: entries.length,
                contextSize: window.contextSize ?? 0,
                averageImportance: avgImportance,
                averageConfidence: avgConfidence,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findWindow(id, tx) {
        this.validateUuid(id, 'contextId');
        return this.contextRepo.findById(id, tx);
    }
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        return this.contextRepo.findByUser(userId, tx);
    }
    async findByConversation(conversationId, tx) {
        this.validateUuid(conversationId, 'conversationId');
        return this.contextRepo.findByConversation(conversationId, tx);
    }
    async findActive(tx) {
        return this.contextRepo.findActive(tx);
    }
    async findEntries(contextId, tx) {
        this.validateUuid(contextId, 'contextId');
        return this.contextRepo.findEntries(contextId, tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteWindow(id, actor, tx) {
        this.validateUuid(id, 'contextId');
        const runInTx = async (transaction) => {
            const existing = await this.contextRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ContextWindow "${id}" not found.`);
            }
            await this.contextRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ContextWindowDeleted', { contextId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'contextId');
        const runInTx = async (transaction) => {
            const existing = await this.contextRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ContextWindow "${id}" not found.`);
            }
            const updated = await this.contextRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { window: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ContextWindowService = ContextWindowService;
