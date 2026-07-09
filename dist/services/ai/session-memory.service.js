"use strict";
/**
 * SessionMemoryService — Phase A5.3.4
 * ======================================
 * Manages session memory lifecycle: creation, archiving, entry management,
 * importance scoring, confidence tracking, and state-based search.
 * Publishes events on memory mutations and threshold events.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionMemoryService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class SessionMemoryService extends BaseService_1.BaseService {
    constructor(memoryRepo = ai_1.sessionMemoryRepository) {
        super();
        this.memoryRepo = memoryRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createMemory(data, tx) {
        this.validateRequired(data, ['conversationId', 'projectId', 'createdBy', 'updatedBy']);
        this.validateUuid(data.conversationId, 'conversationId');
        this.validateUuid(data.projectId, 'projectId');
        if (data.investigationId)
            this.validateUuid(data.investigationId, 'investigationId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            const memory = await this.memoryRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('SessionMemoryCreated', { memory });
            return memory;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async archiveMemory(id, actor, tx) {
        return this._transition(id, 'ARCHIVED', actor, 'SessionMemoryArchived', tx);
    }
    async activateMemory(id, actor, tx) {
        return this._transition(id, 'ACTIVE', actor, 'SessionMemoryActivated', tx);
    }
    // ── Entry management ─────────────────────────────────────────────────────────
    async addEntry(memoryId, data, tx) {
        this.validateUuid(memoryId, 'memoryId');
        this.validateRequired(data, ['memoryType', 'state', 'title', 'content', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const memory = await this.memoryRepo.findById(memoryId, transaction);
            if (!memory || memory.deletedAt) {
                throw new Error(`SessionMemory "${memoryId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const entry = await client.memoryEntry.create({
                data: {
                    memoryId,
                    memoryType: data.memoryType,
                    state: data.state,
                    title: data.title,
                    content: data.content,
                    importanceScore: data.importanceScore ?? 50.0,
                    confidence: data.confidence ?? 0.0,
                    sourceId: data.sourceId ?? null,
                    tags: data.tags ?? [],
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            // Update memory context size accounting
            const newContextSize = (memory.contextSize ?? 0) + data.content.length;
            await this.memoryRepo.update(memoryId, { contextSize: newContextSize, updatedBy: data.updatedBy }, transaction);
            await EventPublisher_1.eventPublisher.publish('MemoryEntryAdded', { memoryId, entry });
            return entry;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateEntry(entryId, data, tx) {
        this.validateUuid(entryId, 'entryId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.memoryEntry.findUnique({ where: { id: entryId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`MemoryEntry "${entryId}" not found.`);
            }
            const updated = await client.memoryEntry.update({
                where: { id: entryId },
                data: {
                    ...data,
                    updatedAt: new Date(),
                    version: (existing.version ?? 1) + 1,
                },
            });
            await EventPublisher_1.eventPublisher.publish('MemoryEntryUpdated', { entry: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async deleteEntry(entryId, actor, tx) {
        this.validateUuid(entryId, 'entryId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.memoryEntry.findUnique({ where: { id: entryId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`MemoryEntry "${entryId}" not found.`);
            }
            await client.memoryEntry.update({
                where: { id: entryId },
                data: {
                    deletedAt: new Date(),
                    updatedBy: actor,
                    version: (existing.version ?? 1) + 1,
                },
            });
            await EventPublisher_1.eventPublisher.publish('MemoryEntryDeleted', { entryId });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Search ───────────────────────────────────────────────────────────────────
    async searchEntries(query, tx) {
        if (!query || query.trim().length === 0) {
            throw new Error('Validation failed: search query must not be empty.');
        }
        return this.memoryRepo.searchEntries(query, tx);
    }
    // ── Importance / Confidence ──────────────────────────────────────────────────
    async calculateAverageImportance(memoryId, tx) {
        this.validateUuid(memoryId, 'memoryId');
        const runInTx = async (transaction) => {
            const entries = await this.memoryRepo.findEntries(memoryId, transaction);
            if (entries.length === 0)
                return 0.0;
            const sum = entries.reduce((total, e) => total + (e.importanceScore ?? 0.0), 0.0);
            return sum / entries.length;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async calculateAverageConfidence(memoryId, tx) {
        this.validateUuid(memoryId, 'memoryId');
        const runInTx = async (transaction) => {
            const entries = await this.memoryRepo.findEntries(memoryId, transaction);
            if (entries.length === 0)
                return 0.0;
            const sum = entries.reduce((total, e) => total + (e.confidence ?? 0.0), 0.0);
            return sum / entries.length;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Statistics ───────────────────────────────────────────────────────────────
    async getMemoryStats(memoryId, tx) {
        this.validateUuid(memoryId, 'memoryId');
        const runInTx = async (transaction) => {
            const memory = await this.memoryRepo.findById(memoryId, transaction);
            if (!memory || memory.deletedAt) {
                throw new Error(`SessionMemory "${memoryId}" not found.`);
            }
            const entries = await this.memoryRepo.findEntries(memoryId, transaction);
            const avgImportance = await this.calculateAverageImportance(memoryId, transaction);
            const avgConfidence = await this.calculateAverageConfidence(memoryId, transaction);
            return {
                entryCount: entries.length,
                contextSize: memory.contextSize ?? 0,
                averageImportance: avgImportance,
                averageConfidence: avgConfidence,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findMemory(id, tx) {
        this.validateUuid(id, 'memoryId');
        return this.memoryRepo.findById(id, tx);
    }
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        return this.memoryRepo.findByProject(projectId, tx);
    }
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        return this.memoryRepo.findByUser(userId, tx);
    }
    async findByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.memoryRepo.findByInvestigation(investigationId, tx);
    }
    async findActive(tx) {
        return this.memoryRepo.findActive(tx);
    }
    async findEntries(memoryId, tx) {
        this.validateUuid(memoryId, 'memoryId');
        return this.memoryRepo.findEntries(memoryId, tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteMemory(id, actor, tx) {
        this.validateUuid(id, 'memoryId');
        const runInTx = async (transaction) => {
            const existing = await this.memoryRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`SessionMemory "${id}" not found.`);
            }
            await this.memoryRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('SessionMemoryDeleted', { memoryId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'memoryId');
        const runInTx = async (transaction) => {
            const existing = await this.memoryRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`SessionMemory "${id}" not found.`);
            }
            const updated = await this.memoryRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { memory: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.SessionMemoryService = SessionMemoryService;
