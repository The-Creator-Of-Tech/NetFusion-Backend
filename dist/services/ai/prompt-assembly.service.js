"use strict";
/**
 * PromptAssemblyService — Phase A5.3.4
 * ======================================
 * Manages prompt assembly lifecycle: creation, publishing, archiving,
 * section management, template application, token budget tracking.
 * Publishes events on prompt mutations and token threshold events.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PromptAssemblyService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class PromptAssemblyService extends BaseService_1.BaseService {
    constructor(promptRepo = ai_1.promptAssemblyRepository) {
        super();
        this.promptRepo = promptRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createPrompt(data, tx) {
        this.validateRequired(data, ['investigationId', 'projectId', 'systemPrompt', 'userPrompt', 'createdBy', 'updatedBy']);
        this.validateUuid(data.investigationId, 'investigationId');
        this.validateUuid(data.projectId, 'projectId');
        if (data.reasoningId)
            this.validateUuid(data.reasoningId, 'reasoningId');
        if (data.contextId)
            this.validateUuid(data.contextId, 'contextId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            const prompt = await this.promptRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('PromptAssemblyCreated', { prompt });
            return prompt;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async publishPrompt(id, actor, tx) {
        return this._transition(id, 'ACTIVE', actor, 'PromptAssemblyPublished', tx);
    }
    async archivePrompt(id, actor, tx) {
        return this._transition(id, 'ARCHIVED', actor, 'PromptAssemblyArchived', tx);
    }
    async draftPrompt(id, actor, tx) {
        return this._transition(id, 'DRAFT', actor, 'PromptAssemblyDrafted', tx);
    }
    // ── Section management ───────────────────────────────────────────────────────
    async addSection(promptId, data, tx) {
        this.validateUuid(promptId, 'promptId');
        this.validateRequired(data, ['title', 'content', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const prompt = await this.promptRepo.findById(promptId, transaction);
            if (!prompt || prompt.deletedAt) {
                throw new Error(`PromptAssembly "${promptId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const section = await client.promptSection.create({
                data: {
                    promptId,
                    title: data.title,
                    content: data.content,
                    priority: data.priority ?? 50,
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            await EventPublisher_1.eventPublisher.publish('PromptSectionAdded', { promptId, section });
            return section;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateSection(sectionId, data, tx) {
        this.validateUuid(sectionId, 'sectionId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.promptSection.findUnique({ where: { id: sectionId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`PromptSection "${sectionId}" not found.`);
            }
            const updated = await client.promptSection.update({
                where: { id: sectionId },
                data: {
                    ...data,
                    updatedAt: new Date(),
                    version: (existing.version ?? 1) + 1,
                },
            });
            await EventPublisher_1.eventPublisher.publish('PromptSectionUpdated', { section: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async deleteSection(sectionId, actor, tx) {
        this.validateUuid(sectionId, 'sectionId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.promptSection.findUnique({ where: { id: sectionId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`PromptSection "${sectionId}" not found.`);
            }
            await client.promptSection.update({
                where: { id: sectionId },
                data: {
                    deletedAt: new Date(),
                    updatedBy: actor,
                    version: (existing.version ?? 1) + 1,
                },
            });
            await EventPublisher_1.eventPublisher.publish('PromptSectionDeleted', { sectionId });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Assembly / Token budget ──────────────────────────────────────────────────
    async assemblePrompt(promptId, tx) {
        this.validateUuid(promptId, 'promptId');
        const runInTx = async (transaction) => {
            const prompt = await this.promptRepo.findById(promptId, transaction);
            if (!prompt || prompt.deletedAt) {
                throw new Error(`PromptAssembly "${promptId}" not found.`);
            }
            const sections = await this.promptRepo.findSections(promptId, transaction);
            const sortedSections = sections.sort((a, b) => (b.priority ?? 50) - (a.priority ?? 50));
            let assembled = `SYSTEM:\n${prompt.systemPrompt}\n\nUSER:\n${prompt.userPrompt}\n\n`;
            for (const section of sortedSections) {
                assembled += `--- ${section.title} ---\n${section.content}\n\n`;
            }
            return assembled;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async calculateTokenUsage(promptId, tx) {
        this.validateUuid(promptId, 'promptId');
        const assembled = await this.assemblePrompt(promptId, tx);
        // Rough token estimate: 1 token ≈ 4 characters (GPT-style tokenization heuristic)
        return Math.ceil(assembled.length / 4);
    }
    async checkTokenBudget(promptId, tx) {
        this.validateUuid(promptId, 'promptId');
        const runInTx = async (transaction) => {
            const prompt = await this.promptRepo.findById(promptId, transaction);
            if (!prompt || prompt.deletedAt) {
                throw new Error(`PromptAssembly "${promptId}" not found.`);
            }
            const estimatedTokens = await this.calculateTokenUsage(promptId, transaction);
            const maxTokens = prompt.maxTokens ?? 8192;
            const reservedTokens = prompt.reservedTokens ?? 1024;
            const withinBudget = estimatedTokens <= maxTokens - reservedTokens;
            return { estimatedTokens, maxTokens, reservedTokens, withinBudget };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Search ───────────────────────────────────────────────────────────────────
    async searchSections(query, tx) {
        if (!query || query.trim().length === 0) {
            throw new Error('Validation failed: search query must not be empty.');
        }
        return this.promptRepo.searchSections(query, tx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findPrompt(id, tx) {
        this.validateUuid(id, 'promptId');
        return this.promptRepo.findById(id, tx);
    }
    async findByProject(projectId, tx) {
        this.validateUuid(projectId, 'projectId');
        return this.promptRepo.findByProject(projectId, tx);
    }
    async findPublished(tx) {
        return this.promptRepo.findPublished(tx);
    }
    async findSections(promptId, tx) {
        this.validateUuid(promptId, 'promptId');
        return this.promptRepo.findSections(promptId, tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deletePrompt(id, actor, tx) {
        this.validateUuid(id, 'promptId');
        const runInTx = async (transaction) => {
            const existing = await this.promptRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`PromptAssembly "${id}" not found.`);
            }
            await this.promptRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('PromptAssemblyDeleted', { promptId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'promptId');
        const runInTx = async (transaction) => {
            const existing = await this.promptRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`PromptAssembly "${id}" not found.`);
            }
            const updated = await this.promptRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { prompt: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.PromptAssemblyService = PromptAssemblyService;
