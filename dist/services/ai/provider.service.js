"use strict";
/**
 * ProviderService — Phase A5.3.4
 * ================================
 * Manages AI provider registry: provider creation, model registration,
 * health monitoring, capability discovery, priority-based selection,
 * and enablement toggling.
 * Publishes events on provider health changes and model registrations.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProviderService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ProviderService extends BaseService_1.BaseService {
    constructor(providerRepo = ai_1.providerRepository) {
        super();
        this.providerRepo = providerRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async registerProvider(data, tx) {
        this.validateRequired(data, ['providerName', 'displayName', 'apiVersion', 'endpoint', 'defaultModel', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const provider = await this.providerRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('ProviderRegistered', { provider });
            return provider;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async registerModel(providerId, data, tx) {
        this.validateUuid(providerId, 'providerId');
        this.validateRequired(data, ['modelName', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const provider = await this.providerRepo.findById(providerId, transaction);
            if (!provider || provider.deletedAt) {
                throw new Error(`Provider "${providerId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const model = await client.providerModel.create({
                data: {
                    providerId,
                    modelName: data.modelName,
                    alias: data.alias ?? null,
                    streaming: data.streaming ?? false,
                    toolCalling: data.toolCalling ?? false,
                    jsonMode: data.jsonMode ?? false,
                    vision: data.vision ?? false,
                    embeddings: data.embeddings ?? false,
                    maxContextTokens: data.maxContextTokens ?? 8192,
                    maxOutputTokens: data.maxOutputTokens ?? 4096,
                    enabled: data.enabled ?? true,
                    priority: data.priority ?? 50,
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ProviderModelRegistered', { providerId, model });
            return model;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Provider management ──────────────────────────────────────────────────────
    async enableProvider(id, actor, tx) {
        this.validateUuid(id, 'providerId');
        const runInTx = async (transaction) => {
            const existing = await this.providerRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Provider "${id}" not found.`);
            }
            const updated = await this.providerRepo.update(id, { enabled: true, status: 'ACTIVE', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ProviderEnabled', { provider: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async disableProvider(id, actor, tx) {
        this.validateUuid(id, 'providerId');
        const runInTx = async (transaction) => {
            const existing = await this.providerRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Provider "${id}" not found.`);
            }
            const updated = await this.providerRepo.update(id, { enabled: false, status: 'INACTIVE', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ProviderDisabled', { provider: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateHealthScore(id, healthScore, actor, tx) {
        this.validateUuid(id, 'providerId');
        const clampedScore = Math.max(0.0, Math.min(100.0, healthScore));
        const runInTx = async (transaction) => {
            const existing = await this.providerRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Provider "${id}" not found.`);
            }
            const updated = await this.providerRepo.update(id, { healthScore: clampedScore, updatedBy: actor }, transaction);
            const previousStatus = existing.status;
            const newStatus = clampedScore >= 80.0 ? 'ACTIVE' : 'DEGRADED';
            if (previousStatus !== newStatus) {
                await this.providerRepo.update(id, { status: newStatus, updatedBy: actor }, transaction);
                await EventPublisher_1.eventPublisher.publish('ProviderHealthChanged', {
                    provider: updated,
                    previousStatus,
                    newStatus,
                    healthScore: clampedScore,
                });
            }
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Priority-based selection ─────────────────────────────────────────────────
    async selectProvider(options = {}, tx) {
        const runInTx = async (transaction) => {
            let providers = await this.providerRepo.findHealthy(transaction);
            // Filter by capabilities if required
            if (options.requireStreaming || options.requireToolCalling || options.requireJsonMode) {
                const filtered = [];
                for (const provider of providers) {
                    const caps = await this.providerRepo.findCapabilities(provider.id, transaction);
                    const ok = (!options.requireStreaming || caps.streaming) &&
                        (!options.requireToolCalling || caps.toolCalling) &&
                        (!options.requireJsonMode || caps.jsonMode);
                    if (ok)
                        filtered.push(provider);
                }
                providers = filtered;
            }
            if (providers.length === 0)
                return null;
            switch (options.strategy ?? 'priority') {
                case 'health':
                    providers.sort((a, b) => (b.healthScore ?? 0) - (a.healthScore ?? 0));
                    return providers[0];
                case 'random':
                    return providers[Math.floor(Math.random() * providers.length)];
                case 'priority':
                default:
                    providers.sort((a, b) => (a.priority ?? 50) - (b.priority ?? 50));
                    return providers[0];
            }
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Capability discovery ─────────────────────────────────────────────────────
    async getCapabilities(providerId, tx) {
        this.validateUuid(providerId, 'providerId');
        return this.providerRepo.findCapabilities(providerId, tx);
    }
    async getModelCapabilities(modelId, tx) {
        this.validateUuid(modelId, 'modelId');
        const client = tx || prisma_1.default;
        return client.providerModel.findUnique({ where: { id: modelId } });
    }
    // ── Statistics ───────────────────────────────────────────────────────────────
    async getProviderStats(providerId, tx) {
        this.validateUuid(providerId, 'providerId');
        const runInTx = async (transaction) => {
            const provider = await this.providerRepo.findById(providerId, transaction);
            if (!provider || provider.deletedAt) {
                throw new Error(`Provider "${providerId}" not found.`);
            }
            const models = await this.providerRepo.findModels(providerId, transaction);
            const enabledModels = models.filter((m) => m.enabled).length;
            const capabilities = await this.providerRepo.findCapabilities(providerId, transaction);
            return {
                totalModels: models.length,
                enabledModels,
                healthScore: provider.healthScore ?? 100.0,
                status: provider.status,
                capabilities,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findProvider(id, tx) {
        this.validateUuid(id, 'providerId');
        return this.providerRepo.findById(id, tx);
    }
    async findEnabled(tx) {
        return this.providerRepo.findEnabled(tx);
    }
    async findHealthy(tx) {
        return this.providerRepo.findHealthy(tx);
    }
    async findModels(providerId, tx) {
        this.validateUuid(providerId, 'providerId');
        return this.providerRepo.findModels(providerId, tx);
    }
    async findModelByName(providerId, modelName, tx) {
        this.validateUuid(providerId, 'providerId');
        return this.providerRepo.findModelByName(providerId, modelName, tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteProvider(id, actor, tx) {
        this.validateUuid(id, 'providerId');
        const runInTx = async (transaction) => {
            const existing = await this.providerRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Provider "${id}" not found.`);
            }
            await this.providerRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ProviderDeleted', { providerId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ProviderService = ProviderService;
