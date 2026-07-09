"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProviderRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ProviderRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('provider');
    }
    /**
     * Finds enabled providers where not deleted.
     */
    async findEnabled(tx) {
        return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
    }
    /**
     * Finds disabled providers where not deleted.
     */
    async findDisabled(tx) {
        return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
    }
    /**
     * Finds healthy providers (status: ACTIVE, healthScore >= 80.0, and not deleted).
     */
    async findHealthy(tx) {
        return this.findMany({
            filter: {
                status: 'ACTIVE',
                healthScore: { gte: 80.0 },
                deletedAt: null,
            },
        }, tx);
    }
    /**
     * Finds provider models associated with a specific provider ID where not deleted.
     */
    async findModels(providerId, tx) {
        const client = tx || prisma_1.default;
        return client.providerModel.findMany({
            where: { providerId, deletedAt: null },
        });
    }
    /**
     * Finds a specific provider model by provider ID and model name where not deleted.
     */
    async findModelByName(providerId, modelName, tx) {
        const client = tx || prisma_1.default;
        return client.providerModel.findFirst({
            where: { providerId, modelName, deletedAt: null },
        });
    }
    /**
     * Aggregates capabilities of all enabled models for a provider.
     */
    async findCapabilities(providerId, tx) {
        const models = await this.findModels(providerId, tx);
        const enabledModels = models.filter((m) => m.enabled);
        return {
            streaming: enabledModels.some((m) => m.streaming),
            toolCalling: enabledModels.some((m) => m.toolCalling),
            jsonMode: enabledModels.some((m) => m.jsonMode),
            vision: enabledModels.some((m) => m.vision),
            embeddings: enabledModels.some((m) => m.embeddings),
        };
    }
}
exports.ProviderRepository = ProviderRepository;
