"use strict";
/**
 * ApiKeyOrchestrator.ts
 * =====================================
 * Orchestrates API key management and validation.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.apiKeyOrchestrator = exports.ApiKeyOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ApiKeyOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ApiKeyOrchestrator');
    }
    async createApiKey(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Creating API key for user ${input.userId}: ${input.name}`);
        this.validateUuid(input.userId, 'userId', ctx);
        this.validateRequired(input, ['name', 'keyHash'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const apiKey = await shared_1.apiKeyService.createApiKey({
                userId: input.userId,
                name: input.name,
                keyHash: input.keyHash,
                expiresAt: input.expiresAt,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            }, null);
            compensation.register(`delete-apikey-${apiKey.id}`, async () => {
                try {
                    await prisma_1.default.apiKey.delete({ where: { id: apiKey.id } });
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.API_KEY_CREATED, ctx, {
                apiKeyId: apiKey.id,
                userId: input.userId,
                name: input.name,
            });
            compensation.clear();
            return apiKey;
        });
    }
    async revokeApiKey(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Revoking API key ${input.apiKeyId}`);
        this.validateRequired(input, ['apiKeyId'], ctx);
        this.validateUuid(input.apiKeyId, 'apiKeyId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.apiKey.findUnique({
                where: { id: input.apiKeyId },
            });
            if (!existing || existing.deletedAt) {
                throw new Error(`ApiKey "${input.apiKeyId}" not found.`);
            }
            const revoked = await shared_1.apiKeyService.revokeApiKey(input.apiKeyId, input.actor, null);
            compensation.register(`restore-apikey-${input.apiKeyId}`, async () => {
                await prisma_1.default.apiKey.update({
                    where: { id: input.apiKeyId },
                    data: {
                        status: existing.status,
                        updatedBy: 'system',
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.API_KEY_REVOKED, ctx, {
                apiKeyId: input.apiKeyId,
                userId: revoked.userId,
            });
            compensation.clear();
            return revoked;
        });
    }
    async validateApiKey(keyHash, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Validating API key hash`);
        if (!keyHash || !keyHash.trim()) {
            throw new Error('Validation failed: keyHash must not be empty.');
        }
        const result = await shared_1.apiKeyService.validateApiKey(keyHash);
        if (result.valid && result.apiKey) {
            await shared_1.apiKeyService.recordUsage(result.apiKey.id, actor);
        }
        return result;
    }
    async getApiKeysForUser(userId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching API keys for user ${userId}`);
        this.validateUuid(userId, 'userId', ctx);
        return shared_1.apiKeyService.findByUser(userId);
    }
}
exports.ApiKeyOrchestrator = ApiKeyOrchestrator;
exports.apiKeyOrchestrator = new ApiKeyOrchestrator();
