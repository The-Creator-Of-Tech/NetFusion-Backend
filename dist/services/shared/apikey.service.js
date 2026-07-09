"use strict";
/**
 * ApiKeyService — Phase A5.3.7
 * ================================
 * Business logic for API Key lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, revoke, expire, and soft-delete API keys
 * - Hash-based lookup (keyHash is the unique identifier; plaintext never stored)
 * - Status management: ACTIVE → REVOKED / EXPIRED
 * - Expiry enforcement
 * - Filter by user, status
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.apiKeyService = exports.ApiKeyService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const VALID_STATUSES = ['ACTIVE', 'REVOKED', 'EXPIRED'];
class ApiKeyService extends BaseService_1.BaseService {
    constructor(apiKeyRepo = core_1.apiKeyRepository) {
        super();
        this.apiKeyRepo = apiKeyRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createApiKey(data, tx) {
        this.validateRequired(data, ['userId', 'name', 'keyHash', 'createdBy', 'updatedBy']);
        if (!String(data.name).trim()) {
            throw new Error('Validation failed: name must not be empty.');
        }
        if (!String(data.keyHash).trim()) {
            throw new Error('Validation failed: keyHash must not be empty.');
        }
        if (data.expiresAt !== undefined && data.expiresAt !== null) {
            const exp = new Date(data.expiresAt);
            if (isNaN(exp.getTime()) || exp <= new Date()) {
                throw new Error('Validation failed: expiresAt must be a future date.');
            }
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            // Unique keyHash
            const existing = await client.apiKey.findFirst({
                where: { keyHash: String(data.keyHash), deletedAt: null },
            });
            if (existing) {
                throw new Error(`An API key with this hash already exists.`);
            }
            const apiKey = await client.apiKey.create({ data });
            await EventPublisher_1.eventPublisher.publish('ApiKeyCreated', { apiKey });
            return apiKey;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ──────────────────────────────────────────────────────────────────
    async updateApiKey(id, data, tx) {
        this.validateUuid(id, 'apiKeyId');
        if (data.expiresAt !== undefined && data.expiresAt !== null) {
            const exp = new Date(data.expiresAt);
            if (isNaN(exp.getTime())) {
                throw new Error('Validation failed: expiresAt must be a valid date.');
            }
        }
        const runInTx = async (transaction) => {
            const existing = await this.apiKeyRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ApiKey "${id}" not found.`);
            }
            const updated = await this.apiKeyRepo.update(id, data, transaction);
            await EventPublisher_1.eventPublisher.publish('ApiKeyUpdated', { apiKey: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Revoke ──────────────────────────────────────────────────────────────────
    async revokeApiKey(id, actor, tx) {
        this.validateUuid(id, 'apiKeyId');
        const runInTx = async (transaction) => {
            const existing = await this.apiKeyRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ApiKey "${id}" not found.`);
            }
            if (existing.status === 'REVOKED') {
                throw new Error(`ApiKey "${id}" is already revoked.`);
            }
            const updated = await this.apiKeyRepo.update(id, { status: 'REVOKED', updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ApiKeyRevoked', { apiKey: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async expireApiKey(id, actor, tx) {
        this.validateUuid(id, 'apiKeyId');
        const runInTx = async (transaction) => {
            const existing = await this.apiKeyRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ApiKey "${id}" not found.`);
            }
            const updated = await this.apiKeyRepo.update(id, { status: 'EXPIRED', expiresAt: new Date(), updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ApiKeyExpired', { apiKey: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    async deleteApiKey(id, actor, tx) {
        this.validateUuid(id, 'apiKeyId');
        const runInTx = async (transaction) => {
            const existing = await this.apiKeyRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ApiKey "${id}" not found.`);
            }
            const deleted = await this.apiKeyRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ApiKeyDeleted', { apiKey: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Record Usage ────────────────────────────────────────────────────────────
    async recordUsage(id, actor, tx) {
        this.validateUuid(id, 'apiKeyId');
        const runInTx = async (transaction) => {
            const existing = await this.apiKeyRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`ApiKey "${id}" not found.`);
            }
            // Auto-expire if past expiresAt
            const key = existing;
            if (key.expiresAt && new Date(key.expiresAt) < new Date() && key.status === 'ACTIVE') {
                return this.expireApiKey(id, actor, transaction);
            }
            const updated = await this.apiKeyRepo.update(id, { lastUsedAt: new Date(), updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ApiKeyUsed', { apiKey: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async findByUser(userId, tx) {
        this.validateUuid(userId, 'userId');
        const client = tx || prisma_1.default;
        return client.apiKey.findMany({
            where: { userId, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByStatus(status, tx) {
        if (!VALID_STATUSES.includes(String(status).toUpperCase())) {
            throw new Error(`Validation failed: status "${status}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.apiKey.findMany({
            where: { status, deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findByKeyHash(keyHash, tx) {
        if (!keyHash || !keyHash.trim()) {
            throw new Error('Validation failed: keyHash must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.apiKey.findFirst({
            where: { keyHash, deletedAt: null },
        });
    }
    async findActive(tx) {
        const client = tx || prisma_1.default;
        return client.apiKey.findMany({
            where: { status: 'ACTIVE', deletedAt: null },
            orderBy: { createdAt: 'desc' },
        });
    }
    async findExpired(tx) {
        const client = tx || prisma_1.default;
        return client.apiKey.findMany({
            where: {
                deletedAt: null,
                OR: [
                    { status: 'EXPIRED' },
                    { status: 'ACTIVE', expiresAt: { lt: new Date() } },
                ],
            },
            orderBy: { expiresAt: 'asc' },
        });
    }
    // ── Validation ──────────────────────────────────────────────────────────────
    async validateApiKey(keyHash, tx) {
        if (!keyHash || !keyHash.trim()) {
            throw new Error('Validation failed: keyHash must not be empty.');
        }
        const apiKey = await this.findByKeyHash(keyHash, tx);
        if (!apiKey)
            return { valid: false, reason: 'Key not found' };
        const key = apiKey;
        if (key.status === 'REVOKED')
            return { valid: false, reason: 'Key is revoked', apiKey };
        if (key.status === 'EXPIRED')
            return { valid: false, reason: 'Key is expired', apiKey };
        if (key.expiresAt && new Date(key.expiresAt) < new Date()) {
            return { valid: false, reason: 'Key has expired', apiKey };
        }
        return { valid: true, apiKey };
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.apiKey.findMany({ where: { deletedAt: null } });
        let active = 0, revoked = 0, expired = 0;
        const userCounts = {};
        for (const k of all) {
            if (k.status === 'ACTIVE')
                active++;
            else if (k.status === 'REVOKED')
                revoked++;
            else if (k.status === 'EXPIRED')
                expired++;
            userCounts[k.userId] = (userCounts[k.userId] ?? 0) + 1;
        }
        return {
            totalApiKeys: all.length,
            activeKeys: active,
            revokedKeys: revoked,
            expiredKeys: expired,
            userCounts,
        };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkRevoke(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.revokeApiKey(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('ApiKeysBulkRevoked', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkDelete(ids, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const id of ids) {
            try {
                await this.deleteApiKey(id, actor, tx);
                succeeded.push(id);
            }
            catch (e) {
                failed.push({ id, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('ApiKeysBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.ApiKeyService = ApiKeyService;
exports.apiKeyService = new ApiKeyService();
