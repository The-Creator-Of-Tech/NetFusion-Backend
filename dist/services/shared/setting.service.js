"use strict";
/**
 * SettingService — Phase A5.3.7
 * ================================
 * Business logic for SystemSetting lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Upsert, read, delete system settings
 * - Filter by scope (GLOBAL / PROJECT / USER)
 * - Key validation and normalization
 * - Typed value retrieval helpers (string, number, boolean, JSON)
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.settingService = exports.SettingService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const prisma_1 = __importDefault(require("../../lib/prisma"));
const VALID_SCOPES = ['GLOBAL', 'PROJECT', 'USER'];
class SettingService extends BaseService_1.BaseService {
    // ── Upsert ──────────────────────────────────────────────────────────────────
    async upsert(data, tx) {
        this.validateRequired(data, ['key', 'value', 'createdBy', 'updatedBy']);
        const key = String(data.key).trim();
        if (!key) {
            throw new Error('Validation failed: key must not be empty.');
        }
        if (data.value === undefined || data.value === null || String(data.value).trim() === '') {
            throw new Error('Validation failed: value must not be empty.');
        }
        if (data.scope !== undefined && !VALID_SCOPES.includes(String(data.scope).toUpperCase())) {
            throw new Error(`Validation failed: scope "${data.scope}" is not valid.`);
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.systemSetting.findFirst({
                where: { key, deletedAt: null },
            });
            let setting;
            if (existing) {
                setting = await client.systemSetting.update({
                    where: { id: existing.id },
                    data: {
                        value: String(data.value),
                        scope: data.scope ?? existing.scope,
                        description: data.description ?? existing.description,
                        updatedBy: data.updatedBy,
                        version: { increment: 1 },
                    },
                });
                await EventPublisher_1.eventPublisher.publish('SettingUpdated', { setting });
            }
            else {
                setting = await client.systemSetting.create({
                    data: { ...data, key },
                });
                await EventPublisher_1.eventPublisher.publish('SettingCreated', { setting });
            }
            return setting;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Delete ──────────────────────────────────────────────────────────────────
    async deleteSetting(key, actor, tx) {
        if (!key || !key.trim()) {
            throw new Error('Validation failed: key must not be empty.');
        }
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.systemSetting.findFirst({
                where: { key: key.trim(), deletedAt: null },
            });
            if (!existing) {
                throw new Error(`Setting "${key}" not found.`);
            }
            const deleted = await client.systemSetting.update({
                where: { id: existing.id },
                data: { deletedAt: new Date(), updatedBy: actor, version: { increment: 1 } },
            });
            await EventPublisher_1.eventPublisher.publish('SettingDeleted', { setting: deleted });
            return deleted;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lookups ─────────────────────────────────────────────────────────────────
    async get(key, tx) {
        if (!key || !key.trim()) {
            throw new Error('Validation failed: key must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.systemSetting.findFirst({
            where: { key: key.trim(), deletedAt: null },
        });
    }
    async getOrThrow(key, tx) {
        const setting = await this.get(key, tx);
        if (!setting) {
            throw new Error(`Setting "${key}" not found.`);
        }
        return setting;
    }
    async getValue(key, defaultValue, tx) {
        const setting = await this.get(key, tx);
        return setting ? setting.value : defaultValue;
    }
    async getNumberValue(key, defaultValue, tx) {
        const setting = await this.get(key, tx);
        if (!setting)
            return defaultValue;
        const n = Number(setting.value);
        if (isNaN(n))
            throw new Error(`Setting "${key}" value "${setting.value}" is not a valid number.`);
        return n;
    }
    async getBoolValue(key, defaultValue, tx) {
        const setting = await this.get(key, tx);
        if (!setting)
            return defaultValue;
        const v = setting.value.toLowerCase();
        if (v === 'true' || v === '1' || v === 'yes')
            return true;
        if (v === 'false' || v === '0' || v === 'no')
            return false;
        throw new Error(`Setting "${key}" value "${setting.value}" is not a valid boolean.`);
    }
    async getJsonValue(key, tx) {
        const setting = await this.get(key, tx);
        if (!setting)
            return null;
        try {
            return JSON.parse(setting.value);
        }
        catch {
            throw new Error(`Setting "${key}" value is not valid JSON.`);
        }
    }
    async findByScope(scope, tx) {
        if (!VALID_SCOPES.includes(String(scope).toUpperCase())) {
            throw new Error(`Validation failed: scope "${scope}" is not valid.`);
        }
        const client = tx || prisma_1.default;
        return client.systemSetting.findMany({
            where: { scope, deletedAt: null },
            orderBy: { key: 'asc' },
        });
    }
    async findAll(tx) {
        const client = tx || prisma_1.default;
        return client.systemSetting.findMany({
            where: { deletedAt: null },
            orderBy: { key: 'asc' },
        });
    }
    async findByPrefix(prefix, tx) {
        if (!prefix || !prefix.trim()) {
            throw new Error('Validation failed: prefix must not be empty.');
        }
        const client = tx || prisma_1.default;
        return client.systemSetting.findMany({
            where: {
                key: { startsWith: prefix.trim() },
                deletedAt: null,
            },
            orderBy: { key: 'asc' },
        });
    }
    // ── Statistics ──────────────────────────────────────────────────────────────
    async getStatistics(tx) {
        const client = tx || prisma_1.default;
        const all = await client.systemSetting.findMany({ where: { deletedAt: null } });
        const scopeCounts = {};
        for (const s of all) {
            const scope = String(s.scope);
            scopeCounts[scope] = (scopeCounts[scope] ?? 0) + 1;
        }
        return { totalSettings: all.length, scopeCounts };
    }
    // ── Bulk Operations ─────────────────────────────────────────────────────────
    async bulkUpsert(items, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const item of items) {
            try {
                const s = await this.upsert({ ...item, createdBy: actor, updatedBy: actor }, tx);
                succeeded.push(s.id);
            }
            catch (e) {
                failed.push({ key: String(item.key ?? ''), reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('SettingsBulkUpserted', { succeeded, failed });
        return { succeeded, failed };
    }
    async bulkDelete(keys, actor, tx) {
        const succeeded = [];
        const failed = [];
        for (const key of keys) {
            try {
                const s = await this.deleteSetting(key, actor, tx);
                succeeded.push(s.id);
            }
            catch (e) {
                failed.push({ key, reason: e.message ?? 'Unknown error' });
            }
        }
        await EventPublisher_1.eventPublisher.publish('SettingsBulkDeleted', { succeeded, failed });
        return { succeeded, failed };
    }
}
exports.SettingService = SettingService;
exports.settingService = new SettingService();
