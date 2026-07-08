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

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import prisma from '../../lib/prisma';
import { SystemSetting, SettingScope, Prisma } from '@prisma/client';

const VALID_SCOPES: string[] = ['GLOBAL', 'PROJECT', 'USER'];

export class SettingService extends BaseService {

  // ── Upsert ──────────────────────────────────────────────────────────────────

  async upsert(
    data: Prisma.SystemSettingUncheckedCreateInput,
    tx?: any,
  ): Promise<SystemSetting> {
    this.validateRequired(data as any, ['key', 'value', 'createdBy', 'updatedBy']);
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

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.systemSetting.findFirst({
        where: { key, deletedAt: null },
      });

      let setting: SystemSetting;
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
        await eventPublisher.publish('SettingUpdated', { setting });
      } else {
        setting = await client.systemSetting.create({
          data: { ...data, key },
        });
        await eventPublisher.publish('SettingCreated', { setting });
      }
      return setting;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  async deleteSetting(key: string, actor: string, tx?: any): Promise<SystemSetting> {
    if (!key || !key.trim()) {
      throw new Error('Validation failed: key must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
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
      await eventPublisher.publish('SettingDeleted', { setting: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async get(key: string, tx?: any): Promise<SystemSetting | null> {
    if (!key || !key.trim()) {
      throw new Error('Validation failed: key must not be empty.');
    }
    const client = tx || prisma;
    return client.systemSetting.findFirst({
      where: { key: key.trim(), deletedAt: null },
    });
  }

  async getOrThrow(key: string, tx?: any): Promise<SystemSetting> {
    const setting = await this.get(key, tx);
    if (!setting) {
      throw new Error(`Setting "${key}" not found.`);
    }
    return setting;
  }

  async getValue(key: string, defaultValue?: string, tx?: any): Promise<string | undefined> {
    const setting = await this.get(key, tx);
    return setting ? setting.value : defaultValue;
  }

  async getNumberValue(key: string, defaultValue?: number, tx?: any): Promise<number | undefined> {
    const setting = await this.get(key, tx);
    if (!setting) return defaultValue;
    const n = Number(setting.value);
    if (isNaN(n)) throw new Error(`Setting "${key}" value "${setting.value}" is not a valid number.`);
    return n;
  }

  async getBoolValue(key: string, defaultValue?: boolean, tx?: any): Promise<boolean | undefined> {
    const setting = await this.get(key, tx);
    if (!setting) return defaultValue;
    const v = setting.value.toLowerCase();
    if (v === 'true' || v === '1' || v === 'yes') return true;
    if (v === 'false' || v === '0' || v === 'no') return false;
    throw new Error(`Setting "${key}" value "${setting.value}" is not a valid boolean.`);
  }

  async getJsonValue<T = any>(key: string, tx?: any): Promise<T | null> {
    const setting = await this.get(key, tx);
    if (!setting) return null;
    try {
      return JSON.parse(setting.value) as T;
    } catch {
      throw new Error(`Setting "${key}" value is not valid JSON.`);
    }
  }

  async findByScope(scope: SettingScope, tx?: any): Promise<SystemSetting[]> {
    if (!VALID_SCOPES.includes(String(scope).toUpperCase())) {
      throw new Error(`Validation failed: scope "${scope}" is not valid.`);
    }
    const client = tx || prisma;
    return client.systemSetting.findMany({
      where: { scope, deletedAt: null },
      orderBy: { key: 'asc' },
    });
  }

  async findAll(tx?: any): Promise<SystemSetting[]> {
    const client = tx || prisma;
    return client.systemSetting.findMany({
      where: { deletedAt: null },
      orderBy: { key: 'asc' },
    });
  }

  async findByPrefix(prefix: string, tx?: any): Promise<SystemSetting[]> {
    if (!prefix || !prefix.trim()) {
      throw new Error('Validation failed: prefix must not be empty.');
    }
    const client = tx || prisma;
    return client.systemSetting.findMany({
      where: {
        key: { startsWith: prefix.trim() },
        deletedAt: null,
      },
      orderBy: { key: 'asc' },
    });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalSettings: number;
    scopeCounts: Record<string, number>;
  }> {
    const client = tx || prisma;
    const all = await client.systemSetting.findMany({ where: { deletedAt: null } });

    const scopeCounts: Record<string, number> = {};
    for (const s of all) {
      const scope = String(s.scope);
      scopeCounts[scope] = (scopeCounts[scope] ?? 0) + 1;
    }

    return { totalSettings: all.length, scopeCounts };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  async bulkUpsert(
    items: Prisma.SystemSettingUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { key: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { key: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const s = await this.upsert({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(s.id);
      } catch (e: any) {
        failed.push({ key: String(item.key ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('SettingsBulkUpserted', { succeeded, failed });
    return { succeeded, failed };
  }

  async bulkDelete(
    keys: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { key: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { key: string; reason: string }[] = [];

    for (const key of keys) {
      try {
        const s = await this.deleteSetting(key, actor, tx);
        succeeded.push(s.id);
      } catch (e: any) {
        failed.push({ key, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('SettingsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const settingService = new SettingService();
