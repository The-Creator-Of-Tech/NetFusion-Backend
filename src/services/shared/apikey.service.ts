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

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { apiKeyRepository } from '../../repositories/core';
import prisma from '../../lib/prisma';
import { ApiKey, ApiKeyStatus, Prisma } from '@prisma/client';

const VALID_STATUSES: string[] = ['ACTIVE', 'REVOKED', 'EXPIRED'];

export class ApiKeyService extends BaseService {
  constructor(private readonly apiKeyRepo = apiKeyRepository) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createApiKey(
    data: Prisma.ApiKeyUncheckedCreateInput,
    tx?: any,
  ): Promise<ApiKey> {
    this.validateRequired(data as any, ['userId', 'name', 'keyHash', 'createdBy', 'updatedBy']);
    if (!String(data.name).trim()) {
      throw new Error('Validation failed: name must not be empty.');
    }
    if (!String(data.keyHash).trim()) {
      throw new Error('Validation failed: keyHash must not be empty.');
    }
    if (data.expiresAt !== undefined && data.expiresAt !== null) {
      const exp = new Date(data.expiresAt as string);
      if (isNaN(exp.getTime()) || exp <= new Date()) {
        throw new Error('Validation failed: expiresAt must be a future date.');
      }
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;

      // Unique keyHash
      const existing = await client.apiKey.findFirst({
        where: { keyHash: String(data.keyHash), deletedAt: null },
      });
      if (existing) {
        throw new Error(`An API key with this hash already exists.`);
      }

      const apiKey = await client.apiKey.create({ data });
      await eventPublisher.publish('ApiKeyCreated', { apiKey });
      return apiKey;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  async updateApiKey(
    id: string,
    data: Prisma.ApiKeyUncheckedUpdateInput,
    tx?: any,
  ): Promise<ApiKey> {
    this.validateUuid(id, 'apiKeyId');

    if (data.expiresAt !== undefined && data.expiresAt !== null) {
      const exp = new Date(data.expiresAt as string);
      if (isNaN(exp.getTime())) {
        throw new Error('Validation failed: expiresAt must be a valid date.');
      }
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.apiKeyRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`ApiKey "${id}" not found.`);
      }
      const updated = await this.apiKeyRepo.update(id, data, transaction);
      await eventPublisher.publish('ApiKeyUpdated', { apiKey: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Revoke ──────────────────────────────────────────────────────────────────

  async revokeApiKey(id: string, actor: string, tx?: any): Promise<ApiKey> {
    this.validateUuid(id, 'apiKeyId');

    const runInTx = async (transaction: any) => {
      const existing = await this.apiKeyRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`ApiKey "${id}" not found.`);
      }
      if ((existing as any).status === 'REVOKED') {
        throw new Error(`ApiKey "${id}" is already revoked.`);
      }
      const updated = await this.apiKeyRepo.update(
        id,
        { status: 'REVOKED' as ApiKeyStatus, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('ApiKeyRevoked', { apiKey: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async expireApiKey(id: string, actor: string, tx?: any): Promise<ApiKey> {
    this.validateUuid(id, 'apiKeyId');

    const runInTx = async (transaction: any) => {
      const existing = await this.apiKeyRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`ApiKey "${id}" not found.`);
      }
      const updated = await this.apiKeyRepo.update(
        id,
        { status: 'EXPIRED' as ApiKeyStatus, expiresAt: new Date(), updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('ApiKeyExpired', { apiKey: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  async deleteApiKey(id: string, actor: string, tx?: any): Promise<ApiKey> {
    this.validateUuid(id, 'apiKeyId');

    const runInTx = async (transaction: any) => {
      const existing = await this.apiKeyRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`ApiKey "${id}" not found.`);
      }
      const deleted = await this.apiKeyRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('ApiKeyDeleted', { apiKey: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Record Usage ────────────────────────────────────────────────────────────

  async recordUsage(id: string, actor: string, tx?: any): Promise<ApiKey> {
    this.validateUuid(id, 'apiKeyId');

    const runInTx = async (transaction: any) => {
      const existing = await this.apiKeyRepo.findById(id, transaction);
      if (!existing || (existing as any).deletedAt) {
        throw new Error(`ApiKey "${id}" not found.`);
      }
      // Auto-expire if past expiresAt
      const key = existing as any;
      if (key.expiresAt && new Date(key.expiresAt) < new Date() && key.status === 'ACTIVE') {
        return this.expireApiKey(id, actor, transaction);
      }
      const updated = await this.apiKeyRepo.update(
        id,
        { lastUsedAt: new Date(), updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('ApiKeyUsed', { apiKey: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByUser(userId: string, tx?: any): Promise<ApiKey[]> {
    this.validateUuid(userId, 'userId');
    const client = tx || prisma;
    return client.apiKey.findMany({
      where: { userId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByStatus(status: ApiKeyStatus, tx?: any): Promise<ApiKey[]> {
    if (!VALID_STATUSES.includes(String(status).toUpperCase())) {
      throw new Error(`Validation failed: status "${status}" is not valid.`);
    }
    const client = tx || prisma;
    return client.apiKey.findMany({
      where: { status, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByKeyHash(keyHash: string, tx?: any): Promise<ApiKey | null> {
    if (!keyHash || !keyHash.trim()) {
      throw new Error('Validation failed: keyHash must not be empty.');
    }
    const client = tx || prisma;
    return client.apiKey.findFirst({
      where: { keyHash, deletedAt: null },
    });
  }

  async findActive(tx?: any): Promise<ApiKey[]> {
    const client = tx || prisma;
    return client.apiKey.findMany({
      where: { status: 'ACTIVE', deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findExpired(tx?: any): Promise<ApiKey[]> {
    const client = tx || prisma;
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

  async validateApiKey(keyHash: string, tx?: any): Promise<{ valid: boolean; apiKey?: ApiKey; reason?: string }> {
    if (!keyHash || !keyHash.trim()) {
      throw new Error('Validation failed: keyHash must not be empty.');
    }
    const apiKey = await this.findByKeyHash(keyHash, tx);
    if (!apiKey) return { valid: false, reason: 'Key not found' };

    const key = apiKey as any;
    if (key.status === 'REVOKED') return { valid: false, reason: 'Key is revoked', apiKey };
    if (key.status === 'EXPIRED') return { valid: false, reason: 'Key is expired', apiKey };
    if (key.expiresAt && new Date(key.expiresAt) < new Date()) {
      return { valid: false, reason: 'Key has expired', apiKey };
    }

    return { valid: true, apiKey };
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalApiKeys: number;
    activeKeys: number;
    revokedKeys: number;
    expiredKeys: number;
    userCounts: Record<string, number>;
  }> {
    const client = tx || prisma;
    const all = await client.apiKey.findMany({ where: { deletedAt: null } });

    let active = 0, revoked = 0, expired = 0;
    const userCounts: Record<string, number> = {};

    for (const k of all) {
      if (k.status === 'ACTIVE') active++;
      else if (k.status === 'REVOKED') revoked++;
      else if (k.status === 'EXPIRED') expired++;
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

  async bulkRevoke(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.revokeApiKey(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('ApiKeysBulkRevoked', { succeeded, failed });
    return { succeeded, failed };
  }

  async bulkDelete(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteApiKey(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('ApiKeysBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const apiKeyService = new ApiKeyService();
