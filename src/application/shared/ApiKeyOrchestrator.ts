/**
 * ApiKeyOrchestrator.ts
 * =====================================
 * Orchestrates API key management and validation.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { apiKeyService } from '../../services/shared';
import { ApiKey, ApiKeyStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface CreateApiKeyInput {
  userId: string;
  name: string;
  keyHash: string;
  expiresAt?: Date | null;
  actor: string;
}

export interface RevokeApiKeyInput {
  apiKeyId: string;
  actor: string;
}

export class ApiKeyOrchestrator extends BaseApplicationService {
  constructor() {
    super('ApiKeyOrchestrator');
  }

  async createApiKey(input: CreateApiKeyInput, parentCtx?: OperationContext): Promise<ApiKey> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Creating API key for user ${input.userId}: ${input.name}`);
    this.validateUuid(input.userId, 'userId', ctx);
    this.validateRequired(input, ['name', 'keyHash'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const apiKey = await apiKeyService.createApiKey({
        userId: input.userId,
        name: input.name,
        keyHash: input.keyHash,
        expiresAt: input.expiresAt,
        status: 'ACTIVE' as ApiKeyStatus,
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      compensation.register(`delete-apikey-${apiKey.id}`, async () => {
        try {
          await prisma.apiKey.delete({ where: { id: apiKey.id } });
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.API_KEY_CREATED, ctx, {
        apiKeyId: apiKey.id,
        userId: input.userId,
        name: input.name,
      });

      compensation.clear();
      return apiKey;
    });
  }

  async revokeApiKey(input: RevokeApiKeyInput, parentCtx?: OperationContext): Promise<ApiKey> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Revoking API key ${input.apiKeyId}`);
    this.validateRequired(input, ['apiKeyId'], ctx);
    this.validateUuid(input.apiKeyId, 'apiKeyId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.apiKey.findUnique({
        where: { id: input.apiKeyId },
      });
      if (!existing || existing.deletedAt) {
        throw new Error(`ApiKey "${input.apiKeyId}" not found.`);
      }

      const revoked = await apiKeyService.revokeApiKey(input.apiKeyId, input.actor, null);

      compensation.register(`restore-apikey-${input.apiKeyId}`, async () => {
        await prisma.apiKey.update({
          where: { id: input.apiKeyId },
          data: {
            status: existing.status,
            updatedBy: 'system',
          },
        });
      });

      await this.publishEvent(APP_EVENTS.API_KEY_REVOKED, ctx, {
        apiKeyId: input.apiKeyId,
        userId: revoked.userId,
      });

      compensation.clear();
      return revoked;
    });
  }

  async validateApiKey(keyHash: string, actor: string, parentCtx?: OperationContext): Promise<{ valid: boolean; apiKey?: ApiKey; reason?: string }> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Validating API key hash`);
    if (!keyHash || !keyHash.trim()) {
      throw new Error('Validation failed: keyHash must not be empty.');
    }

    const result = await apiKeyService.validateApiKey(keyHash);
    if (result.valid && result.apiKey) {
      await apiKeyService.recordUsage(result.apiKey.id, actor);
    }
    return result;
  }

  async getApiKeysForUser(userId: string, actor: string, parentCtx?: OperationContext): Promise<ApiKey[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching API keys for user ${userId}`);
    this.validateUuid(userId, 'userId', ctx);
    return apiKeyService.findByUser(userId);
  }
}

export const apiKeyOrchestrator = new ApiKeyOrchestrator();
