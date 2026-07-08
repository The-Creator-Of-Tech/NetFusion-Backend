/**
 * ProviderService — Phase A5.3.4
 * ================================
 * Manages AI provider registry: provider creation, model registration,
 * health monitoring, capability discovery, priority-based selection,
 * and enablement toggling.
 * Publishes events on provider health changes and model registrations.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { providerRepository } from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  Provider,
  ProviderModel,
  ProviderType,
  ProviderStatus,
  Prisma,
} from '@prisma/client';

export class ProviderService extends BaseService {
  constructor(
    private readonly providerRepo = providerRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async registerProvider(
    data: Prisma.ProviderUncheckedCreateInput,
    tx?: any,
  ): Promise<Provider> {
    this.validateRequired(data as any, ['providerName', 'displayName', 'apiVersion', 'endpoint', 'defaultModel', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const provider = await this.providerRepo.create(data, transaction);
      await eventPublisher.publish('ProviderRegistered', { provider });
      return provider;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async registerModel(
    providerId: string,
    data: {
      modelName: string;
      alias?: string;
      streaming?: boolean;
      toolCalling?: boolean;
      jsonMode?: boolean;
      vision?: boolean;
      embeddings?: boolean;
      maxContextTokens?: number;
      maxOutputTokens?: number;
      enabled?: boolean;
      priority?: number;
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<ProviderModel> {
    this.validateUuid(providerId, 'providerId');
    this.validateRequired(data as any, ['modelName', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const provider = await this.providerRepo.findById(providerId, transaction);
      if (!provider || provider.deletedAt) {
        throw new Error(`Provider "${providerId}" not found.`);
      }

      const client = transaction || prisma;
      const model: ProviderModel = await client.providerModel.create({
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

      await eventPublisher.publish('ProviderModelRegistered', { providerId, model });
      return model;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Provider management ──────────────────────────────────────────────────────

  async enableProvider(id: string, actor: string, tx?: any): Promise<Provider> {
    this.validateUuid(id, 'providerId');
    const runInTx = async (transaction: any) => {
      const existing = await this.providerRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Provider "${id}" not found.`);
      }
      const updated = await this.providerRepo.update(
        id,
        { enabled: true, status: 'ACTIVE', updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('ProviderEnabled', { provider: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async disableProvider(id: string, actor: string, tx?: any): Promise<Provider> {
    this.validateUuid(id, 'providerId');
    const runInTx = async (transaction: any) => {
      const existing = await this.providerRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Provider "${id}" not found.`);
      }
      const updated = await this.providerRepo.update(
        id,
        { enabled: false, status: 'INACTIVE', updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('ProviderDisabled', { provider: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateHealthScore(id: string, healthScore: number, actor: string, tx?: any): Promise<Provider> {
    this.validateUuid(id, 'providerId');
    const clampedScore = Math.max(0.0, Math.min(100.0, healthScore));

    const runInTx = async (transaction: any) => {
      const existing = await this.providerRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Provider "${id}" not found.`);
      }

      const updated = await this.providerRepo.update(
        id,
        { healthScore: clampedScore, updatedBy: actor },
        transaction,
      );

      const previousStatus = existing.status;
      const newStatus: ProviderStatus = clampedScore >= 80.0 ? 'ACTIVE' : 'DEGRADED';
      if (previousStatus !== newStatus) {
        await this.providerRepo.update(id, { status: newStatus, updatedBy: actor }, transaction);
        await eventPublisher.publish('ProviderHealthChanged', {
          provider: updated,
          previousStatus,
          newStatus,
          healthScore: clampedScore,
        });
      }

      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Priority-based selection ─────────────────────────────────────────────────

  async selectProvider(
    options: {
      strategy?: 'priority' | 'health' | 'random';
      requireStreaming?: boolean;
      requireToolCalling?: boolean;
      requireJsonMode?: boolean;
    } = {},
    tx?: any,
  ): Promise<Provider | null> {
    const runInTx = async (transaction: any) => {
      let providers = await this.providerRepo.findHealthy(transaction);

      // Filter by capabilities if required
      if (options.requireStreaming || options.requireToolCalling || options.requireJsonMode) {
        const filtered: Provider[] = [];
        for (const provider of providers) {
          const caps = await this.providerRepo.findCapabilities(provider.id, transaction);
          const ok =
            (!options.requireStreaming || caps.streaming) &&
            (!options.requireToolCalling || caps.toolCalling) &&
            (!options.requireJsonMode || caps.jsonMode);
          if (ok) filtered.push(provider);
        }
        providers = filtered;
      }

      if (providers.length === 0) return null;

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
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Capability discovery ─────────────────────────────────────────────────────

  async getCapabilities(providerId: string, tx?: any): Promise<{
    streaming: boolean;
    toolCalling: boolean;
    jsonMode: boolean;
    vision: boolean;
    embeddings: boolean;
  }> {
    this.validateUuid(providerId, 'providerId');
    return this.providerRepo.findCapabilities(providerId, tx);
  }

  async getModelCapabilities(modelId: string, tx?: any): Promise<ProviderModel | null> {
    this.validateUuid(modelId, 'modelId');
    const client = tx || prisma;
    return client.providerModel.findUnique({ where: { id: modelId } });
  }

  // ── Statistics ───────────────────────────────────────────────────────────────

  async getProviderStats(providerId: string, tx?: any): Promise<{
    totalModels: number;
    enabledModels: number;
    healthScore: number;
    status: string;
    capabilities: { streaming: boolean; toolCalling: boolean; jsonMode: boolean; vision: boolean; embeddings: boolean };
  }> {
    this.validateUuid(providerId, 'providerId');
    const runInTx = async (transaction: any) => {
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
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findProvider(id: string, tx?: any): Promise<Provider | null> {
    this.validateUuid(id, 'providerId');
    return this.providerRepo.findById(id, tx);
  }

  async findEnabled(tx?: any): Promise<Provider[]> {
    return this.providerRepo.findEnabled(tx);
  }

  async findHealthy(tx?: any): Promise<Provider[]> {
    return this.providerRepo.findHealthy(tx);
  }

  async findModels(providerId: string, tx?: any): Promise<ProviderModel[]> {
    this.validateUuid(providerId, 'providerId');
    return this.providerRepo.findModels(providerId, tx);
  }

  async findModelByName(providerId: string, modelName: string, tx?: any): Promise<ProviderModel | null> {
    this.validateUuid(providerId, 'providerId');
    return this.providerRepo.findModelByName(providerId, modelName, tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteProvider(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'providerId');
    const runInTx = async (transaction: any) => {
      const existing = await this.providerRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Provider "${id}" not found.`);
      }
      await this.providerRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('ProviderDeleted', { providerId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
