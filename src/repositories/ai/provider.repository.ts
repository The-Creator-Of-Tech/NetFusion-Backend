import { BaseRepository } from '../base/BaseRepository';
import { Provider, ProviderModel, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class ProviderRepository extends BaseRepository<Provider, Prisma.ProviderUncheckedCreateInput, Prisma.ProviderUncheckedUpdateInput> {
  constructor() {
    super('provider');
  }

  /**
   * Finds enabled providers where not deleted.
   */
  async findEnabled(tx?: any): Promise<Provider[]> {
    return this.findMany({ filter: { enabled: true, deletedAt: null } }, tx);
  }

  /**
   * Finds disabled providers where not deleted.
   */
  async findDisabled(tx?: any): Promise<Provider[]> {
    return this.findMany({ filter: { enabled: false, deletedAt: null } }, tx);
  }

  /**
   * Finds healthy providers (status: ACTIVE, healthScore >= 80.0, and not deleted).
   */
  async findHealthy(tx?: any): Promise<Provider[]> {
    return this.findMany(
      {
        filter: {
          status: 'ACTIVE',
          healthScore: { gte: 80.0 },
          deletedAt: null,
        },
      },
      tx
    );
  }

  /**
   * Finds provider models associated with a specific provider ID where not deleted.
   */
  async findModels(providerId: string, tx?: any): Promise<ProviderModel[]> {
    const client = tx || prisma;
    return client.providerModel.findMany({
      where: { providerId, deletedAt: null },
    });
  }

  /**
   * Finds a specific provider model by provider ID and model name where not deleted.
   */
  async findModelByName(providerId: string, modelName: string, tx?: any): Promise<ProviderModel | null> {
    const client = tx || prisma;
    return client.providerModel.findFirst({
      where: { providerId, modelName, deletedAt: null },
    });
  }

  /**
   * Aggregates capabilities of all enabled models for a provider.
   */
  async findCapabilities(providerId: string, tx?: any): Promise<{
    streaming: boolean;
    toolCalling: boolean;
    jsonMode: boolean;
    vision: boolean;
    embeddings: boolean;
  }> {
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
