/**
 * SettingsOrchestrator.ts
 * =====================================
 * Orchestrates platform and system settings workflows.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { settingService } from '../../services/shared';
import { SystemSetting, SettingScope, Prisma } from '@prisma/client';

export interface UpdateSettingInput {
  key: string;
  value: string;
  scope?: SettingScope;
  description?: string;
  actor: string;
}

export interface DeleteSettingInput {
  key: string;
  actor: string;
}

export class SettingsOrchestrator extends BaseApplicationService {
  constructor() {
    super('SettingsOrchestrator');
  }

  async getSetting(key: string, actor: string, parentCtx?: OperationContext): Promise<SystemSetting | null> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching setting value for key "${key}"`);
    if (!key || !key.trim()) {
      throw new Error('Validation failed: key must not be empty.');
    }
    return settingService.get(key);
  }

  async getSettingOrThrow(key: string, actor: string, parentCtx?: OperationContext): Promise<SystemSetting> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching setting value or throw for key "${key}"`);
    if (!key || !key.trim()) {
      throw new Error('Validation failed: key must not be empty.');
    }
    return settingService.getOrThrow(key);
  }

  async updateSetting(input: UpdateSettingInput, parentCtx?: OperationContext): Promise<SystemSetting> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Updating setting "${input.key}" to "${input.value}"`);
    this.validateRequired(input, ['key', 'value'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await settingService.get(input.key).catch(() => null);

      const setting = await settingService.upsert({
        key: input.key,
        value: input.value,
        scope: input.scope,
        description: input.description,
        createdBy: input.actor,
        updatedBy: input.actor,
      });

      if (existing) {
        compensation.register(`restore-setting-${input.key}`, async () => {
          await settingService.upsert({
            key: existing.key,
            value: existing.value,
            scope: existing.scope,
            description: existing.description ?? undefined,
            createdBy: existing.createdBy,
            updatedBy: 'system',
          });
        });
      } else {
        compensation.register(`delete-setting-${input.key}`, async () => {
          await settingService.deleteSetting(input.key, 'system');
        });
      }

      await this.publishEvent(APP_EVENTS.SETTINGS_UPDATED, ctx, {
        key: setting.key,
        scope: setting.scope,
      });

      compensation.clear();
      return setting;
    });
  }

  async deleteSetting(input: DeleteSettingInput, parentCtx?: OperationContext): Promise<SystemSetting> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Deleting setting "${input.key}"`);
    this.validateRequired(input, ['key'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await settingService.getOrThrow(input.key);

      const deleted = await settingService.deleteSetting(input.key, input.actor);

      compensation.register(`restore-setting-${input.key}`, async () => {
        await settingService.upsert({
          key: existing.key,
          value: existing.value,
          scope: existing.scope,
          description: existing.description ?? undefined,
          createdBy: existing.createdBy,
          updatedBy: 'system',
        });
      });

      await this.publishEvent(APP_EVENTS.SETTINGS_UPDATED, ctx, {
        key: input.key,
        deleted: true,
      });

      compensation.clear();
      return deleted;
    });
  }

  async getTypedSettingValue(
    key: string,
    type: 'string' | 'number' | 'boolean' | 'json',
    actor: string,
    defaultValue?: any,
    parentCtx?: OperationContext
  ): Promise<any> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching typed setting "${key}" as type "${type}"`);
    if (!key || !key.trim()) {
      throw new Error('Validation failed: key must not be empty.');
    }

    switch (type) {
      case 'number':
        return settingService.getNumberValue(key, defaultValue);
      case 'boolean':
        return settingService.getBoolValue(key, defaultValue);
      case 'json':
        return settingService.getJsonValue(key);
      default:
        return settingService.getValue(key, defaultValue);
    }
  }

  async getTypedSetting(
    key: string,
    type: 'string' | 'number' | 'boolean' | 'json',
    actor: string,
    defaultValue?: any,
    parentCtx?: OperationContext
  ): Promise<any> {
    return this.getTypedSettingValue(key, type, actor, defaultValue, parentCtx);
  }
}

export const settingsOrchestrator = new SettingsOrchestrator();
