"use strict";
/**
 * SettingsOrchestrator.ts
 * =====================================
 * Orchestrates platform and system settings workflows.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.settingsOrchestrator = exports.SettingsOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
class SettingsOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('SettingsOrchestrator');
    }
    async getSetting(key, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching setting value for key "${key}"`);
        if (!key || !key.trim()) {
            throw new Error('Validation failed: key must not be empty.');
        }
        return shared_1.settingService.get(key);
    }
    async getSettingOrThrow(key, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching setting value or throw for key "${key}"`);
        if (!key || !key.trim()) {
            throw new Error('Validation failed: key must not be empty.');
        }
        return shared_1.settingService.getOrThrow(key);
    }
    async updateSetting(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Updating setting "${input.key}" to "${input.value}"`);
        this.validateRequired(input, ['key', 'value'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await shared_1.settingService.get(input.key).catch(() => null);
            const setting = await shared_1.settingService.upsert({
                key: input.key,
                value: input.value,
                scope: input.scope,
                description: input.description,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            if (existing) {
                compensation.register(`restore-setting-${input.key}`, async () => {
                    await shared_1.settingService.upsert({
                        key: existing.key,
                        value: existing.value,
                        scope: existing.scope,
                        description: existing.description ?? undefined,
                        createdBy: existing.createdBy,
                        updatedBy: 'system',
                    });
                });
            }
            else {
                compensation.register(`delete-setting-${input.key}`, async () => {
                    await shared_1.settingService.deleteSetting(input.key, 'system');
                });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.SETTINGS_UPDATED, ctx, {
                key: setting.key,
                scope: setting.scope,
            });
            compensation.clear();
            return setting;
        });
    }
    async deleteSetting(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Deleting setting "${input.key}"`);
        this.validateRequired(input, ['key'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await shared_1.settingService.getOrThrow(input.key);
            const deleted = await shared_1.settingService.deleteSetting(input.key, input.actor);
            compensation.register(`restore-setting-${input.key}`, async () => {
                await shared_1.settingService.upsert({
                    key: existing.key,
                    value: existing.value,
                    scope: existing.scope,
                    description: existing.description ?? undefined,
                    createdBy: existing.createdBy,
                    updatedBy: 'system',
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.SETTINGS_UPDATED, ctx, {
                key: input.key,
                deleted: true,
            });
            compensation.clear();
            return deleted;
        });
    }
    async getTypedSettingValue(key, type, actor, defaultValue, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching typed setting "${key}" as type "${type}"`);
        if (!key || !key.trim()) {
            throw new Error('Validation failed: key must not be empty.');
        }
        switch (type) {
            case 'number':
                return shared_1.settingService.getNumberValue(key, defaultValue);
            case 'boolean':
                return shared_1.settingService.getBoolValue(key, defaultValue);
            case 'json':
                return shared_1.settingService.getJsonValue(key);
            default:
                return shared_1.settingService.getValue(key, defaultValue);
        }
    }
    async getTypedSetting(key, type, actor, defaultValue, parentCtx) {
        return this.getTypedSettingValue(key, type, actor, defaultValue, parentCtx);
    }
}
exports.SettingsOrchestrator = SettingsOrchestrator;
exports.settingsOrchestrator = new SettingsOrchestrator();
