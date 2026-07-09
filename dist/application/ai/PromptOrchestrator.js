"use strict";
/**
 * PromptOrchestrator.ts — Phase A5.4.2
 * ========================================
 * Responsible for:
 *  - Prompt building from conversation context
 *  - Context compression (pruning low-importance entries to fit token budget)
 *  - Prompt optimization (section reordering by priority)
 *  - Token estimation
 *  - Cost estimation
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.promptOrchestrator = exports.PromptOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const ai_1 = require("../../services/ai");
// ─────────────────────────────────────────────────────────────────────────────
// PromptOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class PromptOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('PromptOrchestrator');
    }
    // ── Build Prompt ──────────────────────────────────────────────────────────
    async buildPrompt(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Building prompt for investigation: ${input.investigationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const prompt = await ai_1.promptAssemblyService.createPrompt({
                investigationId: input.investigationId,
                projectId: input.projectId,
                contextId: input.contextId ?? null,
                systemPrompt: input.systemPrompt,
                userPrompt: input.userPrompt,
                maxTokens: input.maxTokens ?? 8192,
                reservedTokens: input.reservedTokens ?? 1024,
                status: 'DRAFT',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`delete-prompt-${prompt.id}`, async () => {
                try {
                    await ai_1.promptAssemblyService.deletePrompt(prompt.id, input.actor);
                }
                catch (_) { }
            });
            // Add sections ordered by priority (highest first)
            const sections = [...(input.sections ?? [])].sort((a, b) => (b.priority ?? 50) - (a.priority ?? 50));
            for (const section of sections) {
                await ai_1.promptAssemblyService.addSection(prompt.id, {
                    title: section.title,
                    content: section.content,
                    priority: section.priority ?? 50,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            await ai_1.promptAssemblyService.publishPrompt(prompt.id, input.actor);
            const assembled = await ai_1.promptAssemblyService.assemblePrompt(prompt.id);
            const budget = await ai_1.promptAssemblyService.checkTokenBudget(prompt.id);
            const promptSections = await ai_1.promptAssemblyService.findSections(prompt.id);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_PROMPT_BUILT, ctx, {
                promptId: prompt.id,
                conversationId: input.conversationId,
                estimatedTokens: budget.estimatedTokens,
                withinBudget: budget.withinBudget,
            });
            this.logTiming(ctx, 'buildPrompt');
            compensation.clear();
            return {
                promptId: prompt.id,
                assembled,
                estimatedTokens: budget.estimatedTokens,
                maxTokens: budget.maxTokens,
                reservedTokens: budget.reservedTokens,
                withinBudget: budget.withinBudget,
                sectionCount: promptSections.length,
                correlationId: ctx.correlationId,
            };
        });
    }
    // ── Compress Context ──────────────────────────────────────────────────────
    async compressContext(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.contextId, 'contextId', ctx);
        this.logInfo(ctx, `Compressing context window: ${input.contextId}`);
        const window = await ai_1.contextWindowService.findWindow(input.contextId);
        if (!window || window.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('ContextWindow', input.contextId, ctx.correlationId);
        }
        // Rank by importance — remove least important entries first
        const ranked = await ai_1.contextWindowService.rankEntriesByImportance(input.contextId);
        const originalCount = ranked.length;
        let usedTokens = 0;
        let prunedCount = 0;
        // Keep highest-importance entries that fit in the budget
        const toKeep = new Set();
        for (const entry of ranked) {
            const entryTokens = Math.ceil((entry.content?.length ?? 0) / 4);
            if (usedTokens + entryTokens <= input.maxTokenBudget) {
                toKeep.add(entry.id);
                usedTokens += entryTokens;
            }
        }
        // Delete entries not in the keep set
        for (const entry of ranked) {
            if (!toKeep.has(entry.id)) {
                await ai_1.contextWindowService.deleteEntry(entry.id, input.actor);
                prunedCount++;
            }
        }
        const remaining = await ai_1.contextWindowService.findEntries(input.contextId);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
            contextId: input.contextId,
            conversationId: window.conversationId ?? 'unknown',
            entryCount: remaining.length,
            tokenEstimate: usedTokens,
        });
        this.logTiming(ctx, 'compressContext');
        return {
            contextId: input.contextId,
            originalEntryCount: originalCount,
            remainingEntryCount: remaining.length,
            prunedEntryCount: prunedCount,
            estimatedTokens: usedTokens,
        };
    }
    // ── Optimize Prompt ───────────────────────────────────────────────────────
    async optimizePrompt(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.promptId, 'promptId', ctx);
        this.logInfo(ctx, `Optimizing prompt: ${input.promptId}`);
        const prompt = await ai_1.promptAssemblyService.findPrompt(input.promptId);
        if (!prompt || prompt.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('PromptAssembly', input.promptId, ctx.correlationId);
        }
        // Re-assemble with current sections (already ordered by priority in assemblePrompt)
        const assembled = await ai_1.promptAssemblyService.assemblePrompt(input.promptId);
        const tokens = await ai_1.promptAssemblyService.calculateTokenUsage(input.promptId);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_PROMPT_OPTIMIZED, ctx, {
            promptId: input.promptId,
            estimatedTokens: tokens,
        });
        this.logTiming(ctx, 'optimizePrompt');
        return { promptId: input.promptId, assembled, estimatedTokens: tokens };
    }
    // ── Token Estimation ──────────────────────────────────────────────────────
    async estimateTokens(promptId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(promptId, 'promptId', ctx);
        const budget = await ai_1.promptAssemblyService.checkTokenBudget(promptId);
        const remaining = budget.maxTokens - budget.reservedTokens - budget.estimatedTokens;
        return {
            promptId,
            estimatedTokens: budget.estimatedTokens,
            maxTokens: budget.maxTokens,
            reservedTokens: budget.reservedTokens,
            withinBudget: budget.withinBudget,
            remainingTokens: Math.max(0, remaining),
        };
    }
    // ── Cost Estimation ───────────────────────────────────────────────────────
    async estimateCost(promptId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(promptId, 'promptId', ctx);
        this.logInfo(ctx, `Estimating cost for prompt: ${promptId}`);
        const budget = await ai_1.promptAssemblyService.checkTokenBudget(promptId);
        // Select best available provider for cost reference
        const provider = await ai_1.providerService.selectProvider({ strategy: 'priority' });
        const providerName = provider?.providerName ?? 'unknown';
        const providerId = provider?.id ?? 'unknown';
        // GPT-4 class pricing heuristic: $0.002 per 1000 tokens
        const costPer1kTokens = 0.002;
        const estimatedCostUsd = (budget.estimatedTokens / 1000) * costPer1kTokens;
        // Get default model name
        const modelName = provider?.defaultModel ?? 'default';
        return {
            promptId,
            estimatedTokens: budget.estimatedTokens,
            estimatedCostUsd,
            providerId,
            providerName,
            modelName,
        };
    }
}
exports.PromptOrchestrator = PromptOrchestrator;
exports.promptOrchestrator = new PromptOrchestrator();
