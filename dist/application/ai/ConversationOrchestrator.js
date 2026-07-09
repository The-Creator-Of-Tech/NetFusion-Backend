"use strict";
/**
 * ConversationOrchestrator.ts — Phase A5.4.2
 * ==============================================
 * Orchestrates the full conversation turn lifecycle:
 *   User Message → ConversationService → SessionMemoryService →
 *   ContextWindowService → PromptAssemblyService → ProviderSelection →
 *   ExecutionService → StreamingService → Store Conversation → Publish Events
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.conversationOrchestrator = exports.ConversationOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const ai_1 = require("../../services/ai");
// ─────────────────────────────────────────────────────────────────────────────
// ConversationOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class ConversationOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ConversationOrchestrator');
    }
    // ── Full Conversation Turn ────────────────────────────────────────────────
    async processTurn(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Processing conversation turn: ${input.conversationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            // ── Step 1: Verify conversation ───────────────────────────────────────
            const conversation = await ai_1.conversationService.findConversation(input.conversationId);
            if (!conversation || conversation.deletedAt) {
                throw new BaseApplicationService_1.OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
            }
            // ── Step 2: Load / ensure memory ─────────────────────────────────────
            const memories = await ai_1.sessionMemoryService.findByProject(input.projectId);
            let memory = memories.find((m) => !m.deletedAt && m.conversationId === input.conversationId);
            if (!memory) {
                memory = await ai_1.sessionMemoryService.createMemory({
                    conversationId: input.conversationId,
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    userId: input.userId ?? null,
                    status: 'ACTIVE',
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_MEMORY_LOADED, ctx, {
                memoryId: memory.id,
                conversationId: input.conversationId,
                entryCount: (await ai_1.sessionMemoryService.findEntries(memory.id)).length,
            });
            // Save new memory entries if provided
            for (const entry of (input.memoryEntriesToSave ?? [])) {
                await ai_1.sessionMemoryService.addEntry(memory.id, {
                    ...entry,
                    importanceScore: entry.importanceScore ?? 50.0,
                    confidence: entry.confidence ?? 0.5,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            // ── Step 3: Build context window ──────────────────────────────────────
            const windows = await ai_1.contextWindowService.findByConversation(input.conversationId);
            let contextWindow = windows.find((w) => !w.deletedAt && w.status === 'ACTIVE');
            if (!contextWindow) {
                contextWindow = await ai_1.contextWindowService.createWindow({
                    projectId: input.projectId,
                    conversationId: input.conversationId,
                    investigationId: input.investigationId,
                    userId: input.userId ?? null,
                    status: 'ACTIVE',
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            for (const entry of (input.contextEntriesToAdd ?? [])) {
                await ai_1.contextWindowService.addEntry(contextWindow.id, {
                    ...entry,
                    importanceScore: entry.importanceScore ?? 50.0,
                    confidence: entry.confidence ?? 0.5,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            const windowStats = await ai_1.contextWindowService.getWindowStats(contextWindow.id);
            const tokenEstimate = Math.ceil(windowStats.contextSize / 4);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
                contextId: contextWindow.id,
                conversationId: input.conversationId,
                entryCount: windowStats.entryCount,
                tokenEstimate,
            });
            // ── Step 4: Assemble prompt ───────────────────────────────────────────
            const systemPrompt = input.systemPrompt ?? `You are a NetFusion AI SOC Assistant.`;
            const prompt = await ai_1.promptAssemblyService.createPrompt({
                investigationId: input.investigationId,
                projectId: input.projectId,
                contextId: contextWindow.id,
                systemPrompt,
                userPrompt: input.userMessage,
                maxTokens: 8192,
                reservedTokens: 1024,
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
            await ai_1.promptAssemblyService.publishPrompt(prompt.id, input.actor);
            const budget = await ai_1.promptAssemblyService.checkTokenBudget(prompt.id);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_PROMPT_BUILT, ctx, {
                promptId: prompt.id,
                conversationId: input.conversationId,
                estimatedTokens: budget.estimatedTokens,
                withinBudget: budget.withinBudget,
            });
            // ── Step 5: Select provider ───────────────────────────────────────────
            const provider = await ai_1.providerService.selectProvider({
                strategy: input.providerStrategy ?? 'priority',
                requireStreaming: input.preferStreaming,
            });
            if (!provider) {
                throw new BaseApplicationService_1.OrchestrationError('No healthy AI provider available.', ctx.correlationId, 'NO_PROVIDER');
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_PROVIDER_SELECTED, ctx, {
                providerId: provider.id,
                providerName: provider.providerName,
                strategy: input.providerStrategy ?? 'priority',
                healthScore: provider.healthScore ?? 100,
            });
            // ── Step 6: Submit and start execution ────────────────────────────────
            const userMsg = await ai_1.conversationService.addMessage(input.conversationId, {
                role: 'user',
                content: input.userMessage,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            const execution = await ai_1.executionService.submitExecution({
                providerId: provider.id,
                projectId: input.projectId,
                investigationId: input.investigationId,
                userId: input.userId ?? null,
                systemPrompt,
                userPrompt: input.userMessage,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`cancel-execution-${execution.id}`, async () => {
                try {
                    await ai_1.executionService.cancelExecution(execution.id, input.actor);
                }
                catch (_) { }
            });
            await ai_1.executionService.startExecution(execution.id, input.actor);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_EXECUTION_STARTED, ctx, {
                executionId: execution.id,
                providerId: provider.id,
                providerName: provider.providerName,
                projectId: input.projectId,
            });
            // ── Step 7: Streaming (optional) ──────────────────────────────────────
            let streamingId;
            if (input.preferStreaming) {
                const stream = await ai_1.streamingService.createSession({
                    executionId: execution.id,
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    userId: input.userId ?? null,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
                streamingId = stream.id;
                await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_STARTED, ctx, {
                    streamingId: stream.id,
                    executionId: execution.id,
                    projectId: input.projectId,
                });
            }
            // ── Step 8: Complete execution + record usage ─────────────────────────
            const simulatedResponse = `[AI SOC response for: "${input.userMessage.slice(0, 60)}"]`;
            await ai_1.executionService.recordUsage(execution.id, {
                promptTokens: budget.estimatedTokens,
                completionTokens: Math.ceil(simulatedResponse.length / 4),
                totalTokens: budget.estimatedTokens + Math.ceil(simulatedResponse.length / 4),
                estimatedCost: (budget.estimatedTokens + Math.ceil(simulatedResponse.length / 4)) * 0.000002,
                latencyMs: 350,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            await ai_1.executionService.completeExecution(execution.id, input.actor);
            const usageStats = await ai_1.executionService.getUsageStats(execution.id);
            // ── Step 9: Store assistant reply ─────────────────────────────────────
            const assistantMsg = await ai_1.conversationService.addMessage(input.conversationId, {
                role: 'assistant',
                content: simulatedResponse,
                parentMessageId: userMsg.id,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            // ── Step 10: Publish completion events ────────────────────────────────
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_EXECUTION_COMPLETED, ctx, {
                executionId: execution.id,
                providerId: provider.id,
                projectId: input.projectId,
                totalTokens: usageStats?.totalTokens ?? 0,
                estimatedCost: usageStats?.estimatedCost ?? 0,
                latencyMs: usageStats?.latencyMs ?? 0,
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONVERSATION_CONTINUED, ctx, {
                conversationId: input.conversationId,
                projectId: input.projectId,
                messageId: userMsg.id,
                executionId: execution.id,
            });
            this.logTiming(ctx, 'processTurn');
            compensation.clear();
            return {
                conversationId: input.conversationId,
                userMessageId: userMsg.id,
                assistantMessageId: assistantMsg.id,
                executionId: execution.id,
                streamingId,
                promptId: prompt.id,
                memoryId: memory.id,
                contextId: contextWindow.id,
                tokensUsed: usageStats?.totalTokens ?? 0,
                correlationId: ctx.correlationId,
            };
        });
    }
    // ── Get Conversation History ──────────────────────────────────────────────
    async getHistory(conversationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(conversationId, 'conversationId', ctx);
        const stats = await ai_1.conversationService.getConversationStats(conversationId);
        return { conversationId, ...stats };
    }
    // ── Prune Context ─────────────────────────────────────────────────────────
    async pruneContext(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.logInfo(ctx, `Pruning context for conversation: ${input.conversationId}`);
        const windows = await ai_1.contextWindowService.findByConversation(input.conversationId);
        const active = windows.find((w) => !w.deletedAt && w.status === 'ACTIVE');
        if (!active) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('ContextWindow', input.conversationId, ctx.correlationId);
        }
        const maxBudget = input.maxTokenBudget ?? 4096;
        const entries = await ai_1.contextWindowService.rankEntriesByImportance(active.id);
        let tokenCount = 0;
        let prunedEntries = 0;
        for (const entry of [...entries].reverse()) {
            const entryTokens = Math.ceil((entry.content?.length ?? 0) / 4);
            if (tokenCount + entryTokens > maxBudget) {
                await ai_1.contextWindowService.deleteEntry(entry.id, input.actor);
                prunedEntries++;
            }
            else {
                tokenCount += entryTokens;
            }
        }
        const remaining = await ai_1.contextWindowService.findEntries(active.id);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
            contextId: active.id,
            conversationId: input.conversationId,
            entryCount: remaining.length,
            tokenEstimate: tokenCount,
        });
        this.logTiming(ctx, 'pruneContext');
        return { contextId: active.id, prunedEntries, remainingEntries: remaining.length };
    }
}
exports.ConversationOrchestrator = ConversationOrchestrator;
exports.conversationOrchestrator = new ConversationOrchestrator();
