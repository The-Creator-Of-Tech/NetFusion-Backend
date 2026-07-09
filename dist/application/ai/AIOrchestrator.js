"use strict";
/**
 * AIOrchestrator.ts — Phase A5.4.2
 * ====================================
 * Master AI orchestrator: coordinates all AI services into complete workflows.
 *
 * Implements the full conversation flow:
 *   User Message → ConversationService → SessionMemoryService →
 *   ContextWindowService → PromptAssemblyService → ProviderSelection →
 *   ExecutionService → StreamingService → Store Conversation → Publish Events
 *
 * Every public method:
 *  1. Creates or receives an OperationContext with a correlationId
 *  2. Delegates exclusively to Service Layer singletons
 *  3. Handles cross-service coordination
 *  4. Publishes AI application-level events after successful completion
 *  5. Uses withCompensation() to roll back partial state on failure
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.aiOrchestrator = exports.AIOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// AI service singletons
const ai_1 = require("../../services/ai");
// ─────────────────────────────────────────────────────────────────────────────
// AIOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class AIOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('AIOrchestrator');
    }
    // ── Start Conversation ────────────────────────────────────────────────────
    async startConversation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.projectId, 'projectId', ctx);
        if (input.investigationId)
            this.validateUuid(input.investigationId, 'investigationId', ctx);
        if (input.userId)
            this.validateUuid(input.userId, 'userId', ctx);
        this.logInfo(ctx, `Starting conversation: "${input.title}"`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Create conversation
            const conversation = await ai_1.conversationService.createConversation({
                projectId: input.projectId,
                title: input.title,
                status: 'ACTIVE',
                tags: input.tags ?? [],
                userId: input.userId ?? null,
                investigationId: input.investigationId ?? null,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`delete-conversation-${conversation.id}`, async () => {
                try {
                    await ai_1.conversationService.deleteConversation(conversation.id, input.actor);
                }
                catch (_) { }
            });
            // 2. Create session memory
            const memory = await ai_1.sessionMemoryService.createMemory({
                conversationId: conversation.id,
                projectId: input.projectId,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`delete-memory-${memory.id}`, async () => {
                try {
                    await ai_1.sessionMemoryService.deleteMemory(memory.id, input.actor);
                }
                catch (_) { }
            });
            // 3. Create context window
            const context = await ai_1.contextWindowService.createWindow({
                projectId: input.projectId,
                conversationId: conversation.id,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`delete-context-${context.id}`, async () => {
                try {
                    await ai_1.contextWindowService.deleteWindow(context.id, input.actor);
                }
                catch (_) { }
            });
            // 4. Publish event
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONVERSATION_STARTED, ctx, {
                conversationId: conversation.id,
                projectId: input.projectId,
                title: input.title,
                memoryId: memory.id,
                contextId: context.id,
            });
            this.logTiming(ctx, 'startConversation');
            compensation.clear();
            return {
                conversationId: conversation.id,
                memoryId: memory.id,
                contextId: context.id,
                projectId: input.projectId,
                title: input.title,
                correlationId: ctx.correlationId,
            };
        });
    }
    // ── Continue Conversation ─────────────────────────────────────────────────
    async continueConversation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Continuing conversation: ${input.conversationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Verify conversation exists
            const conversation = await ai_1.conversationService.findConversation(input.conversationId);
            if (!conversation || conversation.deletedAt) {
                throw new BaseApplicationService_1.OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
            }
            // 2. Add user message
            const userMsg = await ai_1.conversationService.addMessage(input.conversationId, {
                role: 'user',
                content: input.userMessage,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            // 3. Select provider
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
            // 4. Submit execution
            const execution = await ai_1.executionService.submitExecution({
                providerId: provider.id,
                projectId: input.projectId,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                systemPrompt: `You are a NetFusion AI SOC Assistant. Project: ${input.projectId}.`,
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
            // 5. Optionally create streaming session
            let streamingId;
            if (input.preferStreaming) {
                const stream = await ai_1.streamingService.createSession({
                    executionId: execution.id,
                    projectId: input.projectId,
                    investigationId: input.investigationId ?? null,
                    userId: input.userId ?? null,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
                streamingId = stream.id;
            }
            // 6. Complete execution (simulate — real provider call happens in Python layer)
            const simulatedResponse = `[AI response to: "${input.userMessage.slice(0, 80)}"]`;
            await ai_1.executionService.recordUsage(execution.id, {
                promptTokens: Math.ceil(input.userMessage.length / 4),
                completionTokens: Math.ceil(simulatedResponse.length / 4),
                totalTokens: Math.ceil((input.userMessage.length + simulatedResponse.length) / 4),
                estimatedCost: 0.0001,
                latencyMs: 200,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            await ai_1.executionService.completeExecution(execution.id, input.actor);
            // 7. Add assistant reply to conversation
            await ai_1.conversationService.addMessage(input.conversationId, {
                role: 'assistant',
                content: simulatedResponse,
                parentMessageId: userMsg.id,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            const usageStats = await ai_1.executionService.getUsageStats(execution.id);
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
            this.logTiming(ctx, 'continueConversation');
            compensation.clear();
            return {
                conversationId: input.conversationId,
                userMessageId: userMsg.id,
                executionId: execution.id,
                streamingId,
                response: simulatedResponse,
                tokensUsed: usageStats?.totalTokens ?? 0,
                correlationId: ctx.correlationId,
            };
        });
    }
    // ── Close Conversation ────────────────────────────────────────────────────
    async closeConversation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.logInfo(ctx, `Closing conversation: ${input.conversationId}`);
        const conversation = await ai_1.conversationService.findConversation(input.conversationId);
        if (!conversation || conversation.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
        }
        await ai_1.conversationService.completeConversation(input.conversationId, input.actor);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONVERSATION_CLOSED, ctx, {
            conversationId: input.conversationId,
            projectId: conversation.projectId,
            closedAt: new Date(),
        });
        this.logTiming(ctx, 'closeConversation');
    }
    // ── Summarize Conversation ────────────────────────────────────────────────
    async summarizeConversation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.logInfo(ctx, `Summarizing conversation: ${input.conversationId}`);
        const conversation = await ai_1.conversationService.findConversation(input.conversationId);
        if (!conversation || conversation.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
        }
        const stats = await ai_1.conversationService.getConversationStats(input.conversationId);
        const summary = `Conversation "${conversation.title}": ${stats.messageCount} messages, ` +
            `~${stats.contextSize} chars, ${stats.memoryCount} memory entries, ${stats.windowCount} context windows.`;
        await ai_1.conversationService.updateSummary(input.conversationId, summary, input.actor);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONVERSATION_SUMMARIZED, ctx, {
            conversationId: input.conversationId,
            projectId: conversation.projectId,
            summaryLength: summary.length,
        });
        this.logTiming(ctx, 'summarizeConversation');
        return summary;
    }
    // ── Load Memory ───────────────────────────────────────────────────────────
    async loadMemory(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Loading memory for conversation: ${input.conversationId}`);
        const memories = await ai_1.sessionMemoryService.findByProject(input.projectId);
        const active = memories.find((m) => !m.deletedAt && m.conversationId === input.conversationId);
        if (!active) {
            // Create fresh memory if none exists
            const memory = await ai_1.sessionMemoryService.createMemory({
                conversationId: input.conversationId,
                projectId: input.projectId,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_MEMORY_LOADED, ctx, {
                memoryId: memory.id,
                conversationId: input.conversationId,
                entryCount: 0,
            });
            this.logTiming(ctx, 'loadMemory');
            return { memoryId: memory.id, entryCount: 0 };
        }
        const entries = await ai_1.sessionMemoryService.findEntries(active.id);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_MEMORY_LOADED, ctx, {
            memoryId: active.id,
            conversationId: input.conversationId,
            entryCount: entries.length,
        });
        this.logTiming(ctx, 'loadMemory');
        return { memoryId: active.id, entryCount: entries.length };
    }
    // ── Save Memory ───────────────────────────────────────────────────────────
    async saveMemory(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Saving ${input.entries.length} memory entries`);
        // Ensure memory exists
        const { memoryId } = await this.loadMemory({
            conversationId: input.conversationId,
            projectId: input.projectId,
            actor: input.actor,
        });
        let saved = 0;
        for (const entry of input.entries) {
            await ai_1.sessionMemoryService.addEntry(memoryId, {
                memoryType: entry.memoryType,
                state: entry.state,
                title: entry.title,
                content: entry.content,
                importanceScore: entry.importanceScore ?? 50.0,
                confidence: entry.confidence ?? 0.5,
                tags: entry.tags ?? [],
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            saved++;
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_MEMORY_SAVED, ctx, {
            memoryId,
            conversationId: input.conversationId,
            entryCount: saved,
        });
        this.logTiming(ctx, 'saveMemory');
        return { memoryId, entryCount: saved };
    }
    // ── Build Context ─────────────────────────────────────────────────────────
    async buildContext(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.conversationId, 'conversationId', ctx);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Building context for conversation: ${input.conversationId}`);
        // Find or create context window
        const windows = await ai_1.contextWindowService.findByConversation(input.conversationId);
        let contextWindow = windows.find((w) => !w.deletedAt && w.status === 'ACTIVE');
        if (!contextWindow) {
            contextWindow = await ai_1.contextWindowService.createWindow({
                projectId: input.projectId,
                conversationId: input.conversationId,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
        }
        let entryCount = 0;
        for (const entry of (input.entries ?? [])) {
            await ai_1.contextWindowService.addEntry(contextWindow.id, {
                source: entry.source,
                priority: entry.priority,
                title: entry.title,
                content: entry.content,
                referenceId: entry.referenceId,
                importanceScore: entry.importanceScore ?? 50.0,
                confidence: entry.confidence ?? 0.5,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            entryCount++;
        }
        const stats = await ai_1.contextWindowService.getWindowStats(contextWindow.id);
        const tokenEstimate = Math.ceil(stats.contextSize / 4);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
            contextId: contextWindow.id,
            conversationId: input.conversationId,
            entryCount: stats.entryCount,
            tokenEstimate,
        });
        this.logTiming(ctx, 'buildContext');
        return { contextId: contextWindow.id, entryCount: stats.entryCount, tokenEstimate };
    }
    // ── Run Prompt ────────────────────────────────────────────────────────────
    async runPrompt(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Running prompt assembly for conversation: ${input.conversationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            // Build prompt
            const prompt = await ai_1.promptAssemblyService.createPrompt({
                investigationId: input.investigationId,
                projectId: input.projectId,
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
            // Add sections
            for (const section of (input.sections ?? [])) {
                await ai_1.promptAssemblyService.addSection(prompt.id, {
                    title: section.title,
                    content: section.content,
                    priority: section.priority ?? 50,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            // Publish and assemble
            await ai_1.promptAssemblyService.publishPrompt(prompt.id, input.actor);
            const assembled = await ai_1.promptAssemblyService.assemblePrompt(prompt.id);
            const budget = await ai_1.promptAssemblyService.checkTokenBudget(prompt.id);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_PROMPT_BUILT, ctx, {
                promptId: prompt.id,
                conversationId: input.conversationId,
                estimatedTokens: budget.estimatedTokens,
                withinBudget: budget.withinBudget,
            });
            this.logTiming(ctx, 'runPrompt');
            compensation.clear();
            return {
                promptId: prompt.id,
                assembled,
                estimatedTokens: budget.estimatedTokens,
                withinBudget: budget.withinBudget,
            };
        });
    }
    // ── Run Reasoning ─────────────────────────────────────────────────────────
    async runReasoning(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Running reasoning for investigation: ${input.investigationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const session = await ai_1.reasoningService.createSession({
                projectId: input.projectId,
                investigationId: input.investigationId,
                userId: input.userId ?? null,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`cancel-reasoning-${session.id}`, async () => {
                try {
                    await ai_1.reasoningService.failSession(session.id, input.actor);
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_REASONING_STARTED, ctx, {
                reasoningId: session.id,
                projectId: input.projectId,
                investigationId: input.investigationId,
            });
            // Add steps
            let stepNum = 1;
            for (const step of (input.steps ?? [])) {
                await ai_1.reasoningService.addStep(session.id, {
                    stepNumber: stepNum++,
                    stage: step.stage,
                    inputSummary: step.inputSummary,
                    outputSummary: step.outputSummary,
                    confidence: step.confidence,
                    evidenceIds: step.evidenceIds ?? [],
                    findingIds: step.findingIds ?? [],
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            const decision = input.decision ?? 'Analysis complete.';
            const completed = await ai_1.reasoningService.completeSession(session.id, decision, input.actor);
            const risk = await ai_1.reasoningService.calculateOverallRisk(session.id);
            const stats = await ai_1.reasoningService.getSessionStats(session.id);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_REASONING_COMPLETED, ctx, {
                reasoningId: session.id,
                projectId: input.projectId,
                investigationId: input.investigationId,
                overallConfidence: stats.overallConfidence,
                overallRisk: risk,
                stepCount: stats.stepCount,
                decision,
            });
            this.logTiming(ctx, 'runReasoning');
            compensation.clear();
            return {
                reasoningId: session.id,
                overallConfidence: stats.overallConfidence,
                overallRisk: risk,
                decision,
            };
        });
    }
    // ── Execute AI ────────────────────────────────────────────────────────────
    async executeAI(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Executing AI request for project: ${input.projectId}`);
        return this.withCompensation(ctx, async (compensation) => {
            // Select provider with intelligent routing
            const provider = await ai_1.providerService.selectProvider({
                strategy: input.providerStrategy ?? 'priority',
                requireStreaming: input.requireStreaming,
                requireToolCalling: input.requireToolCalling,
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
            const execution = await ai_1.executionService.submitExecution({
                providerId: provider.id,
                projectId: input.projectId,
                investigationId: input.investigationId ?? null,
                userId: input.userId ?? null,
                systemPrompt: input.systemPrompt,
                userPrompt: input.userPrompt,
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
            this.logTiming(ctx, 'executeAI');
            compensation.clear();
            return { executionId: execution.id, providerId: provider.id, status: 'ACTIVE' };
        });
    }
    // ── Stream Response ───────────────────────────────────────────────────────
    async streamResponse(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.executionId, 'executionId', ctx);
        this.logInfo(ctx, `Streaming response for execution: ${input.executionId}`);
        return this.withCompensation(ctx, async (compensation) => {
            // Create streaming session
            const stream = await ai_1.streamingService.createSession({
                executionId: input.executionId,
                projectId: input.projectId ?? null,
                investigationId: input.investigationId ?? null,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`cancel-stream-${stream.id}`, async () => {
                try {
                    await ai_1.streamingService.cancelSession(stream.id, input.actor);
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_STARTED, ctx, {
                streamingId: stream.id,
                executionId: input.executionId,
                projectId: input.projectId,
            });
            // Ingest chunks
            for (const chunk of input.chunks) {
                await ai_1.streamingService.appendChunk(stream.id, {
                    sequenceNumber: chunk.sequenceNumber,
                    content: chunk.content,
                    finishReason: chunk.finishReason,
                    createdBy: input.actor,
                    updatedBy: input.actor,
                });
            }
            const reconstructed = await ai_1.streamingService.reconstructContent(stream.id);
            const stats = await ai_1.streamingService.getStreamingStats(stream.id);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_FINISHED, ctx, {
                streamingId: stream.id,
                executionId: input.executionId,
                projectId: input.projectId,
                chunkCount: stats.chunkCount,
                totalLength: stats.totalLength,
            });
            this.logTiming(ctx, 'streamResponse');
            compensation.clear();
            return { streamingId: stream.id, chunkCount: stats.chunkCount, reconstructed };
        });
    }
    // ── Cancel Execution ──────────────────────────────────────────────────────
    async cancelExecution(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.executionId, 'executionId', ctx);
        this.logInfo(ctx, `Cancelling execution: ${input.executionId}`);
        const execution = await ai_1.executionService.findExecution(input.executionId);
        if (!execution || execution.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Execution', input.executionId, ctx.correlationId);
        }
        await ai_1.executionService.cancelExecution(input.executionId, input.actor);
        if (input.streamingId) {
            this.validateUuid(input.streamingId, 'streamingId', ctx);
            await ai_1.streamingService.cancelSession(input.streamingId, input.actor);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_STREAMING_CANCELLED, ctx, {
                streamingId: input.streamingId,
                executionId: input.executionId,
            });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_EXECUTION_CANCELLED, ctx, {
            executionId: input.executionId,
            projectId: execution.projectId,
        });
        this.logTiming(ctx, 'cancelExecution');
    }
}
exports.AIOrchestrator = AIOrchestrator;
exports.aiOrchestrator = new AIOrchestrator();
