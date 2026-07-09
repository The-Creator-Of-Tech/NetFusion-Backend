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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationError,
  OrchestrationNotFoundError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

import {
  conversationService,
  sessionMemoryService,
  contextWindowService,
  promptAssemblyService,
  executionService,
  providerService,
  streamingService,
} from '../../services/ai';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface ConversationTurnInput {
  conversationId: string;
  projectId: string;
  investigationId: string;
  actor: string;
  userId?: string;
  userMessage: string;
  systemPrompt?: string;
  memoryEntriesToSave?: Array<{
    memoryType: string;
    state: string;
    title: string;
    content: string;
    importanceScore?: number;
    confidence?: number;
  }>;
  contextEntriesToAdd?: Array<{
    source: string;
    priority: string;
    title: string;
    content: string;
    referenceId: string;
    importanceScore?: number;
    confidence?: number;
  }>;
  preferStreaming?: boolean;
  providerStrategy?: 'priority' | 'health' | 'random';
}

export interface ConversationTurnResult {
  conversationId: string;
  userMessageId: string;
  assistantMessageId?: string;
  executionId: string;
  streamingId?: string;
  promptId?: string;
  memoryId?: string;
  contextId?: string;
  tokensUsed: number;
  correlationId: string;
}

export interface ConversationHistoryResult {
  conversationId: string;
  messageCount: number;
  contextSize: number;
  memoryCount: number;
  windowCount: number;
}

export interface PruneContextInput {
  conversationId: string;
  actor: string;
  maxTokenBudget?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// ConversationOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class ConversationOrchestrator extends BaseApplicationService {
  constructor() {
    super('ConversationOrchestrator');
  }

  // ── Full Conversation Turn ────────────────────────────────────────────────

  async processTurn(
    input: ConversationTurnInput,
    parentCtx?: OperationContext,
  ): Promise<ConversationTurnResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Processing conversation turn: ${input.conversationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // ── Step 1: Verify conversation ───────────────────────────────────────
      const conversation = await conversationService.findConversation(input.conversationId);
      if (!conversation || conversation.deletedAt) {
        throw new OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
      }

      // ── Step 2: Load / ensure memory ─────────────────────────────────────
      const memories = await sessionMemoryService.findByProject(input.projectId);
      let memory = memories.find((m) => !m.deletedAt && m.conversationId === input.conversationId);

      if (!memory) {
        memory = await sessionMemoryService.createMemory({
          conversationId: input.conversationId,
          projectId: input.projectId,
          investigationId: input.investigationId,
          userId: input.userId ?? null,
          status: 'ACTIVE',
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.SessionMemoryUncheckedCreateInput);
      }

      await this.publishEvent(APP_EVENTS.AI_MEMORY_LOADED, ctx, {
        memoryId: memory.id,
        conversationId: input.conversationId,
        entryCount: (await sessionMemoryService.findEntries(memory.id)).length,
      });

      // Save new memory entries if provided
      for (const entry of (input.memoryEntriesToSave ?? [])) {
        await sessionMemoryService.addEntry(memory.id, {
          ...entry,
          importanceScore: entry.importanceScore ?? 50.0,
          confidence: entry.confidence ?? 0.5,
          createdBy: input.actor,
          updatedBy: input.actor,
        });
      }

      // ── Step 3: Build context window ──────────────────────────────────────
      const windows = await contextWindowService.findByConversation(input.conversationId);
      let contextWindow = windows.find((w) => !w.deletedAt && w.status === 'ACTIVE');

      if (!contextWindow) {
        contextWindow = await contextWindowService.createWindow({
          projectId: input.projectId,
          conversationId: input.conversationId,
          investigationId: input.investigationId,
          userId: input.userId ?? null,
          status: 'ACTIVE',
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.ContextWindowUncheckedCreateInput);
      }

      for (const entry of (input.contextEntriesToAdd ?? [])) {
        await contextWindowService.addEntry(contextWindow.id, {
          ...entry,
          importanceScore: entry.importanceScore ?? 50.0,
          confidence: entry.confidence ?? 0.5,
          createdBy: input.actor,
          updatedBy: input.actor,
        });
      }

      const windowStats = await contextWindowService.getWindowStats(contextWindow.id);
      const tokenEstimate = Math.ceil(windowStats.contextSize / 4);

      await this.publishEvent(APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
        contextId: contextWindow.id,
        conversationId: input.conversationId,
        entryCount: windowStats.entryCount,
        tokenEstimate,
      });

      // ── Step 4: Assemble prompt ───────────────────────────────────────────
      const systemPrompt = input.systemPrompt ?? `You are a NetFusion AI SOC Assistant.`;
      const prompt = await promptAssemblyService.createPrompt({
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
      } as Prisma.PromptAssemblyUncheckedCreateInput);

      compensation.register(`delete-prompt-${prompt.id}`, async () => {
        try { await promptAssemblyService.deletePrompt(prompt.id, input.actor); } catch (_) {}
      });

      await promptAssemblyService.publishPrompt(prompt.id, input.actor);
      const budget = await promptAssemblyService.checkTokenBudget(prompt.id);

      await this.publishEvent(APP_EVENTS.AI_PROMPT_BUILT, ctx, {
        promptId: prompt.id,
        conversationId: input.conversationId,
        estimatedTokens: budget.estimatedTokens,
        withinBudget: budget.withinBudget,
      });

      // ── Step 5: Select provider ───────────────────────────────────────────
      const provider = await providerService.selectProvider({
        strategy: input.providerStrategy ?? 'priority',
        requireStreaming: input.preferStreaming,
      });
      if (!provider) {
        throw new OrchestrationError('No healthy AI provider available.', ctx.correlationId, 'NO_PROVIDER');
      }

      await this.publishEvent(APP_EVENTS.AI_PROVIDER_SELECTED, ctx, {
        providerId: provider.id,
        providerName: provider.providerName,
        strategy: input.providerStrategy ?? 'priority',
        healthScore: provider.healthScore ?? 100,
      });

      // ── Step 6: Submit and start execution ────────────────────────────────
      const userMsg = await conversationService.addMessage(input.conversationId, {
        role: 'user',
        content: input.userMessage,
        createdBy: input.actor,
        updatedBy: input.actor,
      });

      const execution = await executionService.submitExecution({
        providerId: provider.id,
        projectId: input.projectId,
        investigationId: input.investigationId,
        userId: input.userId ?? null,
        systemPrompt,
        userPrompt: input.userMessage,
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.ExecutionUncheckedCreateInput);

      compensation.register(`cancel-execution-${execution.id}`, async () => {
        try { await executionService.cancelExecution(execution.id, input.actor); } catch (_) {}
      });

      await executionService.startExecution(execution.id, input.actor);

      await this.publishEvent(APP_EVENTS.AI_EXECUTION_STARTED, ctx, {
        executionId: execution.id,
        providerId: provider.id,
        providerName: provider.providerName,
        projectId: input.projectId,
      });

      // ── Step 7: Streaming (optional) ──────────────────────────────────────
      let streamingId: string | undefined;
      if (input.preferStreaming) {
        const stream = await streamingService.createSession({
          executionId: execution.id,
          projectId: input.projectId,
          investigationId: input.investigationId,
          userId: input.userId ?? null,
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.StreamingUncheckedCreateInput);
        streamingId = stream.id;

        await this.publishEvent(APP_EVENTS.AI_STREAMING_STARTED, ctx, {
          streamingId: stream.id,
          executionId: execution.id,
          projectId: input.projectId,
        });
      }

      // ── Step 8: Complete execution + record usage ─────────────────────────
      const simulatedResponse = `[AI SOC response for: "${input.userMessage.slice(0, 60)}"]`;
      await executionService.recordUsage(execution.id, {
        promptTokens: budget.estimatedTokens,
        completionTokens: Math.ceil(simulatedResponse.length / 4),
        totalTokens: budget.estimatedTokens + Math.ceil(simulatedResponse.length / 4),
        estimatedCost: (budget.estimatedTokens + Math.ceil(simulatedResponse.length / 4)) * 0.000002,
        latencyMs: 350,
        createdBy: input.actor,
        updatedBy: input.actor,
      });
      await executionService.completeExecution(execution.id, input.actor);

      const usageStats = await executionService.getUsageStats(execution.id);

      // ── Step 9: Store assistant reply ─────────────────────────────────────
      const assistantMsg = await conversationService.addMessage(input.conversationId, {
        role: 'assistant',
        content: simulatedResponse,
        parentMessageId: userMsg.id,
        createdBy: input.actor,
        updatedBy: input.actor,
      });

      // ── Step 10: Publish completion events ────────────────────────────────
      await this.publishEvent(APP_EVENTS.AI_EXECUTION_COMPLETED, ctx, {
        executionId: execution.id,
        providerId: provider.id,
        projectId: input.projectId,
        totalTokens: usageStats?.totalTokens ?? 0,
        estimatedCost: usageStats?.estimatedCost ?? 0,
        latencyMs: usageStats?.latencyMs ?? 0,
      });

      await this.publishEvent(APP_EVENTS.AI_CONVERSATION_CONTINUED, ctx, {
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

  async getHistory(
    conversationId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<ConversationHistoryResult> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(conversationId, 'conversationId', ctx);

    const stats = await conversationService.getConversationStats(conversationId);
    return { conversationId, ...stats };
  }

  // ── Prune Context ─────────────────────────────────────────────────────────

  async pruneContext(
    input: PruneContextInput,
    parentCtx?: OperationContext,
  ): Promise<{ contextId: string; prunedEntries: number; remainingEntries: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.logInfo(ctx, `Pruning context for conversation: ${input.conversationId}`);

    const windows = await contextWindowService.findByConversation(input.conversationId);
    const active = windows.find((w) => !w.deletedAt && w.status === 'ACTIVE');
    if (!active) {
      throw new OrchestrationNotFoundError('ContextWindow', input.conversationId, ctx.correlationId);
    }

    const maxBudget = input.maxTokenBudget ?? 4096;
    const entries = await contextWindowService.rankEntriesByImportance(active.id);
    let tokenCount = 0;
    let prunedEntries = 0;

    for (const entry of [...entries].reverse()) {
      const entryTokens = Math.ceil((entry.content?.length ?? 0) / 4);
      if (tokenCount + entryTokens > maxBudget) {
        await contextWindowService.deleteEntry(entry.id, input.actor);
        prunedEntries++;
      } else {
        tokenCount += entryTokens;
      }
    }

    const remaining = await contextWindowService.findEntries(active.id);

    await this.publishEvent(APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
      contextId: active.id,
      conversationId: input.conversationId,
      entryCount: remaining.length,
      tokenEstimate: tokenCount,
    });

    this.logTiming(ctx, 'pruneContext');
    return { contextId: active.id, prunedEntries, remainingEntries: remaining.length };
  }
}

export const conversationOrchestrator = new ConversationOrchestrator();
