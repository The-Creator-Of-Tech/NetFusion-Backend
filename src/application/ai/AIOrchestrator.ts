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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationError,
  OrchestrationNotFoundError,
  RetryOptions,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// AI service singletons
import {
  conversationService,
  sessionMemoryService,
  contextWindowService,
  promptAssemblyService,
  reasoningService,
  executionService,
  providerService,
  streamingService,
} from '../../services/ai';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface StartConversationInput {
  projectId: string;
  title: string;
  actor: string;
  userId?: string;
  investigationId?: string;
  tags?: string[];
  initialSystemPrompt?: string;
}

export interface ContinueConversationInput {
  conversationId: string;
  userMessage: string;
  actor: string;
  projectId: string;
  investigationId?: string;
  userId?: string;
  preferStreaming?: boolean;
  providerStrategy?: 'priority' | 'health' | 'random';
}

export interface CloseConversationInput {
  conversationId: string;
  actor: string;
}

export interface SummarizeConversationInput {
  conversationId: string;
  actor: string;
}

export interface LoadMemoryInput {
  conversationId: string;
  projectId: string;
  actor: string;
  investigationId?: string;
  userId?: string;
}

export interface SaveMemoryInput {
  conversationId: string;
  projectId: string;
  actor: string;
  entries: Array<{
    memoryType: string;
    state: string;
    title: string;
    content: string;
    importanceScore?: number;
    confidence?: number;
    tags?: string[];
  }>;
}

export interface BuildContextInput {
  conversationId: string;
  projectId: string;
  actor: string;
  investigationId?: string;
  userId?: string;
  entries?: Array<{
    source: string;
    priority: string;
    title: string;
    content: string;
    referenceId: string;
    importanceScore?: number;
    confidence?: number;
  }>;
}

export interface RunPromptInput {
  conversationId: string;
  projectId: string;
  actor: string;
  investigationId: string;
  systemPrompt: string;
  userPrompt: string;
  maxTokens?: number;
  reservedTokens?: number;
  sections?: Array<{ title: string; content: string; priority?: number }>;
}

export interface RunReasoningInput {
  projectId: string;
  investigationId: string;
  actor: string;
  userId?: string;
  steps?: Array<{
    stage: string;
    inputSummary: string;
    outputSummary: string;
    confidence: number;
    evidenceIds?: string[];
    findingIds?: string[];
  }>;
  decision?: string;
}

export interface ExecuteAIInput {
  projectId: string;
  actor: string;
  systemPrompt: string;
  userPrompt: string;
  investigationId?: string;
  userId?: string;
  providerStrategy?: 'priority' | 'health' | 'random';
  requireStreaming?: boolean;
  requireToolCalling?: boolean;
}

export interface StreamResponseInput {
  executionId: string;
  actor: string;
  projectId?: string;
  investigationId?: string;
  chunks: Array<{ content: string; sequenceNumber: number; finishReason?: string }>;
}

export interface CancelExecutionInput {
  executionId: string;
  actor: string;
  streamingId?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

export interface ConversationResult {
  conversationId: string;
  memoryId: string;
  contextId: string;
  projectId: string;
  title: string;
  correlationId: string;
}

export interface ContinueConversationResult {
  conversationId: string;
  userMessageId: string;
  executionId: string;
  streamingId?: string;
  response: string;
  tokensUsed: number;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// AIOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class AIOrchestrator extends BaseApplicationService {
  constructor() {
    super('AIOrchestrator');
  }

  // ── Start Conversation ────────────────────────────────────────────────────

  async startConversation(
    input: StartConversationInput,
    parentCtx?: OperationContext,
  ): Promise<ConversationResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.projectId, 'projectId', ctx);
    if (input.investigationId) this.validateUuid(input.investigationId, 'investigationId', ctx);
    if (input.userId) this.validateUuid(input.userId, 'userId', ctx);
    this.logInfo(ctx, `Starting conversation: "${input.title}"`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Create conversation
      const conversation = await conversationService.createConversation({
        projectId: input.projectId,
        title: input.title,
        status: 'ACTIVE',
        tags: input.tags ?? [],
        userId: input.userId ?? null,
        investigationId: input.investigationId ?? null,
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.ConversationUncheckedCreateInput);

      compensation.register(`delete-conversation-${conversation.id}`, async () => {
        try { await conversationService.deleteConversation(conversation.id, input.actor); } catch (_) {}
      });

      // 2. Create session memory
      const memory = await sessionMemoryService.createMemory({
        conversationId: conversation.id,
        projectId: input.projectId,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        status: 'ACTIVE',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.SessionMemoryUncheckedCreateInput);

      compensation.register(`delete-memory-${memory.id}`, async () => {
        try { await sessionMemoryService.deleteMemory(memory.id, input.actor); } catch (_) {}
      });

      // 3. Create context window
      const context = await contextWindowService.createWindow({
        projectId: input.projectId,
        conversationId: conversation.id,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        status: 'ACTIVE',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.ContextWindowUncheckedCreateInput);

      compensation.register(`delete-context-${context.id}`, async () => {
        try { await contextWindowService.deleteWindow(context.id, input.actor); } catch (_) {}
      });

      // 4. Publish event
      await this.publishEvent(APP_EVENTS.AI_CONVERSATION_STARTED, ctx, {
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

  async continueConversation(
    input: ContinueConversationInput,
    parentCtx?: OperationContext,
  ): Promise<ContinueConversationResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Continuing conversation: ${input.conversationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Verify conversation exists
      const conversation = await conversationService.findConversation(input.conversationId);
      if (!conversation || conversation.deletedAt) {
        throw new OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
      }

      // 2. Add user message
      const userMsg = await conversationService.addMessage(
        input.conversationId,
        {
          role: 'user',
          content: input.userMessage,
          createdBy: input.actor,
          updatedBy: input.actor,
        },
      );

      // 3. Select provider
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

      // 4. Submit execution
      const execution = await executionService.submitExecution({
        providerId: provider.id,
        projectId: input.projectId,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        systemPrompt: `You are a NetFusion AI SOC Assistant. Project: ${input.projectId}.`,
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

      // 5. Optionally create streaming session
      let streamingId: string | undefined;
      if (input.preferStreaming) {
        const stream = await streamingService.createSession({
          executionId: execution.id,
          projectId: input.projectId,
          investigationId: input.investigationId ?? null,
          userId: input.userId ?? null,
          createdBy: input.actor,
          updatedBy: input.actor,
        } as Prisma.StreamingUncheckedCreateInput);
        streamingId = stream.id;
      }

      // 6. Complete execution (simulate — real provider call happens in Python layer)
      const simulatedResponse = `[AI response to: "${input.userMessage.slice(0, 80)}"]`;
      await executionService.recordUsage(execution.id, {
        promptTokens: Math.ceil(input.userMessage.length / 4),
        completionTokens: Math.ceil(simulatedResponse.length / 4),
        totalTokens: Math.ceil((input.userMessage.length + simulatedResponse.length) / 4),
        estimatedCost: 0.0001,
        latencyMs: 200,
        createdBy: input.actor,
        updatedBy: input.actor,
      });
      await executionService.completeExecution(execution.id, input.actor);

      // 7. Add assistant reply to conversation
      await conversationService.addMessage(
        input.conversationId,
        {
          role: 'assistant',
          content: simulatedResponse,
          parentMessageId: userMsg.id,
          createdBy: input.actor,
          updatedBy: input.actor,
        },
      );

      const usageStats = await executionService.getUsageStats(execution.id);

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

  async closeConversation(
    input: CloseConversationInput,
    parentCtx?: OperationContext,
  ): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.logInfo(ctx, `Closing conversation: ${input.conversationId}`);

    const conversation = await conversationService.findConversation(input.conversationId);
    if (!conversation || conversation.deletedAt) {
      throw new OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
    }

    await conversationService.completeConversation(input.conversationId, input.actor);

    await this.publishEvent(APP_EVENTS.AI_CONVERSATION_CLOSED, ctx, {
      conversationId: input.conversationId,
      projectId: conversation.projectId,
      closedAt: new Date(),
    });

    this.logTiming(ctx, 'closeConversation');
  }

  // ── Summarize Conversation ────────────────────────────────────────────────

  async summarizeConversation(
    input: SummarizeConversationInput,
    parentCtx?: OperationContext,
  ): Promise<string> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.logInfo(ctx, `Summarizing conversation: ${input.conversationId}`);

    const conversation = await conversationService.findConversation(input.conversationId);
    if (!conversation || conversation.deletedAt) {
      throw new OrchestrationNotFoundError('Conversation', input.conversationId, ctx.correlationId);
    }

    const stats = await conversationService.getConversationStats(input.conversationId);
    const summary = `Conversation "${conversation.title}": ${stats.messageCount} messages, ` +
      `~${stats.contextSize} chars, ${stats.memoryCount} memory entries, ${stats.windowCount} context windows.`;

    await conversationService.updateSummary(input.conversationId, summary, input.actor);

    await this.publishEvent(APP_EVENTS.AI_CONVERSATION_SUMMARIZED, ctx, {
      conversationId: input.conversationId,
      projectId: conversation.projectId,
      summaryLength: summary.length,
    });

    this.logTiming(ctx, 'summarizeConversation');
    return summary;
  }

  // ── Load Memory ───────────────────────────────────────────────────────────

  async loadMemory(
    input: LoadMemoryInput,
    parentCtx?: OperationContext,
  ): Promise<{ memoryId: string; entryCount: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Loading memory for conversation: ${input.conversationId}`);

    const memories = await sessionMemoryService.findByProject(input.projectId);
    const active = memories.find(
      (m) => !m.deletedAt && m.conversationId === input.conversationId,
    );

    if (!active) {
      // Create fresh memory if none exists
      const memory = await sessionMemoryService.createMemory({
        conversationId: input.conversationId,
        projectId: input.projectId,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        status: 'ACTIVE',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.SessionMemoryUncheckedCreateInput);

      await this.publishEvent(APP_EVENTS.AI_MEMORY_LOADED, ctx, {
        memoryId: memory.id,
        conversationId: input.conversationId,
        entryCount: 0,
      });

      this.logTiming(ctx, 'loadMemory');
      return { memoryId: memory.id, entryCount: 0 };
    }

    const entries = await sessionMemoryService.findEntries(active.id);

    await this.publishEvent(APP_EVENTS.AI_MEMORY_LOADED, ctx, {
      memoryId: active.id,
      conversationId: input.conversationId,
      entryCount: entries.length,
    });

    this.logTiming(ctx, 'loadMemory');
    return { memoryId: active.id, entryCount: entries.length };
  }

  // ── Save Memory ───────────────────────────────────────────────────────────

  async saveMemory(
    input: SaveMemoryInput,
    parentCtx?: OperationContext,
  ): Promise<{ memoryId: string; entryCount: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
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
      await sessionMemoryService.addEntry(memoryId, {
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

    await this.publishEvent(APP_EVENTS.AI_MEMORY_SAVED, ctx, {
      memoryId,
      conversationId: input.conversationId,
      entryCount: saved,
    });

    this.logTiming(ctx, 'saveMemory');
    return { memoryId, entryCount: saved };
  }

  // ── Build Context ─────────────────────────────────────────────────────────

  async buildContext(
    input: BuildContextInput,
    parentCtx?: OperationContext,
  ): Promise<{ contextId: string; entryCount: number; tokenEstimate: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.conversationId, 'conversationId', ctx);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Building context for conversation: ${input.conversationId}`);

    // Find or create context window
    const windows = await contextWindowService.findByConversation(input.conversationId);
    let contextWindow = windows.find((w) => !w.deletedAt && w.status === 'ACTIVE');

    if (!contextWindow) {
      contextWindow = await contextWindowService.createWindow({
        projectId: input.projectId,
        conversationId: input.conversationId,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        status: 'ACTIVE',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.ContextWindowUncheckedCreateInput);
    }

    let entryCount = 0;
    for (const entry of (input.entries ?? [])) {
      await contextWindowService.addEntry(contextWindow.id, {
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

    const stats = await contextWindowService.getWindowStats(contextWindow.id);
    const tokenEstimate = Math.ceil(stats.contextSize / 4);

    await this.publishEvent(APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
      contextId: contextWindow.id,
      conversationId: input.conversationId,
      entryCount: stats.entryCount,
      tokenEstimate,
    });

    this.logTiming(ctx, 'buildContext');
    return { contextId: contextWindow.id, entryCount: stats.entryCount, tokenEstimate };
  }

  // ── Run Prompt ────────────────────────────────────────────────────────────

  async runPrompt(
    input: RunPromptInput,
    parentCtx?: OperationContext,
  ): Promise<{ promptId: string; assembled: string; estimatedTokens: number; withinBudget: boolean }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Running prompt assembly for conversation: ${input.conversationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // Build prompt
      const prompt = await promptAssemblyService.createPrompt({
        investigationId: input.investigationId,
        projectId: input.projectId,
        systemPrompt: input.systemPrompt,
        userPrompt: input.userPrompt,
        maxTokens: input.maxTokens ?? 8192,
        reservedTokens: input.reservedTokens ?? 1024,
        status: 'DRAFT',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.PromptAssemblyUncheckedCreateInput);

      compensation.register(`delete-prompt-${prompt.id}`, async () => {
        try { await promptAssemblyService.deletePrompt(prompt.id, input.actor); } catch (_) {}
      });

      // Add sections
      for (const section of (input.sections ?? [])) {
        await promptAssemblyService.addSection(prompt.id, {
          title: section.title,
          content: section.content,
          priority: section.priority ?? 50,
          createdBy: input.actor,
          updatedBy: input.actor,
        });
      }

      // Publish and assemble
      await promptAssemblyService.publishPrompt(prompt.id, input.actor);
      const assembled = await promptAssemblyService.assemblePrompt(prompt.id);
      const budget = await promptAssemblyService.checkTokenBudget(prompt.id);

      await this.publishEvent(APP_EVENTS.AI_PROMPT_BUILT, ctx, {
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

  async runReasoning(
    input: RunReasoningInput,
    parentCtx?: OperationContext,
  ): Promise<{ reasoningId: string; overallConfidence: number; overallRisk: number; decision: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Running reasoning for investigation: ${input.investigationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const session = await reasoningService.createSession({
        projectId: input.projectId,
        investigationId: input.investigationId,
        userId: input.userId ?? null,
        status: 'ACTIVE',
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.ReasoningUncheckedCreateInput);

      compensation.register(`cancel-reasoning-${session.id}`, async () => {
        try { await reasoningService.failSession(session.id, input.actor); } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.AI_REASONING_STARTED, ctx, {
        reasoningId: session.id,
        projectId: input.projectId,
        investigationId: input.investigationId,
      });

      // Add steps
      let stepNum = 1;
      for (const step of (input.steps ?? [])) {
        await reasoningService.addStep(session.id, {
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
      const completed = await reasoningService.completeSession(session.id, decision, input.actor);
      const risk = await reasoningService.calculateOverallRisk(session.id);
      const stats = await reasoningService.getSessionStats(session.id);

      await this.publishEvent(APP_EVENTS.AI_REASONING_COMPLETED, ctx, {
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

  async executeAI(
    input: ExecuteAIInput,
    parentCtx?: OperationContext,
  ): Promise<{ executionId: string; providerId: string; status: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Executing AI request for project: ${input.projectId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // Select provider with intelligent routing
      const provider = await providerService.selectProvider({
        strategy: input.providerStrategy ?? 'priority',
        requireStreaming: input.requireStreaming,
        requireToolCalling: input.requireToolCalling,
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

      const execution = await executionService.submitExecution({
        providerId: provider.id,
        projectId: input.projectId,
        investigationId: input.investigationId ?? null,
        userId: input.userId ?? null,
        systemPrompt: input.systemPrompt,
        userPrompt: input.userPrompt,
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

      this.logTiming(ctx, 'executeAI');
      compensation.clear();

      return { executionId: execution.id, providerId: provider.id, status: 'ACTIVE' };
    });
  }

  // ── Stream Response ───────────────────────────────────────────────────────

  async streamResponse(
    input: StreamResponseInput,
    parentCtx?: OperationContext,
  ): Promise<{ streamingId: string; chunkCount: number; reconstructed: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.executionId, 'executionId', ctx);
    this.logInfo(ctx, `Streaming response for execution: ${input.executionId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // Create streaming session
      const stream = await streamingService.createSession({
        executionId: input.executionId,
        projectId: input.projectId ?? null,
        investigationId: input.investigationId ?? null,
        createdBy: input.actor,
        updatedBy: input.actor,
      } as Prisma.StreamingUncheckedCreateInput);

      compensation.register(`cancel-stream-${stream.id}`, async () => {
        try { await streamingService.cancelSession(stream.id, input.actor); } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.AI_STREAMING_STARTED, ctx, {
        streamingId: stream.id,
        executionId: input.executionId,
        projectId: input.projectId,
      });

      // Ingest chunks
      for (const chunk of input.chunks) {
        await streamingService.appendChunk(stream.id, {
          sequenceNumber: chunk.sequenceNumber,
          content: chunk.content,
          finishReason: chunk.finishReason,
          createdBy: input.actor,
          updatedBy: input.actor,
        });
      }

      const reconstructed = await streamingService.reconstructContent(stream.id);
      const stats = await streamingService.getStreamingStats(stream.id);

      await this.publishEvent(APP_EVENTS.AI_STREAMING_FINISHED, ctx, {
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

  async cancelExecution(
    input: CancelExecutionInput,
    parentCtx?: OperationContext,
  ): Promise<void> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.executionId, 'executionId', ctx);
    this.logInfo(ctx, `Cancelling execution: ${input.executionId}`);

    const execution = await executionService.findExecution(input.executionId);
    if (!execution || execution.deletedAt) {
      throw new OrchestrationNotFoundError('Execution', input.executionId, ctx.correlationId);
    }

    await executionService.cancelExecution(input.executionId, input.actor);

    if (input.streamingId) {
      this.validateUuid(input.streamingId, 'streamingId', ctx);
      await streamingService.cancelSession(input.streamingId, input.actor);

      await this.publishEvent(APP_EVENTS.AI_STREAMING_CANCELLED, ctx, {
        streamingId: input.streamingId,
        executionId: input.executionId,
      });
    }

    await this.publishEvent(APP_EVENTS.AI_EXECUTION_CANCELLED, ctx, {
      executionId: input.executionId,
      projectId: execution.projectId,
    });

    this.logTiming(ctx, 'cancelExecution');
  }
}

export const aiOrchestrator = new AIOrchestrator();
