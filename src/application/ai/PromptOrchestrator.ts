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

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationNotFoundError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

import {
  contextWindowService,
  promptAssemblyService,
  providerService,
} from '../../services/ai';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface BuildPromptInput {
  projectId: string;
  investigationId: string;
  conversationId: string;
  actor: string;
  systemPrompt: string;
  userPrompt: string;
  contextId?: string;
  sections?: Array<{ title: string; content: string; priority?: number }>;
  maxTokens?: number;
  reservedTokens?: number;
}

export interface BuildPromptResult {
  promptId: string;
  assembled: string;
  estimatedTokens: number;
  maxTokens: number;
  reservedTokens: number;
  withinBudget: boolean;
  sectionCount: number;
  correlationId: string;
}

export interface CompressContextInput {
  contextId: string;
  actor: string;
  maxTokenBudget: number;
}

export interface CompressContextResult {
  contextId: string;
  originalEntryCount: number;
  remainingEntryCount: number;
  prunedEntryCount: number;
  estimatedTokens: number;
}

export interface OptimizePromptInput {
  promptId: string;
  actor: string;
}

export interface TokenEstimateResult {
  promptId: string;
  estimatedTokens: number;
  maxTokens: number;
  reservedTokens: number;
  withinBudget: boolean;
  remainingTokens: number;
}

export interface CostEstimateResult {
  promptId: string;
  estimatedTokens: number;
  estimatedCostUsd: number;
  providerId: string;
  providerName: string;
  modelName: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// PromptOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class PromptOrchestrator extends BaseApplicationService {
  constructor() {
    super('PromptOrchestrator');
  }

  // ── Build Prompt ──────────────────────────────────────────────────────────

  async buildPrompt(
    input: BuildPromptInput,
    parentCtx?: OperationContext,
  ): Promise<BuildPromptResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Building prompt for investigation: ${input.investigationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const prompt = await promptAssemblyService.createPrompt({
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
      } as Prisma.PromptAssemblyUncheckedCreateInput);

      compensation.register(`delete-prompt-${prompt.id}`, async () => {
        try { await promptAssemblyService.deletePrompt(prompt.id, input.actor); } catch (_) {}
      });

      // Add sections ordered by priority (highest first)
      const sections = [...(input.sections ?? [])].sort(
        (a, b) => (b.priority ?? 50) - (a.priority ?? 50),
      );

      for (const section of sections) {
        await promptAssemblyService.addSection(prompt.id, {
          title: section.title,
          content: section.content,
          priority: section.priority ?? 50,
          createdBy: input.actor,
          updatedBy: input.actor,
        });
      }

      await promptAssemblyService.publishPrompt(prompt.id, input.actor);

      const assembled = await promptAssemblyService.assemblePrompt(prompt.id);
      const budget = await promptAssemblyService.checkTokenBudget(prompt.id);
      const promptSections = await promptAssemblyService.findSections(prompt.id);

      await this.publishEvent(APP_EVENTS.AI_PROMPT_BUILT, ctx, {
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

  async compressContext(
    input: CompressContextInput,
    parentCtx?: OperationContext,
  ): Promise<CompressContextResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.contextId, 'contextId', ctx);
    this.logInfo(ctx, `Compressing context window: ${input.contextId}`);

    const window = await contextWindowService.findWindow(input.contextId);
    if (!window || window.deletedAt) {
      throw new OrchestrationNotFoundError('ContextWindow', input.contextId, ctx.correlationId);
    }

    // Rank by importance — remove least important entries first
    const ranked = await contextWindowService.rankEntriesByImportance(input.contextId);
    const originalCount = ranked.length;
    let usedTokens = 0;
    let prunedCount = 0;

    // Keep highest-importance entries that fit in the budget
    const toKeep = new Set<string>();
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
        await contextWindowService.deleteEntry(entry.id, input.actor);
        prunedCount++;
      }
    }

    const remaining = await contextWindowService.findEntries(input.contextId);

    await this.publishEvent(APP_EVENTS.AI_CONTEXT_BUILT, ctx, {
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

  async optimizePrompt(
    input: OptimizePromptInput,
    parentCtx?: OperationContext,
  ): Promise<{ promptId: string; assembled: string; estimatedTokens: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.promptId, 'promptId', ctx);
    this.logInfo(ctx, `Optimizing prompt: ${input.promptId}`);

    const prompt = await promptAssemblyService.findPrompt(input.promptId);
    if (!prompt || prompt.deletedAt) {
      throw new OrchestrationNotFoundError('PromptAssembly', input.promptId, ctx.correlationId);
    }

    // Re-assemble with current sections (already ordered by priority in assemblePrompt)
    const assembled = await promptAssemblyService.assemblePrompt(input.promptId);
    const tokens = await promptAssemblyService.calculateTokenUsage(input.promptId);

    await this.publishEvent(APP_EVENTS.AI_PROMPT_OPTIMIZED, ctx, {
      promptId: input.promptId,
      estimatedTokens: tokens,
    });

    this.logTiming(ctx, 'optimizePrompt');
    return { promptId: input.promptId, assembled, estimatedTokens: tokens };
  }

  // ── Token Estimation ──────────────────────────────────────────────────────

  async estimateTokens(
    promptId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<TokenEstimateResult> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(promptId, 'promptId', ctx);

    const budget = await promptAssemblyService.checkTokenBudget(promptId);
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

  async estimateCost(
    promptId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<CostEstimateResult> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(promptId, 'promptId', ctx);
    this.logInfo(ctx, `Estimating cost for prompt: ${promptId}`);

    const budget = await promptAssemblyService.checkTokenBudget(promptId);

    // Select best available provider for cost reference
    const provider = await providerService.selectProvider({ strategy: 'priority' });
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

export const promptOrchestrator = new PromptOrchestrator();
