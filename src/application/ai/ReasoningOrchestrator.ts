/**
 * ReasoningOrchestrator.ts — Phase A5.4.2
 * ==========================================
 * Responsible for:
 *  - Multi-step reasoning session management
 *  - Confidence aggregation across steps
 *  - Step execution with retry logic
 *  - Explanation generation from reasoning steps
 *  - Rollback on partial reasoning failure
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

import { reasoningService } from '../../services/ai';

import { Prisma } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface ReasoningStepDefinition {
  stage: string;
  inputSummary: string;
  /** Function that returns the output summary and confidence 0–1 */
  execute?: () => Promise<{ outputSummary: string; confidence: number }>;
  outputSummary?: string;
  confidence?: number;
  evidenceIds?: string[];
  findingIds?: string[];
  alertIds?: string[];
  retryOptions?: RetryOptions;
}

export interface RunReasoningWorkflowInput {
  projectId: string;
  investigationId: string;
  actor: string;
  userId?: string;
  steps: ReasoningStepDefinition[];
  decision?: string;
  minConfidenceThreshold?: number;
}

export interface ReasoningWorkflowResult {
  reasoningId: string;
  overallConfidence: number;
  overallRisk: number;
  stepCount: number;
  decision: string;
  explanation: string;
  belowThreshold: boolean;
  correlationId: string;
}

export interface StepExecutionResult {
  stepId: string;
  stepNumber: number;
  stage: string;
  outputSummary: string;
  confidence: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// ReasoningOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class ReasoningOrchestrator extends BaseApplicationService {
  constructor() {
    super('ReasoningOrchestrator');
  }

  // ── Run Reasoning Workflow ────────────────────────────────────────────────

  async runWorkflow(
    input: RunReasoningWorkflowInput,
    parentCtx?: OperationContext,
  ): Promise<ReasoningWorkflowResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Running reasoning workflow: ${input.steps.length} steps`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      // 1. Create reasoning session
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

      // 2. Execute each step, with retry support
      const stepResults: StepExecutionResult[] = [];
      let stepNumber = 1;

      for (const stepDef of input.steps) {
        this.checkCancellation(ctx);

        const stepResult = await this.executeStep(
          session.id,
          stepNumber,
          stepDef,
          input.actor,
          ctx,
        );
        stepResults.push(stepResult);
        stepNumber++;
      }

      // 3. Aggregate confidence + risk
      const confidence = await reasoningService.calculateConfidence(session.id);
      const risk = await reasoningService.calculateOverallRisk(session.id);

      // 4. Derive decision
      const minThreshold = input.minConfidenceThreshold ?? 0.5;
      const belowThreshold = confidence < minThreshold;
      const decision = input.decision ?? this.deriveDecision(confidence, risk, belowThreshold);

      // 5. Complete session
      await reasoningService.completeSession(session.id, decision, input.actor);

      // 6. Generate explanation
      const explanation = this.generateExplanation(stepResults, confidence, risk, decision);

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

      this.logTiming(ctx, 'runWorkflow');
      compensation.clear();

      return {
        reasoningId: session.id,
        overallConfidence: stats.overallConfidence,
        overallRisk: risk,
        stepCount: stats.stepCount,
        decision,
        explanation,
        belowThreshold,
        correlationId: ctx.correlationId,
      };
    });
  }

  // ── Execute Single Step ───────────────────────────────────────────────────

  private async executeStep(
    reasoningId: string,
    stepNumber: number,
    stepDef: ReasoningStepDefinition,
    actor: string,
    ctx: OperationContext,
  ): Promise<StepExecutionResult> {
    this.logInfo(ctx, `Executing reasoning step ${stepNumber}: ${stepDef.stage}`);

    const retryOpts: RetryOptions = stepDef.retryOptions ?? {
      maxAttempts: 2,
      initialDelayMs: 50,
    };

    return this.withRetry(ctx, `step-${stepNumber}-${stepDef.stage}`, async () => {
      let outputSummary: string;
      let confidence: number;

      if (stepDef.execute) {
        // Dynamic step — call executor function
        const result = await stepDef.execute();
        outputSummary = result.outputSummary;
        confidence = Math.max(0, Math.min(1, result.confidence));
      } else {
        // Static step — use provided values
        outputSummary = stepDef.outputSummary ?? `Step ${stepNumber} completed.`;
        confidence = Math.max(0, Math.min(1, stepDef.confidence ?? 0.5));
      }

      const step = await reasoningService.addStep(reasoningId, {
        stepNumber,
        stage: stepDef.stage,
        inputSummary: stepDef.inputSummary,
        outputSummary,
        confidence,
        evidenceIds: stepDef.evidenceIds ?? [],
        findingIds: stepDef.findingIds ?? [],
        alertIds: stepDef.alertIds ?? [],
        createdBy: actor,
        updatedBy: actor,
      });

      return {
        stepId: step.id,
        stepNumber,
        stage: stepDef.stage,
        outputSummary,
        confidence,
      };
    }, retryOpts);
  }

  // ── Add Step to Existing Session ──────────────────────────────────────────

  async addStep(
    reasoningId: string,
    stepDef: ReasoningStepDefinition & { stepNumber: number },
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<StepExecutionResult> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(reasoningId, 'reasoningId', ctx);

    const session = await reasoningService.findSession(reasoningId);
    if (!session || session.deletedAt) {
      throw new OrchestrationNotFoundError('Reasoning', reasoningId, ctx.correlationId);
    }

    return this.executeStep(reasoningId, stepDef.stepNumber, stepDef, actor, ctx);
  }

  // ── Get Reasoning Stats ───────────────────────────────────────────────────

  async getStats(
    reasoningId: string,
    actor: string,
    parentCtx?: OperationContext,
  ) {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(reasoningId, 'reasoningId', ctx);
    return reasoningService.getSessionStats(reasoningId);
  }

  // ── Private Helpers ───────────────────────────────────────────────────────

  private deriveDecision(confidence: number, risk: number, belowThreshold: boolean): string {
    if (belowThreshold) {
      return `Low-confidence analysis (${(confidence * 100).toFixed(1)}%). Manual review recommended.`;
    }
    if (risk > 0.7) {
      return `High-risk indicators detected (risk: ${(risk * 100).toFixed(1)}%). Immediate investigation required.`;
    }
    if (risk > 0.4) {
      return `Moderate risk detected (risk: ${(risk * 100).toFixed(1)}%). Further analysis recommended.`;
    }
    return `Analysis complete. Confidence: ${(confidence * 100).toFixed(1)}%, Risk: ${(risk * 100).toFixed(1)}%.`;
  }

  private generateExplanation(
    steps: StepExecutionResult[],
    confidence: number,
    risk: number,
    decision: string,
  ): string {
    const lines: string[] = [
      `Reasoning completed with ${steps.length} step(s).`,
      `Overall confidence: ${(confidence * 100).toFixed(1)}%`,
      `Overall risk: ${(risk * 100).toFixed(1)}%`,
      '',
      'Step breakdown:',
    ];

    for (const step of steps) {
      lines.push(
        `  [${step.stepNumber}] ${step.stage}: "${step.outputSummary}" ` +
        `(confidence: ${(step.confidence * 100).toFixed(1)}%)`,
      );
    }

    lines.push('', `Decision: ${decision}`);
    return lines.join('\n');
  }
}

export const reasoningOrchestrator = new ReasoningOrchestrator();
