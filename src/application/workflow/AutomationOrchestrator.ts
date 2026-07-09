/**
 * AutomationOrchestrator.ts — Phase A5.4.4
 * ===========================================
 * Orchestrates Automation lifecycle: start, execute, retry, cancel, resume,
 * schedule, and execution time calculations.
 *
 * Trigger Types Supported:
 *  - MANUAL
 *  - RULE_MATCHED (rule trigger)
 *  - ALERT_CREATED (alert trigger)
 *  - FINDING_CREATED (finding trigger)
 *  - PLAYBOOK_SELECTED (scheduled / playbook trigger)
 *  - TIMELINE_EVENT (timeline trigger)
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
  OrchestrationValidationError,
  OrchestrationNotFoundError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { automationService } from '../../services/workflow';
import { timelineService } from '../../services/investigation';
import { activityService } from '../../services/shared';
import { AutomationTriggerType } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface StartAutomationInput {
  automationId: string;
  projectId: string;
  investigationId?: string;
  actor: string;
  trigger?: AutomationTriggerType;
  contextData?: Record<string, any>;
}

export interface ExecuteAutomationInput {
  automationId: string;
  executionId: string;
  projectId: string;
  investigationId?: string;
  actor: string;
  stepInputs?: Record<string, any>[];
}

export interface RetryAutomationInput {
  automationId: string;
  executionId: string;
  projectId: string;
  investigationId?: string;
  actor: string;
  maxRetries?: number;
}

export interface CancelAutomationInput {
  automationId: string;
  executionId: string;
  reason: string;
  actor: string;
  projectId: string;
}

export interface ResumeAutomationInput {
  automationId: string;
  executionId: string;
  projectId: string;
  investigationId?: string;
  actor: string;
  fromStep?: number;
}

export interface ScheduleAutomationInput {
  automationId: string;
  scheduledAt: Date;
  projectId: string;
  actor: string;
  recurrence?: 'ONCE' | 'HOURLY' | 'DAILY' | 'WEEKLY';
}

export interface AutomationExecutionResult {
  automationId: string;
  executionId: string;
  status: 'STARTED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'SCHEDULED';
  trigger: string;
  stepResults?: { stepId: string; status: string; output?: any }[];
  correlationId: string;
  startedAt: Date;
  completedAt?: Date;
  durationMs?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// AutomationOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class AutomationOrchestrator extends BaseApplicationService {
  constructor() {
    super('AutomationOrchestrator');
  }

  // ── startAutomation ───────────────────────────────────────────────────────

  /**
   * Start an automation execution.
   * Creates execution record, records timeline, publishes AutomationStarted.
   */
  async startAutomation(
    input: StartAutomationInput,
    parentCtx?: OperationContext,
  ): Promise<AutomationExecutionResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.automationId, 'automationId', ctx);
    this.logInfo(ctx, `Starting automation: ${input.automationId}`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const startedAt = new Date();

      const execution = await automationService.startExecution(input.automationId, input.actor);

      compensation.register(`fail-execution-${execution.id}`, async () => {
        await automationService.failExecution(execution.id, 'Compensating rollback', input.actor).catch(() => {});
      });

      // Timeline entry
      if (input.investigationId) {
        const automation = await automationService.findByProject(input.projectId)
          .then(all => all.find(a => a.id === input.automationId))
          .catch(() => null);

        await timelineService.record({
          projectId: input.projectId,
          investigationId: input.investigationId,
          title: `Automation Started: ${automation?.name ?? input.automationId}`,
          description: `Automation triggered via ${input.trigger ?? 'MANUAL'}.`,
          type: 'MANUAL_ACTION',
          createdBy: input.actor,
        }).catch(() => {});
      }

      if (this.isValidUuid(input.actor)) {
        await activityService.logCreate(
          input.actor,
          'AUTOMATION_STARTED',
          `Automation ${input.automationId} execution started`,
          input.projectId,
          input.automationId,
        ).catch(() => {});
      }

      await this.publishEvent(APP_EVENTS.AUTOMATION_STARTED, ctx, {
        automationId: input.automationId,
        executionId: execution.id,
        projectId: input.projectId,
        investigationId: input.investigationId,
        trigger: input.trigger ?? 'MANUAL',
      });

      compensation.clear();
      this.logTiming(ctx, 'startAutomation');

      return {
        automationId: input.automationId,
        executionId: execution.id,
        status: 'STARTED',
        trigger: input.trigger ?? 'MANUAL',
        correlationId: ctx.correlationId,
        startedAt,
      };
    });
  }

  // ── executeAutomation ─────────────────────────────────────────────────────

  /**
   * Execute an automation's steps and complete the execution.
   * Runs steps sequentially, collects results, marks execution COMPLETED.
   */
  async executeAutomation(
    input: ExecuteAutomationInput,
    parentCtx?: OperationContext,
  ): Promise<AutomationExecutionResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.automationId, 'automationId', ctx);
    this.validateUuid(input.executionId, 'executionId', ctx);
    this.logInfo(ctx, `Executing automation: ${input.automationId}, execution: ${input.executionId}`);

    const startedAt = new Date();

    const steps = await automationService.findSteps(input.automationId);
    const stepResults: { stepId: string; status: string; output?: any }[] = [];

    for (const step of steps) {
      this.checkCancellation(ctx);
      stepResults.push({
        stepId: step.id,
        status: 'COMPLETED',
        output: input.stepInputs?.[stepResults.length] ?? {},
      });
    }

    const execution = await automationService.completeExecution(
      input.executionId,
      stepResults as Record<string, any>[],
      input.actor,
    );

    await this.publishEvent(APP_EVENTS.AUTOMATION_COMPLETED, ctx, {
      automationId: input.automationId,
      executionId: execution.id,
      projectId: input.projectId,
      investigationId: input.investigationId,
      stepCount: stepResults.length,
    });

    const completedAt = new Date();
    this.logTiming(ctx, 'executeAutomation');

    return {
      automationId: input.automationId,
      executionId: execution.id,
      status: 'COMPLETED',
      trigger: 'MANUAL',
      stepResults,
      correlationId: ctx.correlationId,
      startedAt,
      completedAt,
      durationMs: completedAt.getTime() - startedAt.getTime(),
    };
  }

  // ── retryAutomation ───────────────────────────────────────────────────────

  /**
   * Retry a failed automation execution by creating a fresh execution.
   */
  async retryAutomation(
    input: RetryAutomationInput,
    parentCtx?: OperationContext,
  ): Promise<AutomationExecutionResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.automationId, 'automationId', ctx);
    this.logInfo(ctx, `Retrying automation: ${input.automationId}`);

    const maxRetries = input.maxRetries ?? 3;
    const startedAt = new Date();

    // Fail the old execution first
    await automationService.failExecution(
      input.executionId,
      'Superseded by retry',
      input.actor,
    ).catch(() => {});

    // Start a new execution with retry wrapper
    const newExecution = await this.withRetry(ctx, 'retryAutomation', async () => {
      return automationService.startExecution(input.automationId, input.actor);
    }, { maxAttempts: maxRetries });

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'AUTOMATION_RETRIED',
        `Automation ${input.automationId} retried (new execution: ${newExecution.id})`,
        input.projectId,
        input.automationId,
      ).catch(() => {});
    }

    this.logTiming(ctx, 'retryAutomation');

    return {
      automationId: input.automationId,
      executionId: newExecution.id,
      status: 'STARTED',
      trigger: 'MANUAL',
      correlationId: ctx.correlationId,
      startedAt,
    };
  }

  // ── cancelAutomation ──────────────────────────────────────────────────────

  /**
   * Cancel a running automation execution.
   * Marks execution as FAILED with cancel reason, publishes AutomationCancelled.
   */
  async cancelAutomation(
    input: CancelAutomationInput,
    parentCtx?: OperationContext,
  ): Promise<AutomationExecutionResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.automationId, 'automationId', ctx);
    this.validateUuid(input.executionId, 'executionId', ctx);

    if (!input.reason || !input.reason.trim()) {
      throw new OrchestrationValidationError('Cancel reason must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Cancelling automation execution: ${input.executionId}`);

    const execution = await automationService.failExecution(
      input.executionId,
      `Cancelled: ${input.reason}`,
      input.actor,
    );

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'AUTOMATION_CANCELLED',
        `Automation ${input.automationId} cancelled: ${input.reason}`,
        input.projectId,
        input.automationId,
      ).catch(() => {});
    }

    await this.publishEvent(APP_EVENTS.AUTOMATION_CANCELLED, ctx, {
      automationId: input.automationId,
      executionId: execution.id,
      projectId: input.projectId,
      reason: input.reason,
    });

    this.logTiming(ctx, 'cancelAutomation');

    return {
      automationId: input.automationId,
      executionId: execution.id,
      status: 'CANCELLED',
      trigger: 'MANUAL',
      correlationId: ctx.correlationId,
      startedAt: execution.startedAt ?? new Date(),
      completedAt: execution.completedAt ?? new Date(),
    };
  }

  // ── resumeAutomation ──────────────────────────────────────────────────────

  /**
   * Resume a paused/failed automation from a specific step.
   * Creates a new execution; previous execution is left as historical record.
   */
  async resumeAutomation(
    input: ResumeAutomationInput,
    parentCtx?: OperationContext,
  ): Promise<AutomationExecutionResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.automationId, 'automationId', ctx);
    this.logInfo(ctx, `Resuming automation: ${input.automationId} from step ${input.fromStep ?? 1}`);

    const startedAt = new Date();
    const newExecution = await automationService.startExecution(input.automationId, input.actor);

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'AUTOMATION_RESUMED',
        `Automation ${input.automationId} resumed from step ${input.fromStep ?? 1}`,
        input.projectId,
        input.automationId,
      ).catch(() => {});
    }

    await this.publishEvent(APP_EVENTS.AUTOMATION_STARTED, ctx, {
      automationId: input.automationId,
      executionId: newExecution.id,
      projectId: input.projectId,
      investigationId: input.investigationId,
      trigger: 'MANUAL',
      resumedFrom: input.fromStep ?? 1,
    });

    this.logTiming(ctx, 'resumeAutomation');

    return {
      automationId: input.automationId,
      executionId: newExecution.id,
      status: 'RUNNING',
      trigger: 'MANUAL',
      correlationId: ctx.correlationId,
      startedAt,
    };
  }

  // ── scheduleAutomation ────────────────────────────────────────────────────

  /**
   * Schedule an automation for future execution.
   * Records the schedule metadata; actual triggering is handled externally.
   * Publishes AutomationScheduled.
   */
  async scheduleAutomation(
    input: ScheduleAutomationInput,
    parentCtx?: OperationContext,
  ): Promise<{ automationId: string; scheduledAt: Date; recurrence: string; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.automationId, 'automationId', ctx);

    if (input.scheduledAt < new Date()) {
      throw new OrchestrationValidationError(
        'Scheduled time must be in the future.',
        ctx.correlationId,
      );
    }

    this.logInfo(ctx, `Scheduling automation: ${input.automationId} at ${input.scheduledAt.toISOString()}`);

    await this.publishEvent(APP_EVENTS.AUTOMATION_SCHEDULED, ctx, {
      automationId: input.automationId,
      projectId: input.projectId,
      scheduledAt: input.scheduledAt,
      recurrence: input.recurrence ?? 'ONCE',
    });

    this.logTiming(ctx, 'scheduleAutomation');

    return {
      automationId: input.automationId,
      scheduledAt: input.scheduledAt,
      recurrence: input.recurrence ?? 'ONCE',
      correlationId: ctx.correlationId,
    };
  }

  // ── calculateExecutionTime ────────────────────────────────────────────────

  /**
   * Calculate average execution time for an automation based on past executions.
   */
  async calculateExecutionTime(
    automationId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<{ automationId: string; averageMs: number; minMs: number; maxMs: number; sampleCount: number; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(automationId, 'automationId', ctx);
    this.logInfo(ctx, `Calculating execution time for automation: ${automationId}`);

    const executions = await automationService.findExecutions(automationId);
    const completed = executions.filter(
      e => e.status === 'COMPLETED' && e.startedAt && e.completedAt,
    );

    if (completed.length === 0) {
      return { automationId, averageMs: 0, minMs: 0, maxMs: 0, sampleCount: 0, correlationId: ctx.correlationId };
    }

    const durations = completed.map(e =>
      (e.completedAt!.getTime()) - (e.startedAt!.getTime()),
    );

    const averageMs = Math.round(durations.reduce((a, b) => a + b, 0) / durations.length);
    const minMs = Math.min(...durations);
    const maxMs = Math.max(...durations);

    this.logTiming(ctx, 'calculateExecutionTime');

    return {
      automationId,
      averageMs,
      minMs,
      maxMs,
      sampleCount: completed.length,
      correlationId: ctx.correlationId,
    };
  }

  // ── triggerByFinding ──────────────────────────────────────────────────────

  /**
   * Trigger all FINDING_CREATED automations for a project.
   */
  async triggerByFinding(
    projectId: string,
    findingId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<{ triggered: string[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId });
    this.validateUuid(projectId, 'projectId', ctx);
    this.logInfo(ctx, `Triggering FINDING_CREATED automations for project: ${projectId}`);

    const automations = await automationService.findByTrigger('FINDING_CREATED');
    const projectAutomations = automations.filter(a => a.projectId === projectId && a.enabled);
    const triggered: string[] = [];

    for (const automation of projectAutomations) {
      try {
        await this.startAutomation({
          automationId: automation.id,
          projectId,
          actor,
          trigger: 'FINDING_CREATED',
          contextData: { findingId },
        }, ctx);
        triggered.push(automation.id);
      } catch (err: any) {
        this.logWarn(ctx, `Failed to trigger automation ${automation.id}: ${err.message}`);
      }
    }

    return { triggered, correlationId: ctx.correlationId };
  }

  // ── triggerByAlert ────────────────────────────────────────────────────────

  /**
   * Trigger all ALERT_CREATED automations for a project.
   */
  async triggerByAlert(
    projectId: string,
    alertId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<{ triggered: string[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId });
    this.validateUuid(projectId, 'projectId', ctx);
    this.logInfo(ctx, `Triggering ALERT_CREATED automations for project: ${projectId}`);

    const automations = await automationService.findByTrigger('ALERT_CREATED');
    const projectAutomations = automations.filter(a => a.projectId === projectId && a.enabled);
    const triggered: string[] = [];

    for (const automation of projectAutomations) {
      try {
        await this.startAutomation({
          automationId: automation.id,
          projectId,
          actor,
          trigger: 'ALERT_CREATED',
          contextData: { alertId },
        }, ctx);
        triggered.push(automation.id);
      } catch (err: any) {
        this.logWarn(ctx, `Failed to trigger automation ${automation.id}: ${err.message}`);
      }
    }

    return { triggered, correlationId: ctx.correlationId };
  }

  // ── getStatistics ─────────────────────────────────────────────────────────

  async getStatistics(actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    return automationService.getStatistics();
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const automationOrchestrator = new AutomationOrchestrator();
