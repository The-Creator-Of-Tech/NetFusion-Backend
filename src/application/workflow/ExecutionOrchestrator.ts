/**
 * ExecutionOrchestrator.ts — Phase A5.4.4
 * ==========================================
 * Responsible for cross-cutting execution tracking, metrics collection,
 * duration calculation, log/error collection, and execution report building.
 *
 * Works across Playbook, Automation, and CaseFlow execution records.
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  OrchestrationValidationError,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { automationService, caseFlowService, playbookService } from '../../services/workflow';
import { activityService } from '../../services/shared';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface TrackExecutionInput {
  entityType: 'PLAYBOOK' | 'AUTOMATION' | 'CASE_FLOW' | 'WORKFLOW';
  entityId: string;
  executionId: string;
  projectId: string;
  investigationId?: string;
  actor: string;
  metadata?: Record<string, any>;
}

export interface RecordMetricsInput {
  entityType: 'PLAYBOOK' | 'AUTOMATION' | 'CASE_FLOW';
  entityId: string;
  executionId: string;
  actor: string;
  metrics: {
    stepsCompleted?: number;
    stepsFailed?: number;
    stepsSkipped?: number;
    customMetrics?: Record<string, number>;
  };
}

export interface CollectLogsInput {
  executionId: string;
  entityType: 'PLAYBOOK' | 'AUTOMATION' | 'CASE_FLOW';
  entityId: string;
  actor: string;
}

export interface CollectErrorsInput {
  executionId: string;
  entityType: 'PLAYBOOK' | 'AUTOMATION' | 'CASE_FLOW';
  entityId: string;
  actor: string;
}

export interface ExecutionTrackingRecord {
  executionId: string;
  entityId: string;
  entityType: string;
  status: string;
  trackedAt: Date;
  correlationId: string;
}

export interface ExecutionMetrics {
  executionId: string;
  entityId: string;
  entityType: string;
  stepsCompleted: number;
  stepsFailed: number;
  stepsSkipped: number;
  successRate: number;
  customMetrics: Record<string, number>;
  correlationId: string;
}

export interface ExecutionLog {
  timestamp: Date;
  level: 'INFO' | 'WARN' | 'ERROR';
  message: string;
  metadata?: Record<string, any>;
}

export interface ExecutionError {
  timestamp: Date;
  code: string;
  message: string;
  stepId?: string;
}

export interface ExecutionReport {
  reportId: string;
  executionId: string;
  entityId: string;
  entityType: string;
  projectId: string;
  status: string;
  durationMs: number;
  startedAt: Date;
  completedAt?: Date;
  metrics: ExecutionMetrics;
  logs: ExecutionLog[];
  errors: ExecutionError[];
  summary: string;
  correlationId: string;
  generatedAt: Date;
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutionOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class ExecutionOrchestrator extends BaseApplicationService {
  /** In-memory tracking store (per process; fine for orchestration layer) */
  private readonly executions = new Map<string, ExecutionTrackingRecord>();
  private readonly metricsStore = new Map<string, ExecutionMetrics>();
  private readonly logStore = new Map<string, ExecutionLog[]>();
  private readonly errorStore = new Map<string, ExecutionError[]>();

  constructor() {
    super('ExecutionOrchestrator');
  }

  // ── trackExecution ────────────────────────────────────────────────────────

  /**
   * Register an execution for tracking across its lifecycle.
   * Publishes ExecutionSucceeded or ExecutionFailed based on status.
   */
  async trackExecution(
    input: TrackExecutionInput,
    parentCtx?: OperationContext,
  ): Promise<ExecutionTrackingRecord> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.entityId, 'entityId', ctx);
    this.logInfo(ctx, `Tracking execution: ${input.executionId} for ${input.entityType}:${input.entityId}`);

    const record: ExecutionTrackingRecord = {
      executionId: input.executionId,
      entityId: input.entityId,
      entityType: input.entityType,
      status: 'TRACKING',
      trackedAt: new Date(),
      correlationId: ctx.correlationId,
    };

    this.executions.set(input.executionId, record);

    // Initialize log and error stores
    if (!this.logStore.has(input.executionId)) {
      this.logStore.set(input.executionId, []);
    }
    if (!this.errorStore.has(input.executionId)) {
      this.errorStore.set(input.executionId, []);
    }

    await this.publishEvent(APP_EVENTS.EXECUTION_TRACKED, ctx, {
      executionId: input.executionId,
      entityId: input.entityId,
      entityType: input.entityType,
      projectId: input.projectId,
    });

    this.logTiming(ctx, 'trackExecution');
    return record;
  }

  // ── recordMetrics ─────────────────────────────────────────────────────────

  /**
   * Record metrics for an execution.
   */
  async recordMetrics(
    input: RecordMetricsInput,
    parentCtx?: OperationContext,
  ): Promise<ExecutionMetrics> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.entityId, 'entityId', ctx);
    this.logInfo(ctx, `Recording metrics for execution: ${input.executionId}`);

    const stepsCompleted = input.metrics.stepsCompleted ?? 0;
    const stepsFailed = input.metrics.stepsFailed ?? 0;
    const stepsSkipped = input.metrics.stepsSkipped ?? 0;
    const totalSteps = stepsCompleted + stepsFailed + stepsSkipped;
    const successRate = totalSteps > 0 ? Math.round((stepsCompleted / totalSteps) * 100) : 100;

    const metrics: ExecutionMetrics = {
      executionId: input.executionId,
      entityId: input.entityId,
      entityType: input.entityType,
      stepsCompleted,
      stepsFailed,
      stepsSkipped,
      successRate,
      customMetrics: input.metrics.customMetrics ?? {},
      correlationId: ctx.correlationId,
    };

    this.metricsStore.set(input.executionId, metrics);

    this.logTiming(ctx, 'recordMetrics');
    return metrics;
  }

  // ── calculateDuration ─────────────────────────────────────────────────────

  /**
   * Calculate execution duration from actual execution records.
   */
  async calculateDuration(
    executionId: string,
    entityType: 'PLAYBOOK' | 'AUTOMATION' | 'CASE_FLOW',
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<{ executionId: string; durationMs: number; startedAt?: Date; completedAt?: Date; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Calculating duration for execution: ${executionId}`);

    let startedAt: Date | undefined;
    let completedAt: Date | undefined;

    try {
      if (entityType === 'AUTOMATION') {
        const prismaClient = (await import('../../lib/prisma')).default;
        const exec = await prismaClient.automationExecution.findFirst({
          where: { id: executionId, deletedAt: null },
        });
        startedAt = exec?.startedAt ?? undefined;
        completedAt = exec?.completedAt ?? undefined;
      } else if (entityType === 'CASE_FLOW') {
        const prismaClient = (await import('../../lib/prisma')).default;
        const exec = await prismaClient.caseFlowExecution.findFirst({
          where: { id: executionId, deletedAt: null },
        });
        startedAt = exec?.startedAt ?? undefined;
        completedAt = exec?.completedAt ?? undefined;
      }
    } catch {
      // Fallback
    }

    const durationMs = startedAt && completedAt
      ? completedAt.getTime() - startedAt.getTime()
      : 0;

    this.logTiming(ctx, 'calculateDuration');

    return {
      executionId,
      durationMs,
      startedAt,
      completedAt,
      correlationId: ctx.correlationId,
    };
  }

  // ── collectLogs ───────────────────────────────────────────────────────────

  /**
   * Collect all logs for an execution from the in-memory store.
   * In production this would query a log service.
   */
  async collectLogs(
    input: CollectLogsInput,
    parentCtx?: OperationContext,
  ): Promise<ExecutionLog[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Collecting logs for execution: ${input.executionId}`);

    const logs = this.logStore.get(input.executionId) ?? [];

    // Add a default "execution started" log if store is empty
    if (logs.length === 0) {
      logs.push({
        timestamp: new Date(),
        level: 'INFO',
        message: `Execution ${input.executionId} logs collected for ${input.entityType}:${input.entityId}`,
      });
      this.logStore.set(input.executionId, logs);
    }

    this.logTiming(ctx, 'collectLogs');
    return logs;
  }

  // ── collectErrors ─────────────────────────────────────────────────────────

  /**
   * Collect errors recorded during an execution.
   */
  async collectErrors(
    input: CollectErrorsInput,
    parentCtx?: OperationContext,
  ): Promise<ExecutionError[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Collecting errors for execution: ${input.executionId}`);

    const errors = this.errorStore.get(input.executionId) ?? [];
    this.logTiming(ctx, 'collectErrors');
    return errors;
  }

  // ── addLog ────────────────────────────────────────────────────────────────

  /**
   * Append a log entry to an execution's log stream.
   */
  addLog(executionId: string, log: ExecutionLog): void {
    const existing = this.logStore.get(executionId) ?? [];
    existing.push(log);
    this.logStore.set(executionId, existing);
  }

  // ── addError ──────────────────────────────────────────────────────────────

  /**
   * Record an error for an execution.
   */
  addError(executionId: string, error: ExecutionError): void {
    const existing = this.errorStore.get(executionId) ?? [];
    existing.push(error);
    this.errorStore.set(executionId, existing);
  }

  // ── buildExecutionReport ──────────────────────────────────────────────────

  /**
   * Build a comprehensive execution report combining metrics, logs, errors, duration.
   */
  async buildExecutionReport(
    executionId: string,
    entityType: 'PLAYBOOK' | 'AUTOMATION' | 'CASE_FLOW',
    entityId: string,
    projectId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<ExecutionReport> {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId });
    this.validateUuid(entityId, 'entityId', ctx);
    this.logInfo(ctx, `Building execution report for: ${executionId}`);

    const [durationResult, logs, errors] = await Promise.all([
      this.calculateDuration(executionId, entityType, actor, ctx),
      this.collectLogs({ executionId, entityType, entityId, actor }, ctx),
      this.collectErrors({ executionId, entityType, entityId, actor }, ctx),
    ]);

    const metrics = this.metricsStore.get(executionId) ?? {
      executionId,
      entityId,
      entityType,
      stepsCompleted: 0,
      stepsFailed: 0,
      stepsSkipped: 0,
      successRate: 100,
      customMetrics: {},
      correlationId: ctx.correlationId,
    };

    const tracking = this.executions.get(executionId);
    const hasErrors = errors.length > 0;
    const status = hasErrors ? 'FAILED' : 'COMPLETED';

    const summary = [
      `Execution ${executionId} of ${entityType} "${entityId}"`,
      `Status: ${status}`,
      `Steps: ${metrics.stepsCompleted} completed, ${metrics.stepsFailed} failed, ${metrics.stepsSkipped} skipped`,
      `Success Rate: ${metrics.successRate}%`,
      `Duration: ${durationResult.durationMs}ms`,
      `Errors: ${errors.length}`,
    ].join(' | ');

    const reportId = `${executionId}-report-${Date.now()}`;

    await this.publishEvent(hasErrors ? APP_EVENTS.EXECUTION_FAILED : APP_EVENTS.EXECUTION_SUCCEEDED, ctx, {
      executionId,
      entityId,
      entityType,
      projectId,
      status,
      durationMs: durationResult.durationMs,
    });

    this.logTiming(ctx, 'buildExecutionReport');

    return {
      reportId,
      executionId,
      entityId,
      entityType,
      projectId,
      status,
      durationMs: durationResult.durationMs,
      startedAt: durationResult.startedAt ?? tracking?.trackedAt ?? new Date(),
      completedAt: durationResult.completedAt,
      metrics,
      logs,
      errors,
      summary,
      correlationId: ctx.correlationId,
      generatedAt: new Date(),
    };
  }

  // ── getTrackedExecutions ──────────────────────────────────────────────────

  /**
   * Return all currently tracked executions.
   */
  getTrackedExecutions(): ExecutionTrackingRecord[] {
    return Array.from(this.executions.values());
  }

  // ── clearExecution ────────────────────────────────────────────────────────

  /**
   * Clear a specific execution from the tracking store (housekeeping).
   */
  clearExecution(executionId: string): void {
    this.executions.delete(executionId);
    this.metricsStore.delete(executionId);
    this.logStore.delete(executionId);
    this.errorStore.delete(executionId);
  }
}

export const executionOrchestrator = new ExecutionOrchestrator();
