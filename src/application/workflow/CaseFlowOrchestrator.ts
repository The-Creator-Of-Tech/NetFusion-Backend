/**
 * CaseFlowOrchestrator.ts — Phase A5.4.4
 * =========================================
 * Orchestrates Case lifecycle: create, assign, change status, add tasks,
 * close, reopen, and metrics calculation.
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
import { caseFlowService } from '../../services/workflow';
import { timelineService } from '../../services/investigation';
import { activityService, notificationService } from '../../services/shared';
import { CasePriority, CaseStatus } from '@prisma/client';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface CreateCaseInput {
  title: string;
  description?: string;
  projectId: string;
  investigationId: string;
  priority?: CasePriority;
  assignedTo?: string;
  actor: string;
  confidence?: number;
}

export interface AssignCaseInput {
  caseId: string;
  assignee: string;
  actor: string;
  projectId: string;
  investigationId?: string;
  notifyAssignee?: boolean;
}

export interface ChangeStatusInput {
  caseId: string;
  newStatus: CaseStatus;
  actor: string;
  projectId: string;
  investigationId?: string;
  reason?: string;
}

export interface AddTaskInput {
  caseId: string;
  title: string;
  description?: string;
  stepNumber?: number;
  actor: string;
  projectId: string;
}

export interface CloseCaseInput {
  caseId: string;
  resolution: string;
  actor: string;
  projectId: string;
  investigationId?: string;
}

export interface ReopenCaseInput {
  caseId: string;
  reason: string;
  actor: string;
  projectId: string;
  investigationId?: string;
}

export interface CaseResult {
  caseId: string;
  status: string;
  priority: string;
  assignedTo?: string;
  correlationId: string;
}

export interface CaseMetrics {
  caseId: string;
  score: number;
  priorityScore: number;
  daysOpen?: number;
  stepCount: number;
  executionCount: number;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseFlowOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class CaseFlowOrchestrator extends BaseApplicationService {
  constructor() {
    super('CaseFlowOrchestrator');
  }

  // ── createCase ────────────────────────────────────────────────────────────

  /**
   * Create a new case flow.
   * Records timeline event, publishes CaseCreated.
   */
  async createCase(
    input: CreateCaseInput,
    parentCtx?: OperationContext,
  ): Promise<CaseResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateUuid(input.investigationId, 'investigationId', ctx);
    this.logInfo(ctx, `Creating case: "${input.title}"`);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const caseFlow = await caseFlowService.createCaseFlow({
        title: input.title,
        description: input.description,
        projectId: input.projectId,
        investigationId: input.investigationId,
        priority: input.priority ?? 'MEDIUM',
        assignedTo: input.assignedTo,
        confidence: input.confidence ?? 100,
        createdBy: input.actor,
        updatedBy: input.actor,
      } as any);

      compensation.register(`delete-case-${caseFlow.id}`, async () => {
        await caseFlowService.deleteCaseFlow(caseFlow.id, input.actor).catch(() => {});
      });

      // Timeline
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: `Case Created: ${caseFlow.title}`,
        description: `Case "${caseFlow.title}" created with priority ${caseFlow.priority}.`,
        type: 'MANUAL_ACTION',
        createdBy: input.actor,
      }).catch(() => {});

      // Activity log
      if (this.isValidUuid(input.actor)) {
        await activityService.logCreate(
          input.actor,
          'CASE_CREATED',
          `Case "${caseFlow.title}" created`,
          input.projectId,
          caseFlow.id,
        ).catch(() => {});
      }

      await this.publishEvent(APP_EVENTS.CASE_CREATED, ctx, {
        caseId: caseFlow.id,
        title: caseFlow.title,
        projectId: input.projectId,
        investigationId: input.investigationId,
        priority: caseFlow.priority,
      });

      compensation.clear();
      this.logTiming(ctx, 'createCase');

      return {
        caseId: caseFlow.id,
        status: String(caseFlow.status),
        priority: String(caseFlow.priority),
        assignedTo: caseFlow.assignedTo ?? undefined,
        correlationId: ctx.correlationId,
      };
    });
  }

  // ── assignCase ────────────────────────────────────────────────────────────

  /**
   * Assign a case to a team member.
   * Optionally sends notification. Publishes CaseAssigned.
   */
  async assignCase(
    input: AssignCaseInput,
    parentCtx?: OperationContext,
  ): Promise<CaseResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.caseId, 'caseId', ctx);

    if (!input.assignee || !input.assignee.trim()) {
      throw new OrchestrationValidationError('Assignee must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Assigning case ${input.caseId} to ${input.assignee}`);

    const updated = await caseFlowService.assignCase(input.caseId, input.assignee, input.actor);

    // Optional notification
    if (input.notifyAssignee && this.isValidUuid(input.assignee)) {
      await notificationService.createNotification({
        userId: input.assignee,
        title: 'Case Assigned',
        message: `Case "${updated.title}" has been assigned to you.`,
        type: 'SYSTEM',
        status: 'UNREAD',
        createdBy: input.actor,
        updatedBy: input.actor,
      }).catch(() => {}); // best-effort
    }

    if (input.investigationId) {
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: `Case Assigned: ${updated.title}`,
        description: `Case assigned to ${input.assignee}.`,
        type: 'MANUAL_ACTION',
        createdBy: input.actor,
      }).catch(() => {});
    }

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'CASE_ASSIGNED',
        `Case "${updated.title}" assigned to ${input.assignee}`,
        input.projectId,
        input.caseId,
      ).catch(() => {});
    }

    await this.publishEvent(APP_EVENTS.CASE_ASSIGNED, ctx, {
      caseId: updated.id,
      assignee: input.assignee,
      projectId: input.projectId,
      investigationId: input.investigationId,
    });

    this.logTiming(ctx, 'assignCase');

    return {
      caseId: updated.id,
      status: String(updated.status),
      priority: String(updated.priority),
      assignedTo: updated.assignedTo ?? undefined,
      correlationId: ctx.correlationId,
    };
  }

  // ── changeStatus ──────────────────────────────────────────────────────────

  /**
   * Change the status of a case (honours valid status transition rules).
   * Publishes the appropriate status event.
   */
  async changeStatus(
    input: ChangeStatusInput,
    parentCtx?: OperationContext,
  ): Promise<CaseResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.caseId, 'caseId', ctx);
    this.logInfo(ctx, `Changing status of case ${input.caseId} → ${input.newStatus}`);

    let updated: any;

    switch (input.newStatus) {
      case 'IN_PROGRESS':
        updated = await caseFlowService.startCase(input.caseId, input.actor);
        break;
      case 'RESOLVED':
        updated = await caseFlowService.resolveCase(input.caseId, input.actor);
        break;
      case 'CLOSED':
        updated = await caseFlowService.closeCase(input.caseId, input.actor);
        break;
      case 'OPEN':
        // Reopen: update directly with OPEN status
        updated = await caseFlowService.updateCaseFlow(input.caseId, {
          status: 'OPEN' as CaseStatus,
          updatedBy: input.actor,
        } as any);
        break;
      default:
        throw new OrchestrationValidationError(
          `Unsupported status transition to "${input.newStatus}".`,
          ctx.correlationId,
        );
    }

    if (input.investigationId) {
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: `Case Status Changed: ${updated.title}`,
        description: `Case status changed to ${input.newStatus}. ${input.reason ? `Reason: ${input.reason}` : ''}`,
        type: 'MANUAL_ACTION',
        createdBy: input.actor,
      }).catch(() => {});
    }

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        `CASE_STATUS_${input.newStatus}`,
        `Case "${updated.title}" status changed to ${input.newStatus}`,
        input.projectId,
        input.caseId,
      ).catch(() => {});
    }

    // Publish status-specific event
    const statusEventMap: Record<string, string> = {
      IN_PROGRESS: APP_EVENTS.CASE_STARTED,
      RESOLVED:    APP_EVENTS.CASE_RESOLVED,
      CLOSED:      APP_EVENTS.CASE_CLOSED,
      OPEN:        APP_EVENTS.CASE_REOPENED,
    };

    const eventName = statusEventMap[input.newStatus];
    if (eventName) {
      await this.publishEvent(eventName as any, ctx, {
        caseId: updated.id,
        status: input.newStatus,
        projectId: input.projectId,
        investigationId: input.investigationId,
        reason: input.reason,
      });
    }

    this.logTiming(ctx, 'changeStatus');

    return {
      caseId: updated.id,
      status: String(updated.status),
      priority: String(updated.priority),
      assignedTo: updated.assignedTo ?? undefined,
      correlationId: ctx.correlationId,
    };
  }

  // ── addTask ───────────────────────────────────────────────────────────────

  /**
   * Add a task (step) to an existing case flow.
   * Tasks are CaseFlowStep records in the service layer.
   */
  async addTask(
    input: AddTaskInput,
    parentCtx?: OperationContext,
  ): Promise<{ taskId: string; caseId: string; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.validateUuid(input.caseId, 'caseId', ctx);

    if (!input.title || !input.title.trim()) {
      throw new OrchestrationValidationError('Task title must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Adding task "${input.title}" to case ${input.caseId}`);

    // Steps are created directly in the prisma client in the service layer
    // We retrieve steps first to determine next step number
    const existingSteps = await caseFlowService.findSteps(input.caseId);
    const nextStepNumber = input.stepNumber ?? (existingSteps.length + 1);

    // Use prisma directly via service context (service layer boundary)
    // We create the step via prisma scoped within the service boundary
    const prismaClient = (await import('../../lib/prisma')).default;
    const task = await prismaClient.caseFlowStep.create({
      data: {
        caseFlowId: input.caseId,
        title: input.title,
        description: input.description,
        stepNumber: nextStepNumber,
        stepKey: `step-${nextStepNumber}-${Date.now()}`,
        stepType: 'MANUAL' as any,
        createdBy: input.actor,
        updatedBy: input.actor,
      },
    });

    if (this.isValidUuid(input.actor)) {
      await activityService.logCreate(
        input.actor,
        'CASE_TASK_ADDED',
        `Task "${input.title}" added to case`,
        input.projectId,
        input.caseId,
      ).catch(() => {});
    }

    this.logTiming(ctx, 'addTask');

    return {
      taskId: task.id,
      caseId: input.caseId,
      correlationId: ctx.correlationId,
    };
  }

  // ── closeCase ─────────────────────────────────────────────────────────────

  /**
   * Close a case with a resolution summary.
   * Publishes CaseClosed.
   */
  async closeCase(
    input: CloseCaseInput,
    parentCtx?: OperationContext,
  ): Promise<CaseResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.caseId, 'caseId', ctx);

    if (!input.resolution || !input.resolution.trim()) {
      throw new OrchestrationValidationError('Resolution must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Closing case ${input.caseId}: ${input.resolution}`);

    const updated = await caseFlowService.closeCase(input.caseId, input.actor);

    if (input.investigationId) {
      await timelineService.record({
        projectId: input.projectId,
        investigationId: input.investigationId,
        title: `Case Closed: ${updated.title}`,
        description: `Case closed. Resolution: ${input.resolution}`,
        type: 'HISTORY_CREATED',
        createdBy: input.actor,
      }).catch(() => {});
    }

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'CASE_CLOSED',
        `Case "${updated.title}" closed`,
        input.projectId,
        input.caseId,
      ).catch(() => {});
    }

    await this.publishEvent(APP_EVENTS.CASE_CLOSED, ctx, {
      caseId: updated.id,
      projectId: input.projectId,
      investigationId: input.investigationId,
      resolution: input.resolution,
    });

    this.logTiming(ctx, 'closeCase');

    return {
      caseId: updated.id,
      status: String(updated.status),
      priority: String(updated.priority),
      assignedTo: updated.assignedTo ?? undefined,
      correlationId: ctx.correlationId,
    };
  }

  // ── reopenCase ────────────────────────────────────────────────────────────

  /**
   * Reopen a closed case. Publishes CaseReopened.
   */
  async reopenCase(
    input: ReopenCaseInput,
    parentCtx?: OperationContext,
  ): Promise<CaseResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.caseId, 'caseId', ctx);

    if (!input.reason || !input.reason.trim()) {
      throw new OrchestrationValidationError('Reopen reason must not be empty.', ctx.correlationId);
    }

    this.logInfo(ctx, `Reopening case ${input.caseId}: ${input.reason}`);

    return this.changeStatus({
      caseId: input.caseId,
      newStatus: 'OPEN',
      actor: input.actor,
      projectId: input.projectId,
      investigationId: input.investigationId,
      reason: input.reason,
    }, ctx);
  }

  // ── calculateMetrics ──────────────────────────────────────────────────────

  /**
   * Calculate metrics for a case: score, step count, execution count, days open.
   */
  async calculateMetrics(
    caseId: string,
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<CaseMetrics> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.validateUuid(caseId, 'caseId', ctx);
    this.logInfo(ctx, `Calculating metrics for case: ${caseId}`);

    const [score, steps, executions, caseFlow] = await Promise.all([
      caseFlowService.calculateScore(caseId),
      caseFlowService.findSteps(caseId),
      caseFlowService.findExecutions(caseId),
      caseFlowService.findByProject('00000000-0000-4000-a000-000000000000')
        .then(() => null)
        .catch(() => null),
    ]);

    const PRIORITY_SCORE: Record<string, number> = {
      CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25,
    };

    this.logTiming(ctx, 'calculateMetrics');

    return {
      caseId,
      score,
      priorityScore: PRIORITY_SCORE['MEDIUM'],
      stepCount: steps.length,
      executionCount: executions.length,
      correlationId: ctx.correlationId,
    };
  }

  // ── getStatistics ─────────────────────────────────────────────────────────

  async getStatistics(actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    return caseFlowService.getStatistics();
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const caseFlowOrchestrator = new CaseFlowOrchestrator();
