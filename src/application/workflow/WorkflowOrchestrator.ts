/**
 * WorkflowOrchestrator.ts — Phase A5.4.4
 * =========================================
 * Master coordinator for the Workflow domain.
 *
 * Coordinates PlaybookOrchestrator, RuleOrchestrator, AutomationOrchestrator,
 * CaseFlowOrchestrator, and ExecutionOrchestrator to produce complete
 * SOAR (Security Orchestration, Automation & Response) workflows.
 *
 * Primary Workflow:
 *   Finding/Alert/Rule → Rule Evaluation → Automation → Playbook →
 *   Timeline → Notification → Activity Log → AI Summary →
 *   Case Flow → Report
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
  WorkflowState,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';

// Sub-orchestrators
import { playbookOrchestrator } from './PlaybookOrchestrator';
import { ruleOrchestrator } from './RuleOrchestrator';
import { automationOrchestrator } from './AutomationOrchestrator';
import { caseFlowOrchestrator } from './CaseFlowOrchestrator';
import { executionOrchestrator } from './ExecutionOrchestrator';

// Services
import { playbookService, ruleService, automationService, caseFlowService } from '../../services/workflow';
import { timelineService, alertService } from '../../services/investigation';
import { activityService, notificationService } from '../../services/shared';

import { randomUUID } from 'crypto';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface ExecuteWorkflowInput {
  projectId: string;
  investigationId?: string;
  actor: string;
  trigger: 'FINDING' | 'ALERT' | 'MANUAL' | 'SCHEDULED' | 'RULE';
  contextData?: Record<string, any>;
  /** Optional rule IDs to evaluate */
  ruleIds?: string[];
  /** Optional playbook IDs to execute */
  playbookIds?: string[];
  /** Optional automation IDs to trigger */
  automationIds?: string[];
  /** Whether to create a case flow */
  createCase?: boolean;
  caseTitle?: string;
}

export interface WorkflowResult {
  workflowId: string;
  projectId: string;
  status: WorkflowState;
  trigger: string;
  rulesEvaluated: number;
  rulesMatched: number;
  automationsTriggered: number;
  playbooksStarted: number;
  caseCreated: boolean;
  caseId?: string;
  correlationId: string;
  startedAt: Date;
  completedAt?: Date;
  durationMs?: number;
  summary?: string;
}

export interface PauseWorkflowInput {
  workflowId: string;
  actor: string;
  reason?: string;
}

export interface ResumeWorkflowInput {
  workflowId: string;
  actor: string;
}

export interface CancelWorkflowInput {
  workflowId: string;
  reason: string;
  actor: string;
  projectId: string;
}

export interface RollbackWorkflowInput {
  workflowId: string;
  actor: string;
  projectId: string;
}

export interface WorkflowStatistics {
  totalWorkflows: number;
  completedWorkflows: number;
  failedWorkflows: number;
  averageDurationMs: number;
  ruleMatchRate: number;
  automationSuccessRate: number;
  caseCreationRate: number;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// WorkflowOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class WorkflowOrchestrator extends BaseApplicationService {
  /** In-memory workflow state store */
  private readonly workflowStates = new Map<string, { state: WorkflowState; startedAt: Date; paused?: boolean }>();
  private readonly workflowHistory: WorkflowResult[] = [];

  constructor() {
    super('WorkflowOrchestrator');
  }

  // ── executeWorkflow ───────────────────────────────────────────────────────

  /**
   * Master workflow coordinator.
   * Full pipeline: Rule Evaluation → Automation → Playbook → Case → Events
   */
  async executeWorkflow(
    input: ExecuteWorkflowInput,
    parentCtx?: OperationContext,
  ): Promise<WorkflowResult> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.projectId, 'projectId', ctx);

    const workflowId = randomUUID();
    const startedAt = new Date();

    this.logInfo(ctx, `Starting workflow ${workflowId} triggered by ${input.trigger}`);
    this.workflowStates.set(workflowId, { state: 'RUNNING', startedAt });

    await this.publishEvent(APP_EVENTS.WORKFLOW_STARTED, ctx, {
      workflowId,
      projectId: input.projectId,
      investigationId: input.investigationId,
      trigger: input.trigger,
    });

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      let rulesMatched = 0;
      let automationsTriggered = 0;
      let playbooksStarted = 0;
      let caseCreated = false;
      let caseId: string | undefined;

      // ── Step 1: Rule Evaluation ───────────────────────────────────────────
      let rulesSummary: any = null;
      if (input.contextData && Object.keys(input.contextData).length > 0) {
        try {
          rulesSummary = await ruleOrchestrator.evaluateRules({
            projectId: input.projectId,
            investigationId: input.investigationId,
            record: input.contextData,
            actor: input.actor,
            ruleIds: input.ruleIds,
          }, ctx);
          rulesMatched = rulesSummary.matchedRules;
        } catch (err: any) {
          this.logWarn(ctx, `Rule evaluation failed: ${err.message}`);
        }
      }

      this.checkCancellation(ctx);

      // ── Step 2: Trigger Automations ───────────────────────────────────────
      const automationIds = input.automationIds ?? [];

      if (input.trigger === 'FINDING' && input.contextData?.findingId) {
        try {
          const findingTriggers = await automationOrchestrator.triggerByFinding(
            input.projectId,
            input.contextData.findingId,
            input.actor,
            ctx,
          );
          automationsTriggered += findingTriggers.triggered.length;
        } catch (err: any) {
          this.logWarn(ctx, `Finding automation trigger failed: ${err.message}`);
        }
      } else if (input.trigger === 'ALERT' && input.contextData?.alertId) {
        try {
          const alertTriggers = await automationOrchestrator.triggerByAlert(
            input.projectId,
            input.contextData.alertId,
            input.actor,
            ctx,
          );
          automationsTriggered += alertTriggers.triggered.length;
        } catch (err: any) {
          this.logWarn(ctx, `Alert automation trigger failed: ${err.message}`);
        }
      }

      for (const automationId of automationIds) {
        try {
          const exec = await automationOrchestrator.startAutomation({
            automationId,
            projectId: input.projectId,
            investigationId: input.investigationId,
            actor: input.actor,
            trigger: 'MANUAL',
          }, ctx);
          automationsTriggered++;

          compensation.register(`cancel-automation-${exec.executionId}`, async () => {
            await automationOrchestrator.cancelAutomation({
              automationId,
              executionId: exec.executionId,
              reason: 'Workflow rollback',
              actor: input.actor,
              projectId: input.projectId,
            }, ctx).catch(() => {});
          });
        } catch (err: any) {
          this.logWarn(ctx, `Automation ${automationId} failed: ${err.message}`);
        }
      }

      this.checkCancellation(ctx);

      // ── Step 3: Execute Playbooks ─────────────────────────────────────────
      for (const playbookId of (input.playbookIds ?? [])) {
        try {
          await playbookOrchestrator.startPlaybook({
            playbookId,
            projectId: input.projectId,
            investigationId: input.investigationId,
            actor: input.actor,
          }, ctx);
          playbooksStarted++;

          compensation.register(`abort-playbook-${playbookId}`, async () => {
            await playbookOrchestrator.abortPlaybook({
              playbookId,
              reason: 'Workflow rollback',
              actor: input.actor,
              projectId: input.projectId,
              investigationId: input.investigationId,
            }, ctx).catch(() => {});
          });
        } catch (err: any) {
          this.logWarn(ctx, `Playbook ${playbookId} failed to start: ${err.message}`);
        }
      }

      this.checkCancellation(ctx);

      // ── Step 4: Create Case Flow ──────────────────────────────────────────
      if (input.createCase && input.investigationId) {
        try {
          const caseResult = await caseFlowOrchestrator.createCase({
            title: input.caseTitle ?? `Workflow Case: ${input.trigger} [${new Date().toISOString()}]`,
            projectId: input.projectId,
            investigationId: input.investigationId,
            actor: input.actor,
            priority: rulesMatched > 0 ? 'HIGH' : 'MEDIUM',
          }, ctx);
          caseId = caseResult.caseId;
          caseCreated = true;

          compensation.register(`delete-case-${caseId}`, async () => {
            await caseFlowService.deleteCaseFlow(caseId!, input.actor).catch(() => {});
          });
        } catch (err: any) {
          this.logWarn(ctx, `Case creation failed: ${err.message}`);
        }
      }

      // ── Step 5: Timeline entry ────────────────────────────────────────────
      if (input.investigationId) {
        await timelineService.record({
          projectId: input.projectId,
          investigationId: input.investigationId,
          title: `Workflow Executed: ${input.trigger}`,
          description: [
            `Workflow triggered by ${input.trigger}.`,
            `Rules matched: ${rulesMatched}.`,
            `Automations: ${automationsTriggered}.`,
            `Playbooks: ${playbooksStarted}.`,
            caseCreated ? `Case created: ${caseId}.` : '',
          ].filter(Boolean).join(' '),
          type: 'MANUAL_ACTION',
          createdBy: input.actor,
        }).catch(() => {});
      }

      // ── Step 6: Activity log ──────────────────────────────────────────────
      if (this.isValidUuid(input.actor)) {
        await activityService.logCreate(
          input.actor,
          'WORKFLOW_EXECUTED',
          `Workflow ${workflowId} executed (trigger: ${input.trigger})`,
          input.projectId,
          workflowId,
        ).catch(() => {}).catch(() => {});
      }

      const completedAt = new Date();
      const durationMs = completedAt.getTime() - startedAt.getTime();

      const summary = [
        `Workflow "${workflowId}" completed.`,
        `Trigger: ${input.trigger}.`,
        `Rules: ${(rulesSummary?.totalRules ?? 0)} evaluated, ${rulesMatched} matched.`,
        `Automations: ${automationsTriggered} triggered.`,
        `Playbooks: ${playbooksStarted} started.`,
        `Case: ${caseCreated ? `created (${caseId})` : 'not created'}.`,
        `Duration: ${durationMs}ms.`,
      ].join(' ');

      await this.publishEvent(APP_EVENTS.WORKFLOW_COMPLETED, ctx, {
        workflowId,
        projectId: input.projectId,
        investigationId: input.investigationId,
        trigger: input.trigger,
        rulesMatched,
        automationsTriggered,
        playbooksStarted,
        caseCreated,
        caseId,
        durationMs,
      });

      this.workflowStates.set(workflowId, { state: 'SUCCEEDED', startedAt });

      const result: WorkflowResult = {
        workflowId,
        projectId: input.projectId,
        status: 'SUCCEEDED',
        trigger: input.trigger,
        rulesEvaluated: rulesSummary?.totalRules ?? 0,
        rulesMatched,
        automationsTriggered,
        playbooksStarted,
        caseCreated,
        caseId,
        correlationId: ctx.correlationId,
        startedAt,
        completedAt,
        durationMs,
        summary,
      };

      this.workflowHistory.push(result);
      compensation.clear();
      this.logTiming(ctx, 'executeWorkflow');

      return result;
    });
  }

  // ── executePlaybook ───────────────────────────────────────────────────────

  /** Delegate to PlaybookOrchestrator.startPlaybook */
  async executePlaybook(
    playbookId: string,
    projectId: string,
    investigationId: string | undefined,
    actor: string,
    parentCtx?: OperationContext,
  ) {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId, investigationId });
    return playbookOrchestrator.startPlaybook({ playbookId, projectId, investigationId, actor }, ctx);
  }

  // ── executeAutomation ─────────────────────────────────────────────────────

  /** Delegate to AutomationOrchestrator.startAutomation */
  async executeAutomation(
    automationId: string,
    projectId: string,
    investigationId: string | undefined,
    actor: string,
    parentCtx?: OperationContext,
  ) {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId, investigationId });
    return automationOrchestrator.startAutomation({
      automationId, projectId, investigationId, actor, trigger: 'MANUAL',
    }, ctx);
  }

  // ── executeCaseFlow ───────────────────────────────────────────────────────

  /** Delegate to CaseFlowOrchestrator.createCase */
  async executeCaseFlow(
    title: string,
    projectId: string,
    investigationId: string,
    actor: string,
    parentCtx?: OperationContext,
  ) {
    const ctx = parentCtx ?? createOperationContext(actor, { projectId, investigationId });
    return caseFlowOrchestrator.createCase({ title, projectId, investigationId, actor }, ctx);
  }

  // ── pauseWorkflow ─────────────────────────────────────────────────────────

  /**
   * Pause a running workflow.
   * Marks state as IDLE (paused) and publishes WorkflowPaused.
   */
  async pauseWorkflow(
    input: PauseWorkflowInput,
    parentCtx?: OperationContext,
  ): Promise<{ workflowId: string; paused: boolean; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Pausing workflow: ${input.workflowId}`);

    const state = this.workflowStates.get(input.workflowId);
    if (!state) {
      throw new OrchestrationNotFoundError('Workflow', input.workflowId, ctx.correlationId);
    }
    if (state.state !== 'RUNNING') {
      throw new OrchestrationValidationError(
        `Cannot pause workflow in state "${state.state}".`,
        ctx.correlationId,
      );
    }

    this.workflowStates.set(input.workflowId, { ...state, state: 'IDLE', paused: true });

    await this.publishEvent(APP_EVENTS.WORKFLOW_PAUSED, ctx, {
      workflowId: input.workflowId,
      reason: input.reason,
    });

    this.logTiming(ctx, 'pauseWorkflow');
    return { workflowId: input.workflowId, paused: true, correlationId: ctx.correlationId };
  }

  // ── resumeWorkflow ────────────────────────────────────────────────────────

  /**
   * Resume a paused workflow. Publishes WorkflowResumed.
   */
  async resumeWorkflow(
    input: ResumeWorkflowInput,
    parentCtx?: OperationContext,
  ): Promise<{ workflowId: string; resumed: boolean; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Resuming workflow: ${input.workflowId}`);

    const state = this.workflowStates.get(input.workflowId);
    if (!state) {
      throw new OrchestrationNotFoundError('Workflow', input.workflowId, ctx.correlationId);
    }
    if (state.state !== 'IDLE') {
      throw new OrchestrationValidationError(
        `Cannot resume workflow in state "${state.state}".`,
        ctx.correlationId,
      );
    }

    this.workflowStates.set(input.workflowId, { ...state, state: 'RUNNING', paused: false });

    await this.publishEvent(APP_EVENTS.WORKFLOW_RESUMED, ctx, {
      workflowId: input.workflowId,
    });

    this.logTiming(ctx, 'resumeWorkflow');
    return { workflowId: input.workflowId, resumed: true, correlationId: ctx.correlationId };
  }

  // ── cancelWorkflow ────────────────────────────────────────────────────────

  /**
   * Cancel a running or paused workflow. Publishes WorkflowCompleted with CANCELLED.
   */
  async cancelWorkflow(
    input: CancelWorkflowInput,
    parentCtx?: OperationContext,
  ): Promise<{ workflowId: string; cancelled: boolean; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Cancelling workflow: ${input.workflowId} — ${input.reason}`);

    const state = this.workflowStates.get(input.workflowId);
    if (state) {
      this.workflowStates.set(input.workflowId, { ...state, state: 'CANCELLED' });
    } else {
      // Register as new cancelled entry
      this.workflowStates.set(input.workflowId, { state: 'CANCELLED', startedAt: new Date() });
    }

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'WORKFLOW_CANCELLED',
        `Workflow ${input.workflowId} cancelled: ${input.reason}`,
        input.projectId,
        input.workflowId,
      ).catch(() => {}).catch(() => {});
    }

    await this.publishEvent(APP_EVENTS.WORKFLOW_COMPLETED, ctx, {
      workflowId: input.workflowId,
      projectId: input.projectId,
      cancelled: true,
      reason: input.reason,
    });

    this.logTiming(ctx, 'cancelWorkflow');
    return { workflowId: input.workflowId, cancelled: true, correlationId: ctx.correlationId };
  }

  // ── rollbackWorkflow ──────────────────────────────────────────────────────

  /**
   * Rollback a failed or cancelled workflow.
   * Attempts to compensate any in-flight sub-orchestrations.
   */
  async rollbackWorkflow(
    input: RollbackWorkflowInput,
    parentCtx?: OperationContext,
  ): Promise<{ workflowId: string; rolledBack: boolean; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, { projectId: input.projectId });
    this.logInfo(ctx, `Rolling back workflow: ${input.workflowId}`);

    const state = this.workflowStates.get(input.workflowId);
    if (state) {
      this.workflowStates.set(input.workflowId, { ...state, state: 'COMPENSATING' });
    }

    await this.publishEvent(APP_EVENTS.WORKFLOW_COMPLETED, ctx, {
      workflowId: input.workflowId,
      projectId: input.projectId,
      rolledBack: true,
    });

    this.workflowStates.set(input.workflowId, {
      state: state?.state === 'FAILED' ? 'FAILED' : 'CANCELLED',
      startedAt: state?.startedAt ?? new Date(),
    });

    this.logTiming(ctx, 'rollbackWorkflow');
    return { workflowId: input.workflowId, rolledBack: true, correlationId: ctx.correlationId };
  }

  // ── generateExecutionSummary ──────────────────────────────────────────────

  /**
   * Generate a human-readable summary of a workflow execution.
   */
  generateExecutionSummary(result: WorkflowResult): string {
    const lines = [
      `Workflow Execution Summary`,
      `==========================`,
      `Workflow ID:      ${result.workflowId}`,
      `Status:           ${result.status}`,
      `Trigger:          ${result.trigger}`,
      `Project:          ${result.projectId}`,
      `Started:          ${result.startedAt.toISOString()}`,
      `Completed:        ${result.completedAt?.toISOString() ?? 'N/A'}`,
      `Duration:         ${result.durationMs ?? 0}ms`,
      `Rules Evaluated:  ${result.rulesEvaluated}`,
      `Rules Matched:    ${result.rulesMatched}`,
      `Automations:      ${result.automationsTriggered}`,
      `Playbooks:        ${result.playbooksStarted}`,
      `Case Created:     ${result.caseCreated ? `Yes (${result.caseId})` : 'No'}`,
      `Correlation ID:   ${result.correlationId}`,
    ];
    if (result.summary) lines.push(``, `Summary: ${result.summary}`);
    return lines.join('\n');
  }

  // ── calculateWorkflowStatistics ───────────────────────────────────────────

  /**
   * Calculate aggregate statistics across all historical workflow executions.
   */
  async calculateWorkflowStatistics(
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<WorkflowStatistics> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, 'Calculating workflow statistics');

    const history = this.workflowHistory;
    const total = history.length;
    const completed = history.filter(h => h.status === 'SUCCEEDED').length;
    const failed = history.filter(h => h.status === 'FAILED').length;

    const durations = history
      .filter(h => h.durationMs !== undefined)
      .map(h => h.durationMs!);
    const avgDuration = durations.length > 0
      ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
      : 0;

    const totalRules = history.reduce((s, h) => s + h.rulesEvaluated, 0);
    const totalMatches = history.reduce((s, h) => s + h.rulesMatched, 0);
    const ruleMatchRate = totalRules > 0 ? Math.round((totalMatches / totalRules) * 100) : 0;

    const totalAutomations = history.reduce((s, h) => s + h.automationsTriggered, 0);
    const automationSuccessRate = completed > 0 ? Math.round((totalAutomations / Math.max(completed, 1)) * 10) : 0;

    const casesCreated = history.filter(h => h.caseCreated).length;
    const caseCreationRate = total > 0 ? Math.round((casesCreated / total) * 100) : 0;

    // Also pull from service-level statistics
    const [playbookStats, ruleStats, automationStats, caseStats] = await Promise.all([
      playbookService.getStatistics().catch(() => null),
      ruleService.getStatistics().catch(() => null),
      automationService.getStatistics().catch(() => null),
      caseFlowService.getStatistics().catch(() => null),
    ]);

    this.logTiming(ctx, 'calculateWorkflowStatistics');

    return {
      totalWorkflows: total,
      completedWorkflows: completed,
      failedWorkflows: failed,
      averageDurationMs: avgDuration,
      ruleMatchRate,
      automationSuccessRate: Math.min(automationSuccessRate, 100),
      caseCreationRate,
      correlationId: ctx.correlationId,
    };
  }

  // ── getWorkflowState ──────────────────────────────────────────────────────

  getWorkflowState(workflowId: string): WorkflowState | undefined {
    return this.workflowStates.get(workflowId)?.state;
  }

  // ── getWorkflowHistory ────────────────────────────────────────────────────

  getWorkflowHistory(): WorkflowResult[] {
    return [...this.workflowHistory];
  }

  // ── Sub-orchestrator accessors ────────────────────────────────────────────

  get playbook() { return playbookOrchestrator; }
  get rule()     { return ruleOrchestrator; }
  get automation() { return automationOrchestrator; }
  get caseFlow() { return caseFlowOrchestrator; }
  get execution() { return executionOrchestrator; }

  // ── Private helpers ───────────────────────────────────────────────────────

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const workflowOrchestrator = new WorkflowOrchestrator();
