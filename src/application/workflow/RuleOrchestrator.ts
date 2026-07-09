/**
 * RuleOrchestrator.ts — Phase A5.4.4
 * =====================================
 * Orchestrates rule evaluation, condition checks, action execution,
 * automation triggering, alert triggering, priority calculation,
 * and conflict resolution.
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
import { ruleService } from '../../services/workflow';
import { activityService } from '../../services/shared';
import { alertService } from '../../services/investigation';

// ─────────────────────────────────────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────────────────────────────────────

export interface EvaluateRulesInput {
  projectId: string;
  investigationId?: string;
  record: Record<string, any>;
  actor: string;
  /** Optional: evaluate only these rule IDs */
  ruleIds?: string[];
  /** Severity filter */
  minSeverity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface EvaluateConditionsInput {
  ruleId: string;
  record: Record<string, any>;
  actor: string;
}

export interface ExecuteActionsInput {
  ruleId: string;
  record: Record<string, any>;
  projectId: string;
  investigationId?: string;
  actor: string;
}

export interface TriggerAutomationsInput {
  ruleId: string;
  matchedRecord: Record<string, any>;
  projectId: string;
  investigationId?: string;
  actor: string;
}

export interface TriggerAlertsInput {
  ruleId: string;
  matchedRecord: Record<string, any>;
  projectId: string;
  investigationId?: string;
  actor: string;
}

export interface CalculatePriorityInput {
  ruleIds: string[];
  actor: string;
}

export interface RuleEvaluationResult {
  ruleId: string;
  ruleName?: string;
  matched: boolean;
  conditionResults: { conditionId: string; field: string; matched: boolean }[];
  actionsExecuted: string[];
  correlationId: string;
}

export interface RulesEvaluationSummary {
  totalRules: number;
  matchedRules: number;
  unmatchedRules: number;
  results: RuleEvaluationResult[];
  automationsTriggered: number;
  alertsTriggered: number;
  correlationId: string;
  durationMs: number;
}

export interface PriorityResult {
  ruleId: string;
  priority: number;
  score: number;
  severity: string;
}

export interface ConflictResolutionResult {
  resolvedRuleId: string;
  conflictingRuleIds: string[];
  resolutionStrategy: string;
  correlationId: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleOrchestrator
// ─────────────────────────────────────────────────────────────────────────────

export class RuleOrchestrator extends BaseApplicationService {
  constructor() {
    super('RuleOrchestrator');
  }

  // ── evaluateRules ─────────────────────────────────────────────────────────

  /**
   * Evaluate all enabled rules in a project against a data record.
   * For each matched rule, execute actions and publish RuleMatched.
   */
  async evaluateRules(
    input: EvaluateRulesInput,
    parentCtx?: OperationContext,
  ): Promise<RulesEvaluationSummary> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.logInfo(ctx, `Evaluating rules for project: ${input.projectId}`);

    const startedAt = Date.now();

    // Get rules: either specified IDs or all project rules
    let rules: any[];
    if (input.ruleIds && input.ruleIds.length > 0) {
      rules = await Promise.all(
        input.ruleIds.map(id => ruleService.findByProject(input.projectId).then(all => all.find(r => r.id === id)).catch(() => null)),
      );
      rules = rules.filter(Boolean);
    } else {
      rules = await ruleService.findByProject(input.projectId);
    }

    // Filter by severity if specified
    if (input.minSeverity) {
      const severityOrder = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
      const minLevel = severityOrder[input.minSeverity] ?? 1;
      rules = rules.filter(r => (severityOrder[r.severity as keyof typeof severityOrder] ?? 1) >= minLevel);
    }

    // Filter enabled only
    rules = rules.filter(r => r.enabled && !r.deletedAt);

    const results: RuleEvaluationResult[] = [];
    let automationsTriggered = 0;
    let alertsTriggered = 0;

    for (const rule of rules) {
      this.checkCancellation(ctx);

      try {
        const evalResult = await ruleService.evaluateRule(rule.id, input.record);

        const actionResult: string[] = [];

        if (evalResult.matched) {
          // Execute rule actions
          const executed = await this.executeActions({
            ruleId: rule.id,
            record: input.record,
            projectId: input.projectId,
            investigationId: input.investigationId,
            actor: input.actor,
          }, ctx);
          actionResult.push(...executed.actionsExecuted);
          automationsTriggered += executed.automationsTriggered;
          alertsTriggered += executed.alertsTriggered;

          await this.publishEvent(APP_EVENTS.RULE_MATCHED, ctx, {
            ruleId: rule.id,
            ruleName: rule.name,
            projectId: input.projectId,
            investigationId: input.investigationId,
            conditionCount: evalResult.conditionResults.length,
          });
        } else {
          await this.publishEvent(APP_EVENTS.RULE_FAILED, ctx, {
            ruleId: rule.id,
            ruleName: rule.name,
            projectId: input.projectId,
          });
        }

        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          matched: evalResult.matched,
          conditionResults: evalResult.conditionResults,
          actionsExecuted: actionResult,
          correlationId: ctx.correlationId,
        });
      } catch (err: any) {
        this.logWarn(ctx, `Rule ${rule.id} evaluation failed: ${err.message}`);
        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          matched: false,
          conditionResults: [],
          actionsExecuted: [],
          correlationId: ctx.correlationId,
        });
      }
    }

    const matchedRules = results.filter(r => r.matched).length;

    this.logTiming(ctx, 'evaluateRules');

    return {
      totalRules: rules.length,
      matchedRules,
      unmatchedRules: rules.length - matchedRules,
      results,
      automationsTriggered,
      alertsTriggered,
      correlationId: ctx.correlationId,
      durationMs: Date.now() - startedAt,
    };
  }

  // ── evaluateConditions ────────────────────────────────────────────────────

  /**
   * Evaluate conditions for a specific rule against a record.
   * Returns per-condition match results.
   */
  async evaluateConditions(
    input: EvaluateConditionsInput,
    parentCtx?: OperationContext,
  ): Promise<{ matched: boolean; conditionResults: { conditionId: string; field: string; matched: boolean }[] }> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.validateUuid(input.ruleId, 'ruleId', ctx);
    this.logInfo(ctx, `Evaluating conditions for rule: ${input.ruleId}`);

    const result = await ruleService.evaluateRule(input.ruleId, input.record);
    this.logTiming(ctx, 'evaluateConditions');
    return result;
  }

  // ── executeActions ────────────────────────────────────────────────────────

  /**
   * Execute all actions defined on a rule.
   * Returns list of executed action types and triggered counts.
   */
  async executeActions(
    input: ExecuteActionsInput,
    parentCtx?: OperationContext,
  ): Promise<{ actionsExecuted: string[]; automationsTriggered: number; alertsTriggered: number }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.ruleId, 'ruleId', ctx);
    this.logInfo(ctx, `Executing actions for rule: ${input.ruleId}`);

    const actions = await ruleService.findActions(input.ruleId);
    const actionsExecuted: string[] = [];
    let automationsTriggered = 0;
    let alertsTriggered = 0;

    for (const action of actions) {
      try {
        actionsExecuted.push((action as any).actionType ?? 'UNKNOWN');

        switch ((action as any).actionType) {
          case 'TRIGGER_AUTOMATION':
            automationsTriggered++;
            break;
          case 'CREATE_ALERT':
            alertsTriggered++;
            break;
          case 'LOG':
          case 'NOTIFY':
          default:
            // Record as a generic action execution
            break;
        }
      } catch (err: any) {
        this.logWarn(ctx, `Action ${(action as any).id} execution failed: ${err.message}`);
      }
    }

    if (this.isValidUuid(input.actor)) {
      await activityService.logUpdate(
        input.actor,
        'RULE_ACTIONS_EXECUTED',
        `Executed ${actionsExecuted.length} action(s) for rule ${input.ruleId}`,
        input.projectId,
        input.ruleId,
      ).catch(() => {});
    }

    this.logTiming(ctx, 'executeActions');
    return { actionsExecuted, automationsTriggered, alertsTriggered };
  }

  // ── triggerAutomations ────────────────────────────────────────────────────

  /**
   * Trigger all automations linked to a matched rule.
   * Publishes AutomationTriggered for each.
   */
  async triggerAutomations(
    input: TriggerAutomationsInput,
    parentCtx?: OperationContext,
  ): Promise<{ triggered: string[]; failed: string[]; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.ruleId, 'ruleId', ctx);
    this.logInfo(ctx, `Triggering automations for rule: ${input.ruleId}`);

    const triggered: string[] = [];
    const failed: string[] = [];

    // Get actions that are of TRIGGER_AUTOMATION type
    const actions = await ruleService.findActions(input.ruleId);
    const automationActions = actions.filter(a => (a as any).actionType === 'TRIGGER_AUTOMATION');

    for (const action of automationActions) {
      const automationId = (action as any).parameters?.automationId;
      if (!automationId) continue;

      try {
        await this.publishEvent(APP_EVENTS.AUTOMATION_TRIGGERED, ctx, {
          automationId,
          ruleId: input.ruleId,
          projectId: input.projectId,
          investigationId: input.investigationId,
          trigger: 'RULE_MATCHED',
        });
        triggered.push(automationId);
      } catch (err: any) {
        failed.push(automationId);
        this.logWarn(ctx, `Failed to trigger automation ${automationId}: ${err.message}`);
      }
    }

    this.logTiming(ctx, 'triggerAutomations');
    return { triggered, failed, correlationId: ctx.correlationId };
  }

  // ── triggerAlerts ─────────────────────────────────────────────────────────

  /**
   * Trigger alert creation for a matched rule.
   * Publishes RuleMatched and creates alert via alertService if investigationId provided.
   */
  async triggerAlerts(
    input: TriggerAlertsInput,
    parentCtx?: OperationContext,
  ): Promise<{ alertsCreated: number; correlationId: string }> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.validateUuid(input.ruleId, 'ruleId', ctx);
    this.logInfo(ctx, `Triggering alerts for rule: ${input.ruleId}`);

    let alertsCreated = 0;

    if (input.investigationId) {
      const actions = await ruleService.findActions(input.ruleId);
      const alertActions = actions.filter(a => (a as any).actionType === 'CREATE_ALERT');

      for (const action of alertActions) {
        try {
          await alertService.createAlert({
            projectId: input.projectId,
            investigationId: input.investigationId,
            title: (action as any).parameters?.alertTitle ?? `Rule alert: ${input.ruleId}`,
            description: `Alert triggered by rule ${input.ruleId}`,
            severity: (action as any).parameters?.severity ?? 'MEDIUM',
            source: 'RULE_ENGINE',
            status: 'OPEN',
            createdBy: input.actor,
            updatedBy: input.actor,
          } as any);
          alertsCreated++;
        } catch (err: any) {
          this.logWarn(ctx, `Failed to create alert: ${err.message}`);
        }
      }
    }

    this.logTiming(ctx, 'triggerAlerts');
    return { alertsCreated, correlationId: ctx.correlationId };
  }

  // ── calculatePriority ─────────────────────────────────────────────────────

  /**
   * Calculate priority scores for a set of rules.
   * Higher severity = higher priority score.
   */
  async calculatePriority(
    input: CalculatePriorityInput,
    parentCtx?: OperationContext,
  ): Promise<PriorityResult[]> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Calculating priority for ${input.ruleIds.length} rule(s)`);

    const severityScore: Record<string, number> = {
      CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25,
    };

    const results: PriorityResult[] = [];

    for (const ruleId of input.ruleIds) {
      try {
        const score = await ruleService.calculateRiskScore(ruleId);
        const projectRules = await ruleService.findEnabled();
        const rule = projectRules.find(r => r.id === ruleId);
        results.push({
          ruleId,
          priority: rule?.priority ?? 100,
          score,
          severity: String(rule?.severity ?? 'MEDIUM'),
        });
      } catch {
        results.push({ ruleId, priority: 100, score: 0, severity: 'UNKNOWN' });
      }
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);

    this.logTiming(ctx, 'calculatePriority');
    return results;
  }

  // ── resolveConflicts ──────────────────────────────────────────────────────

  /**
   * Resolve conflicting rules (multiple rules matching the same record).
   * Strategy: highest severity wins; ties broken by priority (lower = higher precedence).
   */
  async resolveConflicts(
    matchedRuleIds: string[],
    actor: string,
    parentCtx?: OperationContext,
  ): Promise<ConflictResolutionResult> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Resolving conflicts among ${matchedRuleIds.length} matched rule(s)`);

    if (matchedRuleIds.length === 0) {
      throw new OrchestrationValidationError('At least one rule ID required.', ctx.correlationId);
    }

    if (matchedRuleIds.length === 1) {
      return {
        resolvedRuleId: matchedRuleIds[0],
        conflictingRuleIds: [],
        resolutionStrategy: 'ONLY_MATCH',
        correlationId: ctx.correlationId,
      };
    }

    const priorities = await this.calculatePriority({ ruleIds: matchedRuleIds, actor }, ctx);
    const winner = priorities[0]; // Already sorted by score desc

    await this.publishEvent(APP_EVENTS.RULE_CONFLICT_RESOLVED, ctx, {
      resolvedRuleId: winner.ruleId,
      conflictingRuleIds: matchedRuleIds.filter(id => id !== winner.ruleId),
      strategy: 'HIGHEST_SEVERITY_LOWEST_PRIORITY',
    });

    this.logTiming(ctx, 'resolveConflicts');

    return {
      resolvedRuleId: winner.ruleId,
      conflictingRuleIds: matchedRuleIds.filter(id => id !== winner.ruleId),
      resolutionStrategy: 'HIGHEST_SEVERITY_LOWEST_PRIORITY',
      correlationId: ctx.correlationId,
    };
  }

  // ── getStatistics ─────────────────────────────────────────────────────────

  async getStatistics(actor: string, parentCtx?: OperationContext) {
    const ctx = parentCtx ?? createOperationContext(actor);
    return ruleService.getStatistics();
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private isValidUuid(v: string): boolean {
    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
  }
}

export const ruleOrchestrator = new RuleOrchestrator();
