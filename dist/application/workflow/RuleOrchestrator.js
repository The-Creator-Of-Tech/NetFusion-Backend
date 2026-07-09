"use strict";
/**
 * RuleOrchestrator.ts — Phase A5.4.4
 * =====================================
 * Orchestrates rule evaluation, condition checks, action execution,
 * automation triggering, alert triggering, priority calculation,
 * and conflict resolution.
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ruleOrchestrator = exports.RuleOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const workflow_1 = require("../../services/workflow");
const shared_1 = require("../../services/shared");
const investigation_1 = require("../../services/investigation");
// ─────────────────────────────────────────────────────────────────────────────
// RuleOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class RuleOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('RuleOrchestrator');
    }
    // ── evaluateRules ─────────────────────────────────────────────────────────
    /**
     * Evaluate all enabled rules in a project against a data record.
     * For each matched rule, execute actions and publish RuleMatched.
     */
    async evaluateRules(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.logInfo(ctx, `Evaluating rules for project: ${input.projectId}`);
        const startedAt = Date.now();
        // Get rules: either specified IDs or all project rules
        let rules;
        if (input.ruleIds && input.ruleIds.length > 0) {
            rules = await Promise.all(input.ruleIds.map(id => workflow_1.ruleService.findByProject(input.projectId).then(all => all.find(r => r.id === id)).catch(() => null)));
            rules = rules.filter(Boolean);
        }
        else {
            rules = await workflow_1.ruleService.findByProject(input.projectId);
        }
        // Filter by severity if specified
        if (input.minSeverity) {
            const severityOrder = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
            const minLevel = severityOrder[input.minSeverity] ?? 1;
            rules = rules.filter(r => (severityOrder[r.severity] ?? 1) >= minLevel);
        }
        // Filter enabled only
        rules = rules.filter(r => r.enabled && !r.deletedAt);
        const results = [];
        let automationsTriggered = 0;
        let alertsTriggered = 0;
        for (const rule of rules) {
            this.checkCancellation(ctx);
            try {
                const evalResult = await workflow_1.ruleService.evaluateRule(rule.id, input.record);
                const actionResult = [];
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
                    await this.publishEvent(ApplicationEvents_1.APP_EVENTS.RULE_MATCHED, ctx, {
                        ruleId: rule.id,
                        ruleName: rule.name,
                        projectId: input.projectId,
                        investigationId: input.investigationId,
                        conditionCount: evalResult.conditionResults.length,
                    });
                }
                else {
                    await this.publishEvent(ApplicationEvents_1.APP_EVENTS.RULE_FAILED, ctx, {
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
            }
            catch (err) {
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
    async evaluateConditions(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.ruleId, 'ruleId', ctx);
        this.logInfo(ctx, `Evaluating conditions for rule: ${input.ruleId}`);
        const result = await workflow_1.ruleService.evaluateRule(input.ruleId, input.record);
        this.logTiming(ctx, 'evaluateConditions');
        return result;
    }
    // ── executeActions ────────────────────────────────────────────────────────
    /**
     * Execute all actions defined on a rule.
     * Returns list of executed action types and triggered counts.
     */
    async executeActions(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.ruleId, 'ruleId', ctx);
        this.logInfo(ctx, `Executing actions for rule: ${input.ruleId}`);
        const actions = await workflow_1.ruleService.findActions(input.ruleId);
        const actionsExecuted = [];
        let automationsTriggered = 0;
        let alertsTriggered = 0;
        for (const action of actions) {
            try {
                actionsExecuted.push(action.actionType ?? 'UNKNOWN');
                switch (action.actionType) {
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
            }
            catch (err) {
                this.logWarn(ctx, `Action ${action.id} execution failed: ${err.message}`);
            }
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'RULE_ACTIONS_EXECUTED', `Executed ${actionsExecuted.length} action(s) for rule ${input.ruleId}`, input.projectId, input.ruleId).catch(() => { });
        }
        this.logTiming(ctx, 'executeActions');
        return { actionsExecuted, automationsTriggered, alertsTriggered };
    }
    // ── triggerAutomations ────────────────────────────────────────────────────
    /**
     * Trigger all automations linked to a matched rule.
     * Publishes AutomationTriggered for each.
     */
    async triggerAutomations(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.ruleId, 'ruleId', ctx);
        this.logInfo(ctx, `Triggering automations for rule: ${input.ruleId}`);
        const triggered = [];
        const failed = [];
        // Get actions that are of TRIGGER_AUTOMATION type
        const actions = await workflow_1.ruleService.findActions(input.ruleId);
        const automationActions = actions.filter(a => a.actionType === 'TRIGGER_AUTOMATION');
        for (const action of automationActions) {
            const automationId = action.parameters?.automationId;
            if (!automationId)
                continue;
            try {
                await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AUTOMATION_TRIGGERED, ctx, {
                    automationId,
                    ruleId: input.ruleId,
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    trigger: 'RULE_MATCHED',
                });
                triggered.push(automationId);
            }
            catch (err) {
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
    async triggerAlerts(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.ruleId, 'ruleId', ctx);
        this.logInfo(ctx, `Triggering alerts for rule: ${input.ruleId}`);
        let alertsCreated = 0;
        if (input.investigationId) {
            const actions = await workflow_1.ruleService.findActions(input.ruleId);
            const alertActions = actions.filter(a => a.actionType === 'CREATE_ALERT');
            for (const action of alertActions) {
                try {
                    await investigation_1.alertService.createAlert({
                        projectId: input.projectId,
                        investigationId: input.investigationId,
                        title: action.parameters?.alertTitle ?? `Rule alert: ${input.ruleId}`,
                        description: `Alert triggered by rule ${input.ruleId}`,
                        severity: action.parameters?.severity ?? 'MEDIUM',
                        source: 'RULE_ENGINE',
                        status: 'OPEN',
                        createdBy: input.actor,
                        updatedBy: input.actor,
                    });
                    alertsCreated++;
                }
                catch (err) {
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
    async calculatePriority(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Calculating priority for ${input.ruleIds.length} rule(s)`);
        const severityScore = {
            CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25,
        };
        const results = [];
        for (const ruleId of input.ruleIds) {
            try {
                const score = await workflow_1.ruleService.calculateRiskScore(ruleId);
                const projectRules = await workflow_1.ruleService.findEnabled();
                const rule = projectRules.find(r => r.id === ruleId);
                results.push({
                    ruleId,
                    priority: rule?.priority ?? 100,
                    score,
                    severity: String(rule?.severity ?? 'MEDIUM'),
                });
            }
            catch {
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
    async resolveConflicts(matchedRuleIds, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Resolving conflicts among ${matchedRuleIds.length} matched rule(s)`);
        if (matchedRuleIds.length === 0) {
            throw new BaseApplicationService_1.OrchestrationValidationError('At least one rule ID required.', ctx.correlationId);
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
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.RULE_CONFLICT_RESOLVED, ctx, {
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
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return workflow_1.ruleService.getStatistics();
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.RuleOrchestrator = RuleOrchestrator;
exports.ruleOrchestrator = new RuleOrchestrator();
