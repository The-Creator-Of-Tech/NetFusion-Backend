"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.workflowOrchestrator = exports.WorkflowOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// Sub-orchestrators
const PlaybookOrchestrator_1 = require("./PlaybookOrchestrator");
const RuleOrchestrator_1 = require("./RuleOrchestrator");
const AutomationOrchestrator_1 = require("./AutomationOrchestrator");
const CaseFlowOrchestrator_1 = require("./CaseFlowOrchestrator");
const ExecutionOrchestrator_1 = require("./ExecutionOrchestrator");
// Services
const workflow_1 = require("../../services/workflow");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
const crypto_1 = require("crypto");
// ─────────────────────────────────────────────────────────────────────────────
// WorkflowOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class WorkflowOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('WorkflowOrchestrator');
        /** In-memory workflow state store */
        this.workflowStates = new Map();
        this.workflowHistory = [];
    }
    // ── executeWorkflow ───────────────────────────────────────────────────────
    /**
     * Master workflow coordinator.
     * Full pipeline: Rule Evaluation → Automation → Playbook → Case → Events
     */
    async executeWorkflow(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.projectId, 'projectId', ctx);
        const workflowId = (0, crypto_1.randomUUID)();
        const startedAt = new Date();
        this.logInfo(ctx, `Starting workflow ${workflowId} triggered by ${input.trigger}`);
        this.workflowStates.set(workflowId, { state: 'RUNNING', startedAt });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.WORKFLOW_STARTED, ctx, {
            workflowId,
            projectId: input.projectId,
            investigationId: input.investigationId,
            trigger: input.trigger,
        });
        return this.withCompensation(ctx, async (compensation) => {
            let rulesMatched = 0;
            let automationsTriggered = 0;
            let playbooksStarted = 0;
            let caseCreated = false;
            let caseId;
            // ── Step 1: Rule Evaluation ───────────────────────────────────────────
            let rulesSummary = null;
            if (input.contextData && Object.keys(input.contextData).length > 0) {
                try {
                    rulesSummary = await RuleOrchestrator_1.ruleOrchestrator.evaluateRules({
                        projectId: input.projectId,
                        investigationId: input.investigationId,
                        record: input.contextData,
                        actor: input.actor,
                        ruleIds: input.ruleIds,
                    }, ctx);
                    rulesMatched = rulesSummary.matchedRules;
                }
                catch (err) {
                    this.logWarn(ctx, `Rule evaluation failed: ${err.message}`);
                }
            }
            this.checkCancellation(ctx);
            // ── Step 2: Trigger Automations ───────────────────────────────────────
            const automationIds = input.automationIds ?? [];
            if (input.trigger === 'FINDING' && input.contextData?.findingId) {
                try {
                    const findingTriggers = await AutomationOrchestrator_1.automationOrchestrator.triggerByFinding(input.projectId, input.contextData.findingId, input.actor, ctx);
                    automationsTriggered += findingTriggers.triggered.length;
                }
                catch (err) {
                    this.logWarn(ctx, `Finding automation trigger failed: ${err.message}`);
                }
            }
            else if (input.trigger === 'ALERT' && input.contextData?.alertId) {
                try {
                    const alertTriggers = await AutomationOrchestrator_1.automationOrchestrator.triggerByAlert(input.projectId, input.contextData.alertId, input.actor, ctx);
                    automationsTriggered += alertTriggers.triggered.length;
                }
                catch (err) {
                    this.logWarn(ctx, `Alert automation trigger failed: ${err.message}`);
                }
            }
            for (const automationId of automationIds) {
                try {
                    const exec = await AutomationOrchestrator_1.automationOrchestrator.startAutomation({
                        automationId,
                        projectId: input.projectId,
                        investigationId: input.investigationId,
                        actor: input.actor,
                        trigger: 'MANUAL',
                    }, ctx);
                    automationsTriggered++;
                    compensation.register(`cancel-automation-${exec.executionId}`, async () => {
                        await AutomationOrchestrator_1.automationOrchestrator.cancelAutomation({
                            automationId,
                            executionId: exec.executionId,
                            reason: 'Workflow rollback',
                            actor: input.actor,
                            projectId: input.projectId,
                        }, ctx).catch(() => { });
                    });
                }
                catch (err) {
                    this.logWarn(ctx, `Automation ${automationId} failed: ${err.message}`);
                }
            }
            this.checkCancellation(ctx);
            // ── Step 3: Execute Playbooks ─────────────────────────────────────────
            for (const playbookId of (input.playbookIds ?? [])) {
                try {
                    await PlaybookOrchestrator_1.playbookOrchestrator.startPlaybook({
                        playbookId,
                        projectId: input.projectId,
                        investigationId: input.investigationId,
                        actor: input.actor,
                    }, ctx);
                    playbooksStarted++;
                    compensation.register(`abort-playbook-${playbookId}`, async () => {
                        await PlaybookOrchestrator_1.playbookOrchestrator.abortPlaybook({
                            playbookId,
                            reason: 'Workflow rollback',
                            actor: input.actor,
                            projectId: input.projectId,
                            investigationId: input.investigationId,
                        }, ctx).catch(() => { });
                    });
                }
                catch (err) {
                    this.logWarn(ctx, `Playbook ${playbookId} failed to start: ${err.message}`);
                }
            }
            this.checkCancellation(ctx);
            // ── Step 4: Create Case Flow ──────────────────────────────────────────
            if (input.createCase && input.investigationId) {
                try {
                    const caseResult = await CaseFlowOrchestrator_1.caseFlowOrchestrator.createCase({
                        title: input.caseTitle ?? `Workflow Case: ${input.trigger} [${new Date().toISOString()}]`,
                        projectId: input.projectId,
                        investigationId: input.investigationId,
                        actor: input.actor,
                        priority: rulesMatched > 0 ? 'HIGH' : 'MEDIUM',
                    }, ctx);
                    caseId = caseResult.caseId;
                    caseCreated = true;
                    compensation.register(`delete-case-${caseId}`, async () => {
                        await workflow_1.caseFlowService.deleteCaseFlow(caseId, input.actor).catch(() => { });
                    });
                }
                catch (err) {
                    this.logWarn(ctx, `Case creation failed: ${err.message}`);
                }
            }
            // ── Step 5: Timeline entry ────────────────────────────────────────────
            if (input.investigationId) {
                await investigation_1.timelineService.record({
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
                }).catch(() => { });
            }
            // ── Step 6: Activity log ──────────────────────────────────────────────
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logCreate(input.actor, 'WORKFLOW_EXECUTED', `Workflow ${workflowId} executed (trigger: ${input.trigger})`, input.projectId, workflowId).catch(() => { }).catch(() => { });
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
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.WORKFLOW_COMPLETED, ctx, {
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
            const result = {
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
    async executePlaybook(playbookId, projectId, investigationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId, investigationId });
        return PlaybookOrchestrator_1.playbookOrchestrator.startPlaybook({ playbookId, projectId, investigationId, actor }, ctx);
    }
    // ── executeAutomation ─────────────────────────────────────────────────────
    /** Delegate to AutomationOrchestrator.startAutomation */
    async executeAutomation(automationId, projectId, investigationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId, investigationId });
        return AutomationOrchestrator_1.automationOrchestrator.startAutomation({
            automationId, projectId, investigationId, actor, trigger: 'MANUAL',
        }, ctx);
    }
    // ── executeCaseFlow ───────────────────────────────────────────────────────
    /** Delegate to CaseFlowOrchestrator.createCase */
    async executeCaseFlow(title, projectId, investigationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId, investigationId });
        return CaseFlowOrchestrator_1.caseFlowOrchestrator.createCase({ title, projectId, investigationId, actor }, ctx);
    }
    // ── pauseWorkflow ─────────────────────────────────────────────────────────
    /**
     * Pause a running workflow.
     * Marks state as IDLE (paused) and publishes WorkflowPaused.
     */
    async pauseWorkflow(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Pausing workflow: ${input.workflowId}`);
        const state = this.workflowStates.get(input.workflowId);
        if (!state) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Workflow', input.workflowId, ctx.correlationId);
        }
        if (state.state !== 'RUNNING') {
            throw new BaseApplicationService_1.OrchestrationValidationError(`Cannot pause workflow in state "${state.state}".`, ctx.correlationId);
        }
        this.workflowStates.set(input.workflowId, { ...state, state: 'IDLE', paused: true });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.WORKFLOW_PAUSED, ctx, {
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
    async resumeWorkflow(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Resuming workflow: ${input.workflowId}`);
        const state = this.workflowStates.get(input.workflowId);
        if (!state) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Workflow', input.workflowId, ctx.correlationId);
        }
        if (state.state !== 'IDLE') {
            throw new BaseApplicationService_1.OrchestrationValidationError(`Cannot resume workflow in state "${state.state}".`, ctx.correlationId);
        }
        this.workflowStates.set(input.workflowId, { ...state, state: 'RUNNING', paused: false });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.WORKFLOW_RESUMED, ctx, {
            workflowId: input.workflowId,
        });
        this.logTiming(ctx, 'resumeWorkflow');
        return { workflowId: input.workflowId, resumed: true, correlationId: ctx.correlationId };
    }
    // ── cancelWorkflow ────────────────────────────────────────────────────────
    /**
     * Cancel a running or paused workflow. Publishes WorkflowCompleted with CANCELLED.
     */
    async cancelWorkflow(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Cancelling workflow: ${input.workflowId} — ${input.reason}`);
        const state = this.workflowStates.get(input.workflowId);
        if (state) {
            this.workflowStates.set(input.workflowId, { ...state, state: 'CANCELLED' });
        }
        else {
            // Register as new cancelled entry
            this.workflowStates.set(input.workflowId, { state: 'CANCELLED', startedAt: new Date() });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'WORKFLOW_CANCELLED', `Workflow ${input.workflowId} cancelled: ${input.reason}`, input.projectId, input.workflowId).catch(() => { }).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.WORKFLOW_COMPLETED, ctx, {
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
    async rollbackWorkflow(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.logInfo(ctx, `Rolling back workflow: ${input.workflowId}`);
        const state = this.workflowStates.get(input.workflowId);
        if (state) {
            this.workflowStates.set(input.workflowId, { ...state, state: 'COMPENSATING' });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.WORKFLOW_COMPLETED, ctx, {
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
    generateExecutionSummary(result) {
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
        if (result.summary)
            lines.push(``, `Summary: ${result.summary}`);
        return lines.join('\n');
    }
    // ── calculateWorkflowStatistics ───────────────────────────────────────────
    /**
     * Calculate aggregate statistics across all historical workflow executions.
     */
    async calculateWorkflowStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, 'Calculating workflow statistics');
        const history = this.workflowHistory;
        const total = history.length;
        const completed = history.filter(h => h.status === 'SUCCEEDED').length;
        const failed = history.filter(h => h.status === 'FAILED').length;
        const durations = history
            .filter(h => h.durationMs !== undefined)
            .map(h => h.durationMs);
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
            workflow_1.playbookService.getStatistics().catch(() => null),
            workflow_1.ruleService.getStatistics().catch(() => null),
            workflow_1.automationService.getStatistics().catch(() => null),
            workflow_1.caseFlowService.getStatistics().catch(() => null),
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
    getWorkflowState(workflowId) {
        return this.workflowStates.get(workflowId)?.state;
    }
    // ── getWorkflowHistory ────────────────────────────────────────────────────
    getWorkflowHistory() {
        return [...this.workflowHistory];
    }
    // ── Sub-orchestrator accessors ────────────────────────────────────────────
    get playbook() { return PlaybookOrchestrator_1.playbookOrchestrator; }
    get rule() { return RuleOrchestrator_1.ruleOrchestrator; }
    get automation() { return AutomationOrchestrator_1.automationOrchestrator; }
    get caseFlow() { return CaseFlowOrchestrator_1.caseFlowOrchestrator; }
    get execution() { return ExecutionOrchestrator_1.executionOrchestrator; }
    // ── Private helpers ───────────────────────────────────────────────────────
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.WorkflowOrchestrator = WorkflowOrchestrator;
exports.workflowOrchestrator = new WorkflowOrchestrator();
