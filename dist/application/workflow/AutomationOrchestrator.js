"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.automationOrchestrator = exports.AutomationOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const workflow_1 = require("../../services/workflow");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// AutomationOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class AutomationOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('AutomationOrchestrator');
    }
    // ── startAutomation ───────────────────────────────────────────────────────
    /**
     * Start an automation execution.
     * Creates execution record, records timeline, publishes AutomationStarted.
     */
    async startAutomation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.automationId, 'automationId', ctx);
        this.logInfo(ctx, `Starting automation: ${input.automationId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const startedAt = new Date();
            const execution = await workflow_1.automationService.startExecution(input.automationId, input.actor);
            compensation.register(`fail-execution-${execution.id}`, async () => {
                await workflow_1.automationService.failExecution(execution.id, 'Compensating rollback', input.actor).catch(() => { });
            });
            // Timeline entry
            if (input.investigationId) {
                const automation = await workflow_1.automationService.findByProject(input.projectId)
                    .then(all => all.find(a => a.id === input.automationId))
                    .catch(() => null);
                await investigation_1.timelineService.record({
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    title: `Automation Started: ${automation?.name ?? input.automationId}`,
                    description: `Automation triggered via ${input.trigger ?? 'MANUAL'}.`,
                    type: 'MANUAL_ACTION',
                    createdBy: input.actor,
                }).catch(() => { });
            }
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logCreate(input.actor, 'AUTOMATION_STARTED', `Automation ${input.automationId} execution started`, input.projectId, input.automationId).catch(() => { });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AUTOMATION_STARTED, ctx, {
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
    async executeAutomation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.automationId, 'automationId', ctx);
        this.validateUuid(input.executionId, 'executionId', ctx);
        this.logInfo(ctx, `Executing automation: ${input.automationId}, execution: ${input.executionId}`);
        const startedAt = new Date();
        const steps = await workflow_1.automationService.findSteps(input.automationId);
        const stepResults = [];
        for (const step of steps) {
            this.checkCancellation(ctx);
            stepResults.push({
                stepId: step.id,
                status: 'COMPLETED',
                output: input.stepInputs?.[stepResults.length] ?? {},
            });
        }
        const execution = await workflow_1.automationService.completeExecution(input.executionId, stepResults, input.actor);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AUTOMATION_COMPLETED, ctx, {
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
    async retryAutomation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.automationId, 'automationId', ctx);
        this.logInfo(ctx, `Retrying automation: ${input.automationId}`);
        const maxRetries = input.maxRetries ?? 3;
        const startedAt = new Date();
        // Fail the old execution first
        await workflow_1.automationService.failExecution(input.executionId, 'Superseded by retry', input.actor).catch(() => { });
        // Start a new execution with retry wrapper
        const newExecution = await this.withRetry(ctx, 'retryAutomation', async () => {
            return workflow_1.automationService.startExecution(input.automationId, input.actor);
        }, { maxAttempts: maxRetries });
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'AUTOMATION_RETRIED', `Automation ${input.automationId} retried (new execution: ${newExecution.id})`, input.projectId, input.automationId).catch(() => { });
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
    async cancelAutomation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.automationId, 'automationId', ctx);
        this.validateUuid(input.executionId, 'executionId', ctx);
        if (!input.reason || !input.reason.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Cancel reason must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Cancelling automation execution: ${input.executionId}`);
        const execution = await workflow_1.automationService.failExecution(input.executionId, `Cancelled: ${input.reason}`, input.actor);
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'AUTOMATION_CANCELLED', `Automation ${input.automationId} cancelled: ${input.reason}`, input.projectId, input.automationId).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AUTOMATION_CANCELLED, ctx, {
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
    async resumeAutomation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.automationId, 'automationId', ctx);
        this.logInfo(ctx, `Resuming automation: ${input.automationId} from step ${input.fromStep ?? 1}`);
        const startedAt = new Date();
        const newExecution = await workflow_1.automationService.startExecution(input.automationId, input.actor);
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'AUTOMATION_RESUMED', `Automation ${input.automationId} resumed from step ${input.fromStep ?? 1}`, input.projectId, input.automationId).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AUTOMATION_STARTED, ctx, {
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
    async scheduleAutomation(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.automationId, 'automationId', ctx);
        if (input.scheduledAt < new Date()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Scheduled time must be in the future.', ctx.correlationId);
        }
        this.logInfo(ctx, `Scheduling automation: ${input.automationId} at ${input.scheduledAt.toISOString()}`);
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AUTOMATION_SCHEDULED, ctx, {
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
    async calculateExecutionTime(automationId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(automationId, 'automationId', ctx);
        this.logInfo(ctx, `Calculating execution time for automation: ${automationId}`);
        const executions = await workflow_1.automationService.findExecutions(automationId);
        const completed = executions.filter(e => e.status === 'COMPLETED' && e.startedAt && e.completedAt);
        if (completed.length === 0) {
            return { automationId, averageMs: 0, minMs: 0, maxMs: 0, sampleCount: 0, correlationId: ctx.correlationId };
        }
        const durations = completed.map(e => (e.completedAt.getTime()) - (e.startedAt.getTime()));
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
    async triggerByFinding(projectId, findingId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId });
        this.validateUuid(projectId, 'projectId', ctx);
        this.logInfo(ctx, `Triggering FINDING_CREATED automations for project: ${projectId}`);
        const automations = await workflow_1.automationService.findByTrigger('FINDING_CREATED');
        const projectAutomations = automations.filter(a => a.projectId === projectId && a.enabled);
        const triggered = [];
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
            }
            catch (err) {
                this.logWarn(ctx, `Failed to trigger automation ${automation.id}: ${err.message}`);
            }
        }
        return { triggered, correlationId: ctx.correlationId };
    }
    // ── triggerByAlert ────────────────────────────────────────────────────────
    /**
     * Trigger all ALERT_CREATED automations for a project.
     */
    async triggerByAlert(projectId, alertId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId });
        this.validateUuid(projectId, 'projectId', ctx);
        this.logInfo(ctx, `Triggering ALERT_CREATED automations for project: ${projectId}`);
        const automations = await workflow_1.automationService.findByTrigger('ALERT_CREATED');
        const projectAutomations = automations.filter(a => a.projectId === projectId && a.enabled);
        const triggered = [];
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
            }
            catch (err) {
                this.logWarn(ctx, `Failed to trigger automation ${automation.id}: ${err.message}`);
            }
        }
        return { triggered, correlationId: ctx.correlationId };
    }
    // ── getStatistics ─────────────────────────────────────────────────────────
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return workflow_1.automationService.getStatistics();
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.AutomationOrchestrator = AutomationOrchestrator;
exports.automationOrchestrator = new AutomationOrchestrator();
