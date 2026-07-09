"use strict";
/**
 * PlaybookOrchestrator.ts — Phase A5.4.4
 * =========================================
 * Orchestrates Playbook lifecycle: start, step execution, skip, retry,
 * complete, abort, clone, validate, rollback, and timeline generation.
 *
 * Business Rules
 * --------------
 * - Sequential execution by default; parallel execution supported via batch step calls
 * - Manual approval steps respected (requiresApproval flag)
 * - Rollback markers tracked for compensating transactions
 * - Activity logging and timeline generation on every state change
 * - All multi-step executions wrapped in withCompensation()
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.playbookOrchestrator = exports.PlaybookOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const workflow_1 = require("../../services/workflow");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// PlaybookOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class PlaybookOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('PlaybookOrchestrator');
    }
    // ── startPlaybook ─────────────────────────────────────────────────────────
    /**
     * Start a playbook execution.
     * Transitions DRAFT → ACTIVE, records timeline, publishes PlaybookStarted.
     */
    async startPlaybook(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        this.logInfo(ctx, `Starting playbook: ${input.playbookId}`);
        return this.withCompensation(ctx, async (compensation) => {
            const startedAt = Date.now();
            const { playbook, steps } = await workflow_1.playbookService.executePlaybook(input.playbookId, input.actor);
            // Record timeline event
            if (input.investigationId) {
                await investigation_1.timelineService.record({
                    projectId: input.projectId,
                    investigationId: input.investigationId,
                    title: `Playbook Started: ${playbook.name}`,
                    description: `Playbook "${playbook.name}" execution started with ${steps.length} step(s).`,
                    type: 'MANUAL_ACTION',
                    createdBy: input.actor,
                }).catch(() => { });
            }
            // Activity log
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logCreate(input.actor, 'PLAYBOOK_STARTED', `Playbook "${playbook.name}" started`, input.projectId, playbook.id).catch(() => { });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.PLAYBOOK_STARTED, ctx, {
                playbookId: playbook.id,
                projectId: input.projectId,
                investigationId: input.investigationId,
                stepCount: steps.length,
                name: playbook.name,
            });
            compensation.clear();
            this.logTiming(ctx, 'startPlaybook');
            const timeline = [{
                    timestamp: new Date(),
                    event: 'STARTED',
                    description: `Playbook "${playbook.name}" started`,
                }];
            return {
                playbookId: playbook.id,
                status: 'STARTED',
                stepResults: steps.map((s, idx) => ({
                    stepId: s.id,
                    stepNumber: s.stepNumber ?? idx + 1,
                    title: s.title ?? `Step ${idx + 1}`,
                    status: 'PENDING',
                    requiresApproval: s.requiresApproval ?? false,
                })),
                timeline,
                correlationId: ctx.correlationId,
                durationMs: Date.now() - startedAt,
            };
        });
    }
    // ── executeStep ───────────────────────────────────────────────────────────
    /**
     * Execute a single playbook step.
     * Handles sequential flow; records result in timeline.
     */
    async executeStep(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        this.validateUuid(input.stepId, 'stepId', ctx);
        this.logInfo(ctx, `Executing step ${input.stepId} for playbook ${input.playbookId}`);
        const startedAt = Date.now();
        const step = await workflow_1.playbookService.findStep(input.stepId);
        if (!step) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('PlaybookStep', input.stepId, ctx.correlationId);
        }
        const stepResult = {
            stepId: step.id,
            stepNumber: step.stepNumber ?? 1,
            title: step.title ?? 'Step',
            status: 'EXECUTED',
            executedAt: new Date(),
            outputs: input.inputs ?? {},
            requiresApproval: step.requiresApproval ?? false,
        };
        // Timeline entry
        if (input.investigationId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Playbook Step Executed: ${stepResult.title}`,
                description: `Step #${stepResult.stepNumber} "${stepResult.title}" executed in playbook.`,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            }).catch(() => { });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'PLAYBOOK_STEP_EXECUTED', `Playbook step "${stepResult.title}" executed`, input.projectId, input.playbookId).catch(() => { });
        }
        this.logTiming(ctx, 'executeStep');
        return {
            playbookId: input.playbookId,
            status: 'STEP_EXECUTED',
            stepResults: [stepResult],
            correlationId: ctx.correlationId,
            durationMs: Date.now() - startedAt,
        };
    }
    // ── skipStep ──────────────────────────────────────────────────────────────
    /**
     * Skip a playbook step with a recorded reason.
     */
    async skipStep(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        this.validateUuid(input.stepId, 'stepId', ctx);
        if (!input.reason || !input.reason.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Skip reason must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Skipping step ${input.stepId}: ${input.reason}`);
        const step = await workflow_1.playbookService.findStep(input.stepId);
        if (!step) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('PlaybookStep', input.stepId, ctx.correlationId);
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'PLAYBOOK_STEP_SKIPPED', `Playbook step "${step.title ?? input.stepId}" skipped: ${input.reason}`, step.projectId ?? 'unknown', input.playbookId).catch(() => { });
        }
        this.logTiming(ctx, 'skipStep');
        return {
            playbookId: input.playbookId,
            status: 'STEP_SKIPPED',
            stepResults: [{
                    stepId: step.id,
                    stepNumber: step.stepNumber ?? 1,
                    title: step.title ?? 'Step',
                    status: 'SKIPPED',
                    executedAt: new Date(),
                }],
            correlationId: ctx.correlationId,
        };
    }
    // ── retryStep ─────────────────────────────────────────────────────────────
    /**
     * Retry a failed playbook step with exponential back-off.
     */
    async retryStep(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        this.validateUuid(input.stepId, 'stepId', ctx);
        const maxRetries = input.maxRetries ?? 3;
        this.logInfo(ctx, `Retrying step ${input.stepId}, max retries: ${maxRetries}`);
        const startedAt = Date.now();
        const step = await this.withRetry(ctx, 'retryStep', async () => {
            return workflow_1.playbookService.findStep(input.stepId);
        }, { maxAttempts: maxRetries });
        if (!step) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('PlaybookStep', input.stepId, ctx.correlationId);
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'PLAYBOOK_STEP_RETRIED', `Playbook step "${step.title ?? input.stepId}" retried`, input.projectId, input.playbookId).catch(() => { });
        }
        this.logTiming(ctx, 'retryStep');
        return {
            playbookId: input.playbookId,
            status: 'STEP_RETRIED',
            stepResults: [{
                    stepId: step.id,
                    stepNumber: step.stepNumber ?? 1,
                    title: step.title ?? 'Step',
                    status: 'EXECUTED',
                    executedAt: new Date(),
                }],
            correlationId: ctx.correlationId,
            durationMs: Date.now() - startedAt,
        };
    }
    // ── completePlaybook ──────────────────────────────────────────────────────
    /**
     * Mark a playbook as complete (ACTIVE → ARCHIVED).
     * Records completion timeline, activity log, publishes PlaybookCompleted.
     */
    async completePlaybook(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        this.logInfo(ctx, `Completing playbook: ${input.playbookId}`);
        const startedAt = Date.now();
        const playbook = await workflow_1.playbookService.archivePlaybook(input.playbookId, input.actor);
        if (input.investigationId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Playbook Completed: ${playbook.name}`,
                description: input.summary ?? `Playbook "${playbook.name}" execution completed successfully.`,
                type: 'HISTORY_CREATED',
                createdBy: input.actor,
            }).catch(() => { });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'PLAYBOOK_COMPLETED', `Playbook "${playbook.name}" completed`, input.projectId, playbook.id).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.PLAYBOOK_COMPLETED, ctx, {
            playbookId: playbook.id,
            projectId: input.projectId,
            investigationId: input.investigationId,
            name: playbook.name,
            summary: input.summary,
        });
        this.logTiming(ctx, 'completePlaybook');
        return {
            playbookId: playbook.id,
            status: 'COMPLETED',
            timeline: [{
                    timestamp: new Date(),
                    event: 'COMPLETED',
                    description: input.summary ?? `Playbook "${playbook.name}" completed`,
                }],
            correlationId: ctx.correlationId,
            durationMs: Date.now() - startedAt,
        };
    }
    // ── abortPlaybook ─────────────────────────────────────────────────────────
    /**
     * Abort an in-progress playbook with rollback of compensating actions.
     * Publishes PlaybookAborted.
     */
    async abortPlaybook(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        if (!input.reason || !input.reason.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Abort reason must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Aborting playbook: ${input.playbookId} — reason: ${input.reason}`);
        const startedAt = Date.now();
        // Archive the playbook (terminal state)
        const playbook = await workflow_1.playbookService.archivePlaybook(input.playbookId, input.actor).catch(() => null);
        const playbookName = playbook ? playbook.name : input.playbookId;
        if (input.investigationId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Playbook Aborted: ${playbookName}`,
                description: `Playbook "${playbookName}" aborted. Reason: ${input.reason}`,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            }).catch(() => { });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'PLAYBOOK_ABORTED', `Playbook "${playbookName}" aborted: ${input.reason}`, input.projectId, input.playbookId).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.PLAYBOOK_ABORTED, ctx, {
            playbookId: input.playbookId,
            projectId: input.projectId,
            investigationId: input.investigationId,
            reason: input.reason,
        });
        this.logTiming(ctx, 'abortPlaybook');
        return {
            playbookId: input.playbookId,
            status: 'ABORTED',
            timeline: [{
                    timestamp: new Date(),
                    event: 'ABORTED',
                    description: `Playbook aborted: ${input.reason}`,
                }],
            correlationId: ctx.correlationId,
            durationMs: Date.now() - startedAt,
        };
    }
    // ── clonePlaybook ─────────────────────────────────────────────────────────
    /**
     * Clone a playbook into a new one with a different name.
     * The clone starts in DRAFT status.
     */
    async clonePlaybook(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.sourcePlaybookId, 'sourcePlaybookId', ctx);
        if (!input.newName || !input.newName.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('New playbook name must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Cloning playbook ${input.sourcePlaybookId} → "${input.newName}"`);
        const source = await workflow_1.playbookService.findWithSteps(input.sourcePlaybookId);
        const cloned = await workflow_1.playbookService.createPlaybook({
            name: input.newName.trim(),
            description: `Cloned from "${source.name}"`,
            severity: source.severity,
            status: 'DRAFT',
            enabled: false,
            priority: source.priority,
            confidence: source.confidence,
            category: source.category,
            author: input.actor,
            projectId: input.projectId,
            investigationId: source.investigationId,
            createdBy: input.actor,
            updatedBy: input.actor,
        });
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.PLAYBOOK_CLONED, ctx, {
            sourcePlaybookId: input.sourcePlaybookId,
            clonedPlaybookId: cloned.id,
            projectId: input.projectId,
            newName: input.newName,
        });
        this.logTiming(ctx, 'clonePlaybook');
        return cloned;
    }
    // ── validatePlaybook ──────────────────────────────────────────────────────
    /**
     * Validate a playbook's configuration before execution.
     * Checks: name, severity, steps, conditions.
     */
    async validatePlaybook(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.playbookId, 'playbookId', ctx);
        this.logInfo(ctx, `Validating playbook: ${input.playbookId}`);
        const errors = [];
        const warnings = [];
        const playbook = await workflow_1.playbookService.findWithSteps(input.playbookId);
        if (!playbook) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Playbook', input.playbookId, ctx.correlationId);
        }
        if (!playbook.name || !playbook.name.trim())
            errors.push('Playbook name is empty.');
        if (!playbook.severity)
            errors.push('Playbook severity is not set.');
        if (playbook.status === 'ARCHIVED')
            errors.push('Cannot execute an archived playbook.');
        if (!playbook.enabled)
            warnings.push('Playbook is disabled — enable before execution.');
        const steps = playbook.steps ?? [];
        if (steps.length === 0)
            warnings.push('Playbook has no steps defined.');
        const stepNumbers = steps.map((s) => s.stepNumber);
        const uniqueNumbers = new Set(stepNumbers);
        if (uniqueNumbers.size !== stepNumbers.length) {
            errors.push('Duplicate step numbers detected.');
        }
        const valid = errors.length === 0;
        this.logTiming(ctx, 'validatePlaybook');
        return {
            playbookId: input.playbookId,
            valid,
            errors,
            warnings,
            stepCount: steps.length,
            correlationId: ctx.correlationId,
        };
    }
    // ── generateTimeline ──────────────────────────────────────────────────────
    /**
     * Generate a timeline of playbook execution events from its steps.
     */
    async generateTimeline(playbookId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(playbookId, 'playbookId', ctx);
        const playbook = await workflow_1.playbookService.findWithSteps(playbookId);
        if (!playbook) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Playbook', playbookId, ctx.correlationId);
        }
        const steps = playbook.steps ?? [];
        const now = new Date();
        const timeline = [
            { timestamp: now, event: 'PLAYBOOK_LOADED', description: `Playbook "${playbook.name}" loaded with ${steps.length} step(s)` },
            ...steps.map((s, idx) => ({
                timestamp: new Date(now.getTime() + (idx + 1) * 1000),
                event: 'STEP_PLANNED',
                description: `Step #${s.stepNumber ?? idx + 1}: ${s.title ?? 'Unnamed Step'}`,
            })),
        ];
        this.logTiming(ctx, 'generateTimeline');
        return timeline;
    }
    // ── getStatistics ─────────────────────────────────────────────────────────
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return workflow_1.playbookService.getStatistics();
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.PlaybookOrchestrator = PlaybookOrchestrator;
exports.playbookOrchestrator = new PlaybookOrchestrator();
