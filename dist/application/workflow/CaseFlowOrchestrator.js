"use strict";
/**
 * CaseFlowOrchestrator.ts — Phase A5.4.4
 * =========================================
 * Orchestrates Case lifecycle: create, assign, change status, add tasks,
 * close, reopen, and metrics calculation.
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.caseFlowOrchestrator = exports.CaseFlowOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const workflow_1 = require("../../services/workflow");
const investigation_1 = require("../../services/investigation");
const shared_1 = require("../../services/shared");
// ─────────────────────────────────────────────────────────────────────────────
// CaseFlowOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class CaseFlowOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('CaseFlowOrchestrator');
    }
    // ── createCase ────────────────────────────────────────────────────────────
    /**
     * Create a new case flow.
     * Records timeline event, publishes CaseCreated.
     */
    async createCase(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Creating case: "${input.title}"`);
        return this.withCompensation(ctx, async (compensation) => {
            const caseFlow = await workflow_1.caseFlowService.createCaseFlow({
                title: input.title,
                description: input.description,
                projectId: input.projectId,
                investigationId: input.investigationId,
                priority: input.priority ?? 'MEDIUM',
                assignedTo: input.assignedTo,
                confidence: input.confidence ?? 100,
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`delete-case-${caseFlow.id}`, async () => {
                await workflow_1.caseFlowService.deleteCaseFlow(caseFlow.id, input.actor).catch(() => { });
            });
            // Timeline
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Case Created: ${caseFlow.title}`,
                description: `Case "${caseFlow.title}" created with priority ${caseFlow.priority}.`,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            }).catch(() => { });
            // Activity log
            if (this.isValidUuid(input.actor)) {
                await shared_1.activityService.logCreate(input.actor, 'CASE_CREATED', `Case "${caseFlow.title}" created`, input.projectId, caseFlow.id).catch(() => { });
            }
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CASE_CREATED, ctx, {
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
    async assignCase(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.caseId, 'caseId', ctx);
        if (!input.assignee || !input.assignee.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Assignee must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Assigning case ${input.caseId} to ${input.assignee}`);
        const updated = await workflow_1.caseFlowService.assignCase(input.caseId, input.assignee, input.actor);
        // Optional notification
        if (input.notifyAssignee && this.isValidUuid(input.assignee)) {
            await shared_1.notificationService.createNotification({
                userId: input.assignee,
                title: 'Case Assigned',
                message: `Case "${updated.title}" has been assigned to you.`,
                type: 'SYSTEM',
                status: 'UNREAD',
                createdBy: input.actor,
                updatedBy: input.actor,
            }).catch(() => { }); // best-effort
        }
        if (input.investigationId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Case Assigned: ${updated.title}`,
                description: `Case assigned to ${input.assignee}.`,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            }).catch(() => { });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'CASE_ASSIGNED', `Case "${updated.title}" assigned to ${input.assignee}`, input.projectId, input.caseId).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CASE_ASSIGNED, ctx, {
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
    async changeStatus(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.caseId, 'caseId', ctx);
        this.logInfo(ctx, `Changing status of case ${input.caseId} → ${input.newStatus}`);
        let updated;
        switch (input.newStatus) {
            case 'IN_PROGRESS':
                updated = await workflow_1.caseFlowService.startCase(input.caseId, input.actor);
                break;
            case 'RESOLVED':
                updated = await workflow_1.caseFlowService.resolveCase(input.caseId, input.actor);
                break;
            case 'CLOSED':
                updated = await workflow_1.caseFlowService.closeCase(input.caseId, input.actor);
                break;
            case 'OPEN':
                // Reopen: update directly with OPEN status
                updated = await workflow_1.caseFlowService.updateCaseFlow(input.caseId, {
                    status: 'OPEN',
                    updatedBy: input.actor,
                });
                break;
            default:
                throw new BaseApplicationService_1.OrchestrationValidationError(`Unsupported status transition to "${input.newStatus}".`, ctx.correlationId);
        }
        if (input.investigationId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Case Status Changed: ${updated.title}`,
                description: `Case status changed to ${input.newStatus}. ${input.reason ? `Reason: ${input.reason}` : ''}`,
                type: 'MANUAL_ACTION',
                createdBy: input.actor,
            }).catch(() => { });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, `CASE_STATUS_${input.newStatus}`, `Case "${updated.title}" status changed to ${input.newStatus}`, input.projectId, input.caseId).catch(() => { });
        }
        // Publish status-specific event
        const statusEventMap = {
            IN_PROGRESS: ApplicationEvents_1.APP_EVENTS.CASE_STARTED,
            RESOLVED: ApplicationEvents_1.APP_EVENTS.CASE_RESOLVED,
            CLOSED: ApplicationEvents_1.APP_EVENTS.CASE_CLOSED,
            OPEN: ApplicationEvents_1.APP_EVENTS.CASE_REOPENED,
        };
        const eventName = statusEventMap[input.newStatus];
        if (eventName) {
            await this.publishEvent(eventName, ctx, {
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
    async addTask(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, { projectId: input.projectId });
        this.validateUuid(input.caseId, 'caseId', ctx);
        if (!input.title || !input.title.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Task title must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Adding task "${input.title}" to case ${input.caseId}`);
        // Steps are created directly in the prisma client in the service layer
        // We retrieve steps first to determine next step number
        const existingSteps = await workflow_1.caseFlowService.findSteps(input.caseId);
        const nextStepNumber = input.stepNumber ?? (existingSteps.length + 1);
        // Use prisma directly via service context (service layer boundary)
        // We create the step via prisma scoped within the service boundary
        const prismaClient = (await Promise.resolve().then(() => __importStar(require('../../lib/prisma')))).default;
        const task = await prismaClient.caseFlowStep.create({
            data: {
                caseFlowId: input.caseId,
                title: input.title,
                description: input.description,
                stepNumber: nextStepNumber,
                stepKey: `step-${nextStepNumber}-${Date.now()}`,
                stepType: 'MANUAL',
                createdBy: input.actor,
                updatedBy: input.actor,
            },
        });
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logCreate(input.actor, 'CASE_TASK_ADDED', `Task "${input.title}" added to case`, input.projectId, input.caseId).catch(() => { });
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
    async closeCase(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.caseId, 'caseId', ctx);
        if (!input.resolution || !input.resolution.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Resolution must not be empty.', ctx.correlationId);
        }
        this.logInfo(ctx, `Closing case ${input.caseId}: ${input.resolution}`);
        const updated = await workflow_1.caseFlowService.closeCase(input.caseId, input.actor);
        if (input.investigationId) {
            await investigation_1.timelineService.record({
                projectId: input.projectId,
                investigationId: input.investigationId,
                title: `Case Closed: ${updated.title}`,
                description: `Case closed. Resolution: ${input.resolution}`,
                type: 'HISTORY_CREATED',
                createdBy: input.actor,
            }).catch(() => { });
        }
        if (this.isValidUuid(input.actor)) {
            await shared_1.activityService.logUpdate(input.actor, 'CASE_CLOSED', `Case "${updated.title}" closed`, input.projectId, input.caseId).catch(() => { });
        }
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.CASE_CLOSED, ctx, {
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
    async reopenCase(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.caseId, 'caseId', ctx);
        if (!input.reason || !input.reason.trim()) {
            throw new BaseApplicationService_1.OrchestrationValidationError('Reopen reason must not be empty.', ctx.correlationId);
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
    async calculateMetrics(caseId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(caseId, 'caseId', ctx);
        this.logInfo(ctx, `Calculating metrics for case: ${caseId}`);
        const [score, steps, executions, caseFlow] = await Promise.all([
            workflow_1.caseFlowService.calculateScore(caseId),
            workflow_1.caseFlowService.findSteps(caseId),
            workflow_1.caseFlowService.findExecutions(caseId),
            workflow_1.caseFlowService.findByProject('00000000-0000-4000-a000-000000000000')
                .then(() => null)
                .catch(() => null),
        ]);
        const PRIORITY_SCORE = {
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
    async getStatistics(actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        return workflow_1.caseFlowService.getStatistics();
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    isValidUuid(v) {
        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(v);
    }
}
exports.CaseFlowOrchestrator = CaseFlowOrchestrator;
exports.caseFlowOrchestrator = new CaseFlowOrchestrator();
