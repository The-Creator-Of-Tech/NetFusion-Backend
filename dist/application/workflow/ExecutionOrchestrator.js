"use strict";
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
exports.executionOrchestrator = exports.ExecutionOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
// ─────────────────────────────────────────────────────────────────────────────
// ExecutionOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class ExecutionOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ExecutionOrchestrator');
        /** In-memory tracking store (per process; fine for orchestration layer) */
        this.executions = new Map();
        this.metricsStore = new Map();
        this.logStore = new Map();
        this.errorStore = new Map();
    }
    // ── trackExecution ────────────────────────────────────────────────────────
    /**
     * Register an execution for tracking across its lifecycle.
     * Publishes ExecutionSucceeded or ExecutionFailed based on status.
     */
    async trackExecution(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.entityId, 'entityId', ctx);
        this.logInfo(ctx, `Tracking execution: ${input.executionId} for ${input.entityType}:${input.entityId}`);
        const record = {
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
        await this.publishEvent(ApplicationEvents_1.APP_EVENTS.EXECUTION_TRACKED, ctx, {
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
    async recordMetrics(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.validateUuid(input.entityId, 'entityId', ctx);
        this.logInfo(ctx, `Recording metrics for execution: ${input.executionId}`);
        const stepsCompleted = input.metrics.stepsCompleted ?? 0;
        const stepsFailed = input.metrics.stepsFailed ?? 0;
        const stepsSkipped = input.metrics.stepsSkipped ?? 0;
        const totalSteps = stepsCompleted + stepsFailed + stepsSkipped;
        const successRate = totalSteps > 0 ? Math.round((stepsCompleted / totalSteps) * 100) : 100;
        const metrics = {
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
    async calculateDuration(executionId, entityType, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Calculating duration for execution: ${executionId}`);
        let startedAt;
        let completedAt;
        try {
            if (entityType === 'AUTOMATION') {
                const prismaClient = (await Promise.resolve().then(() => __importStar(require('../../lib/prisma')))).default;
                const exec = await prismaClient.automationExecution.findFirst({
                    where: { id: executionId, deletedAt: null },
                });
                startedAt = exec?.startedAt ?? undefined;
                completedAt = exec?.completedAt ?? undefined;
            }
            else if (entityType === 'CASE_FLOW') {
                const prismaClient = (await Promise.resolve().then(() => __importStar(require('../../lib/prisma')))).default;
                const exec = await prismaClient.caseFlowExecution.findFirst({
                    where: { id: executionId, deletedAt: null },
                });
                startedAt = exec?.startedAt ?? undefined;
                completedAt = exec?.completedAt ?? undefined;
            }
        }
        catch {
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
    async collectLogs(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
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
    async collectErrors(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Collecting errors for execution: ${input.executionId}`);
        const errors = this.errorStore.get(input.executionId) ?? [];
        this.logTiming(ctx, 'collectErrors');
        return errors;
    }
    // ── addLog ────────────────────────────────────────────────────────────────
    /**
     * Append a log entry to an execution's log stream.
     */
    addLog(executionId, log) {
        const existing = this.logStore.get(executionId) ?? [];
        existing.push(log);
        this.logStore.set(executionId, existing);
    }
    // ── addError ──────────────────────────────────────────────────────────────
    /**
     * Record an error for an execution.
     */
    addError(executionId, error) {
        const existing = this.errorStore.get(executionId) ?? [];
        existing.push(error);
        this.errorStore.set(executionId, existing);
    }
    // ── buildExecutionReport ──────────────────────────────────────────────────
    /**
     * Build a comprehensive execution report combining metrics, logs, errors, duration.
     */
    async buildExecutionReport(executionId, entityType, entityId, projectId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor, { projectId });
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
        await this.publishEvent(hasErrors ? ApplicationEvents_1.APP_EVENTS.EXECUTION_FAILED : ApplicationEvents_1.APP_EVENTS.EXECUTION_SUCCEEDED, ctx, {
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
    getTrackedExecutions() {
        return Array.from(this.executions.values());
    }
    // ── clearExecution ────────────────────────────────────────────────────────
    /**
     * Clear a specific execution from the tracking store (housekeeping).
     */
    clearExecution(executionId) {
        this.executions.delete(executionId);
        this.metricsStore.delete(executionId);
        this.logStore.delete(executionId);
        this.errorStore.delete(executionId);
    }
}
exports.ExecutionOrchestrator = ExecutionOrchestrator;
exports.executionOrchestrator = new ExecutionOrchestrator();
