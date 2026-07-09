"use strict";
/**
 * ReasoningOrchestrator.ts — Phase A5.4.2
 * ==========================================
 * Responsible for:
 *  - Multi-step reasoning session management
 *  - Confidence aggregation across steps
 *  - Step execution with retry logic
 *  - Explanation generation from reasoning steps
 *  - Rollback on partial reasoning failure
 *
 * CONSTRAINT: No direct repository access. Service layer only.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.reasoningOrchestrator = exports.ReasoningOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const ai_1 = require("../../services/ai");
// ─────────────────────────────────────────────────────────────────────────────
// ReasoningOrchestrator
// ─────────────────────────────────────────────────────────────────────────────
class ReasoningOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('ReasoningOrchestrator');
    }
    // ── Run Reasoning Workflow ────────────────────────────────────────────────
    async runWorkflow(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateUuid(input.investigationId, 'investigationId', ctx);
        this.logInfo(ctx, `Running reasoning workflow: ${input.steps.length} steps`);
        return this.withCompensation(ctx, async (compensation) => {
            // 1. Create reasoning session
            const session = await ai_1.reasoningService.createSession({
                projectId: input.projectId,
                investigationId: input.investigationId,
                userId: input.userId ?? null,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            });
            compensation.register(`cancel-reasoning-${session.id}`, async () => {
                try {
                    await ai_1.reasoningService.failSession(session.id, input.actor);
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_REASONING_STARTED, ctx, {
                reasoningId: session.id,
                projectId: input.projectId,
                investigationId: input.investigationId,
            });
            // 2. Execute each step, with retry support
            const stepResults = [];
            let stepNumber = 1;
            for (const stepDef of input.steps) {
                this.checkCancellation(ctx);
                const stepResult = await this.executeStep(session.id, stepNumber, stepDef, input.actor, ctx);
                stepResults.push(stepResult);
                stepNumber++;
            }
            // 3. Aggregate confidence + risk
            const confidence = await ai_1.reasoningService.calculateConfidence(session.id);
            const risk = await ai_1.reasoningService.calculateOverallRisk(session.id);
            // 4. Derive decision
            const minThreshold = input.minConfidenceThreshold ?? 0.5;
            const belowThreshold = confidence < minThreshold;
            const decision = input.decision ?? this.deriveDecision(confidence, risk, belowThreshold);
            // 5. Complete session
            await ai_1.reasoningService.completeSession(session.id, decision, input.actor);
            // 6. Generate explanation
            const explanation = this.generateExplanation(stepResults, confidence, risk, decision);
            const stats = await ai_1.reasoningService.getSessionStats(session.id);
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.AI_REASONING_COMPLETED, ctx, {
                reasoningId: session.id,
                projectId: input.projectId,
                investigationId: input.investigationId,
                overallConfidence: stats.overallConfidence,
                overallRisk: risk,
                stepCount: stats.stepCount,
                decision,
            });
            this.logTiming(ctx, 'runWorkflow');
            compensation.clear();
            return {
                reasoningId: session.id,
                overallConfidence: stats.overallConfidence,
                overallRisk: risk,
                stepCount: stats.stepCount,
                decision,
                explanation,
                belowThreshold,
                correlationId: ctx.correlationId,
            };
        });
    }
    // ── Execute Single Step ───────────────────────────────────────────────────
    async executeStep(reasoningId, stepNumber, stepDef, actor, ctx) {
        this.logInfo(ctx, `Executing reasoning step ${stepNumber}: ${stepDef.stage}`);
        const retryOpts = stepDef.retryOptions ?? {
            maxAttempts: 2,
            initialDelayMs: 50,
        };
        return this.withRetry(ctx, `step-${stepNumber}-${stepDef.stage}`, async () => {
            let outputSummary;
            let confidence;
            if (stepDef.execute) {
                // Dynamic step — call executor function
                const result = await stepDef.execute();
                outputSummary = result.outputSummary;
                confidence = Math.max(0, Math.min(1, result.confidence));
            }
            else {
                // Static step — use provided values
                outputSummary = stepDef.outputSummary ?? `Step ${stepNumber} completed.`;
                confidence = Math.max(0, Math.min(1, stepDef.confidence ?? 0.5));
            }
            const step = await ai_1.reasoningService.addStep(reasoningId, {
                stepNumber,
                stage: stepDef.stage,
                inputSummary: stepDef.inputSummary,
                outputSummary,
                confidence,
                evidenceIds: stepDef.evidenceIds ?? [],
                findingIds: stepDef.findingIds ?? [],
                alertIds: stepDef.alertIds ?? [],
                createdBy: actor,
                updatedBy: actor,
            });
            return {
                stepId: step.id,
                stepNumber,
                stage: stepDef.stage,
                outputSummary,
                confidence,
            };
        }, retryOpts);
    }
    // ── Add Step to Existing Session ──────────────────────────────────────────
    async addStep(reasoningId, stepDef, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(reasoningId, 'reasoningId', ctx);
        const session = await ai_1.reasoningService.findSession(reasoningId);
        if (!session || session.deletedAt) {
            throw new BaseApplicationService_1.OrchestrationNotFoundError('Reasoning', reasoningId, ctx.correlationId);
        }
        return this.executeStep(reasoningId, stepDef.stepNumber, stepDef, actor, ctx);
    }
    // ── Get Reasoning Stats ───────────────────────────────────────────────────
    async getStats(reasoningId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.validateUuid(reasoningId, 'reasoningId', ctx);
        return ai_1.reasoningService.getSessionStats(reasoningId);
    }
    // ── Private Helpers ───────────────────────────────────────────────────────
    deriveDecision(confidence, risk, belowThreshold) {
        if (belowThreshold) {
            return `Low-confidence analysis (${(confidence * 100).toFixed(1)}%). Manual review recommended.`;
        }
        if (risk > 0.7) {
            return `High-risk indicators detected (risk: ${(risk * 100).toFixed(1)}%). Immediate investigation required.`;
        }
        if (risk > 0.4) {
            return `Moderate risk detected (risk: ${(risk * 100).toFixed(1)}%). Further analysis recommended.`;
        }
        return `Analysis complete. Confidence: ${(confidence * 100).toFixed(1)}%, Risk: ${(risk * 100).toFixed(1)}%.`;
    }
    generateExplanation(steps, confidence, risk, decision) {
        const lines = [
            `Reasoning completed with ${steps.length} step(s).`,
            `Overall confidence: ${(confidence * 100).toFixed(1)}%`,
            `Overall risk: ${(risk * 100).toFixed(1)}%`,
            '',
            'Step breakdown:',
        ];
        for (const step of steps) {
            lines.push(`  [${step.stepNumber}] ${step.stage}: "${step.outputSummary}" ` +
                `(confidence: ${(step.confidence * 100).toFixed(1)}%)`);
        }
        lines.push('', `Decision: ${decision}`);
        return lines.join('\n');
    }
}
exports.ReasoningOrchestrator = ReasoningOrchestrator;
exports.reasoningOrchestrator = new ReasoningOrchestrator();
