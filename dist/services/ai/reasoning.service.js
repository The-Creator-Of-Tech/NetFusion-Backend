"use strict";
/**
 * ReasoningService — Phase A5.3.4
 * ==================================
 * Orchestrates reasoning session lifecycle: creation, step management,
 * confidence calculation, risk scoring, evidence/finding linkage,
 * and decision recording.
 * Publishes events on reasoning state changes and completion.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReasoningService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const ai_1 = require("../../repositories/ai");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ReasoningService extends BaseService_1.BaseService {
    constructor(reasoningRepo = ai_1.reasoningRepository) {
        super();
        this.reasoningRepo = reasoningRepo;
    }
    // ── Create ──────────────────────────────────────────────────────────────────
    async createSession(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        this.validateUuid(data.investigationId, 'investigationId');
        if (data.userId)
            this.validateUuid(data.userId, 'userId');
        const runInTx = async (transaction) => {
            const session = await this.reasoningRepo.create(data, transaction);
            await EventPublisher_1.eventPublisher.publish('ReasoningSessionCreated', { session });
            return session;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Lifecycle transitions ────────────────────────────────────────────────────
    async completeSession(id, decision, actor, tx) {
        this.validateUuid(id, 'reasoningId');
        const runInTx = async (transaction) => {
            const existing = await this.reasoningRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Reasoning session "${id}" not found.`);
            }
            const confidence = await this.reasoningRepo.calculateConfidence(id, transaction);
            const updated = await this.reasoningRepo.update(id, { status: 'COMPLETED', decision, overallConfidence: confidence, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('ReasoningSessionCompleted', { session: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async failSession(id, actor, tx) {
        return this._transition(id, 'FAILED', actor, 'ReasoningSessionFailed', tx);
    }
    async cancelSession(id, actor, tx) {
        return this._transition(id, 'FAILED', actor, 'ReasoningSessionCancelled', tx);
    }
    // ── Step management ──────────────────────────────────────────────────────────
    async addStep(reasoningId, data, tx) {
        this.validateUuid(reasoningId, 'reasoningId');
        this.validateRequired(data, ['stepNumber', 'stage', 'inputSummary', 'outputSummary', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const session = await this.reasoningRepo.findById(reasoningId, transaction);
            if (!session || session.deletedAt) {
                throw new Error(`Reasoning session "${reasoningId}" not found.`);
            }
            const client = transaction || prisma_1.default;
            const step = await client.reasoningStep.create({
                data: {
                    reasoningId,
                    stepNumber: data.stepNumber,
                    stage: data.stage,
                    inputSummary: data.inputSummary,
                    outputSummary: data.outputSummary,
                    confidence: Math.max(0.0, Math.min(1.0, data.confidence ?? 0.0)),
                    evidenceIds: data.evidenceIds ?? [],
                    findingIds: data.findingIds ?? [],
                    alertIds: data.alertIds ?? [],
                    relationshipIds: data.relationshipIds ?? [],
                    timelineEventIds: data.timelineEventIds ?? [],
                    metadata: data.metadata ?? null,
                    createdBy: data.createdBy,
                    updatedBy: data.updatedBy,
                },
            });
            // Recalculate overall confidence
            const newConfidence = await this.reasoningRepo.calculateConfidence(reasoningId, transaction);
            await this.reasoningRepo.update(reasoningId, { overallConfidence: newConfidence, updatedBy: data.updatedBy }, transaction);
            await EventPublisher_1.eventPublisher.publish('ReasoningStepAdded', { reasoningId, step });
            return step;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateStep(stepId, data, tx) {
        this.validateUuid(stepId, 'stepId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.reasoningStep.findUnique({ where: { id: stepId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ReasoningStep "${stepId}" not found.`);
            }
            const updated = await client.reasoningStep.update({
                where: { id: stepId },
                data: {
                    ...data,
                    updatedAt: new Date(),
                    version: (existing.version ?? 1) + 1,
                },
            });
            await EventPublisher_1.eventPublisher.publish('ReasoningStepUpdated', { step: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Risk scoring ─────────────────────────────────────────────────────────────
    async calculateOverallRisk(reasoningId, tx) {
        this.validateUuid(reasoningId, 'reasoningId');
        const runInTx = async (transaction) => {
            const steps = await this.reasoningRepo.findSteps(reasoningId, transaction);
            if (steps.length === 0)
                return 0.0;
            // Risk = average of (1 - confidence) across steps, scaled 0–1
            const riskSum = steps.reduce((sum, s) => sum + (1.0 - Math.min(1.0, Math.max(0.0, s.confidence ?? 0.0))), 0.0);
            const risk = riskSum / steps.length;
            await this.reasoningRepo.update(reasoningId, { overallRisk: risk, updatedBy: 'system' }, transaction);
            return risk;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async calculateConfidence(reasoningId, tx) {
        this.validateUuid(reasoningId, 'reasoningId');
        return this.reasoningRepo.calculateConfidence(reasoningId, tx);
    }
    // ── Evidence/Finding linkage ─────────────────────────────────────────────────
    async linkEvidenceToStep(stepId, evidenceId, actor, tx) {
        this.validateUuid(stepId, 'stepId');
        this.validateUuid(evidenceId, 'evidenceId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.reasoningStep.findUnique({ where: { id: stepId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ReasoningStep "${stepId}" not found.`);
            }
            const evidenceIds = Array.from(new Set([...(existing.evidenceIds ?? []), evidenceId]));
            const updated = await client.reasoningStep.update({
                where: { id: stepId },
                data: { evidenceIds, updatedBy: actor, version: (existing.version ?? 1) + 1 },
            });
            await EventPublisher_1.eventPublisher.publish('EvidenceLinkedToStep', { stepId, evidenceId });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async linkFindingToStep(stepId, findingId, actor, tx) {
        this.validateUuid(stepId, 'stepId');
        this.validateUuid(findingId, 'findingId');
        const runInTx = async (transaction) => {
            const client = transaction || prisma_1.default;
            const existing = await client.reasoningStep.findUnique({ where: { id: stepId } });
            if (!existing || existing.deletedAt) {
                throw new Error(`ReasoningStep "${stepId}" not found.`);
            }
            const findingIds = Array.from(new Set([...(existing.findingIds ?? []), findingId]));
            const updated = await client.reasoningStep.update({
                where: { id: stepId },
                data: { findingIds, updatedBy: actor, version: (existing.version ?? 1) + 1 },
            });
            await EventPublisher_1.eventPublisher.publish('FindingLinkedToStep', { stepId, findingId });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Statistics ───────────────────────────────────────────────────────────────
    async getSessionStats(reasoningId, tx) {
        this.validateUuid(reasoningId, 'reasoningId');
        const runInTx = async (transaction) => {
            const session = await this.reasoningRepo.findById(reasoningId, transaction);
            if (!session || session.deletedAt) {
                throw new Error(`Reasoning session "${reasoningId}" not found.`);
            }
            const steps = await this.reasoningRepo.findSteps(reasoningId, transaction);
            const totalEvidenceLinks = steps.reduce((sum, s) => sum + (s.evidenceIds?.length ?? 0), 0);
            const totalFindingLinks = steps.reduce((sum, s) => sum + (s.findingIds?.length ?? 0), 0);
            const totalAlertLinks = steps.reduce((sum, s) => sum + (s.alertIds?.length ?? 0), 0);
            return {
                stepCount: steps.length,
                overallConfidence: session.overallConfidence ?? 0.0,
                overallRisk: session.overallRisk ?? 0.0,
                totalEvidenceLinks,
                totalFindingLinks,
                totalAlertLinks,
            };
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Read helpers ─────────────────────────────────────────────────────────────
    async findSession(id, tx) {
        this.validateUuid(id, 'reasoningId');
        return this.reasoningRepo.findById(id, tx);
    }
    async findByStatus(status, tx) {
        return this.reasoningRepo.findByStatus(status, tx);
    }
    async findCompleted(tx) {
        return this.reasoningRepo.findCompleted(tx);
    }
    async findSteps(reasoningId, tx) {
        this.validateUuid(reasoningId, 'reasoningId');
        return this.reasoningRepo.findSteps(reasoningId, tx);
    }
    // ── Soft delete ──────────────────────────────────────────────────────────────
    async deleteSession(id, actor, tx) {
        this.validateUuid(id, 'reasoningId');
        const runInTx = async (transaction) => {
            const existing = await this.reasoningRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Reasoning session "${id}" not found.`);
            }
            await this.reasoningRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('ReasoningSessionDeleted', { reasoningId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Internal ─────────────────────────────────────────────────────────────────
    async _transition(id, status, actor, event, tx) {
        this.validateUuid(id, 'reasoningId');
        const runInTx = async (transaction) => {
            const existing = await this.reasoningRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Reasoning session "${id}" not found.`);
            }
            const updated = await this.reasoningRepo.update(id, { status, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish(event, { session: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ReasoningService = ReasoningService;
