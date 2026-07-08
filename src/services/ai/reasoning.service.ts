/**
 * ReasoningService — Phase A5.3.4
 * ==================================
 * Orchestrates reasoning session lifecycle: creation, step management,
 * confidence calculation, risk scoring, evidence/finding linkage,
 * and decision recording.
 * Publishes events on reasoning state changes and completion.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { reasoningRepository } from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  Reasoning,
  ReasoningStep,
  ReasoningStatus,
  Prisma,
} from '@prisma/client';

export class ReasoningService extends BaseService {
  constructor(
    private readonly reasoningRepo = reasoningRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createSession(
    data: Prisma.ReasoningUncheckedCreateInput,
    tx?: any,
  ): Promise<Reasoning> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'createdBy', 'updatedBy']);
    this.validateUuid(data.projectId, 'projectId');
    this.validateUuid(data.investigationId, 'investigationId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      const session = await this.reasoningRepo.create(data, transaction);
      await eventPublisher.publish('ReasoningSessionCreated', { session });
      return session;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async completeSession(id: string, decision: string, actor: string, tx?: any): Promise<Reasoning> {
    this.validateUuid(id, 'reasoningId');
    const runInTx = async (transaction: any) => {
      const existing = await this.reasoningRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Reasoning session "${id}" not found.`);
      }

      const confidence = await this.reasoningRepo.calculateConfidence(id, transaction);
      const updated = await this.reasoningRepo.update(
        id,
        { status: 'COMPLETED', decision, overallConfidence: confidence, updatedBy: actor },
        transaction,
      );

      await eventPublisher.publish('ReasoningSessionCompleted', { session: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async failSession(id: string, actor: string, tx?: any): Promise<Reasoning> {
    return this._transition(id, 'FAILED', actor, 'ReasoningSessionFailed', tx);
  }

  async cancelSession(id: string, actor: string, tx?: any): Promise<Reasoning> {
    return this._transition(id, 'FAILED', actor, 'ReasoningSessionCancelled', tx);
  }

  // ── Step management ──────────────────────────────────────────────────────────

  async addStep(
    reasoningId: string,
    data: {
      stepNumber: number;
      stage: string;
      inputSummary: string;
      outputSummary: string;
      confidence: number;
      evidenceIds?: string[];
      findingIds?: string[];
      alertIds?: string[];
      relationshipIds?: string[];
      timelineEventIds?: string[];
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<ReasoningStep> {
    this.validateUuid(reasoningId, 'reasoningId');
    this.validateRequired(data as any, ['stepNumber', 'stage', 'inputSummary', 'outputSummary', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const session = await this.reasoningRepo.findById(reasoningId, transaction);
      if (!session || session.deletedAt) {
        throw new Error(`Reasoning session "${reasoningId}" not found.`);
      }

      const client = transaction || prisma;
      const step: ReasoningStep = await client.reasoningStep.create({
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
      await this.reasoningRepo.update(
        reasoningId,
        { overallConfidence: newConfidence, updatedBy: data.updatedBy },
        transaction,
      );

      await eventPublisher.publish('ReasoningStepAdded', { reasoningId, step });
      return step;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateStep(
    stepId: string,
    data: Partial<Prisma.ReasoningStepUncheckedUpdateInput>,
    tx?: any,
  ): Promise<ReasoningStep> {
    this.validateUuid(stepId, 'stepId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: ReasoningStep | null = await client.reasoningStep.findUnique({ where: { id: stepId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`ReasoningStep "${stepId}" not found.`);
      }

      const updated: ReasoningStep = await client.reasoningStep.update({
        where: { id: stepId },
        data: {
          ...data,
          updatedAt: new Date(),
          version: (existing.version ?? 1) + 1,
        },
      });

      await eventPublisher.publish('ReasoningStepUpdated', { step: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Risk scoring ─────────────────────────────────────────────────────────────

  async calculateOverallRisk(reasoningId: string, tx?: any): Promise<number> {
    this.validateUuid(reasoningId, 'reasoningId');
    const runInTx = async (transaction: any) => {
      const steps = await this.reasoningRepo.findSteps(reasoningId, transaction);
      if (steps.length === 0) return 0.0;

      // Risk = average of (1 - confidence) across steps, scaled 0–1
      const riskSum = steps.reduce((sum, s) => sum + (1.0 - Math.min(1.0, Math.max(0.0, s.confidence ?? 0.0))), 0.0);
      const risk = riskSum / steps.length;

      await this.reasoningRepo.update(reasoningId, { overallRisk: risk, updatedBy: 'system' }, transaction);
      return risk;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async calculateConfidence(reasoningId: string, tx?: any): Promise<number> {
    this.validateUuid(reasoningId, 'reasoningId');
    return this.reasoningRepo.calculateConfidence(reasoningId, tx);
  }

  // ── Evidence/Finding linkage ─────────────────────────────────────────────────

  async linkEvidenceToStep(stepId: string, evidenceId: string, actor: string, tx?: any): Promise<ReasoningStep> {
    this.validateUuid(stepId, 'stepId');
    this.validateUuid(evidenceId, 'evidenceId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: ReasoningStep | null = await client.reasoningStep.findUnique({ where: { id: stepId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`ReasoningStep "${stepId}" not found.`);
      }

      const evidenceIds = Array.from(new Set([...(existing.evidenceIds ?? []), evidenceId]));
      const updated: ReasoningStep = await client.reasoningStep.update({
        where: { id: stepId },
        data: { evidenceIds, updatedBy: actor, version: (existing.version ?? 1) + 1 },
      });

      await eventPublisher.publish('EvidenceLinkedToStep', { stepId, evidenceId });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async linkFindingToStep(stepId: string, findingId: string, actor: string, tx?: any): Promise<ReasoningStep> {
    this.validateUuid(stepId, 'stepId');
    this.validateUuid(findingId, 'findingId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: ReasoningStep | null = await client.reasoningStep.findUnique({ where: { id: stepId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`ReasoningStep "${stepId}" not found.`);
      }

      const findingIds = Array.from(new Set([...(existing.findingIds ?? []), findingId]));
      const updated: ReasoningStep = await client.reasoningStep.update({
        where: { id: stepId },
        data: { findingIds, updatedBy: actor, version: (existing.version ?? 1) + 1 },
      });

      await eventPublisher.publish('FindingLinkedToStep', { stepId, findingId });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Statistics ───────────────────────────────────────────────────────────────

  async getSessionStats(reasoningId: string, tx?: any): Promise<{
    stepCount: number;
    overallConfidence: number;
    overallRisk: number;
    totalEvidenceLinks: number;
    totalFindingLinks: number;
    totalAlertLinks: number;
  }> {
    this.validateUuid(reasoningId, 'reasoningId');
    const runInTx = async (transaction: any) => {
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
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findSession(id: string, tx?: any): Promise<Reasoning | null> {
    this.validateUuid(id, 'reasoningId');
    return this.reasoningRepo.findById(id, tx);
  }

  async findByStatus(status: ReasoningStatus, tx?: any): Promise<Reasoning[]> {
    return this.reasoningRepo.findByStatus(status, tx);
  }

  async findCompleted(tx?: any): Promise<Reasoning[]> {
    return this.reasoningRepo.findCompleted(tx);
  }

  async findSteps(reasoningId: string, tx?: any): Promise<ReasoningStep[]> {
    this.validateUuid(reasoningId, 'reasoningId');
    return this.reasoningRepo.findSteps(reasoningId, tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteSession(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'reasoningId');
    const runInTx = async (transaction: any) => {
      const existing = await this.reasoningRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Reasoning session "${id}" not found.`);
      }
      await this.reasoningRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('ReasoningSessionDeleted', { reasoningId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: ReasoningStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<Reasoning> {
    this.validateUuid(id, 'reasoningId');
    const runInTx = async (transaction: any) => {
      const existing = await this.reasoningRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Reasoning session "${id}" not found.`);
      }
      const updated = await this.reasoningRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { session: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
