/**
 * CaseFlowService — Phase A5.3.6
 * =================================
 * Business logic for Case Flow lifecycle and execution management.
 *
 * Responsibilities
 * ----------------
 * - CRUD for CaseFlows, CaseFlowSteps, and CaseFlowExecutions
 * - Status/priority/owner-based lookups
 * - Case lifecycle transitions (open → in_progress → resolved → closed)
 * - Execution start/complete/fail
 * - Step orchestration and assignment
 * - Confidence scoring and statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { caseFlowRepository } from '../../repositories/workflow';
import prisma from '../../lib/prisma';
import {
  CaseFlow,
  CaseFlowExecution,
  CaseFlowStep,
  CaseStatus,
  CasePriority,
  CaseExecutionStatus,
  Prisma,
} from '@prisma/client';

// ── Valid status transitions ──────────────────────────────────────────────────
const CASE_STATUS_TRANSITIONS: Record<string, string[]> = {
  OPEN:        ['IN_PROGRESS', 'CLOSED'],
  IN_PROGRESS: ['RESOLVED', 'CLOSED', 'OPEN'],
  RESOLVED:    ['CLOSED', 'IN_PROGRESS'],
  CLOSED:      ['OPEN'],
};

// ── Priority score map ────────────────────────────────────────────────────────
const PRIORITY_SCORE: Record<string, number> = {
  CRITICAL: 100,
  HIGH:     75,
  MEDIUM:   50,
  LOW:      25,
};

// ── Valid priorities ──────────────────────────────────────────────────────────
export const VALID_PRIORITIES: CasePriority[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// ── Valid statuses ────────────────────────────────────────────────────────────
export const VALID_STATUSES: CaseStatus[] = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'];

export class CaseFlowService extends BaseService {
  constructor(private readonly caseFlowRepo = caseFlowRepository) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  /**
   * Create a new case flow. CaseFlow requires projectId + investigationId.
   * Publishes CaseFlowCreated.
   */
  async createCaseFlow(
    data: Prisma.CaseFlowUncheckedCreateInput,
    tx?: any,
  ): Promise<CaseFlow> {
    this.validateRequired(data as any, ['title', 'createdBy', 'updatedBy']);
    if (!data.projectId) {
      throw new Error('Validation failed: projectId is required.');
    }
    if (!data.investigationId) {
      throw new Error('Validation failed: investigationId is required.');
    }

    if (data.priority !== undefined) {
      if (!VALID_PRIORITIES.includes(String(data.priority) as CasePriority)) {
        throw new Error(`Validation failed: priority "${data.priority}" is not valid.`);
      }
    }

    if (data.status !== undefined) {
      if (!VALID_STATUSES.includes(String(data.status) as CaseStatus)) {
        throw new Error(`Validation failed: status "${data.status}" is not valid.`);
      }
    }

    if (data.confidence !== undefined) {
      const conf = Number(data.confidence);
      if (isNaN(conf) || conf < 0 || conf > 100) {
        throw new Error('Validation failed: confidence must be between 0 and 100.');
      }
    }

    const runInTx = async (transaction: any) => {
      const caseFlow = await this.caseFlowRepo.create(data, transaction);
      await eventPublisher.publish('CaseFlowCreated', { caseFlow });
      return caseFlow;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  /**
   * Update a case flow by UUID. Validates status transitions. Publishes CaseFlowUpdated.
   */
  async updateCaseFlow(
    id: string,
    data: Prisma.CaseFlowUncheckedUpdateInput,
    tx?: any,
  ): Promise<CaseFlow> {
    this.validateUuid(id, 'caseFlowId');

    const runInTx = async (transaction: any) => {
      const existing = await this.caseFlowRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CaseFlow "${id}" not found.`);
      }

      if (data.status && data.status !== existing.status) {
        const allowed = CASE_STATUS_TRANSITIONS[existing.status] ?? [];
        if (!allowed.includes(String(data.status))) {
          throw new Error(
            `Invalid status transition from "${existing.status}" to "${data.status}".`,
          );
        }
      }

      if (data.priority !== undefined) {
        if (!VALID_PRIORITIES.includes(String(data.priority) as CasePriority)) {
          throw new Error(`Validation failed: priority "${data.priority}" is not valid.`);
        }
      }

      if (data.confidence !== undefined) {
        const conf = Number(data.confidence);
        if (isNaN(conf) || conf < 0 || conf > 100) {
          throw new Error('Validation failed: confidence must be between 0 and 100.');
        }
      }

      const updated = await this.caseFlowRepo.update(id, data, transaction);
      await eventPublisher.publish('CaseFlowUpdated', { caseFlow: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  /**
   * Soft-delete a case flow by UUID. Publishes CaseFlowDeleted.
   */
  async deleteCaseFlow(id: string, actor: string, tx?: any): Promise<CaseFlow> {
    this.validateUuid(id, 'caseFlowId');

    const runInTx = async (transaction: any) => {
      const existing = await this.caseFlowRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CaseFlow "${id}" not found.`);
      }
      const deleted = await this.caseFlowRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('CaseFlowDeleted', { caseFlow: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  /** Find case flows by project UUID. */
  async findByProject(projectId: string, tx?: any): Promise<CaseFlow[]> {
    this.validateUuid(projectId, 'projectId');
    return this.caseFlowRepo.findByProject(projectId, tx);
  }

  /** Find case flows by investigation UUID. */
  async findByInvestigation(investigationId: string, tx?: any): Promise<CaseFlow[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.caseFlowRepo.findByInvestigation(investigationId, tx);
  }

  /** Find case flows by owner (non-empty string). */
  async findByOwner(owner: string, tx?: any): Promise<CaseFlow[]> {
    if (!owner || !owner.trim()) {
      throw new Error('Validation failed: owner must not be empty.');
    }
    return this.caseFlowRepo.findByOwner(owner.trim(), tx);
  }

  /** Find case flows by priority. */
  async findByPriority(priority: CasePriority, tx?: any): Promise<CaseFlow[]> {
    if (!VALID_PRIORITIES.includes(priority)) {
      throw new Error(`Validation failed: priority "${priority}" is not valid.`);
    }
    return this.caseFlowRepo.findByPriority(priority, tx);
  }

  /** Find case flows by status. */
  async findByStatus(status: CaseStatus, tx?: any): Promise<CaseFlow[]> {
    if (!VALID_STATUSES.includes(status)) {
      throw new Error(`Validation failed: status "${status}" is not valid.`);
    }
    return this.caseFlowRepo.findByStatus(status, tx);
  }

  /** Find all OPEN case flows. */
  async findOpen(tx?: any): Promise<CaseFlow[]> {
    return this.caseFlowRepo.findOpen(tx);
  }

  /** Find all IN_PROGRESS case flows. */
  async findInProgress(tx?: any): Promise<CaseFlow[]> {
    return this.caseFlowRepo.findInProgress(tx);
  }

  /** Find all RESOLVED case flows. */
  async findResolved(tx?: any): Promise<CaseFlow[]> {
    return this.caseFlowRepo.findResolved(tx);
  }

  /** Find all CLOSED case flows. */
  async findClosed(tx?: any): Promise<CaseFlow[]> {
    return this.caseFlowRepo.findClosed(tx);
  }

  /** Find executions for a case flow UUID. */
  async findExecutions(caseFlowId: string, tx?: any): Promise<CaseFlowExecution[]> {
    this.validateUuid(caseFlowId, 'caseFlowId');
    return this.caseFlowRepo.findExecutions(caseFlowId, tx);
  }

  /** Find steps for a case flow UUID. */
  async findSteps(caseFlowId: string, tx?: any): Promise<CaseFlowStep[]> {
    this.validateUuid(caseFlowId, 'caseFlowId');
    return this.caseFlowRepo.findSteps(caseFlowId, tx);
  }

  /** Search case flow steps by keyword. */
  async searchSteps(query: string, tx?: any): Promise<CaseFlowStep[]> {
    if (!query || !query.trim()) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.caseFlowRepo.searchSteps(query.trim(), tx);
  }

  // ── Lifecycle Transitions ───────────────────────────────────────────────────

  /**
   * Transition a case to IN_PROGRESS. Publishes CaseFlowInProgress.
   */
  async startCase(id: string, actor: string, tx?: any): Promise<CaseFlow> {
    this.validateUuid(id, 'caseFlowId');

    const runInTx = async (transaction: any) => {
      const existing = await this.caseFlowRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CaseFlow "${id}" not found.`);
      }
      const allowed = CASE_STATUS_TRANSITIONS[existing.status] ?? [];
      if (!allowed.includes('IN_PROGRESS')) {
        throw new Error(`Cannot transition CaseFlow "${id}" from "${existing.status}" to IN_PROGRESS.`);
      }
      const updated = await this.caseFlowRepo.update(
        id,
        { status: 'IN_PROGRESS' as CaseStatus, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('CaseFlowInProgress', { caseFlow: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Transition a case to RESOLVED. Publishes CaseFlowResolved.
   */
  async resolveCase(id: string, actor: string, tx?: any): Promise<CaseFlow> {
    this.validateUuid(id, 'caseFlowId');

    const runInTx = async (transaction: any) => {
      const existing = await this.caseFlowRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CaseFlow "${id}" not found.`);
      }
      const allowed = CASE_STATUS_TRANSITIONS[existing.status] ?? [];
      if (!allowed.includes('RESOLVED')) {
        throw new Error(`Cannot resolve CaseFlow "${id}" from status "${existing.status}".`);
      }
      const updated = await this.caseFlowRepo.update(
        id,
        { status: 'RESOLVED' as CaseStatus, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('CaseFlowResolved', { caseFlow: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Transition a case to CLOSED. Publishes CaseFlowClosed.
   */
  async closeCase(id: string, actor: string, tx?: any): Promise<CaseFlow> {
    this.validateUuid(id, 'caseFlowId');

    const runInTx = async (transaction: any) => {
      const existing = await this.caseFlowRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CaseFlow "${id}" not found.`);
      }
      const updated = await this.caseFlowRepo.update(
        id,
        { status: 'CLOSED' as CaseStatus, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('CaseFlowClosed', { caseFlow: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Assign a case to a user. Publishes CaseFlowAssigned.
   */
  async assignCase(id: string, assignee: string, actor: string, tx?: any): Promise<CaseFlow> {
    this.validateUuid(id, 'caseFlowId');
    if (!assignee || !assignee.trim()) {
      throw new Error('Validation failed: assignee must not be empty.');
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.caseFlowRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`CaseFlow "${id}" not found.`);
      }
      const updated = await this.caseFlowRepo.update(
        id,
        { assignedTo: assignee.trim(), updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish('CaseFlowAssigned', { caseFlow: updated, assignee });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Execution Lifecycle ─────────────────────────────────────────────────────

  /**
   * Start a new execution for a case flow. Publishes CaseFlowExecutionStarted.
   */
  async startExecution(
    caseFlowId: string,
    actor: string,
    tx?: any,
  ): Promise<CaseFlowExecution> {
    this.validateUuid(caseFlowId, 'caseFlowId');

    const runInTx = async (transaction: any) => {
      const caseFlow = await this.caseFlowRepo.findById(caseFlowId, transaction);
      if (!caseFlow || caseFlow.deletedAt) {
        throw new Error(`CaseFlow "${caseFlowId}" not found.`);
      }

      const client = transaction || prisma;
      const execution = await client.caseFlowExecution.create({
        data: {
          caseFlowId,
          status: 'ACTIVE' as CaseExecutionStatus,
          startedAt: new Date(),
          createdBy: actor,
          updatedBy: actor,
        },
      });

      await eventPublisher.publish('CaseFlowExecutionStarted', { execution, caseFlowId });
      return execution;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  /**
   * Complete a case flow execution. Publishes CaseFlowExecutionCompleted.
   */
  async completeExecution(
    executionId: string,
    stepResults: Record<string, any>[],
    actor: string,
    tx?: any,
  ): Promise<CaseFlowExecution> {
    this.validateUuid(executionId, 'executionId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.caseFlowExecution.findFirst({
        where: { id: executionId, deletedAt: null },
      });
      if (!existing) {
        throw new Error(`CaseFlowExecution "${executionId}" not found.`);
      }

      const updated = await client.caseFlowExecution.update({
        where: { id: executionId },
        data: {
          status: 'COMPLETED' as CaseExecutionStatus,
          completedAt: new Date(),
          stepResults: stepResults as any,
          updatedBy: actor,
        },
      });

      await eventPublisher.publish('CaseFlowExecutionCompleted', { execution: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Scoring ─────────────────────────────────────────────────────────────────

  /**
   * Calculate a score (0–100) for a case flow based on priority and confidence.
   */
  async calculateScore(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'caseFlowId');
    const caseFlow = await this.caseFlowRepo.findById(id, tx);
    if (!caseFlow || caseFlow.deletedAt) {
      throw new Error(`CaseFlow "${id}" not found.`);
    }

    const priorityScore = PRIORITY_SCORE[String(caseFlow.priority ?? 'MEDIUM')] ?? 50;
    const confidenceBonus = Math.round((Number(caseFlow.confidence ?? 100) / 100) * 10);
    const steps = await this.caseFlowRepo.findSteps(id, tx);
    const stepBonus = Math.min(steps.length * 2, 10);

    return Math.min(priorityScore + confidenceBonus + stepBonus, 100);
  }

  /**
   * Pure scoring utility: score a list of case flow IDs (0–100).
   */
  scoreCaseFlows(ids: string[]): number {
    if (!ids || ids.length === 0) return 0;
    return Math.min(ids.length * 10, 100);
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  /**
   * Compute aggregate statistics across all non-deleted case flows.
   */
  async getStatistics(tx?: any): Promise<{
    totalCases: number;
    openCases: number;
    inProgressCases: number;
    resolvedCases: number;
    closedCases: number;
    priorityCounts: Record<string, number>;
    averageConfidence: number;
    totalExecutions: number;
  }> {
    const stats = await this.caseFlowRepo.calculateStatistics(tx);
    const client = tx || prisma;

    const all = await client.caseFlow.findMany({ where: { deletedAt: null } });
    const confidenceSum = all.reduce((s: number, c: CaseFlow) => s + Number(c.confidence ?? 100), 0);
    const totalExecutions = await client.caseFlowExecution.count({ where: { deletedAt: null } });

    return {
      totalCases: stats.total,
      openCases: stats.open,
      inProgressCases: stats.inProgress,
      resolvedCases: stats.resolved,
      closedCases: stats.closed,
      priorityCounts: stats.priorityCounts as Record<string, number>,
      averageConfidence: all.length > 0 ? Math.round((confidenceSum / all.length) * 10) / 10 : 0,
      totalExecutions,
    };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  /**
   * Bulk-create case flows. Returns succeeded IDs and failed entries.
   */
  async bulkCreateCaseFlows(
    items: Prisma.CaseFlowUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { title: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { title: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const c = await this.createCaseFlow({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(c.id);
      } catch (e: any) {
        failed.push({ title: String(item.title ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('CaseFlowsBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  /**
   * Bulk soft-delete case flows by IDs.
   */
  async bulkDeleteCaseFlows(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteCaseFlow(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('CaseFlowsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const caseFlowService = new CaseFlowService();
