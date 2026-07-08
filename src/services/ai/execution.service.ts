/**
 * ExecutionService — Phase A5.3.4
 * ==================================
 * Manages AI execution lifecycle: submission, status transitions,
 * usage recording, cost calculation, retry logic, and token accounting.
 * Publishes events on execution state changes and usage events.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  executionRepository,
  providerRepository,
} from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  Execution,
  ExecutionUsage,
  ExecutionStatus,
  Prisma,
} from '@prisma/client';

export class ExecutionService extends BaseService {
  constructor(
    private readonly executionRepo = executionRepository,
    private readonly providerRepo  = providerRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async submitExecution(
    data: Prisma.ExecutionUncheckedCreateInput,
    tx?: any,
  ): Promise<Execution> {
    this.validateRequired(data as any, ['providerId', 'systemPrompt', 'userPrompt', 'createdBy', 'updatedBy']);
    this.validateUuid(data.providerId, 'providerId');
    if (data.projectId) this.validateUuid(data.projectId as string, 'projectId');
    if (data.investigationId) this.validateUuid(data.investigationId as string, 'investigationId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      // Verify provider exists and is active
      const provider = await this.providerRepo.findById(data.providerId, transaction);
      if (!provider || provider.deletedAt) {
        throw new Error(`Provider "${data.providerId}" not found.`);
      }
      if (!provider.enabled) {
        throw new Error(`Provider "${data.providerId}" is disabled.`);
      }

      const execution = await this.executionRepo.create(
        { ...data, status: 'PENDING' as ExecutionStatus },
        transaction,
      );

      await eventPublisher.publish('ExecutionSubmitted', { execution });
      return execution;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async startExecution(id: string, actor: string, tx?: any): Promise<Execution> {
    return this._transition(id, 'ACTIVE', actor, 'ExecutionStarted', tx);
  }

  async completeExecution(id: string, actor: string, tx?: any): Promise<Execution> {
    return this._transition(id, 'COMPLETED', actor, 'ExecutionCompleted', tx);
  }

  async failExecution(id: string, actor: string, tx?: any): Promise<Execution> {
    return this._transition(id, 'FAILED', actor, 'ExecutionFailed', tx);
  }

  async cancelExecution(id: string, actor: string, tx?: any): Promise<Execution> {
    return this._transition(id, 'FAILED', actor, 'ExecutionCancelled', tx);
  }

  // ── Usage recording ──────────────────────────────────────────────────────────

  async recordUsage(
    executionId: string,
    data: {
      promptTokens: number;
      completionTokens: number;
      totalTokens: number;
      estimatedCost: number;
      latencyMs: number;
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<ExecutionUsage> {
    this.validateUuid(executionId, 'executionId');
    this.validateRequired(data as any, ['promptTokens', 'completionTokens', 'totalTokens', 'estimatedCost', 'latencyMs', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const execution = await this.executionRepo.findById(executionId, transaction);
      if (!execution || execution.deletedAt) {
        throw new Error(`Execution "${executionId}" not found.`);
      }

      const client = transaction || prisma;
      const usage: ExecutionUsage = await client.executionUsage.create({
        data: {
          executionId,
          promptTokens: data.promptTokens,
          completionTokens: data.completionTokens,
          totalTokens: data.totalTokens,
          estimatedCost: data.estimatedCost,
          latencyMs: data.latencyMs,
          metadata: data.metadata ?? null,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      await eventPublisher.publish('ExecutionUsageRecorded', { executionId, usage });
      return usage;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Cost / token accounting ──────────────────────────────────────────────────

  async calculateCost(id: string, tx?: any): Promise<number> {
    this.validateUuid(id, 'executionId');
    return this.executionRepo.calculateCost(id, tx);
  }

  async getUsageStats(id: string, tx?: any): Promise<{
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    estimatedCost: number;
    latencyMs: number;
  } | null> {
    this.validateUuid(id, 'executionId');
    const usage = await this.executionRepo.findUsage(id, tx);
    if (!usage) return null;
    return {
      promptTokens: usage.promptTokens,
      completionTokens: usage.completionTokens,
      totalTokens: usage.totalTokens,
      estimatedCost: usage.estimatedCost,
      latencyMs: usage.latencyMs,
    };
  }

  async aggregateProjectUsage(
    projectId: string,
    tx?: any,
  ): Promise<{
    totalExecutions: number;
    totalTokens: number;
    totalCost: number;
    avgLatencyMs: number;
  }> {
    this.validateUuid(projectId, 'projectId');
    const runInTx = async (transaction: any) => {
      const executions = await this.executionRepo.findMany(
        { filter: { projectId, deletedAt: null } },
        transaction,
      );

      let totalTokens = 0;
      let totalCost = 0;
      let totalLatency = 0;
      let usageCount = 0;

      for (const exec of executions) {
        const usage = await this.executionRepo.findUsage(exec.id, transaction);
        if (usage) {
          totalTokens += usage.totalTokens;
          totalCost += usage.estimatedCost;
          totalLatency += usage.latencyMs;
          usageCount++;
        }
      }

      return {
        totalExecutions: executions.length,
        totalTokens,
        totalCost,
        avgLatencyMs: usageCount > 0 ? totalLatency / usageCount : 0,
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findExecution(id: string, tx?: any): Promise<Execution | null> {
    this.validateUuid(id, 'executionId');
    return this.executionRepo.findById(id, tx);
  }

  async findByProvider(providerId: string, tx?: any): Promise<Execution[]> {
    this.validateUuid(providerId, 'providerId');
    return this.executionRepo.findByProvider(providerId, tx);
  }

  async findByStatus(status: ExecutionStatus, tx?: any): Promise<Execution[]> {
    return this.executionRepo.findByStatus(status, tx);
  }

  async findPending(tx?: any): Promise<Execution[]> {
    return this.executionRepo.findPending(tx);
  }

  async findCompleted(tx?: any): Promise<Execution[]> {
    return this.executionRepo.findCompleted(tx);
  }

  async findFailed(tx?: any): Promise<Execution[]> {
    return this.executionRepo.findFailed(tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deleteExecution(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'executionId');
    const runInTx = async (transaction: any) => {
      const existing = await this.executionRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Execution "${id}" not found.`);
      }
      await this.executionRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('ExecutionDeleted', { executionId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: ExecutionStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<Execution> {
    this.validateUuid(id, 'executionId');
    const runInTx = async (transaction: any) => {
      const existing = await this.executionRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Execution "${id}" not found.`);
      }
      const updated = await this.executionRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { execution: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
