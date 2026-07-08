import { BaseRepository } from '../base/BaseRepository';
import { Reasoning, ReasoningStep, ReasoningStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class ReasoningRepository extends BaseRepository<Reasoning, Prisma.ReasoningUncheckedCreateInput, Prisma.ReasoningUncheckedUpdateInput> {
  constructor() {
    super('reasoning');
  }

  /**
   * Finds reasoning sessions by execution ID using JSON metadata path where not deleted.
   */
  async findByExecution(executionId: string, tx?: any): Promise<Reasoning[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        metadata: {
          path: ['executionId'],
          equals: executionId,
        },
      },
    });
  }

  /**
   * Finds reasoning sessions by status where not deleted.
   */
  async findByStatus(status: ReasoningStatus, tx?: any): Promise<Reasoning[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds completed reasoning sessions (status: COMPLETED and not deleted).
   */
  async findCompleted(tx?: any): Promise<Reasoning[]> {
    return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
  }

  /**
   * Finds failed reasoning sessions (status: FAILED and not deleted).
   */
  async findFailed(tx?: any): Promise<Reasoning[]> {
    return this.findMany({ filter: { status: 'FAILED', deletedAt: null } }, tx);
  }

  /**
   * Finds reasoning steps associated with a specific reasoning session ID where not deleted.
   */
  async findSteps(reasoningId: string, tx?: any): Promise<ReasoningStep[]> {
    const client = tx || prisma;
    return client.reasoningStep.findMany({
      where: { reasoningId, deletedAt: null },
      orderBy: { stepNumber: 'asc' },
    });
  }

  /**
   * Calculates the average confidence of all steps in a reasoning session.
   */
  async calculateConfidence(id: string, tx?: any): Promise<number> {
    const steps = await this.findSteps(id, tx);
    if (steps.length === 0) return 0.0;
    const sum = steps.reduce((total, step) => total + step.confidence, 0);
    return sum / steps.length;
  }
}
