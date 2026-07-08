import { BaseRepository } from '../base/BaseRepository';
import { Execution, ExecutionUsage, ExecutionStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class ExecutionRepository extends BaseRepository<Execution, Prisma.ExecutionUncheckedCreateInput, Prisma.ExecutionUncheckedUpdateInput> {
  constructor() {
    super('execution');
  }

  /**
   * Finds executions by provider ID where not deleted.
   */
  async findByProvider(providerId: string, tx?: any): Promise<Execution[]> {
    return this.findMany({ filter: { providerId, deletedAt: null } }, tx);
  }

  /**
   * Finds executions by status where not deleted.
   */
  async findByStatus(status: ExecutionStatus, tx?: any): Promise<Execution[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds pending executions (status: PENDING and not deleted).
   */
  async findPending(tx?: any): Promise<Execution[]> {
    return this.findMany({ filter: { status: 'PENDING', deletedAt: null } }, tx);
  }

  /**
   * Finds completed executions (status: COMPLETED and not deleted).
   */
  async findCompleted(tx?: any): Promise<Execution[]> {
    return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
  }

  /**
   * Finds failed executions (status: FAILED and not deleted).
   */
  async findFailed(tx?: any): Promise<Execution[]> {
    return this.findMany({ filter: { status: 'FAILED', deletedAt: null } }, tx);
  }

  /**
   * Finds execution usage details associated with a specific execution ID where not deleted.
   */
  async findUsage(executionId: string, tx?: any): Promise<ExecutionUsage | null> {
    const client = tx || prisma;
    return client.executionUsage.findFirst({
      where: { executionId, deletedAt: null },
    });
  }

  /**
   * Calculates the estimated cost of an execution.
   */
  async calculateCost(id: string, tx?: any): Promise<number> {
    const usage = await this.findUsage(id, tx);
    return usage?.estimatedCost || 0.0;
  }
}
