import { BaseRepository } from '../base/BaseRepository';
import { Streaming, StreamingChunk, StreamingStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class StreamingRepository extends BaseRepository<Streaming, Prisma.StreamingUncheckedCreateInput, Prisma.StreamingUncheckedUpdateInput> {
  constructor() {
    super('streaming');
  }

  /**
   * Finds a streaming session associated with a specific execution ID where not deleted.
   */
  async findByExecution(executionId: string, tx?: any): Promise<Streaming | null> {
    return this.findOne({ executionId, deletedAt: null }, tx);
  }

  /**
   * Finds active streaming sessions (status: ACTIVE and not deleted).
   */
  async findActive(tx?: any): Promise<Streaming[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }

  /**
   * Finds completed streaming sessions (status: COMPLETED and not deleted).
   */
  async findCompleted(tx?: any): Promise<Streaming[]> {
    return this.findMany({ filter: { status: 'COMPLETED', deletedAt: null } }, tx);
  }

  /**
   * Finds streaming chunks associated with a specific streaming ID ordered by sequence number where not deleted.
   */
  async findChunks(streamingId: string, tx?: any): Promise<StreamingChunk[]> {
    const client = tx || prisma;
    return client.streamingChunk.findMany({
      where: { streamingId, deletedAt: null },
      orderBy: { sequenceNumber: 'asc' },
    });
  }

  /**
   * Calculates the streaming progress (returns 100 if completed/failed, otherwise returns the count of chunks).
   */
  async calculateProgress(id: string, tx?: any): Promise<number> {
    const session = await this.findById(id, tx);
    if (!session) return 0;
    if (session.status === 'COMPLETED' || session.status === 'FAILED') return 100;

    const chunks = await this.findChunks(id, tx);
    if (chunks.length > 0 && chunks[chunks.length - 1].finishReason) {
      return 100;
    }
    return chunks.length;
  }
}
