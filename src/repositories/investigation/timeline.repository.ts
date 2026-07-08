import { BaseRepository } from '../base/BaseRepository';
import { TimelineEvent, TimelineEventType, Prisma } from '@prisma/client';

export class TimelineRepository extends BaseRepository<TimelineEvent, Prisma.TimelineEventUncheckedCreateInput, Prisma.TimelineEventUncheckedUpdateInput> {
  constructor() {
    super('timelineEvent');
  }

  /**
   * Finds timeline events associated with a specific investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<TimelineEvent[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds timeline events by type where not deleted.
   */
  async findByEventType(type: TimelineEventType, tx?: any): Promise<TimelineEvent[]> {
    return this.findMany({ filter: { type, deletedAt: null } }, tx);
  }

  /**
   * Finds timeline events within a specific event timestamp range where not deleted.
   */
  async findRange(start: Date, end: Date, tx?: any): Promise<TimelineEvent[]> {
    return this.findMany(
      {
        filter: {
          eventTimestamp: { gte: start, lte: end },
          deletedAt: null,
        },
        sort: [{ field: 'eventTimestamp', direction: 'asc' }],
      },
      tx
    );
  }

  /**
   * Finds the latest timeline events ordered by event timestamp descending where not deleted.
   */
  async findLatest(limit: number = 10, filter?: any, tx?: any): Promise<TimelineEvent[]> {
    return this.findMany(
      {
        filter: { ...filter, deletedAt: null },
        sort: [{ field: 'eventTimestamp', direction: 'desc' }],
        limit,
      },
      tx
    );
  }

  /**
   * Finds the oldest timeline events ordered by event timestamp ascending where not deleted.
   */
  async findOldest(limit: number = 10, filter?: any, tx?: any): Promise<TimelineEvent[]> {
    return this.findMany(
      {
        filter: { ...filter, deletedAt: null },
        sort: [{ field: 'eventTimestamp', direction: 'asc' }],
        limit,
      },
      tx
    );
  }
}
