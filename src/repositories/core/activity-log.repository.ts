import { BaseRepository } from '../base/BaseRepository';
import { ActivityLog, Prisma } from '@prisma/client';

export class ActivityLogRepository extends BaseRepository<ActivityLog, Prisma.ActivityLogUncheckedCreateInput, Prisma.ActivityLogUncheckedUpdateInput> {
  constructor() {
    super('activityLog');
  }
}
