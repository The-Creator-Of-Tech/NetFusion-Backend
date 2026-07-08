import { BaseRepository } from '../base/BaseRepository';
import { Notification, Prisma } from '@prisma/client';

export class NotificationRepository extends BaseRepository<Notification, Prisma.NotificationUncheckedCreateInput, Prisma.NotificationUncheckedUpdateInput> {
  constructor() {
    super('notification');
  }
}
