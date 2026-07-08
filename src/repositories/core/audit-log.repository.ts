import { BaseRepository } from '../base/BaseRepository';
import { AuditLog, Prisma } from '@prisma/client';

export class AuditLogRepository extends BaseRepository<AuditLog, Prisma.AuditLogUncheckedCreateInput, Prisma.AuditLogUncheckedUpdateInput> {
  constructor() {
    super('auditLog');
  }
}
