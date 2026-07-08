import { BaseRepository } from '../base/BaseRepository';
import { Alert, AlertSeverity, AlertStatus, Prisma } from '@prisma/client';

export class AlertRepository extends BaseRepository<Alert, Prisma.AlertUncheckedCreateInput, Prisma.AlertUncheckedUpdateInput> {
  constructor() {
    super('alert');
  }

  /**
   * Finds alerts associated with a specific investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Alert[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds alerts by severity where not deleted.
   */
  async findBySeverity(severity: AlertSeverity, tx?: any): Promise<Alert[]> {
    return this.findMany({ filter: { severity, deletedAt: null } }, tx);
  }

  /**
   * Finds alerts by status where not deleted.
   */
  async findByStatus(status: AlertStatus, tx?: any): Promise<Alert[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds open alerts (status: OPEN and not deleted).
   */
  async findOpenAlerts(tx?: any): Promise<Alert[]> {
    return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
  }

  /**
   * Finds acknowledged alerts (status: ACKNOWLEDGED and not deleted).
   */
  async findAcknowledgedAlerts(tx?: any): Promise<Alert[]> {
    return this.findMany({ filter: { status: 'ACKNOWLEDGED', deletedAt: null } }, tx);
  }
}
