import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  investigationRepository,
  activityLogRepository,
  notificationRepository,
  userRepository,
  projectRepository
} from '../../repositories/core';
import {
  timelineRepository,
  assetRepository,
  findingRepository,
  evidenceRepository
} from '../../repositories/investigation';
import prisma from '../../lib/prisma';
import { Investigation, Prisma, InvestigationStatus } from '@prisma/client';

export class InvestigationService extends BaseService {
  constructor(
    private readonly investigationRepo = investigationRepository,
    private readonly timelineRepo = timelineRepository,
    private readonly activityLogRepo = activityLogRepository,
    private readonly notificationRepo = notificationRepository,
    private readonly userRepo = userRepository,
    private readonly projectRepo = projectRepository,
    private readonly assetRepo = assetRepository,
    private readonly findingRepo = findingRepository,
    private readonly evidenceRepo = evidenceRepository
  ) {
    super();
  }

  async createInvestigation(data: Prisma.InvestigationUncheckedCreateInput, tx?: any): Promise<Investigation> {
    this.validateRequired(data as any, ['title', 'projectId', 'ownerId']);
    this.validateUuid(data.projectId, 'projectId');
    this.validateUuid(data.ownerId, 'ownerId');

    const runInTx = async (transaction: any) => {
      // Validate project exists
      const project = await this.projectRepo.findById(data.projectId, transaction);
      if (!project || project.deletedAt) {
        throw new Error(`Project with ID "${data.projectId}" not found.`);
      }

      // Validate owner user exists
      const owner = await this.userRepo.findById(data.ownerId, transaction);
      if (!owner || owner.deletedAt) {
        throw new Error(`User with ID "${data.ownerId}" not found.`);
      }

      // 1. Create Investigation
      const inv = await this.investigationRepo.create(data, transaction);

      const createdByVal = (data as any).createdBy || 'system';
      const updatedByVal = (data as any).updatedBy || 'system';

      // 2. Create Timeline Event
      await this.timelineRepo.create({
        projectId: inv.projectId,
        investigationId: inv.id,
        title: 'Investigation Created',
        description: `Investigation "${inv.title}" was initialized.`,
        type: 'HISTORY_CREATED',
        eventTimestamp: this.getUtcNow(),
        createdBy: createdByVal,
        updatedBy: updatedByVal,
      }, transaction);

      // 3. Create Activity Log
      await this.activityLogRepo.create({
        userId: inv.ownerId,
        projectId: inv.projectId,
        investigationId: inv.id,
        action: 'CREATE',
        type: 'CREATE',
        details: `Created investigation "${inv.title}"`,
        createdBy: createdByVal,
        updatedBy: updatedByVal,
      }, transaction);

      // 4. Create Notification
      await this.notificationRepo.create({
        userId: inv.ownerId,
        title: 'New Investigation Assigned',
        message: `You have been assigned to investigation "${inv.title}".`,
        type: 'SYSTEM',
        status: 'UNREAD',
        createdBy: createdByVal,
        updatedBy: updatedByVal,
      }, transaction);

      // 5. Publish lifecycle event
      await eventPublisher.publish('InvestigationOpened', { investigation: inv });

      return inv;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateInvestigation(id: string, data: Prisma.InvestigationUncheckedUpdateInput, tx?: any): Promise<Investigation> {
    this.validateUuid(id, 'investigationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.investigationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Investigation with ID "${id}" not found.`);
      }

      const updated = await this.investigationRepo.update(id, data, transaction);

      const changes: string[] = [];
      if (data.title && data.title !== existing.title) changes.push(`title changed to "${data.title}"`);
      if (data.status && data.status !== existing.status) changes.push(`status changed to "${data.status}"`);
      if (data.priority && data.priority !== existing.priority) changes.push(`priority changed to "${data.priority}"`);

      const updatedByVal = (data as any).updatedBy || 'system';

      // Add timeline event
      await this.timelineRepo.create({
        projectId: updated.projectId,
        investigationId: updated.id,
        title: 'Investigation Updated',
        description: changes.length > 0 ? `Investigation updated: ${changes.join(', ')}.` : 'Investigation fields updated.',
        type: 'HISTORY_CREATED',
        eventTimestamp: this.getUtcNow(),
        createdBy: updatedByVal,
        updatedBy: updatedByVal,
      }, transaction);

      // Add activity log
      await this.activityLogRepo.create({
        userId: updated.ownerId,
        projectId: updated.projectId,
        investigationId: updated.id,
        action: 'UPDATE',
        type: 'UPDATE',
        details: `Updated investigation: ${changes.join(', ')}`,
        createdBy: updatedByVal,
        updatedBy: updatedByVal,
      }, transaction);

      await eventPublisher.publish('InvestigationUpdated', { investigation: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async closeInvestigation(id: string, tx?: any): Promise<Investigation> {
    this.validateUuid(id, 'investigationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.investigationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Investigation with ID "${id}" not found.`);
      }

      const updated = await this.investigationRepo.update(id, {
        status: 'CLOSED' as InvestigationStatus,
        closedAt: this.getUtcNow(),
      }, transaction);

      await this.timelineRepo.create({
        projectId: updated.projectId,
        investigationId: updated.id,
        title: 'Investigation Closed',
        description: `Investigation "${updated.title}" was closed.`,
        type: 'HISTORY_CREATED',
        eventTimestamp: this.getUtcNow(),
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await this.activityLogRepo.create({
        userId: updated.ownerId,
        projectId: updated.projectId,
        investigationId: updated.id,
        action: 'UPDATE',
        type: 'UPDATE',
        details: `Closed investigation "${updated.title}"`,
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await eventPublisher.publish('InvestigationClosed', { investigation: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async reopenInvestigation(id: string, tx?: any): Promise<Investigation> {
    this.validateUuid(id, 'investigationId');

    const runInTx = async (transaction: any) => {
      const existing = await this.investigationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Investigation with ID "${id}" not found.`);
      }

      const updated = await this.investigationRepo.update(id, {
        status: 'OPEN' as InvestigationStatus,
        closedAt: null,
      }, transaction);

      await this.timelineRepo.create({
        projectId: updated.projectId,
        investigationId: updated.id,
        title: 'Investigation Reopened',
        description: `Investigation "${updated.title}" was reopened.`,
        type: 'HISTORY_CREATED',
        eventTimestamp: this.getUtcNow(),
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await this.activityLogRepo.create({
        userId: updated.ownerId,
        projectId: updated.projectId,
        investigationId: updated.id,
        action: 'UPDATE',
        type: 'UPDATE',
        details: `Reopened investigation "${updated.title}"`,
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await eventPublisher.publish('InvestigationReopened', { investigation: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async assignOwner(id: string, ownerId: string, tx?: any): Promise<Investigation> {
    this.validateUuid(id, 'investigationId');
    this.validateUuid(ownerId, 'ownerId');

    const runInTx = async (transaction: any) => {
      const existing = await this.investigationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Investigation with ID "${id}" not found.`);
      }

      const user = await this.userRepo.findById(ownerId, transaction);
      if (!user || user.deletedAt) {
        throw new Error(`User with ID "${ownerId}" not found.`);
      }

      const updated = await this.investigationRepo.update(id, { ownerId }, transaction);

      await this.timelineRepo.create({
        projectId: updated.projectId,
        investigationId: updated.id,
        title: 'Owner Assigned',
        description: `Owner changed to ${user.username}.`,
        type: 'HISTORY_CREATED',
        eventTimestamp: this.getUtcNow(),
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await this.activityLogRepo.create({
        userId: ownerId,
        projectId: updated.projectId,
        investigationId: updated.id,
        action: 'UPDATE',
        type: 'UPDATE',
        details: `Assigned owner "${user.username}" to investigation "${updated.title}"`,
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await this.notificationRepo.create({
        userId: ownerId,
        title: 'Investigation Assigned',
        message: `You are now the owner of investigation "${updated.title}".`,
        type: 'SYSTEM',
        status: 'UNREAD',
        createdBy: 'system',
        updatedBy: 'system',
      }, transaction);

      await eventPublisher.publish('InvestigationOwnerAssigned', { investigation: updated, owner: user });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async changeStatus(id: string, status: InvestigationStatus, tx?: any): Promise<Investigation> {
    return this.updateInvestigation(id, { status }, tx);
  }

  async changePriority(id: string, priority: number, tx?: any): Promise<Investigation> {
    return this.updateInvestigation(id, { priority }, tx);
  }

  async deleteInvestigation(id: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'investigationId');
    const runInTx = async (transaction: any) => {
      const existing = await this.investigationRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Investigation with ID "${id}" not found.`);
      }
      await this.investigationRepo.delete(id, transaction);
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async findInvestigation(id: string, tx?: any): Promise<Investigation | null> {
    this.validateUuid(id, 'investigationId');
    return this.investigationRepo.findById(id, tx);
  }

  async calculateStatistics(id: string, tx?: any): Promise<any> {
    this.validateUuid(id, 'investigationId');
    const runInTx = async (transaction: any) => {
      const assetsCount = await this.assetRepo.count({ investigationId: id, deletedAt: null }, transaction);
      const findingsCount = await this.findingRepo.count({ investigationId: id, deletedAt: null }, transaction);
      const timelineCount = await this.timelineRepo.count({ investigationId: id, deletedAt: null }, transaction);
      const evidenceCount = await this.evidenceRepo.count({ investigationId: id, deletedAt: null }, transaction);

      return {
        assetsCount,
        findingsCount,
        timelineCount,
        evidenceCount,
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async buildSummary(id: string, tx?: any): Promise<any> {
    this.validateUuid(id, 'investigationId');
    const runInTx = async (transaction: any) => {
      const inv = await this.investigationRepo.findById(id, transaction);
      if (!inv || inv.deletedAt) {
        throw new Error(`Investigation with ID "${id}" not found.`);
      }
      const stats = await this.calculateStatistics(id, transaction);
      return {
        id: inv.id,
        title: inv.title,
        status: inv.status,
        priority: inv.priority,
        createdAt: inv.createdAt,
        stats,
      };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
