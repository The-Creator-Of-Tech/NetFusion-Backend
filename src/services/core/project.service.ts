import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  projectRepository,
  auditLogRepository,
  investigationRepository
} from '../../repositories/core';
import prisma from '../../lib/prisma';
import { Project, Prisma } from '@prisma/client';

export class ProjectService extends BaseService {
  constructor(
    private readonly projectRepo = projectRepository,
    private readonly auditLogRepo = auditLogRepository,
    private readonly investigationRepo = investigationRepository
  ) {
    super();
  }

  async validateProjectUniqueness(name: string, tx?: any): Promise<void> {
    const existing = await this.projectRepo.findOne({ name, deletedAt: null }, tx);
    if (existing) {
      throw new Error(`Validation failed: Project with name "${name}" already exists.`);
    }
  }

  async createProject(data: Prisma.ProjectUncheckedCreateInput, tx?: any): Promise<Project> {
    this.validateRequired(data as any, ['name', 'ownerId']);
    this.validateUuid(data.ownerId, 'ownerId');

    const runInTx = async (transaction: any) => {
      // 1. Validate uniqueness
      await this.validateProjectUniqueness(data.name, transaction);

      // 2. Initialize default metadata
      const metadata = (data.metadata as any) || {};
      if (!metadata.slug) {
        metadata.slug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
      }
      if (!metadata.initializedAt) {
        metadata.initializedAt = this.getUtcNow().toISOString();
      }

      // 3. Create project record
      const project = await this.projectRepo.create({
        ...data,
        metadata,
      }, transaction);

      // 4. Create Audit Log
      await this.auditLogRepo.create({
        userId: data.ownerId,
        projectId: project.id,
        action: 'CREATE',
        resourceType: 'project',
        resourceId: project.id,
        description: `Project "${project.name}" was created.`,
        metadata: { projectId: project.id, name: project.name } as any,
      }, transaction);

      // 5. Publish lifecycle event
      await eventPublisher.publish('ProjectCreated', { project });

      return project;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateProject(id: string, data: Prisma.ProjectUncheckedUpdateInput, tx?: any): Promise<Project> {
    this.validateUuid(id, 'projectId');

    const runInTx = async (transaction: any) => {
      const existing = await this.projectRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Project with ID "${id}" not found.`);
      }

      if (data.name && typeof data.name === 'string' && data.name !== existing.name) {
        await this.validateProjectUniqueness(data.name, transaction);
      }

      const updated = await this.projectRepo.update(id, data, transaction);

      // Create Audit Log
      const ownerId = (data.ownerId as string) || existing.ownerId;
      await this.auditLogRepo.create({
        userId: ownerId,
        projectId: updated.id,
        action: 'UPDATE',
        resourceType: 'project',
        resourceId: updated.id,
        description: `Project "${updated.name}" was updated.`,
        metadata: JSON.parse(JSON.stringify({ projectId: updated.id, changes: data })),
      }, transaction);

      await eventPublisher.publish('ProjectUpdated', { project: updated });

      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async archiveProject(id: string, tx?: any): Promise<Project> {
    this.validateUuid(id, 'projectId');

    const runInTx = async (transaction: any) => {
      const existing = await this.projectRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Project with ID "${id}" not found.`);
      }

      const updated = await this.projectRepo.update(id, { status: 'ARCHIVED' }, transaction);

      await this.auditLogRepo.create({
        userId: existing.ownerId,
        projectId: updated.id,
        action: 'UPDATE',
        resourceType: 'project',
        resourceId: updated.id,
        description: `Project "${updated.name}" was archived.`,
        metadata: { projectId: updated.id, action: 'archive' } as any,
      }, transaction);

      await eventPublisher.publish('ProjectArchived', { project: updated });

      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async restoreProject(id: string, tx?: any): Promise<Project> {
    this.validateUuid(id, 'projectId');

    const runInTx = async (transaction: any) => {
      const existing = await this.projectRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Project with ID "${id}" not found.`);
      }

      const updated = await this.projectRepo.update(id, { status: 'ACTIVE' }, transaction);

      await this.auditLogRepo.create({
        userId: existing.ownerId,
        projectId: updated.id,
        action: 'UPDATE',
        resourceType: 'project',
        resourceId: updated.id,
        description: `Project "${updated.name}" was restored.`,
        metadata: { projectId: updated.id, action: 'restore' } as any,
      }, transaction);

      await eventPublisher.publish('ProjectRestored', { project: updated });

      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async findProject(id: string, tx?: any): Promise<Project | null> {
    this.validateUuid(id, 'projectId');
    return this.projectRepo.findById(id, tx);
  }

  async findBySlug(slug: string, tx?: any): Promise<Project | null> {
    if (!slug) {
      throw new Error('Validation failed: Slug is required.');
    }
    return this.projectRepo.findBySlug(slug, tx);
  }

  async listProjects(filter?: any, tx?: any): Promise<Project[]> {
    return this.projectRepo.findMany({ filter: filter || {} }, tx);
  }

  async addTag(id: string, tag: string, tx?: any): Promise<Project> {
    this.validateUuid(id, 'projectId');
    if (!tag) {
      throw new Error('Validation failed: Tag is required.');
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.projectRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Project with ID "${id}" not found.`);
      }

      const tags = existing.tags || [];
      if (!tags.includes(tag)) {
        tags.push(tag);
        const updated = await this.projectRepo.update(id, { tags }, transaction);

        await this.auditLogRepo.create({
          userId: existing.ownerId,
          projectId: updated.id,
          action: 'UPDATE',
          resourceType: 'project',
          resourceId: updated.id,
          description: `Added tag "${tag}" to project "${updated.name}".`,
          metadata: { projectId: updated.id, tagAdded: tag } as any,
        }, transaction);

        await eventPublisher.publish('ProjectTagAdded', { project: updated, tag });
        return updated;
      }
      return existing;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async removeTag(id: string, tag: string, tx?: any): Promise<Project> {
    this.validateUuid(id, 'projectId');
    if (!tag) {
      throw new Error('Validation failed: Tag is required.');
    }

    const runInTx = async (transaction: any) => {
      const existing = await this.projectRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`Project with ID "${id}" not found.`);
      }

      const tags = existing.tags || [];
      const index = tags.indexOf(tag);
      if (index !== -1) {
        tags.splice(index, 1);
        const updated = await this.projectRepo.update(id, { tags }, transaction);

        await this.auditLogRepo.create({
          userId: existing.ownerId,
          projectId: updated.id,
          action: 'UPDATE',
          resourceType: 'project',
          resourceId: updated.id,
          description: `Removed tag "${tag}" from project "${updated.name}".`,
          metadata: { projectId: updated.id, tagRemoved: tag } as any,
        }, transaction);

        await eventPublisher.publish('ProjectTagRemoved', { project: updated, tag });
        return updated;
      }
      return existing;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async calculateProjectStatistics(id: string, tx?: any): Promise<any> {
    this.validateUuid(id, 'projectId');
    const runInTx = async (transaction: any) => {
      const investigations = await this.investigationRepo.findByProject(id, transaction);
      const stats = {
        totalInvestigations: investigations.length,
        openCount: investigations.filter(i => i.status === 'OPEN').length,
        inProgressCount: investigations.filter(i => i.status === 'IN_PROGRESS').length,
        resolvedCount: investigations.filter(i => i.status === 'RESOLVED').length,
        closedCount: investigations.filter(i => i.status === 'CLOSED').length,
        archivedCount: investigations.filter(i => i.status === 'ARCHIVED').length,
      };
      return stats;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
