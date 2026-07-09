"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProjectService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class ProjectService extends BaseService_1.BaseService {
    constructor(projectRepo = core_1.projectRepository, auditLogRepo = core_1.auditLogRepository, investigationRepo = core_1.investigationRepository) {
        super();
        this.projectRepo = projectRepo;
        this.auditLogRepo = auditLogRepo;
        this.investigationRepo = investigationRepo;
    }
    async validateProjectUniqueness(name, tx) {
        const existing = await this.projectRepo.findOne({ name, deletedAt: null }, tx);
        if (existing) {
            throw new Error(`Validation failed: Project with name "${name}" already exists.`);
        }
    }
    async createProject(data, tx) {
        this.validateRequired(data, ['name', 'ownerId']);
        this.validateUuid(data.ownerId, 'ownerId');
        const runInTx = async (transaction) => {
            // 1. Validate uniqueness
            await this.validateProjectUniqueness(data.name, transaction);
            // 2. Initialize default metadata
            const metadata = data.metadata || {};
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
                metadata: { projectId: project.id, name: project.name },
            }, transaction);
            // 5. Publish lifecycle event
            await EventPublisher_1.eventPublisher.publish('ProjectCreated', { project });
            return project;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async updateProject(id, data, tx) {
        this.validateUuid(id, 'projectId');
        const runInTx = async (transaction) => {
            const existing = await this.projectRepo.findById(id, transaction);
            if (!existing || existing.deletedAt) {
                throw new Error(`Project with ID "${id}" not found.`);
            }
            if (data.name && typeof data.name === 'string' && data.name !== existing.name) {
                await this.validateProjectUniqueness(data.name, transaction);
            }
            const updated = await this.projectRepo.update(id, data, transaction);
            // Create Audit Log
            const ownerId = data.ownerId || existing.ownerId;
            await this.auditLogRepo.create({
                userId: ownerId,
                projectId: updated.id,
                action: 'UPDATE',
                resourceType: 'project',
                resourceId: updated.id,
                description: `Project "${updated.name}" was updated.`,
                metadata: JSON.parse(JSON.stringify({ projectId: updated.id, changes: data })),
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('ProjectUpdated', { project: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async archiveProject(id, tx) {
        this.validateUuid(id, 'projectId');
        const runInTx = async (transaction) => {
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
                metadata: { projectId: updated.id, action: 'archive' },
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('ProjectArchived', { project: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async restoreProject(id, tx) {
        this.validateUuid(id, 'projectId');
        const runInTx = async (transaction) => {
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
                metadata: { projectId: updated.id, action: 'restore' },
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('ProjectRestored', { project: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async findProject(id, tx) {
        this.validateUuid(id, 'projectId');
        return this.projectRepo.findById(id, tx);
    }
    async findBySlug(slug, tx) {
        if (!slug) {
            throw new Error('Validation failed: Slug is required.');
        }
        return this.projectRepo.findBySlug(slug, tx);
    }
    async listProjects(filter, tx) {
        return this.projectRepo.findMany({ filter: filter || {} }, tx);
    }
    async addTag(id, tag, tx) {
        this.validateUuid(id, 'projectId');
        if (!tag) {
            throw new Error('Validation failed: Tag is required.');
        }
        const runInTx = async (transaction) => {
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
                    metadata: { projectId: updated.id, tagAdded: tag },
                }, transaction);
                await EventPublisher_1.eventPublisher.publish('ProjectTagAdded', { project: updated, tag });
                return updated;
            }
            return existing;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async removeTag(id, tag, tx) {
        this.validateUuid(id, 'projectId');
        if (!tag) {
            throw new Error('Validation failed: Tag is required.');
        }
        const runInTx = async (transaction) => {
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
                    metadata: { projectId: updated.id, tagRemoved: tag },
                }, transaction);
                await EventPublisher_1.eventPublisher.publish('ProjectTagRemoved', { project: updated, tag });
                return updated;
            }
            return existing;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async calculateProjectStatistics(id, tx) {
        this.validateUuid(id, 'projectId');
        const runInTx = async (transaction) => {
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
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.ProjectService = ProjectService;
