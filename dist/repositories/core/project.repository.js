"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProjectRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class ProjectRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('project');
    }
    /**
     * Finds a project by slug where not deleted.
     * Matches name directly (case-insensitive), matches name with hyphens replaced by spaces,
     * or matches the 'slug' key in the metadata JSON object.
     */
    async findBySlug(slug, tx) {
        const delegate = this.getDelegate(tx);
        // Try direct name match
        const matchName = await delegate.findFirst({
            where: {
                name: { equals: slug, mode: 'insensitive' },
                deletedAt: null,
            },
        });
        if (matchName)
            return matchName;
        // Try name with spaces instead of hyphens
        const nameWithSpaces = slug.replace(/-/g, ' ');
        const matchNameSpaces = await delegate.findFirst({
            where: {
                name: { equals: nameWithSpaces, mode: 'insensitive' },
                deletedAt: null,
            },
        });
        if (matchNameSpaces)
            return matchNameSpaces;
        // Try matching slug in metadata JSON
        return delegate.findFirst({
            where: {
                metadata: {
                    path: ['slug'],
                    equals: slug,
                },
                deletedAt: null,
            },
        });
    }
    /**
     * Finds projects owned by a specific user where not deleted.
     */
    async findByOwner(ownerId, tx) {
        return this.findMany({ filter: { ownerId, deletedAt: null } }, tx);
    }
    /**
     * Finds a project by ID and includes its investigations.
     */
    async findWithInvestigations(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                investigations: true,
            },
        });
    }
    /**
     * Finds all active projects (status: ACTIVE and not deleted).
     */
    async findActiveProjects(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
}
exports.ProjectRepository = ProjectRepository;
