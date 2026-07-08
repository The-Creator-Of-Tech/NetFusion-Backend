import { BaseRepository } from '../base/BaseRepository';
import { Project, Prisma } from '@prisma/client';

export class ProjectRepository extends BaseRepository<Project, Prisma.ProjectUncheckedCreateInput, Prisma.ProjectUncheckedUpdateInput> {
  constructor() {
    super('project');
  }

  /**
   * Finds a project by slug where not deleted.
   * Matches name directly (case-insensitive), matches name with hyphens replaced by spaces,
   * or matches the 'slug' key in the metadata JSON object.
   */
  async findBySlug(slug: string, tx?: any): Promise<Project | null> {
    const delegate = this.getDelegate(tx);

    // Try direct name match
    const matchName = await delegate.findFirst({
      where: {
        name: { equals: slug, mode: 'insensitive' },
        deletedAt: null,
      },
    });
    if (matchName) return matchName;

    // Try name with spaces instead of hyphens
    const nameWithSpaces = slug.replace(/-/g, ' ');
    const matchNameSpaces = await delegate.findFirst({
      where: {
        name: { equals: nameWithSpaces, mode: 'insensitive' },
        deletedAt: null,
      },
    });
    if (matchNameSpaces) return matchNameSpaces;

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
  async findByOwner(ownerId: string, tx?: any): Promise<Project[]> {
    return this.findMany({ filter: { ownerId, deletedAt: null } }, tx);
  }

  /**
   * Finds a project by ID and includes its investigations.
   */
  async findWithInvestigations(id: string, tx?: any): Promise<any | null> {
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
  async findActiveProjects(tx?: any): Promise<Project[]> {
    return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
  }
}
