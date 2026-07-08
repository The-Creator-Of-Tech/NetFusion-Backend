import { BaseRepository } from '../base/BaseRepository';
import { Role, Prisma } from '@prisma/client';

export class RoleRepository extends BaseRepository<Role, Prisma.RoleCreateInput, Prisma.RoleUpdateInput> {
  constructor() {
    super('role');
  }

  /**
   * Finds a role by name where not deleted.
   */
  async findByName(name: string, tx?: any): Promise<Role | null> {
    return this.findOne({ name, deletedAt: null }, tx);
  }

  /**
   * Finds a role by ID and includes its permissions.
   */
  async findWithPermissions(id: string, tx?: any): Promise<any | null> {
    return this.getDelegate(tx).findUnique({
      where: { id },
      include: {
        rolePermissions: {
          include: {
            permission: true,
          },
        },
      },
    });
  }

  /**
   * Finds all system roles (isSystem: true and not deleted).
   */
  async findSystemRoles(tx?: any): Promise<Role[]> {
    return this.findMany({ filter: { isSystem: true, deletedAt: null } }, tx);
  }
}
