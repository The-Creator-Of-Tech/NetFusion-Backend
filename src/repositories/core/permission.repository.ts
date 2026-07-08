import { BaseRepository } from '../base/BaseRepository';
import { Permission, Prisma } from '@prisma/client';

export class PermissionRepository extends BaseRepository<Permission, Prisma.PermissionCreateInput, Prisma.PermissionUpdateInput> {
  constructor() {
    super('permission');
  }

  /**
   * Finds permissions by resource where not deleted.
   */
  async findByResource(resource: string, tx?: any): Promise<Permission[]> {
    return this.findMany({ filter: { resource, deletedAt: null } }, tx);
  }

  /**
   * Finds permissions by action where not deleted.
   */
  async findByAction(action: string, tx?: any): Promise<Permission[]> {
    return this.findMany({ filter: { action, deletedAt: null } }, tx);
  }

  /**
   * Finds a permission by resource and action where not deleted.
   */
  async findByResourceAndAction(resource: string, action: string, tx?: any): Promise<Permission | null> {
    return this.findOne({ resource, action, deletedAt: null }, tx);
  }
}
