import { BaseRepository } from '../base/BaseRepository';
import { RolePermission, Prisma } from '@prisma/client';

export class RolePermissionRepository extends BaseRepository<RolePermission, Prisma.RolePermissionUncheckedCreateInput, Prisma.RolePermissionUncheckedUpdateInput> {
  constructor() {
    super('rolePermission');
  }

  /**
   * Assigns a permission to a role. Restores the relation if it was soft-deleted,
   * otherwise creates a new one.
   */
  async assignPermission(roleId: string, permissionId: string, tx?: any): Promise<RolePermission> {
    const existing = await this.findOne({ roleId, permissionId }, tx);
    if (existing) {
      if (existing.deletedAt !== null) {
        return this.restore(existing.id, tx);
      }
      return existing;
    }
    return this.create({ roleId, permissionId }, tx);
  }

  /**
   * Revokes a permission from a role by soft-deleting the junction record.
   */
  async revokePermission(roleId: string, permissionId: string, tx?: any): Promise<RolePermission> {
    const existing = await this.findOne({ roleId, permissionId, deletedAt: null }, tx);
    if (!existing) {
      throw new Error(`Active RolePermission mapping not found for roleId: ${roleId}, permissionId: ${permissionId}`);
    }
    return this.softDelete(existing.id, 'system', tx);
  }

  /**
   * Retrieves all active permission mappings for a role, including permission details.
   */
  async getPermissions(roleId: string, tx?: any): Promise<any[]> {
    return this.findMany(
      {
        filter: { roleId, deletedAt: null },
        include: { permission: true },
      },
      tx
    );
  }
}
