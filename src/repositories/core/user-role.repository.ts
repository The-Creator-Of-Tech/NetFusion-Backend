import { BaseRepository } from '../base/BaseRepository';
import { UserRole, Prisma } from '@prisma/client';

export class UserRoleRepository extends BaseRepository<UserRole, Prisma.UserRoleUncheckedCreateInput, Prisma.UserRoleUncheckedUpdateInput> {
  constructor() {
    super('userRole');
  }

  /**
   * Assigns a role to a user. Restores the relation if it was soft-deleted,
   * otherwise creates a new one.
   */
  async assignRole(userId: string, roleId: string, tx?: any): Promise<UserRole> {
    const existing = await this.findOne({ userId, roleId }, tx);
    if (existing) {
      if (existing.deletedAt !== null) {
        return this.restore(existing.id, tx);
      }
      return existing;
    }
    return this.create({ userId, roleId }, tx);
  }

  /**
   * Removes a role from a user by soft-deleting the junction record.
   */
  async removeRole(userId: string, roleId: string, tx?: any): Promise<UserRole> {
    const existing = await this.findOne({ userId, roleId, deletedAt: null }, tx);
    if (!existing) {
      throw new Error(`Active UserRole mapping not found for userId: ${userId}, roleId: ${roleId}`);
    }
    return this.softDelete(existing.id, 'system', tx);
  }

  /**
   * Retrieves all active role mappings for a user, including role details.
   */
  async getUserRoles(userId: string, tx?: any): Promise<any[]> {
    return this.findMany(
      {
        filter: { userId, deletedAt: null },
        include: { role: true },
      },
      tx
    );
  }
}
