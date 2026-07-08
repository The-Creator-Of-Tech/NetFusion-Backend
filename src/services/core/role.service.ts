import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import {
  roleRepository,
  userRoleRepository,
  rolePermissionRepository,
  auditLogRepository,
  userRepository
} from '../../repositories/core';
import prisma from '../../lib/prisma';
import { Role, UserRole, RolePermission, Prisma } from '@prisma/client';

export class RoleService extends BaseService {
  constructor(
    private readonly roleRepo = roleRepository,
    private readonly userRoleRepo = userRoleRepository,
    private readonly rolePermissionRepo = rolePermissionRepository,
    private readonly auditLogRepo = auditLogRepository,
    private readonly userRepo = userRepository
  ) {
    super();
  }

  async assignRole(userId: string, roleId: string, tx?: any): Promise<UserRole> {
    this.validateUuid(userId, 'userId');
    this.validateUuid(roleId, 'roleId');

    const runInTx = async (transaction: any) => {
      // Validate user existence
      const user = await this.userRepo.findById(userId, transaction);
      if (!user || user.deletedAt) {
        throw new Error(`User with ID "${userId}" not found.`);
      }

      // Validate role existence
      const role = await this.roleRepo.findById(roleId, transaction);
      if (!role || role.deletedAt) {
        throw new Error(`Role with ID "${roleId}" not found.`);
      }

      // Duplicate prevention is handled inside assignRole repository method!
      const userRole = await this.userRoleRepo.assignRole(userId, roleId, transaction);

      await this.auditLogRepo.create({
        userId,
        action: 'UPDATE',
        resourceType: 'user_role',
        resourceId: userRole.id,
        description: `Assigned role "${role.name}" to user "${user.username}".`,
        metadata: { userId, roleId } as any,
      }, transaction);

      await eventPublisher.publish('RoleAssigned', { userId, roleId, userRole });
      return userRole;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async removeRole(userId: string, roleId: string, tx?: any): Promise<UserRole> {
    this.validateUuid(userId, 'userId');
    this.validateUuid(roleId, 'roleId');

    const runInTx = async (transaction: any) => {
      const user = await this.userRepo.findById(userId, transaction);
      if (!user || user.deletedAt) {
        throw new Error(`User with ID "${userId}" not found.`);
      }

      const role = await this.roleRepo.findById(roleId, transaction);
      if (!role || role.deletedAt) {
        throw new Error(`Role with ID "${roleId}" not found.`);
      }

      const userRole = await this.userRoleRepo.removeRole(userId, roleId, transaction);

      await this.auditLogRepo.create({
        userId,
        action: 'UPDATE',
        resourceType: 'user_role',
        resourceId: userRole.id,
        description: `Removed role "${role.name}" from user "${user.username}".`,
        metadata: { userId, roleId } as any,
      }, transaction);

      await eventPublisher.publish('RoleRemoved', { userId, roleId, userRole });
      return userRole;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async syncPermissions(roleId: string, permissionIds: string[], tx?: any): Promise<RolePermission[]> {
    this.validateUuid(roleId, 'roleId');
    for (const permId of permissionIds) {
      this.validateUuid(permId, 'permissionId');
    }

    const runInTx = async (transaction: any) => {
      const role = await this.roleRepo.findById(roleId, transaction);
      if (!role || role.deletedAt) {
        throw new Error(`Role with ID "${roleId}" not found.`);
      }

      // 1. Fetch current permissions
      const currentMappings = await this.rolePermissionRepo.getPermissions(roleId, transaction);
      const currentPermIds = currentMappings.map(m => m.permissionId);

      // 2. Revoke permissions no longer needed
      for (const m of currentMappings) {
        if (!permissionIds.includes(m.permissionId)) {
          await this.rolePermissionRepo.revokePermission(roleId, m.permissionId, transaction);
        }
      }

      // 3. Assign new permissions
      const activeMappings: RolePermission[] = [];
      for (const permId of permissionIds) {
        const mapping = await this.rolePermissionRepo.assignPermission(roleId, permId, transaction);
        activeMappings.push(mapping);
      }

      // 4. Create Audit Log
      let logUserId = '00000000-0000-0000-0000-000000000000';
      const firstUser = await this.userRepo.findOne({ deletedAt: null }, transaction);
      if (firstUser) {
        logUserId = firstUser.id;
      }

      await this.auditLogRepo.create({
        userId: logUserId,
        action: 'UPDATE',
        resourceType: 'role_permissions',
        resourceId: roleId,
        description: `Synchronized permissions for role "${role.name}".`,
        metadata: { roleId, permissionIds } as any,
      }, transaction);

      await eventPublisher.publish('PermissionsSynced', { roleId, permissionIds, activeMappings });
      return activeMappings;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async listUsers(roleId: string, tx?: any): Promise<any[]> {
    this.validateUuid(roleId, 'roleId');
    const mappings = await this.userRoleRepo.findMany({
      filter: { roleId, deletedAt: null },
      include: { user: true }
    }, tx);
    return (mappings as any[]).map(m => m.user).filter(u => u && !u.deletedAt);
  }

  async listPermissions(roleId: string, tx?: any): Promise<any[]> {
    this.validateUuid(roleId, 'roleId');
    const mappings = await this.rolePermissionRepo.getPermissions(roleId, tx);
    return mappings.map(m => m.permission).filter(p => p && !p.deletedAt);
  }
}
