"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.RoleService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class RoleService extends BaseService_1.BaseService {
    constructor(roleRepo = core_1.roleRepository, userRoleRepo = core_1.userRoleRepository, rolePermissionRepo = core_1.rolePermissionRepository, auditLogRepo = core_1.auditLogRepository, userRepo = core_1.userRepository) {
        super();
        this.roleRepo = roleRepo;
        this.userRoleRepo = userRoleRepo;
        this.rolePermissionRepo = rolePermissionRepo;
        this.auditLogRepo = auditLogRepo;
        this.userRepo = userRepo;
    }
    async assignRole(userId, roleId, tx) {
        this.validateUuid(userId, 'userId');
        this.validateUuid(roleId, 'roleId');
        const runInTx = async (transaction) => {
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
                metadata: { userId, roleId },
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('RoleAssigned', { userId, roleId, userRole });
            return userRole;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async removeRole(userId, roleId, tx) {
        this.validateUuid(userId, 'userId');
        this.validateUuid(roleId, 'roleId');
        const runInTx = async (transaction) => {
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
                metadata: { userId, roleId },
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('RoleRemoved', { userId, roleId, userRole });
            return userRole;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async syncPermissions(roleId, permissionIds, tx) {
        this.validateUuid(roleId, 'roleId');
        for (const permId of permissionIds) {
            this.validateUuid(permId, 'permissionId');
        }
        const runInTx = async (transaction) => {
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
            const activeMappings = [];
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
                metadata: { roleId, permissionIds },
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('PermissionsSynced', { roleId, permissionIds, activeMappings });
            return activeMappings;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async listUsers(roleId, tx) {
        this.validateUuid(roleId, 'roleId');
        const mappings = await this.userRoleRepo.findMany({
            filter: { roleId, deletedAt: null },
            include: { user: true }
        }, tx);
        return mappings.map(m => m.user).filter(u => u && !u.deletedAt);
    }
    async listPermissions(roleId, tx) {
        this.validateUuid(roleId, 'roleId');
        const mappings = await this.rolePermissionRepo.getPermissions(roleId, tx);
        return mappings.map(m => m.permission).filter(p => p && !p.deletedAt);
    }
}
exports.RoleService = RoleService;
