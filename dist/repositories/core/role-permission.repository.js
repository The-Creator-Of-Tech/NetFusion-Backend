"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RolePermissionRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class RolePermissionRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('rolePermission');
    }
    /**
     * Assigns a permission to a role. Restores the relation if it was soft-deleted,
     * otherwise creates a new one.
     */
    async assignPermission(roleId, permissionId, tx) {
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
    async revokePermission(roleId, permissionId, tx) {
        const existing = await this.findOne({ roleId, permissionId, deletedAt: null }, tx);
        if (!existing) {
            throw new Error(`Active RolePermission mapping not found for roleId: ${roleId}, permissionId: ${permissionId}`);
        }
        return this.softDelete(existing.id, 'system', tx);
    }
    /**
     * Retrieves all active permission mappings for a role, including permission details.
     */
    async getPermissions(roleId, tx) {
        return this.findMany({
            filter: { roleId, deletedAt: null },
            include: { permission: true },
        }, tx);
    }
}
exports.RolePermissionRepository = RolePermissionRepository;
