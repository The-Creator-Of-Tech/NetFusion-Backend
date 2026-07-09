"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRoleRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class UserRoleRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('userRole');
    }
    /**
     * Assigns a role to a user. Restores the relation if it was soft-deleted,
     * otherwise creates a new one.
     */
    async assignRole(userId, roleId, tx) {
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
    async removeRole(userId, roleId, tx) {
        const existing = await this.findOne({ userId, roleId, deletedAt: null }, tx);
        if (!existing) {
            throw new Error(`Active UserRole mapping not found for userId: ${userId}, roleId: ${roleId}`);
        }
        return this.softDelete(existing.id, 'system', tx);
    }
    /**
     * Retrieves all active role mappings for a user, including role details.
     */
    async getUserRoles(userId, tx) {
        return this.findMany({
            filter: { userId, deletedAt: null },
            include: { role: true },
        }, tx);
    }
}
exports.UserRoleRepository = UserRoleRepository;
