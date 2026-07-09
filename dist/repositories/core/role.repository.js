"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RoleRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class RoleRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('role');
    }
    /**
     * Finds a role by name where not deleted.
     */
    async findByName(name, tx) {
        return this.findOne({ name, deletedAt: null }, tx);
    }
    /**
     * Finds a role by ID and includes its permissions.
     */
    async findWithPermissions(id, tx) {
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
    async findSystemRoles(tx) {
        return this.findMany({ filter: { isSystem: true, deletedAt: null } }, tx);
    }
}
exports.RoleRepository = RoleRepository;
