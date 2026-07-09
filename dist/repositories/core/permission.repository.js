"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PermissionRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class PermissionRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('permission');
    }
    /**
     * Finds permissions by resource where not deleted.
     */
    async findByResource(resource, tx) {
        return this.findMany({ filter: { resource, deletedAt: null } }, tx);
    }
    /**
     * Finds permissions by action where not deleted.
     */
    async findByAction(action, tx) {
        return this.findMany({ filter: { action, deletedAt: null } }, tx);
    }
    /**
     * Finds a permission by resource and action where not deleted.
     */
    async findByResourceAndAction(resource, action, tx) {
        return this.findOne({ resource, action, deletedAt: null }, tx);
    }
}
exports.PermissionRepository = PermissionRepository;
