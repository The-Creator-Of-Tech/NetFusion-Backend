"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PermissionService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const core_1 = require("../../repositories/core");
class PermissionService extends BaseService_1.BaseService {
    constructor(permissionRepo = core_1.permissionRepository) {
        super();
        this.permissionRepo = permissionRepo;
    }
    async listPermissions(tx) {
        return this.permissionRepo.findMany({ filter: { deletedAt: null } }, tx);
    }
    async validatePermission(permissionId, tx) {
        this.validateUuid(permissionId, 'permissionId');
        const existing = await this.permissionRepo.findById(permissionId, tx);
        if (!existing || existing.deletedAt) {
            throw new Error(`Validation failed: Permission with ID "${permissionId}" not found.`);
        }
    }
    async groupByResource(tx) {
        const list = await this.listPermissions(tx);
        const groups = {};
        for (const p of list) {
            const res = p.resource;
            if (!groups[res]) {
                groups[res] = [];
            }
            groups[res].push(p);
        }
        return groups;
    }
    async searchPermissions(query, tx) {
        if (!query) {
            return this.listPermissions(tx);
        }
        const runInTx = async (transaction) => {
            const list = await this.listPermissions(transaction);
            const q = query.toLowerCase();
            const results = list.filter(p => p.name.toLowerCase().includes(q) ||
                p.displayName.toLowerCase().includes(q) ||
                p.resource.toLowerCase().includes(q) ||
                p.action.toLowerCase().includes(q));
            await EventPublisher_1.eventPublisher.publish('PermissionSearched', { query, count: results.length });
            return results;
        };
        return runInTx(tx);
    }
}
exports.PermissionService = PermissionService;
