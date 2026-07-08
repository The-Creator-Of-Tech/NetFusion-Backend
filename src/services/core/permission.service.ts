import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { permissionRepository } from '../../repositories/core';
import { Permission } from '@prisma/client';

export class PermissionService extends BaseService {
  constructor(
    private readonly permissionRepo = permissionRepository
  ) {
    super();
  }

  async listPermissions(tx?: any): Promise<Permission[]> {
    return this.permissionRepo.findMany({ filter: { deletedAt: null } }, tx);
  }

  async validatePermission(permissionId: string, tx?: any): Promise<void> {
    this.validateUuid(permissionId, 'permissionId');
    const existing = await this.permissionRepo.findById(permissionId, tx);
    if (!existing || existing.deletedAt) {
      throw new Error(`Validation failed: Permission with ID "${permissionId}" not found.`);
    }
  }

  async groupByResource(tx?: any): Promise<Record<string, Permission[]>> {
    const list = await this.listPermissions(tx);
    const groups: Record<string, Permission[]> = {};
    for (const p of list) {
      const res = p.resource;
      if (!groups[res]) {
        groups[res] = [];
      }
      groups[res].push(p);
    }
    return groups;
  }

  async searchPermissions(query: string, tx?: any): Promise<Permission[]> {
    if (!query) {
      return this.listPermissions(tx);
    }

    const runInTx = async (transaction: any) => {
      const list = await this.listPermissions(transaction);
      const q = query.toLowerCase();
      const results = list.filter(p =>
        p.name.toLowerCase().includes(q) ||
        p.displayName.toLowerCase().includes(q) ||
        p.resource.toLowerCase().includes(q) ||
        p.action.toLowerCase().includes(q)
      );

      await eventPublisher.publish('PermissionSearched', { query, count: results.length });
      return results;
    };

    return runInTx(tx);
  }
}
