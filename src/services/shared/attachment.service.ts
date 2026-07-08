/**
 * AttachmentService — Phase A5.3.7
 * ===================================
 * Business logic for Attachment lifecycle management.
 *
 * Responsibilities
 * ----------------
 * - Create, read, update, soft-delete attachments
 * - Filter by project, investigation, target, type, status
 * - File metadata validation (fileName, fileSize, mimeType, storageKey)
 * - Status transitions (ACTIVE → DELETED → PENDING)
 * - Bulk operations
 * - Statistics
 * - Event publication after every state change
 * - Transaction safety (all write methods accept optional tx)
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import prisma from '../../lib/prisma';
import {
  Attachment,
  AttachmentType,
  AttachmentStatus,
  Prisma,
} from '@prisma/client';

const VALID_TYPES: string[] = ['FILE', 'IMAGE', 'PDF', 'LOG', 'PCAP', 'OTHER'];
const VALID_STATUSES: string[] = ['ACTIVE', 'DELETED', 'PENDING'];

export class AttachmentService extends BaseService {

  // ── Create ──────────────────────────────────────────────────────────────────

  async createAttachment(
    data: Prisma.AttachmentUncheckedCreateInput,
    tx?: any,
  ): Promise<Attachment> {
    this.validateRequired(data as any, ['projectId', 'fileName', 'fileSize', 'mimeType', 'storageKey', 'type', 'createdBy', 'updatedBy']);

    if (!String(data.fileName).trim()) {
      throw new Error('Validation failed: fileName must not be empty.');
    }
    if (!String(data.storageKey).trim()) {
      throw new Error('Validation failed: storageKey must not be empty.');
    }
    if (!String(data.mimeType).trim()) {
      throw new Error('Validation failed: mimeType must not be empty.');
    }
    const size = Number(data.fileSize);
    if (isNaN(size) || size < 0) {
      throw new Error('Validation failed: fileSize must be a non-negative number.');
    }
    if (!VALID_TYPES.includes(String(data.type).toUpperCase())) {
      throw new Error(`Validation failed: type "${data.type}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const attachment = await client.attachment.create({ data });
      await eventPublisher.publish('AttachmentCreated', { attachment });
      return attachment;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  async updateAttachment(
    id: string,
    data: Prisma.AttachmentUncheckedUpdateInput,
    tx?: any,
  ): Promise<Attachment> {
    this.validateUuid(id, 'attachmentId');

    if (data.fileSize !== undefined) {
      const size = Number(data.fileSize);
      if (isNaN(size) || size < 0) {
        throw new Error('Validation failed: fileSize must be a non-negative number.');
      }
    }
    if (data.type !== undefined && !VALID_TYPES.includes(String(data.type).toUpperCase())) {
      throw new Error(`Validation failed: type "${data.type}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.attachment.findUnique({ where: { id } });
      if (!existing || existing.deletedAt) {
        throw new Error(`Attachment "${id}" not found.`);
      }
      const updated = await client.attachment.update({ where: { id }, data });
      await eventPublisher.publish('AttachmentUpdated', { attachment: updated });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Delete ──────────────────────────────────────────────────────────────────

  async deleteAttachment(id: string, actor: string, tx?: any): Promise<Attachment> {
    this.validateUuid(id, 'attachmentId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.attachment.findUnique({ where: { id } });
      if (!existing || existing.deletedAt) {
        throw new Error(`Attachment "${id}" not found.`);
      }
      const deleted = await client.attachment.update({
        where: { id },
        data: {
          deletedAt: new Date(),
          updatedBy: actor,
          version: { increment: 1 },
        },
      });
      await eventPublisher.publish('AttachmentDeleted', { attachment: deleted });
      return deleted;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Status Transitions ──────────────────────────────────────────────────────

  async setStatus(id: string, status: AttachmentStatus, actor: string, tx?: any): Promise<Attachment> {
    this.validateUuid(id, 'attachmentId');
    if (!VALID_STATUSES.includes(String(status).toUpperCase())) {
      throw new Error(`Validation failed: status "${status}" is not valid.`);
    }

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing = await client.attachment.findUnique({ where: { id } });
      if (!existing || existing.deletedAt) {
        throw new Error(`Attachment "${id}" not found.`);
      }
      const updated = await client.attachment.update({
        where: { id },
        data: { status, updatedBy: actor },
      });
      await eventPublisher.publish('AttachmentStatusChanged', { attachment: updated, status });
      return updated;
    };

    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lookups ─────────────────────────────────────────────────────────────────

  async findByProject(projectId: string, tx?: any): Promise<Attachment[]> {
    this.validateUuid(projectId, 'projectId');
    const client = tx || prisma;
    return client.attachment.findMany({
      where: { projectId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByInvestigation(investigationId: string, tx?: any): Promise<Attachment[]> {
    this.validateUuid(investigationId, 'investigationId');
    const client = tx || prisma;
    return client.attachment.findMany({
      where: { investigationId, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByTarget(targetId: string, targetType: string, tx?: any): Promise<Attachment[]> {
    this.validateUuid(targetId, 'targetId');
    if (!targetType || !targetType.trim()) {
      throw new Error('Validation failed: targetType must not be empty.');
    }
    const client = tx || prisma;
    return client.attachment.findMany({
      where: { targetId, targetType, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByType(type: AttachmentType, tx?: any): Promise<Attachment[]> {
    if (!VALID_TYPES.includes(String(type).toUpperCase())) {
      throw new Error(`Validation failed: type "${type}" is not valid.`);
    }
    const client = tx || prisma;
    return client.attachment.findMany({
      where: { type, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByStatus(status: AttachmentStatus, tx?: any): Promise<Attachment[]> {
    if (!VALID_STATUSES.includes(String(status).toUpperCase())) {
      throw new Error(`Validation failed: status "${status}" is not valid.`);
    }
    const client = tx || prisma;
    return client.attachment.findMany({
      where: { status, deletedAt: null },
      orderBy: { createdAt: 'desc' },
    });
  }

  async findByStorageKey(storageKey: string, tx?: any): Promise<Attachment | null> {
    if (!storageKey || !storageKey.trim()) {
      throw new Error('Validation failed: storageKey must not be empty.');
    }
    const client = tx || prisma;
    return client.attachment.findFirst({
      where: { storageKey, deletedAt: null },
    });
  }

  // ── Statistics ──────────────────────────────────────────────────────────────

  async getStatistics(tx?: any): Promise<{
    totalAttachments: number;
    activeAttachments: number;
    deletedAttachments: number;
    pendingAttachments: number;
    totalFileSize: number;
    averageFileSize: number;
    typeCounts: Record<string, number>;
  }> {
    const client = tx || prisma;
    const all = await client.attachment.findMany({ where: { deletedAt: null } });

    const typeCounts: Record<string, number> = {};
    let active = 0, deleted = 0, pending = 0, totalSize = 0;

    for (const a of all) {
      const t = String(a.type);
      typeCounts[t] = (typeCounts[t] ?? 0) + 1;
      totalSize += Number(a.fileSize ?? 0);
      if (a.status === 'ACTIVE') active++;
      else if (a.status === 'DELETED') deleted++;
      else if (a.status === 'PENDING') pending++;
    }

    return {
      totalAttachments: all.length,
      activeAttachments: active,
      deletedAttachments: deleted,
      pendingAttachments: pending,
      totalFileSize: totalSize,
      averageFileSize: all.length > 0 ? Math.round(totalSize / all.length) : 0,
      typeCounts,
    };
  }

  // ── Bulk Operations ─────────────────────────────────────────────────────────

  async bulkCreate(
    items: Prisma.AttachmentUncheckedCreateInput[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { fileName: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { fileName: string; reason: string }[] = [];

    for (const item of items) {
      try {
        const a = await this.createAttachment({ ...item, createdBy: actor, updatedBy: actor }, tx);
        succeeded.push(a.id);
      } catch (e: any) {
        failed.push({ fileName: String(item.fileName ?? ''), reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('AttachmentsBulkCreated', { succeeded, failed });
    return { succeeded, failed };
  }

  async bulkDelete(
    ids: string[],
    actor: string,
    tx?: any,
  ): Promise<{ succeeded: string[]; failed: { id: string; reason: string }[] }> {
    const succeeded: string[] = [];
    const failed: { id: string; reason: string }[] = [];

    for (const id of ids) {
      try {
        await this.deleteAttachment(id, actor, tx);
        succeeded.push(id);
      } catch (e: any) {
        failed.push({ id, reason: e.message ?? 'Unknown error' });
      }
    }

    await eventPublisher.publish('AttachmentsBulkDeleted', { succeeded, failed });
    return { succeeded, failed };
  }
}

export const attachmentService = new AttachmentService();
