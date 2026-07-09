/**
 * AttachmentOrchestrator.ts
 * =====================================
 * Orchestrates file and evidence attachment lifecycle.
 */

import {
  BaseApplicationService,
  OperationContext,
  createOperationContext,
  CompensatingRegistry,
} from '../base/BaseApplicationService';
import { APP_EVENTS } from '../events/ApplicationEvents';
import { attachmentService } from '../../services/shared';
import { Attachment, AttachmentType, AttachmentStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export interface UploadAttachmentInput {
  projectId: string;
  investigationId?: string;
  targetId?: string;
  targetType?: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  storageKey: string;
  type: AttachmentType;
  actor: string;
}

export interface DeleteAttachmentInput {
  attachmentId: string;
  actor: string;
}

export class AttachmentOrchestrator extends BaseApplicationService {
  constructor() {
    super('AttachmentOrchestrator');
  }

  async uploadAttachment(input: UploadAttachmentInput, parentCtx?: OperationContext): Promise<Attachment> {
    const ctx = parentCtx ?? createOperationContext(input.actor, {
      projectId: input.projectId,
      investigationId: input.investigationId,
    });
    this.logInfo(ctx, `Uploading attachment "${input.fileName}" (storageKey: "${input.storageKey}")`);
    this.validateUuid(input.projectId, 'projectId', ctx);
    this.validateRequired(input, ['fileName', 'fileSize', 'mimeType', 'storageKey', 'type'], ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const attachment = await attachmentService.createAttachment({
        projectId: input.projectId,
        investigationId: input.investigationId,
        targetId: input.targetId,
        targetType: input.targetType,
        fileName: input.fileName,
        fileSize: input.fileSize,
        mimeType: input.mimeType,
        storageKey: input.storageKey,
        type: input.type,
        status: 'ACTIVE' as AttachmentStatus,
        createdBy: input.actor,
        updatedBy: input.actor,
      }, null);

      compensation.register(`delete-attachment-${attachment.id}`, async () => {
        try {
          await prisma.attachment.delete({ where: { id: attachment.id } });
        } catch (_) {}
      });

      await this.publishEvent(APP_EVENTS.ATTACHMENT_UPLOADED, ctx, {
        attachmentId: attachment.id,
        projectId: input.projectId,
        fileName: input.fileName,
      });

      compensation.clear();
      return attachment;
    });
  }

  async deleteAttachment(input: DeleteAttachmentInput, parentCtx?: OperationContext): Promise<Attachment> {
    const ctx = parentCtx ?? createOperationContext(input.actor);
    this.logInfo(ctx, `Deleting attachment ${input.attachmentId}`);
    this.validateRequired(input, ['attachmentId'], ctx);
    this.validateUuid(input.attachmentId, 'attachmentId', ctx);

    return this.withCompensation(ctx, async (compensation: CompensatingRegistry) => {
      const existing = await prisma.attachment.findUnique({
        where: { id: input.attachmentId },
      });
      if (!existing || existing.deletedAt) {
        throw new Error(`Attachment "${input.attachmentId}" not found.`);
      }

      const deleted = await attachmentService.deleteAttachment(input.attachmentId, input.actor, null);

      compensation.register(`restore-attachment-${input.attachmentId}`, async () => {
        await prisma.attachment.update({
          where: { id: input.attachmentId },
          data: {
            deletedAt: null,
            updatedBy: 'system',
            version: { increment: 1 },
          },
        });
      });

      await this.publishEvent(APP_EVENTS.ATTACHMENT_DELETED, ctx, {
        attachmentId: input.attachmentId,
        projectId: deleted.projectId,
        fileName: deleted.fileName,
      });

      compensation.clear();
      return deleted;
    });
  }

  async getAttachment(attachmentId: string, actor: string, parentCtx?: OperationContext): Promise<Attachment> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching attachment ${attachmentId}`);
    this.validateUuid(attachmentId, 'attachmentId', ctx);

    const attachment = await prisma.attachment.findUnique({
      where: { id: attachmentId },
    });
    if (!attachment || attachment.deletedAt) {
      throw new Error(`Attachment "${attachmentId}" not found.`);
    }
    return attachment;
  }

  async getAttachmentsForObject(
    query: { projectId?: string; investigationId?: string; targetId?: string; targetType?: string },
    actor: string,
    parentCtx?: OperationContext
  ): Promise<Attachment[]> {
    const ctx = parentCtx ?? createOperationContext(actor);
    this.logInfo(ctx, `Fetching attachments with query: ${JSON.stringify(query)}`);

    if (query.projectId) {
      this.validateUuid(query.projectId, 'projectId', ctx);
      return attachmentService.findByProject(query.projectId);
    }
    if (query.investigationId) {
      this.validateUuid(query.investigationId, 'investigationId', ctx);
      return attachmentService.findByInvestigation(query.investigationId);
    }
    if (query.targetId && query.targetType) {
      this.validateUuid(query.targetId, 'targetId', ctx);
      return attachmentService.findByTarget(query.targetId, query.targetType);
    }

    throw new Error('Validation failed: either projectId, investigationId, or (targetId and targetType) must be provided.');
  }
}

export const attachmentOrchestrator = new AttachmentOrchestrator();
