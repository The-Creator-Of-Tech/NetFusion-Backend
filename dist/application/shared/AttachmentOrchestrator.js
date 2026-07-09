"use strict";
/**
 * AttachmentOrchestrator.ts
 * =====================================
 * Orchestrates file and evidence attachment lifecycle.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.attachmentOrchestrator = exports.AttachmentOrchestrator = void 0;
const BaseApplicationService_1 = require("../base/BaseApplicationService");
const ApplicationEvents_1 = require("../events/ApplicationEvents");
const shared_1 = require("../../services/shared");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class AttachmentOrchestrator extends BaseApplicationService_1.BaseApplicationService {
    constructor() {
        super('AttachmentOrchestrator');
    }
    async uploadAttachment(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor, {
            projectId: input.projectId,
            investigationId: input.investigationId,
        });
        this.logInfo(ctx, `Uploading attachment "${input.fileName}" (storageKey: "${input.storageKey}")`);
        this.validateUuid(input.projectId, 'projectId', ctx);
        this.validateRequired(input, ['fileName', 'fileSize', 'mimeType', 'storageKey', 'type'], ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const attachment = await shared_1.attachmentService.createAttachment({
                projectId: input.projectId,
                investigationId: input.investigationId,
                targetId: input.targetId,
                targetType: input.targetType,
                fileName: input.fileName,
                fileSize: input.fileSize,
                mimeType: input.mimeType,
                storageKey: input.storageKey,
                type: input.type,
                status: 'ACTIVE',
                createdBy: input.actor,
                updatedBy: input.actor,
            }, null);
            compensation.register(`delete-attachment-${attachment.id}`, async () => {
                try {
                    await prisma_1.default.attachment.delete({ where: { id: attachment.id } });
                }
                catch (_) { }
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.ATTACHMENT_UPLOADED, ctx, {
                attachmentId: attachment.id,
                projectId: input.projectId,
                fileName: input.fileName,
            });
            compensation.clear();
            return attachment;
        });
    }
    async deleteAttachment(input, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(input.actor);
        this.logInfo(ctx, `Deleting attachment ${input.attachmentId}`);
        this.validateRequired(input, ['attachmentId'], ctx);
        this.validateUuid(input.attachmentId, 'attachmentId', ctx);
        return this.withCompensation(ctx, async (compensation) => {
            const existing = await prisma_1.default.attachment.findUnique({
                where: { id: input.attachmentId },
            });
            if (!existing || existing.deletedAt) {
                throw new Error(`Attachment "${input.attachmentId}" not found.`);
            }
            const deleted = await shared_1.attachmentService.deleteAttachment(input.attachmentId, input.actor, null);
            compensation.register(`restore-attachment-${input.attachmentId}`, async () => {
                await prisma_1.default.attachment.update({
                    where: { id: input.attachmentId },
                    data: {
                        deletedAt: null,
                        updatedBy: 'system',
                        version: { increment: 1 },
                    },
                });
            });
            await this.publishEvent(ApplicationEvents_1.APP_EVENTS.ATTACHMENT_DELETED, ctx, {
                attachmentId: input.attachmentId,
                projectId: deleted.projectId,
                fileName: deleted.fileName,
            });
            compensation.clear();
            return deleted;
        });
    }
    async getAttachment(attachmentId, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching attachment ${attachmentId}`);
        this.validateUuid(attachmentId, 'attachmentId', ctx);
        const attachment = await prisma_1.default.attachment.findUnique({
            where: { id: attachmentId },
        });
        if (!attachment || attachment.deletedAt) {
            throw new Error(`Attachment "${attachmentId}" not found.`);
        }
        return attachment;
    }
    async getAttachmentsForObject(query, actor, parentCtx) {
        const ctx = parentCtx ?? (0, BaseApplicationService_1.createOperationContext)(actor);
        this.logInfo(ctx, `Fetching attachments with query: ${JSON.stringify(query)}`);
        if (query.projectId) {
            this.validateUuid(query.projectId, 'projectId', ctx);
            return shared_1.attachmentService.findByProject(query.projectId);
        }
        if (query.investigationId) {
            this.validateUuid(query.investigationId, 'investigationId', ctx);
            return shared_1.attachmentService.findByInvestigation(query.investigationId);
        }
        if (query.targetId && query.targetType) {
            this.validateUuid(query.targetId, 'targetId', ctx);
            return shared_1.attachmentService.findByTarget(query.targetId, query.targetType);
        }
        throw new Error('Validation failed: either projectId, investigationId, or (targetId and targetType) must be provided.');
    }
}
exports.AttachmentOrchestrator = AttachmentOrchestrator;
exports.attachmentOrchestrator = new AttachmentOrchestrator();
