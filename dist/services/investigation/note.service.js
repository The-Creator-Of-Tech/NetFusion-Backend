"use strict";
/**
 * NoteService — Phase A5.3.3
 * ============================
 * Business logic for Note management: creation, update, pin/unpin,
 * full-text search, and export.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NoteService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class NoteService extends BaseService_1.BaseService {
    constructor(noteRepo = investigation_1.noteRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.noteRepo = noteRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Create ─────────────────────────────────────────────────────────────────
    async createNote(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'content', 'createdBy', 'updatedBy']);
        this.validateUuid(data.projectId, 'projectId');
        this.validateUuid(data.investigationId, 'investigationId');
        const runInTx = async (transaction) => {
            const note = await this.noteRepo.create(data, transaction);
            await this.timelineSvc.record({
                projectId: note.projectId, investigationId: note.investigationId,
                title: 'Note Created',
                description: `Note "${note.title ?? '(untitled)'}" added.`,
                type: 'MANUAL_ACTION', createdBy: data.createdBy,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('NoteCreated', { note });
            return note;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Update ─────────────────────────────────────────────────────────────────
    async updateNote(id, data, tx) {
        this.validateUuid(id, 'noteId');
        const runInTx = async (transaction) => {
            const existing = await this.noteRepo.findById(id, transaction);
            if (!existing || existing.deletedAt)
                throw new Error(`Note "${id}" not found.`);
            const updated = await this.noteRepo.update(id, data, transaction);
            await this.timelineSvc.recordUpdate(updated.projectId, updated.investigationId, 'Note', id, 'content updated', data.updatedBy ?? 'system', transaction);
            await EventPublisher_1.eventPublisher.publish('NoteUpdated', { note: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Pin / Unpin ────────────────────────────────────────────────────────────
    async pinNote(id, actor, tx) {
        this.validateUuid(id, 'noteId');
        const runInTx = async (transaction) => {
            const note = await this.noteRepo.findById(id, transaction);
            if (!note || note.deletedAt)
                throw new Error(`Note "${id}" not found.`);
            const meta = { ...(note.metadata ?? {}), pinned: true };
            const updated = await this.noteRepo.update(id, { metadata: meta, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('NotePinned', { note: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async unpinNote(id, actor, tx) {
        this.validateUuid(id, 'noteId');
        const runInTx = async (transaction) => {
            const note = await this.noteRepo.findById(id, transaction);
            if (!note || note.deletedAt)
                throw new Error(`Note "${id}" not found.`);
            const meta = { ...(note.metadata ?? {}), pinned: false };
            const updated = await this.noteRepo.update(id, { metadata: meta, updatedBy: actor }, transaction);
            await EventPublisher_1.eventPublisher.publish('NoteUnpinned', { note: updated });
            return updated;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Search ─────────────────────────────────────────────────────────────────
    async searchNotes(query, tx) {
        if (!query || !query.trim())
            return [];
        return this.noteRepo.searchNotes(query.trim(), tx);
    }
    async getPinned(tx) {
        return this.noteRepo.findPinned(tx);
    }
    async getByInvestigation(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.noteRepo.findByInvestigation(investigationId, tx);
    }
    // ── Export ─────────────────────────────────────────────────────────────────
    async exportNotes(investigationId, format = 'markdown', tx) {
        this.validateUuid(investigationId, 'investigationId');
        const notes = await this.noteRepo.findByInvestigation(investigationId, tx);
        if (format === 'markdown') {
            return notes.map(n => `## ${n.title ?? '(untitled)'}\n\n${n.content}\n\n---\n`).join('\n');
        }
        return notes.map(n => `${n.title ?? '(untitled)'}\n${n.content}\n\n`).join('');
    }
    // ── Delete ─────────────────────────────────────────────────────────────────
    async deleteNote(id, actor, tx) {
        this.validateUuid(id, 'noteId');
        const runInTx = async (transaction) => {
            const note = await this.noteRepo.findById(id, transaction);
            if (!note || note.deletedAt)
                throw new Error(`Note "${id}" not found.`);
            await this.noteRepo.softDelete(id, actor, transaction);
            await EventPublisher_1.eventPublisher.publish('NoteDeleted', { noteId: id });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
}
exports.NoteService = NoteService;
