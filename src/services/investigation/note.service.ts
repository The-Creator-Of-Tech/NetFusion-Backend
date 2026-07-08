/**
 * NoteService — Phase A5.3.3
 * ============================
 * Business logic for Note management: creation, update, pin/unpin,
 * full-text search, and export.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { noteRepository } from '../../repositories/investigation';
import { TimelineService } from './timeline.service';
import prisma from '../../lib/prisma';
import { Note, Prisma } from '@prisma/client';

export class NoteService extends BaseService {
  constructor(
    private readonly noteRepo     = noteRepository,
    private readonly timelineSvc  = new TimelineService(),
  ) { super(); }

  // ── Create ─────────────────────────────────────────────────────────────────

  async createNote(data: Prisma.NoteUncheckedCreateInput, tx?: any): Promise<Note> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'content', 'createdBy', 'updatedBy']);
    this.validateUuid(data.projectId, 'projectId');
    this.validateUuid(data.investigationId, 'investigationId');

    const runInTx = async (transaction: any) => {
      const note = await this.noteRepo.create(data, transaction);
      await this.timelineSvc.record({
        projectId: note.projectId, investigationId: note.investigationId,
        title: 'Note Created',
        description: `Note "${note.title ?? '(untitled)'}" added.`,
        type: 'MANUAL_ACTION', createdBy: data.createdBy as string,
      }, transaction);
      await eventPublisher.publish('NoteCreated', { note });
      return note;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Update ─────────────────────────────────────────────────────────────────

  async updateNote(id: string, data: Prisma.NoteUncheckedUpdateInput, tx?: any): Promise<Note> {
    this.validateUuid(id, 'noteId');
    const runInTx = async (transaction: any) => {
      const existing = await this.noteRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) throw new Error(`Note "${id}" not found.`);
      const updated = await this.noteRepo.update(id, data, transaction);
      await this.timelineSvc.recordUpdate(
        updated.projectId, updated.investigationId, 'Note', id,
        'content updated', (data.updatedBy as string) ?? 'system', transaction,
      );
      await eventPublisher.publish('NoteUpdated', { note: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Pin / Unpin ────────────────────────────────────────────────────────────

  async pinNote(id: string, actor: string, tx?: any): Promise<Note> {
    this.validateUuid(id, 'noteId');
    const runInTx = async (transaction: any) => {
      const note = await this.noteRepo.findById(id, transaction);
      if (!note || note.deletedAt) throw new Error(`Note "${id}" not found.`);
      const meta = { ...(note.metadata as any ?? {}), pinned: true };
      const updated = await this.noteRepo.update(id, { metadata: meta, updatedBy: actor }, transaction);
      await eventPublisher.publish('NotePinned', { note: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async unpinNote(id: string, actor: string, tx?: any): Promise<Note> {
    this.validateUuid(id, 'noteId');
    const runInTx = async (transaction: any) => {
      const note = await this.noteRepo.findById(id, transaction);
      if (!note || note.deletedAt) throw new Error(`Note "${id}" not found.`);
      const meta = { ...(note.metadata as any ?? {}), pinned: false };
      const updated = await this.noteRepo.update(id, { metadata: meta, updatedBy: actor }, transaction);
      await eventPublisher.publish('NoteUnpinned', { note: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Search ─────────────────────────────────────────────────────────────────

  async searchNotes(query: string, tx?: any): Promise<Note[]> {
    if (!query || !query.trim()) return [];
    return this.noteRepo.searchNotes(query.trim(), tx);
  }

  async getPinned(tx?: any): Promise<Note[]> {
    return this.noteRepo.findPinned(tx);
  }

  async getByInvestigation(investigationId: string, tx?: any): Promise<Note[]> {
    this.validateUuid(investigationId, 'investigationId');
    return this.noteRepo.findByInvestigation(investigationId, tx);
  }

  // ── Export ─────────────────────────────────────────────────────────────────

  async exportNotes(investigationId: string, format: 'markdown' | 'text' = 'markdown', tx?: any): Promise<string> {
    this.validateUuid(investigationId, 'investigationId');
    const notes = await this.noteRepo.findByInvestigation(investigationId, tx);
    if (format === 'markdown') {
      return notes.map(n =>
        `## ${n.title ?? '(untitled)'}\n\n${n.content}\n\n---\n`
      ).join('\n');
    }
    return notes.map(n => `${n.title ?? '(untitled)'}\n${n.content}\n\n`).join('');
  }

  // ── Delete ─────────────────────────────────────────────────────────────────

  async deleteNote(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'noteId');
    const runInTx = async (transaction: any) => {
      const note = await this.noteRepo.findById(id, transaction);
      if (!note || note.deletedAt) throw new Error(`Note "${id}" not found.`);
      await this.noteRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('NoteDeleted', { noteId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
