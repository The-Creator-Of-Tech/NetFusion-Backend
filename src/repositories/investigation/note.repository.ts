import { BaseRepository } from '../base/BaseRepository';
import { Note, Prisma } from '@prisma/client';

export class NoteRepository extends BaseRepository<Note, Prisma.NoteUncheckedCreateInput, Prisma.NoteUncheckedUpdateInput> {
  constructor() {
    super('note');
  }

  /**
   * Finds notes associated with a specific investigation where not deleted.
   */
  async findByInvestigation(investigationId: string, tx?: any): Promise<Note[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds pinned notes (stored as metadata.pinned = true) where not deleted.
   */
  async findPinned(tx?: any): Promise<Note[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        metadata: {
          path: ['pinned'],
          equals: true,
        },
      },
    });
  }

  /**
   * Finds notes by their author (createdBy field) where not deleted.
   */
  async findByAuthor(author: string, tx?: any): Promise<Note[]> {
    return this.findMany({ filter: { createdBy: author, deletedAt: null } }, tx);
  }

  /**
   * Searches notes by matching a case-insensitive query in their title or content where not deleted.
   */
  async searchNotes(query: string, tx?: any): Promise<Note[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        OR: [
          { title: { contains: query, mode: 'insensitive' } },
          { content: { contains: query, mode: 'insensitive' } },
        ],
      },
    });
  }
}
