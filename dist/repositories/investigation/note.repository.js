"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NoteRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class NoteRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('note');
    }
    /**
     * Finds notes associated with a specific investigation where not deleted.
     */
    async findByInvestigation(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds pinned notes (stored as metadata.pinned = true) where not deleted.
     */
    async findPinned(tx) {
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
    async findByAuthor(author, tx) {
        return this.findMany({ filter: { createdBy: author, deletedAt: null } }, tx);
    }
    /**
     * Searches notes by matching a case-insensitive query in their title or content where not deleted.
     */
    async searchNotes(query, tx) {
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
exports.NoteRepository = NoteRepository;
