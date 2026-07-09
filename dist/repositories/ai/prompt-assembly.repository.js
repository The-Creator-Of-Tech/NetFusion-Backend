"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PromptAssemblyRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class PromptAssemblyRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('promptAssembly');
    }
    /**
     * Finds draft prompt assemblies (status: DRAFT and not deleted).
     */
    async findDrafts(tx) {
        return this.findMany({ filter: { status: 'DRAFT', deletedAt: null } }, tx);
    }
    /**
     * Finds published/active prompt assemblies (status: ACTIVE and not deleted).
     */
    async findPublished(tx) {
        return this.findMany({ filter: { status: 'ACTIVE', deletedAt: null } }, tx);
    }
    /**
     * Finds archived prompt assemblies (status: ARCHIVED and not deleted).
     */
    async findArchived(tx) {
        return this.findMany({ filter: { status: 'ARCHIVED', deletedAt: null } }, tx);
    }
    /**
     * Finds prompt assemblies by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds prompt sections associated with a specific prompt assembly ID where not deleted.
     */
    async findSections(promptId, tx) {
        const client = tx || prisma_1.default;
        return client.promptSection.findMany({
            where: { promptId, deletedAt: null },
        });
    }
    /**
     * Searches for prompt sections containing a query string case-insensitively in title or content where not deleted.
     */
    async searchSections(query, tx) {
        const client = tx || prisma_1.default;
        return client.promptSection.findMany({
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
exports.PromptAssemblyRepository = PromptAssemblyRepository;
