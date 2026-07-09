"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvestigationRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
class InvestigationRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('investigation');
    }
    /**
     * Finds investigations by project ID where not deleted.
     */
    async findByProject(projectId, tx) {
        return this.findMany({ filter: { projectId, deletedAt: null } }, tx);
    }
    /**
     * Finds investigations by status where not deleted.
     */
    async findByStatus(status, tx) {
        return this.findMany({ filter: { status, deletedAt: null } }, tx);
    }
    /**
     * Finds open investigations (status: OPEN and not deleted).
     */
    async findOpen(tx) {
        return this.findMany({ filter: { status: 'OPEN', deletedAt: null } }, tx);
    }
    /**
     * Finds an investigation by ID and includes its assets.
     */
    async findWithAssets(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                assets: true,
            },
        });
    }
    /**
     * Finds an investigation by ID and includes its findings.
     */
    async findWithFindings(id, tx) {
        return this.getDelegate(tx).findUnique({
            where: { id },
            include: {
                findings: true,
            },
        });
    }
    /**
     * Finds completed investigations (status: RESOLVED or CLOSED, and not deleted).
     */
    async findComplete(tx) {
        return this.findMany({
            filter: {
                status: { in: ['RESOLVED', 'CLOSED'] },
                deletedAt: null,
            },
        }, tx);
    }
}
exports.InvestigationRepository = InvestigationRepository;
