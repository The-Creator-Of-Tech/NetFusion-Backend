"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AttackGraphRepository = void 0;
const BaseRepository_1 = require("../base/BaseRepository");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class AttackGraphRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('attackGraphNode');
    }
    /**
     * Finds all nodes associated with a specific investigation where not deleted.
     */
    async findNodes(investigationId, tx) {
        return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
    }
    /**
     * Finds all edges associated with a specific investigation where not deleted.
     */
    async findEdges(investigationId, tx) {
        const client = tx || prisma_1.default;
        return client.attackGraphEdge.findMany({
            where: { investigationId, deletedAt: null },
        });
    }
    /**
     * Finds a node by ID where not deleted.
     */
    async findNode(id, tx) {
        return this.findOne({ id, deletedAt: null }, tx);
    }
    /**
     * Finds outgoing edges starting from a specific node where not deleted.
     */
    async findOutgoingEdges(nodeId, tx) {
        const client = tx || prisma_1.default;
        return client.attackGraphEdge.findMany({
            where: { sourceNodeId: nodeId, deletedAt: null },
        });
    }
    /**
     * Finds incoming edges ending at a specific node where not deleted.
     */
    async findIncomingEdges(nodeId, tx) {
        const client = tx || prisma_1.default;
        return client.attackGraphEdge.findMany({
            where: { targetNodeId: nodeId, deletedAt: null },
        });
    }
    /**
     * Builds the attack graph (retrieves nodes and edges) for a specific investigation.
     */
    async buildGraph(investigationId, tx) {
        const nodes = await this.findNodes(investigationId, tx);
        const edges = await this.findEdges(investigationId, tx);
        return { nodes, edges };
    }
}
exports.AttackGraphRepository = AttackGraphRepository;
