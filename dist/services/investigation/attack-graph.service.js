"use strict";
/**
 * AttackGraphService — Phase A5.3.3
 * ===================================
 * Business logic for the attack graph: adding/removing nodes and edges,
 * rebuilding the full graph, and computing shortest paths.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AttackGraphService = void 0;
const BaseService_1 = require("../base/BaseService");
const EventPublisher_1 = require("../base/EventPublisher");
const investigation_1 = require("../../repositories/investigation");
const timeline_service_1 = require("./timeline.service");
const prisma_1 = __importDefault(require("../../lib/prisma"));
class AttackGraphService extends BaseService_1.BaseService {
    constructor(graphRepo = investigation_1.attackGraphRepository, timelineSvc = new timeline_service_1.TimelineService()) {
        super();
        this.graphRepo = graphRepo;
        this.timelineSvc = timelineSvc;
    }
    // ── Node management ───────────────────────────────────────────────────────
    async addNode(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'label', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const node = await this.graphRepo.create(data, transaction);
            await this.timelineSvc.record({
                projectId: node.projectId, investigationId: node.investigationId,
                title: 'Attack Graph Node Added',
                description: `Node "${node.label}" (${node.type}) added to attack graph.`,
                type: 'ATTACK_PATTERN', createdBy: data.createdBy,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AttackGraphNodeAdded', { node });
            return node;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async removeNode(nodeId, actor, tx) {
        this.validateUuid(nodeId, 'nodeId');
        const runInTx = async (transaction) => {
            const node = await this.graphRepo.findNode(nodeId, transaction);
            if (!node)
                throw new Error(`Attack graph node "${nodeId}" not found.`);
            // Cascade: delete edges touching this node
            await prisma_1.default.attackGraphEdge.deleteMany({
                where: { OR: [{ sourceNodeId: nodeId }, { targetNodeId: nodeId }] },
            });
            await this.graphRepo.delete(nodeId, transaction);
            await this.timelineSvc.record({
                projectId: node.projectId, investigationId: node.investigationId,
                title: 'Attack Graph Node Removed',
                description: `Node "${node.label}" removed from attack graph.`,
                type: 'ATTACK_PATTERN', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AttackGraphNodeRemoved', { node });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Edge management ───────────────────────────────────────────────────────
    async addEdge(data, tx) {
        this.validateRequired(data, ['projectId', 'investigationId', 'sourceNodeId', 'targetNodeId', 'createdBy', 'updatedBy']);
        const runInTx = async (transaction) => {
            const edge = await prisma_1.default.attackGraphEdge.create({ data });
            await this.timelineSvc.record({
                projectId: edge.projectId, investigationId: edge.investigationId,
                title: 'Attack Graph Edge Added',
                description: `Edge added: ${edge.sourceNodeId} → ${edge.targetNodeId}.`,
                type: 'ATTACK_CHAIN', createdBy: data.createdBy,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AttackGraphEdgeAdded', { edge });
            return edge;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async removeEdge(edgeId, actor, tx) {
        this.validateUuid(edgeId, 'edgeId');
        const runInTx = async (transaction) => {
            const edge = await prisma_1.default.attackGraphEdge.findUnique({ where: { id: edgeId } });
            if (!edge)
                throw new Error(`Attack graph edge "${edgeId}" not found.`);
            await prisma_1.default.attackGraphEdge.delete({ where: { id: edgeId } });
            await this.timelineSvc.record({
                projectId: edge.projectId, investigationId: edge.investigationId,
                title: 'Attack Graph Edge Removed',
                description: `Edge ${edgeId} removed.`,
                type: 'ATTACK_CHAIN', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AttackGraphEdgeRemoved', { edge });
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    // ── Graph operations ─────────────────────────────────────────────────────
    async rebuildGraph(investigationId, actor, tx) {
        this.validateUuid(investigationId, 'investigationId');
        const runInTx = async (transaction) => {
            const graph = await this.graphRepo.buildGraph(investigationId, transaction);
            await this.timelineSvc.record({
                projectId: graph.nodes[0]?.projectId ?? '', investigationId,
                title: 'Attack Graph Rebuilt',
                description: `Graph rebuilt with ${graph.nodes.length} nodes and ${graph.edges.length} edges.`,
                type: 'ATTACK_PATTERN', createdBy: actor,
            }, transaction);
            await EventPublisher_1.eventPublisher.publish('AttackGraphRebuilt', { investigationId, nodeCount: graph.nodes.length });
            return graph;
        };
        return tx ? runInTx(tx) : prisma_1.default.$transaction(runInTx);
    }
    async getGraph(investigationId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        return this.graphRepo.buildGraph(investigationId, tx);
    }
    /**
     * Calculates all shortest paths from `sourceId` to `targetId` using BFS.
     * Returns paths as arrays of node IDs. Limited to 50 paths to prevent runaway.
     */
    async calculatePaths(investigationId, sourceId, targetId, tx) {
        this.validateUuid(investigationId, 'investigationId');
        this.validateUuid(sourceId, 'sourceId');
        this.validateUuid(targetId, 'targetId');
        const { edges } = await this.graphRepo.buildGraph(investigationId, tx);
        // Build adjacency list
        const adj = new Map();
        for (const e of edges) {
            if (!adj.has(e.sourceNodeId))
                adj.set(e.sourceNodeId, []);
            adj.get(e.sourceNodeId).push(e.targetNodeId);
        }
        // BFS shortest-path search
        const paths = [];
        const queue = [[sourceId]];
        let shortestLength = Infinity;
        while (queue.length > 0 && paths.length < 50) {
            const path = queue.shift();
            if (path.length > shortestLength)
                break;
            const last = path[path.length - 1];
            if (last === targetId) {
                shortestLength = path.length;
                paths.push(path);
                continue;
            }
            for (const next of (adj.get(last) ?? [])) {
                if (!path.includes(next))
                    queue.push([...path, next]);
            }
        }
        return paths;
    }
}
exports.AttackGraphService = AttackGraphService;
