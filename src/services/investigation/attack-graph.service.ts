/**
 * AttackGraphService — Phase A5.3.3
 * ===================================
 * Business logic for the attack graph: adding/removing nodes and edges,
 * rebuilding the full graph, and computing shortest paths.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { attackGraphRepository } from '../../repositories/investigation';
import { TimelineService } from './timeline.service';
import prisma from '../../lib/prisma';
import { AttackGraphNode, AttackGraphEdge, Prisma } from '@prisma/client';

interface GraphData {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export class AttackGraphService extends BaseService {
  constructor(
    private readonly graphRepo    = attackGraphRepository,
    private readonly timelineSvc  = new TimelineService(),
  ) { super(); }

  // ── Node management ───────────────────────────────────────────────────────

  async addNode(data: Prisma.AttackGraphNodeUncheckedCreateInput, tx?: any): Promise<AttackGraphNode> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'label', 'createdBy', 'updatedBy']);
    const runInTx = async (transaction: any) => {
      const node = await this.graphRepo.create(data, transaction);
      await this.timelineSvc.record({
        projectId: node.projectId, investigationId: node.investigationId,
        title: 'Attack Graph Node Added',
        description: `Node "${node.label}" (${node.type}) added to attack graph.`,
        type: 'ATTACK_PATTERN', createdBy: data.createdBy as string,
      }, transaction);
      await eventPublisher.publish('AttackGraphNodeAdded', { node });
      return node;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async removeNode(nodeId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(nodeId, 'nodeId');
    const runInTx = async (transaction: any) => {
      const node = await this.graphRepo.findNode(nodeId, transaction);
      if (!node) throw new Error(`Attack graph node "${nodeId}" not found.`);
      // Cascade: delete edges touching this node
      await prisma.attackGraphEdge.deleteMany({
        where: { OR: [{ sourceNodeId: nodeId }, { targetNodeId: nodeId }] },
      });
      await this.graphRepo.delete(nodeId, transaction);
      await this.timelineSvc.record({
        projectId: node.projectId, investigationId: node.investigationId,
        title: 'Attack Graph Node Removed',
        description: `Node "${node.label}" removed from attack graph.`,
        type: 'ATTACK_PATTERN', createdBy: actor,
      }, transaction);
      await eventPublisher.publish('AttackGraphNodeRemoved', { node });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Edge management ───────────────────────────────────────────────────────

  async addEdge(data: Prisma.AttackGraphEdgeUncheckedCreateInput, tx?: any): Promise<AttackGraphEdge> {
    this.validateRequired(data as any, ['projectId', 'investigationId', 'sourceNodeId', 'targetNodeId', 'createdBy', 'updatedBy']);
    const runInTx = async (transaction: any) => {
      const edge = await prisma.attackGraphEdge.create({ data });
      await this.timelineSvc.record({
        projectId: edge.projectId, investigationId: edge.investigationId,
        title: 'Attack Graph Edge Added',
        description: `Edge added: ${edge.sourceNodeId} → ${edge.targetNodeId}.`,
        type: 'ATTACK_CHAIN', createdBy: data.createdBy as string,
      }, transaction);
      await eventPublisher.publish('AttackGraphEdgeAdded', { edge });
      return edge;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async removeEdge(edgeId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(edgeId, 'edgeId');
    const runInTx = async (transaction: any) => {
      const edge = await prisma.attackGraphEdge.findUnique({ where: { id: edgeId } });
      if (!edge) throw new Error(`Attack graph edge "${edgeId}" not found.`);
      await prisma.attackGraphEdge.delete({ where: { id: edgeId } });
      await this.timelineSvc.record({
        projectId: edge.projectId, investigationId: edge.investigationId,
        title: 'Attack Graph Edge Removed',
        description: `Edge ${edgeId} removed.`,
        type: 'ATTACK_CHAIN', createdBy: actor,
      }, transaction);
      await eventPublisher.publish('AttackGraphEdgeRemoved', { edge });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Graph operations ─────────────────────────────────────────────────────

  async rebuildGraph(investigationId: string, actor: string, tx?: any): Promise<GraphData> {
    this.validateUuid(investigationId, 'investigationId');
    const runInTx = async (transaction: any) => {
      const graph = await this.graphRepo.buildGraph(investigationId, transaction);
      await this.timelineSvc.record({
        projectId: graph.nodes[0]?.projectId ?? '', investigationId,
        title: 'Attack Graph Rebuilt',
        description: `Graph rebuilt with ${graph.nodes.length} nodes and ${graph.edges.length} edges.`,
        type: 'ATTACK_PATTERN', createdBy: actor,
      }, transaction);
      await eventPublisher.publish('AttackGraphRebuilt', { investigationId, nodeCount: graph.nodes.length });
      return graph;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async getGraph(investigationId: string, tx?: any): Promise<GraphData> {
    this.validateUuid(investigationId, 'investigationId');
    return this.graphRepo.buildGraph(investigationId, tx);
  }

  /**
   * Calculates all shortest paths from `sourceId` to `targetId` using BFS.
   * Returns paths as arrays of node IDs. Limited to 50 paths to prevent runaway.
   */
  async calculatePaths(investigationId: string, sourceId: string, targetId: string, tx?: any): Promise<string[][]> {
    this.validateUuid(investigationId, 'investigationId');
    this.validateUuid(sourceId,        'sourceId');
    this.validateUuid(targetId,        'targetId');

    const { edges } = await this.graphRepo.buildGraph(investigationId, tx);
    // Build adjacency list
    const adj = new Map<string, string[]>();
    for (const e of edges) {
      if (!adj.has(e.sourceNodeId)) adj.set(e.sourceNodeId, []);
      adj.get(e.sourceNodeId)!.push(e.targetNodeId);
    }

    // BFS shortest-path search
    const paths: string[][] = [];
    const queue: string[][] = [[sourceId]];
    let shortestLength = Infinity;

    while (queue.length > 0 && paths.length < 50) {
      const path = queue.shift()!;
      if (path.length > shortestLength) break;
      const last = path[path.length - 1];
      if (last === targetId) {
        shortestLength = path.length;
        paths.push(path);
        continue;
      }
      for (const next of (adj.get(last) ?? [])) {
        if (!path.includes(next)) queue.push([...path, next]);
      }
    }
    return paths;
  }
}
