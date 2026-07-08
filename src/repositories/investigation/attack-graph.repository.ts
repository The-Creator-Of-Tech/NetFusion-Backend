import { BaseRepository } from '../base/BaseRepository';
import { AttackGraphNode, AttackGraphEdge, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class AttackGraphRepository extends BaseRepository<AttackGraphNode, Prisma.AttackGraphNodeUncheckedCreateInput, Prisma.AttackGraphNodeUncheckedUpdateInput> {
  constructor() {
    super('attackGraphNode');
  }

  /**
   * Finds all nodes associated with a specific investigation where not deleted.
   */
  async findNodes(investigationId: string, tx?: any): Promise<AttackGraphNode[]> {
    return this.findMany({ filter: { investigationId, deletedAt: null } }, tx);
  }

  /**
   * Finds all edges associated with a specific investigation where not deleted.
   */
  async findEdges(investigationId: string, tx?: any): Promise<AttackGraphEdge[]> {
    const client = tx || prisma;
    return client.attackGraphEdge.findMany({
      where: { investigationId, deletedAt: null },
    });
  }

  /**
   * Finds a node by ID where not deleted.
   */
  async findNode(id: string, tx?: any): Promise<AttackGraphNode | null> {
    return this.findOne({ id, deletedAt: null }, tx);
  }

  /**
   * Finds outgoing edges starting from a specific node where not deleted.
   */
  async findOutgoingEdges(nodeId: string, tx?: any): Promise<AttackGraphEdge[]> {
    const client = tx || prisma;
    return client.attackGraphEdge.findMany({
      where: { sourceNodeId: nodeId, deletedAt: null },
    });
  }

  /**
   * Finds incoming edges ending at a specific node where not deleted.
   */
  async findIncomingEdges(nodeId: string, tx?: any): Promise<AttackGraphEdge[]> {
    const client = tx || prisma;
    return client.attackGraphEdge.findMany({
      where: { targetNodeId: nodeId, deletedAt: null },
    });
  }

  /**
   * Builds the attack graph (retrieves nodes and edges) for a specific investigation.
   */
  async buildGraph(investigationId: string, tx?: any): Promise<{ nodes: AttackGraphNode[]; edges: AttackGraphEdge[] }> {
    const nodes = await this.findNodes(investigationId, tx);
    const edges = await this.findEdges(investigationId, tx);
    return { nodes, edges };
  }
}
