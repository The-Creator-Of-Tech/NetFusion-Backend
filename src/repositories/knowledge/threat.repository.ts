import { BaseRepository } from '../base/BaseRepository';
import { ThreatActor, ThreatCampaign, ThreatRelationship, MitreTechnique, IOC, CVE, ThreatLevel, ThreatStatus, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class ThreatRepository extends BaseRepository<ThreatActor, Prisma.ThreatActorUncheckedCreateInput, Prisma.ThreatActorUncheckedUpdateInput> {
  constructor() {
    super('threatActor');
  }

  /**
   * Finds threat actors by severity level where not deleted.
   */
  async findByThreatLevel(severity: ThreatLevel, tx?: any): Promise<ThreatActor[]> {
    return this.findMany({ filter: { severity, deletedAt: null } }, tx);
  }

  /**
   * Finds threat actors by status where not deleted.
   */
  async findByStatus(status: ThreatStatus, tx?: any): Promise<ThreatActor[]> {
    return this.findMany({ filter: { status, deletedAt: null } }, tx);
  }

  /**
   * Finds threat actors by name contains or in aliases where not deleted.
   */
  async findByActor(name: string, tx?: any): Promise<ThreatActor[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        OR: [
          { name: { contains: name, mode: 'insensitive' } },
          { aliases: { has: name } },
        ],
      },
    });
  }

  /**
   * Finds threat actors involved in a campaign by campaign UUID or string code where not deleted.
   */
  async findByCampaign(campaignId: string, tx?: any): Promise<ThreatActor[]> {
    const delegate = this.getDelegate(tx);
    const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(campaignId);
    return delegate.findMany({
      where: {
        deletedAt: null,
        campaigns: {
          some: {
            OR: isUuid
              ? [{ id: campaignId }, { campaignId: campaignId }]
              : [{ campaignId: campaignId }],
            deletedAt: null,
          },
        },
      },
    });
  }

  /**
   * Finds campaigns associated with a specific threat actor ID where not deleted.
   */
  async findCampaigns(threatActorId: string, tx?: any): Promise<ThreatCampaign[]> {
    const client = tx || prisma;
    return client.threatCampaign.findMany({
      where: {
        threatActors: { some: { id: threatActorId } },
        deletedAt: null,
      },
    });
  }

  /**
   * Finds relationships associated with a specific threat actor ID where not deleted.
   */
  async findRelationships(threatActorId: string, tx?: any): Promise<ThreatRelationship[]> {
    const client = tx || prisma;
    return client.threatRelationship.findMany({
      where: {
        threatId: threatActorId,
        deletedAt: null,
      },
    });
  }

  /**
   * Finds techniques used by a threat actor where not deleted.
   */
  async findTechniques(threatActorId: string, tx?: any): Promise<MitreTechnique[]> {
    const client = tx || prisma;
    return client.mitreTechnique.findMany({
      where: {
        threatActors: { some: { id: threatActorId } },
        deletedAt: null,
      },
    });
  }

  /**
   * Finds IOCs associated with a threat actor where not deleted.
   */
  async findAssociatedIOCs(threatActorId: string, tx?: any): Promise<IOC[]> {
    const client = tx || prisma;
    return client.iOC.findMany({
      where: {
        threatActors: { some: { id: threatActorId } },
        deletedAt: null,
      },
    });
  }

  /**
   * Finds CVEs indirectly associated with a threat actor through ThreatRelationship table where not deleted.
   */
  async findAssociatedCVEs(threatActorId: string, tx?: any): Promise<CVE[]> {
    const client = tx || prisma;
    const relationships = await client.threatRelationship.findMany({
      where: {
        threatId: threatActorId,
        cveId: { not: null },
        deletedAt: null,
      },
      select: { cveId: true },
    });
    const cveIds = relationships.map((r: { cveId: string | null }) => r.cveId as string).filter(Boolean);
    if (cveIds.length === 0) return [];
    return client.cVE.findMany({
      where: {
        id: { in: cveIds },
        deletedAt: null,
      },
    });
  }
}
