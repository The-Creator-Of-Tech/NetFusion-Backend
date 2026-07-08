import { BaseRepository } from '../base/BaseRepository';
import { MitreTechnique, MitreMitigation, MitreTacticType, Prisma } from '@prisma/client';
import prisma from '../../lib/prisma';

export class MitreRepository extends BaseRepository<MitreTechnique, Prisma.MitreTechniqueUncheckedCreateInput, Prisma.MitreTechniqueUncheckedUpdateInput> {
  constructor() {
    super('mitreTechnique');
  }

  /**
   * Finds a MITRE technique by its mitreId where not deleted.
   */
  async findTechniqueByMitreId(mitreId: string, tx?: any): Promise<MitreTechnique | null> {
    return this.findOne({ mitreId, deletedAt: null }, tx);
  }

  /**
   * Finds techniques by tactic ID where not deleted.
   */
  async findByTactic(tacticId: string, tx?: any): Promise<MitreTechnique[]> {
    return this.findMany({ filter: { tacticId, deletedAt: null } }, tx);
  }

  /**
   * Finds techniques by platform where not deleted.
   */
  async findByPlatform(platform: string, tx?: any): Promise<MitreTechnique[]> {
    return this.findMany(
      {
        filter: {
          platforms: { has: platform },
          deletedAt: null,
        },
      },
      tx
    );
  }

  /**
   * Finds techniques by data source where not deleted.
   */
  async findByDataSource(dataSource: string, tx?: any): Promise<MitreTechnique[]> {
    return this.findMany({ filter: { dataSource, deletedAt: null } }, tx);
  }

  /**
   * Finds techniques mitigated by a specific mitigation ID where not deleted.
   */
  async findByMitigation(mitigationId: string, tx?: any): Promise<MitreTechnique[]> {
    return this.findMany(
      {
        filter: {
          mitigations: { some: { id: mitigationId } },
          deletedAt: null,
        },
      },
      tx
    );
  }

  /**
   * Finds sub-techniques of a parent technique where not deleted.
   */
  async findSubTechniques(parentMitreId: string, tx?: any): Promise<MitreTechnique[]> {
    return this.findMany(
      {
        filter: {
          mitreId: { startsWith: `${parentMitreId}.` },
          deletedAt: null,
        },
      },
      tx
    );
  }

  /**
   * Finds the parent technique of a sub-technique where not deleted.
   */
  async findParentTechnique(subTechniqueMitreId: string, tx?: any): Promise<MitreTechnique | null> {
    const parts = subTechniqueMitreId.split('.');
    if (parts.length <= 1) return null;
    const parentId = parts[0];
    return this.findTechniqueByMitreId(parentId, tx);
  }

  /**
   * Finds mitigations linked to a specific technique where not deleted.
   */
  async findMitigations(techniqueId: string, tx?: any): Promise<MitreMitigation[]> {
    const client = tx || prisma;
    return client.mitreMitigation.findMany({
      where: {
        techniques: { some: { id: techniqueId } },
        deletedAt: null,
      },
    });
  }

  /**
   * Finds detection rules (from Rules table) associated with a technique where not deleted.
   */
  async findDetectionRules(techniqueId: string, tx?: any): Promise<any[]> {
    const technique = await this.findById(techniqueId, tx);
    if (!technique) return [];
    const client = tx || prisma;
    return client.rule.findMany({
      where: {
        deletedAt: null,
        metadata: {
          path: ['techniques'],
          equals: [technique.mitreId],
        },
      },
    });
  }

  /**
   * Finds techniques by MITRE attack phase (tacticType) where not deleted.
   */
  async findByAttackPhase(phase: MitreTacticType, tx?: any): Promise<MitreTechnique[]> {
    const delegate = this.getDelegate(tx);
    return delegate.findMany({
      where: {
        deletedAt: null,
        tactic: {
          tacticType: phase,
          deletedAt: null,
        },
      },
    });
  }
}
