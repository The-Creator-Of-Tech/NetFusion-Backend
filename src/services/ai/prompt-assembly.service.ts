/**
 * PromptAssemblyService — Phase A5.3.4
 * ======================================
 * Manages prompt assembly lifecycle: creation, publishing, archiving,
 * section management, template application, token budget tracking.
 * Publishes events on prompt mutations and token threshold events.
 */

import { BaseService } from '../base/BaseService';
import { eventPublisher } from '../base/EventPublisher';
import { promptAssemblyRepository } from '../../repositories/ai';
import prisma from '../../lib/prisma';
import {
  PromptAssembly,
  PromptSection,
  PromptStatus,
  Prisma,
} from '@prisma/client';

export class PromptAssemblyService extends BaseService {
  constructor(
    private readonly promptRepo = promptAssemblyRepository,
  ) {
    super();
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  async createPrompt(
    data: Prisma.PromptAssemblyUncheckedCreateInput,
    tx?: any,
  ): Promise<PromptAssembly> {
    this.validateRequired(data as any, ['investigationId', 'projectId', 'systemPrompt', 'userPrompt', 'createdBy', 'updatedBy']);
    this.validateUuid(data.investigationId, 'investigationId');
    this.validateUuid(data.projectId, 'projectId');
    if (data.reasoningId) this.validateUuid(data.reasoningId as string, 'reasoningId');
    if (data.contextId) this.validateUuid(data.contextId as string, 'contextId');
    if (data.userId) this.validateUuid(data.userId as string, 'userId');

    const runInTx = async (transaction: any) => {
      const prompt = await this.promptRepo.create(data, transaction);
      await eventPublisher.publish('PromptAssemblyCreated', { prompt });
      return prompt;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Lifecycle transitions ────────────────────────────────────────────────────

  async publishPrompt(id: string, actor: string, tx?: any): Promise<PromptAssembly> {
    return this._transition(id, 'ACTIVE', actor, 'PromptAssemblyPublished', tx);
  }

  async archivePrompt(id: string, actor: string, tx?: any): Promise<PromptAssembly> {
    return this._transition(id, 'ARCHIVED', actor, 'PromptAssemblyArchived', tx);
  }

  async draftPrompt(id: string, actor: string, tx?: any): Promise<PromptAssembly> {
    return this._transition(id, 'DRAFT', actor, 'PromptAssemblyDrafted', tx);
  }

  // ── Section management ───────────────────────────────────────────────────────

  async addSection(
    promptId: string,
    data: {
      title: string;
      content: string;
      priority?: number;
      metadata?: any;
      createdBy: string;
      updatedBy: string;
    },
    tx?: any,
  ): Promise<PromptSection> {
    this.validateUuid(promptId, 'promptId');
    this.validateRequired(data as any, ['title', 'content', 'createdBy', 'updatedBy']);

    const runInTx = async (transaction: any) => {
      const prompt = await this.promptRepo.findById(promptId, transaction);
      if (!prompt || prompt.deletedAt) {
        throw new Error(`PromptAssembly "${promptId}" not found.`);
      }

      const client = transaction || prisma;
      const section: PromptSection = await client.promptSection.create({
        data: {
          promptId,
          title: data.title,
          content: data.content,
          priority: data.priority ?? 50,
          metadata: data.metadata ?? null,
          createdBy: data.createdBy,
          updatedBy: data.updatedBy,
        },
      });

      await eventPublisher.publish('PromptSectionAdded', { promptId, section });
      return section;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async updateSection(
    sectionId: string,
    data: Partial<Prisma.PromptSectionUncheckedUpdateInput>,
    tx?: any,
  ): Promise<PromptSection> {
    this.validateUuid(sectionId, 'sectionId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: PromptSection | null = await client.promptSection.findUnique({ where: { id: sectionId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`PromptSection "${sectionId}" not found.`);
      }

      const updated: PromptSection = await client.promptSection.update({
        where: { id: sectionId },
        data: {
          ...data,
          updatedAt: new Date(),
          version: (existing.version ?? 1) + 1,
        },
      });

      await eventPublisher.publish('PromptSectionUpdated', { section: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async deleteSection(sectionId: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(sectionId, 'sectionId');

    const runInTx = async (transaction: any) => {
      const client = transaction || prisma;
      const existing: PromptSection | null = await client.promptSection.findUnique({ where: { id: sectionId } });
      if (!existing || existing.deletedAt) {
        throw new Error(`PromptSection "${sectionId}" not found.`);
      }

      await client.promptSection.update({
        where: { id: sectionId },
        data: {
          deletedAt: new Date(),
          updatedBy: actor,
          version: (existing.version ?? 1) + 1,
        },
      });

      await eventPublisher.publish('PromptSectionDeleted', { sectionId });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Assembly / Token budget ──────────────────────────────────────────────────

  async assemblePrompt(promptId: string, tx?: any): Promise<string> {
    this.validateUuid(promptId, 'promptId');
    const runInTx = async (transaction: any) => {
      const prompt = await this.promptRepo.findById(promptId, transaction);
      if (!prompt || prompt.deletedAt) {
        throw new Error(`PromptAssembly "${promptId}" not found.`);
      }

      const sections = await this.promptRepo.findSections(promptId, transaction);
      const sortedSections = sections.sort((a, b) => (b.priority ?? 50) - (a.priority ?? 50));

      let assembled = `SYSTEM:\n${prompt.systemPrompt}\n\nUSER:\n${prompt.userPrompt}\n\n`;
      for (const section of sortedSections) {
        assembled += `--- ${section.title} ---\n${section.content}\n\n`;
      }

      return assembled;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  async calculateTokenUsage(promptId: string, tx?: any): Promise<number> {
    this.validateUuid(promptId, 'promptId');
    const assembled = await this.assemblePrompt(promptId, tx);
    // Rough token estimate: 1 token ≈ 4 characters (GPT-style tokenization heuristic)
    return Math.ceil(assembled.length / 4);
  }

  async checkTokenBudget(promptId: string, tx?: any): Promise<{
    estimatedTokens: number;
    maxTokens: number;
    reservedTokens: number;
    withinBudget: boolean;
  }> {
    this.validateUuid(promptId, 'promptId');
    const runInTx = async (transaction: any) => {
      const prompt = await this.promptRepo.findById(promptId, transaction);
      if (!prompt || prompt.deletedAt) {
        throw new Error(`PromptAssembly "${promptId}" not found.`);
      }

      const estimatedTokens = await this.calculateTokenUsage(promptId, transaction);
      const maxTokens = prompt.maxTokens ?? 8192;
      const reservedTokens = prompt.reservedTokens ?? 1024;
      const withinBudget = estimatedTokens <= maxTokens - reservedTokens;

      return { estimatedTokens, maxTokens, reservedTokens, withinBudget };
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Search ───────────────────────────────────────────────────────────────────

  async searchSections(query: string, tx?: any): Promise<PromptSection[]> {
    if (!query || query.trim().length === 0) {
      throw new Error('Validation failed: search query must not be empty.');
    }
    return this.promptRepo.searchSections(query, tx);
  }

  // ── Read helpers ─────────────────────────────────────────────────────────────

  async findPrompt(id: string, tx?: any): Promise<PromptAssembly | null> {
    this.validateUuid(id, 'promptId');
    return this.promptRepo.findById(id, tx);
  }

  async findByProject(projectId: string, tx?: any): Promise<PromptAssembly[]> {
    this.validateUuid(projectId, 'projectId');
    return this.promptRepo.findByProject(projectId, tx);
  }

  async findPublished(tx?: any): Promise<PromptAssembly[]> {
    return this.promptRepo.findPublished(tx);
  }

  async findSections(promptId: string, tx?: any): Promise<PromptSection[]> {
    this.validateUuid(promptId, 'promptId');
    return this.promptRepo.findSections(promptId, tx);
  }

  // ── Soft delete ──────────────────────────────────────────────────────────────

  async deletePrompt(id: string, actor: string, tx?: any): Promise<void> {
    this.validateUuid(id, 'promptId');
    const runInTx = async (transaction: any) => {
      const existing = await this.promptRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`PromptAssembly "${id}" not found.`);
      }
      await this.promptRepo.softDelete(id, actor, transaction);
      await eventPublisher.publish('PromptAssemblyDeleted', { promptId: id });
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }

  // ── Internal ─────────────────────────────────────────────────────────────────

  private async _transition(
    id: string,
    status: PromptStatus,
    actor: string,
    event: string,
    tx?: any,
  ): Promise<PromptAssembly> {
    this.validateUuid(id, 'promptId');
    const runInTx = async (transaction: any) => {
      const existing = await this.promptRepo.findById(id, transaction);
      if (!existing || existing.deletedAt) {
        throw new Error(`PromptAssembly "${id}" not found.`);
      }
      const updated = await this.promptRepo.update(
        id,
        { status, updatedBy: actor },
        transaction,
      );
      await eventPublisher.publish(event, { prompt: updated });
      return updated;
    };
    return tx ? runInTx(tx) : prisma.$transaction(runInTx);
  }
}
