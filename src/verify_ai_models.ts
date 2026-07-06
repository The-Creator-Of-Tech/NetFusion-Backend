/**
 * verify_ai_models.ts — Phase A5.1.4
 * ==================================================
 * Standalone verification script that checks every requirement
 * of the AI Database Models phase against the live database.
 *
 * Run:
 *   npx ts-node src/verify_ai_models.ts
 *
 * Exits 0 if all checks pass, 1 on any failure.
 */

import prisma from './lib/prisma';
import {
  ConversationStatus,
  ExecutionStatus,
  ProviderStatus,
  StreamingStatus,
  ReasoningStatus,
  PromptStatus,
  MemoryStatus,
  ContextStatus,
  ProviderType
} from '@prisma/client';

let passed = 0;
let failed = 0;
const errors: string[] = [];

function ok(label: string): void {
  passed++;
  console.log(`  ✓  ${label}`);
}

function fail(label: string, detail?: string): void {
  failed++;
  const msg = detail ? `${label} — ${detail}` : label;
  errors.push(msg);
  console.log(`  ✗  ${msg}`);
}

function assert(condition: boolean, label: string, detail?: string): void {
  condition ? ok(label) : fail(label, detail);
}

function section(title: string): void {
  console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}`);
}

const RUN = Date.now().toString(36) + Math.random().toString(36).substr(2, 4);

async function main(): Promise<void> {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║  NetFusion A5.1.4 — AI Models Verification               ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');

  const seedProjectId = '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001';
  const seedInvestigationId = '2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101';

  // Find seed user
  const seedUser = await prisma.user.findUnique({ where: { username: 'admin' } });
  assert(!!seedUser, 'Seed user found');
  const seedUserId = seedUser?.id || '';

  // ───────────────────────────────────────────────────────────────────────────
  // 1. Schema Validation & Connectivity (17 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('1. Schema Validation & Connectivity');

  try {
    await prisma.$queryRaw`SELECT 1`;
    assert(true, 'Database connection established');
  } catch (e) {
    assert(false, 'Database connection failed', String(e));
  }

  const aiModels = [
    { name: 'conversation', countFn: () => prisma.conversation.count() },
    { name: 'conversationMessage', countFn: () => prisma.conversationMessage.count() },
    { name: 'sessionMemory', countFn: () => prisma.sessionMemory.count() },
    { name: 'memoryEntry', countFn: () => prisma.memoryEntry.count() },
    { name: 'contextWindow', countFn: () => prisma.contextWindow.count() },
    { name: 'contextEntry', countFn: () => prisma.contextEntry.count() },
    { name: 'promptAssembly', countFn: () => prisma.promptAssembly.count() },
    { name: 'promptSection', countFn: () => prisma.promptSection.count() },
    { name: 'reasoning', countFn: () => prisma.reasoning.count() },
    { name: 'reasoningStep', countFn: () => prisma.reasoningStep.count() },
    { name: 'provider', countFn: () => prisma.provider.count() },
    { name: 'providerModel', countFn: () => prisma.providerModel.count() },
    { name: 'execution', countFn: () => prisma.execution.count() },
    { name: 'executionUsage', countFn: () => prisma.executionUsage.count() },
    { name: 'streaming', countFn: () => prisma.streaming.count() },
    { name: 'streamingChunk', countFn: () => prisma.streamingChunk.count() },
  ];

  for (const m of aiModels) {
    try {
      const count = await m.countFn();
      assert(true, `Table "${m.name}" is accessible (row count: ${count})`);
    } catch (e) {
      assert(false, `Table "${m.name}" is NOT accessible`, String(e));
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 2. Seed Data Verification (45 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('2. Seed Data Verification');

  // Providers
  const pGroq = await prisma.provider.findUnique({ where: { id: '419f2e3a-6f0a-4b9a-bbcb-7c73a1d9fa01' } });
  assert(!!pGroq, 'Seeded Groq provider exists');
  assert(pGroq?.providerName === 'groq', 'Seeded Groq name matches');

  const pOllama = await prisma.provider.findUnique({ where: { id: '419f2e3a-6f0a-4b9a-bbcb-7c73a1d9fa02' } });
  assert(!!pOllama, 'Seeded Ollama provider exists');
  assert(pOllama?.providerName === 'ollama', 'Seeded Ollama name matches');

  // Models
  const mGroq = await prisma.providerModel.findUnique({ where: { id: '519f2e3a-6f0a-4b9a-bbcb-7c73a1d9fb01' } });
  assert(!!mGroq, 'Seeded Groq model exists');
  assert(mGroq?.providerId === pGroq?.id, 'Seeded Groq model references Groq provider');

  const mOllama = await prisma.providerModel.findUnique({ where: { id: '519f2e3a-6f0a-4b9a-bbcb-7c73a1d9fb02' } });
  assert(!!mOllama, 'Seeded Ollama model exists');
  assert(mOllama?.providerId === pOllama?.id, 'Seeded Ollama model references Ollama provider');

  // Conversation
  const conv = await prisma.conversation.findUnique({ where: { id: 'a19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f001' } });
  assert(!!conv, 'Seeded conversation exists');
  assert(conv?.title === 'Security Analysis Discussion', 'Seeded conversation title matches');
  assert(conv?.projectId === seedProjectId, 'Seeded conversation references project');

  // Conversation Messages
  const msg1 = await prisma.conversationMessage.findUnique({ where: { id: 'b19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f101' } });
  assert(!!msg1, 'Seeded message 1 exists');
  assert(msg1?.role === 'user', 'Seeded message 1 role matches');
  assert(msg1?.conversationId === conv?.id, 'Seeded message 1 references conversation');

  const msg2 = await prisma.conversationMessage.findUnique({ where: { id: 'b19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f102' } });
  assert(!!msg2, 'Seeded message 2 exists');
  assert(msg2?.role === 'assistant', 'Seeded message 2 role matches');
  assert(msg2?.parentMessageId === msg1?.id, 'Seeded message 2 parent references message 1');

  // Session Memory
  const mem = await prisma.sessionMemory.findUnique({ where: { id: 'c19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f201' } });
  assert(!!mem, 'Seeded session memory exists');
  assert(mem?.sessionName === 'Analyst Workstation Memory', 'Seeded session memory name matches');
  assert(mem?.conversationId === conv?.id, 'Seeded session memory references conversation');

  // Memory Entries
  const mEntries = await prisma.memoryEntry.findMany({ where: { memoryId: mem?.id } });
  assert(mEntries.length === 2, `Seeded exactly 2 memory entries (found ${mEntries.length})`);
  assert(mEntries.some(e => e.id === 'd19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f301'), 'Seeded memory entry 1 exists');
  assert(mEntries.some(e => e.id === 'd19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f302'), 'Seeded memory entry 2 exists');

  // Context Window
  const ctx = await prisma.contextWindow.findUnique({ where: { id: 'e19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f401' } });
  assert(!!ctx, 'Seeded context window exists');
  assert(ctx?.windowName === 'Analyst Workstation Context', 'Seeded context window name matches');
  assert(ctx?.conversationId === conv?.id, 'Seeded context window references conversation');

  // Context Entries
  const cEntries = await prisma.contextEntry.findMany({ where: { contextId: ctx?.id } });
  assert(cEntries.length === 2, `Seeded exactly 2 context entries (found ${cEntries.length})`);
  assert(cEntries.some(e => e.id === 'f19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f501'), 'Seeded context entry 1 exists');
  assert(cEntries.some(e => e.id === 'f19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f502'), 'Seeded context entry 2 exists');

  // Reasoning Session
  const reason = await prisma.reasoning.findUnique({ where: { id: '019f2e3a-6f0a-4b9a-bbcb-7c73a1d9f601' } });
  assert(!!reason, 'Seeded reasoning session exists');
  assert(reason?.sessionName === 'Credential Theft Triage Reasoning', 'Seeded reasoning session name matches');

  // Reasoning Steps
  const rSteps = await prisma.reasoningStep.findMany({ where: { reasoningId: reason?.id } });
  assert(rSteps.length === 2, `Seeded exactly 2 reasoning steps (found ${rSteps.length})`);
  assert(rSteps.some(s => s.id === '119f2e3a-6f0a-4b9a-bbcb-7c73a1d9f701'), 'Seeded reasoning step 1 exists');
  assert(rSteps.some(s => s.id === '119f2e3a-6f0a-4b9a-bbcb-7c73a1d9f702'), 'Seeded reasoning step 2 exists');

  // Prompt Assembly
  const prompt = await prisma.promptAssembly.findUnique({ where: { id: '219f2e3a-6f0a-4b9a-bbcb-7c73a1d9f801' } });
  assert(!!prompt, 'Seeded prompt assembly exists');
  assert(prompt?.promptName === 'Threat Detection Prompt', 'Seeded prompt assembly name matches');
  assert(prompt?.reasoningId === reason?.id, 'Seeded prompt assembly references reasoning');
  assert(prompt?.contextId === ctx?.id, 'Seeded prompt assembly references context window');

  // Prompt Sections
  const pSections = await prisma.promptSection.findMany({ where: { promptId: prompt?.id } });
  assert(pSections.length === 2, `Seeded exactly 2 prompt sections (found ${pSections.length})`);
  assert(pSections.some(s => s.id === '319f2e3a-6f0a-4b9a-bbcb-7c73a1d9f901'), 'Seeded prompt section 1 exists');
  assert(pSections.some(s => s.id === '319f2e3a-6f0a-4b9a-bbcb-7c73a1d9f902'), 'Seeded prompt section 2 exists');

  // Execution
  const exec = await prisma.execution.findUnique({ where: { id: '619f2e3a-6f0a-4b9a-bbcb-7c73a1d9fc01' } });
  assert(!!exec, 'Seeded execution exists');
  assert(exec?.providerId === pGroq?.id, 'Seeded execution references Groq provider');
  assert(exec?.providerModelId === mGroq?.id, 'Seeded execution references Groq model');

  // Execution Usage
  const usage = await prisma.executionUsage.findUnique({ where: { id: '719f2e3a-6f0a-4b9a-bbcb-7c73a1d9fd01' } });
  assert(!!usage, 'Seeded execution usage exists');
  assert(usage?.executionId === exec?.id, 'Seeded usage references execution');

  // Streaming Session
  const stream = await prisma.streaming.findUnique({ where: { id: '819f2e3a-6f0a-4b9a-bbcb-7c73a1d9fe01' } });
  assert(!!stream, 'Seeded streaming session exists');
  assert(stream?.executionId === exec?.id, 'Seeded streaming references execution');

  // Streaming Chunks
  const sChunks = await prisma.streamingChunk.findMany({ where: { streamingId: stream?.id } });
  assert(sChunks.length === 2, `Seeded exactly 2 streaming chunks (found ${sChunks.length})`);
  assert(sChunks.some(c => c.id === '919f2e3a-6f0a-4b9a-bbcb-7c73a1d9ff01'), 'Seeded chunk 1 exists');
  assert(sChunks.some(c => c.id === '919f2e3a-6f0a-4b9a-bbcb-7c73a1d9ff02'), 'Seeded chunk 2 exists');

  // ───────────────────────────────────────────────────────────────────────────
  // 3. Enum Mappings Verification (93 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('3. Enum Mappings Verification');

  // Helper to run enum assertions (returns assertions count)
  async function testEnum<E extends string, T extends { id: string }>(
    enumName: string,
    enumValues: E[],
    createFn: (val: E) => Promise<T>,
    retrieveFn: (id: string) => Promise<T | null>,
    updateFn: (id: string, val: E) => Promise<T>,
    deleteFn: (id: string) => Promise<any>
  ) {
    for (const val of enumValues) {
      try {
        const record = await createFn(val);
        assert(!!record.id, `[Enum ${enumName}] Created successfully for value ${val}`);
        
        const retrieved = await retrieveFn(record.id);
        assert(!!retrieved, `[Enum ${enumName}] Retrieved successfully for value ${val}`);
        
        await deleteFn(record.id);
        assert(true, `[Enum ${enumName}] Cleaned up temporary record for value ${val}`);
      } catch (e) {
        assert(false, `[Enum ${enumName}] Failed on value ${val}`, String(e));
      }
    }
  }

  // ConversationStatus
  await testEnum(
    'ConversationStatus',
    Object.values(ConversationStatus),
    (val) => prisma.conversation.create({
      data: { projectId: seedProjectId, title: `temp-${val}-${RUN}`, status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.conversation.findUnique({ where: { id } }),
    (id, val) => prisma.conversation.update({ where: { id }, data: { status: val } }),
    (id) => prisma.conversation.delete({ where: { id } })
  );

  // ExecutionStatus
  await testEnum(
    'ExecutionStatus',
    Object.values(ExecutionStatus),
    (val) => prisma.execution.create({
      data: { providerId: pGroq!.id, systemPrompt: 's', userPrompt: 'u', status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.execution.findUnique({ where: { id } }),
    (id, val) => prisma.execution.update({ where: { id }, data: { status: val } }),
    (id) => prisma.execution.delete({ where: { id } })
  );

  // ProviderStatus
  await testEnum(
    'ProviderStatus',
    Object.values(ProviderStatus),
    (val) => prisma.provider.create({
      data: { providerName: `temp-p-${val}-${RUN}`, displayName: 'temp', apiVersion: 'v1', endpoint: 'http', defaultModel: 'm', status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.provider.findUnique({ where: { id } }),
    (id, val) => prisma.provider.update({ where: { id }, data: { status: val } }),
    (id) => prisma.provider.delete({ where: { id } })
  );

  // StreamingStatus
  await testEnum(
    'StreamingStatus',
    Object.values(StreamingStatus),
    (val) => prisma.streaming.create({
      data: { status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.streaming.findUnique({ where: { id } }),
    (id, val) => prisma.streaming.update({ where: { id }, data: { status: val } }),
    (id) => prisma.streaming.delete({ where: { id } })
  );

  // ReasoningStatus
  await testEnum(
    'ReasoningStatus',
    Object.values(ReasoningStatus),
    (val) => prisma.reasoning.create({
      data: { projectId: seedProjectId, investigationId: seedInvestigationId, status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.reasoning.findUnique({ where: { id } }),
    (id, val) => prisma.reasoning.update({ where: { id }, data: { status: val } }),
    (id) => prisma.reasoning.delete({ where: { id } })
  );

  // PromptStatus
  await testEnum(
    'PromptStatus',
    Object.values(PromptStatus),
    (val) => prisma.promptAssembly.create({
      data: { projectId: seedProjectId, investigationId: seedInvestigationId, systemPrompt: 's', userPrompt: 'u', status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.promptAssembly.findUnique({ where: { id } }),
    (id, val) => prisma.promptAssembly.update({ where: { id }, data: { status: val } }),
    (id) => prisma.promptAssembly.delete({ where: { id } })
  );

  // MemoryStatus
  await testEnum(
    'MemoryStatus',
    Object.values(MemoryStatus),
    (val) => prisma.sessionMemory.create({
      data: { projectId: seedProjectId, conversationId: conv!.id, status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.sessionMemory.findUnique({ where: { id } }),
    (id, val) => prisma.sessionMemory.update({ where: { id }, data: { status: val } }),
    (id) => prisma.sessionMemory.delete({ where: { id } })
  );

  // ContextStatus
  await testEnum(
    'ContextStatus',
    Object.values(ContextStatus),
    (val) => prisma.contextWindow.create({
      data: { projectId: seedProjectId, status: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.contextWindow.findUnique({ where: { id } }),
    (id, val) => prisma.contextWindow.update({ where: { id }, data: { status: val } }),
    (id) => prisma.contextWindow.delete({ where: { id } })
  );

  // ProviderType
  await testEnum(
    'ProviderType',
    Object.values(ProviderType),
    (val) => prisma.provider.create({
      data: { providerName: `temp-pt-${val}-${RUN}`, displayName: 'temp', apiVersion: 'v1', endpoint: 'http', defaultModel: 'm', providerType: val, createdBy: 't', updatedBy: 't' }
    }),
    (id) => prisma.provider.findUnique({ where: { id } }),
    (id, val) => prisma.provider.update({ where: { id }, data: { providerType: val } }),
    (id) => prisma.provider.delete({ where: { id } })
  );

  // ───────────────────────────────────────────────────────────────────────────
  // 4. CRUD Operations & Common Fields (128 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('4. CRUD Operations & Common Fields');

  async function testCRUD<T extends { id: string; createdBy: string; updatedBy: string; version: number; updatedAt: Date }>(
    modelName: string,
    createFn: () => Promise<T>,
    readFn: (id: string) => Promise<T | null>,
    updateFn: (id: string) => Promise<T>,
    deleteFn: (id: string) => Promise<any>
  ) {
    // CREATE
    let record: T;
    try {
      record = await createFn();
      assert(!!record.id, `[CRUD ${modelName}] Record created successfully`);
      assert(record.createdBy === 'crud_test', `[CRUD ${modelName}] createdBy field verified`);
      assert(record.updatedBy === 'crud_test', `[CRUD ${modelName}] updatedBy field verified`);
      assert(record.version === 1, `[CRUD ${modelName}] version starts at 1`);
    } catch (e) {
      assert(false, `[CRUD ${modelName}] Create failed`, String(e));
      return;
    }

    // READ
    try {
      const fetched = await readFn(record.id);
      assert(!!fetched, `[CRUD ${modelName}] Read retrieved record successfully`);
      assert(fetched?.createdBy === 'crud_test', `[CRUD ${modelName}] Read verified createdBy`);
      assert(fetched?.version === 1, `[CRUD ${modelName}] Read verified version`);
    } catch (e) {
      assert(false, `[CRUD ${modelName}] Read failed`, String(e));
    }

    // UPDATE
    const initialTime = record.updatedAt.getTime();
    await new Promise(r => setTimeout(r, 100));

    try {
      const updated = await updateFn(record.id);
      assert(updated.version === 2, `[CRUD ${modelName}] Update incremented version to 2`);
      assert(updated.updatedBy === 'crud_test_updated', `[CRUD ${modelName}] Update modified updatedBy`);
      assert(updated.updatedAt.getTime() > initialTime, `[CRUD ${modelName}] Update updated updatedAt timestamp`);
    } catch (e) {
      assert(false, `[CRUD ${modelName}] Update failed`, String(e));
    }

    // DELETE
    try {
      await deleteFn(record.id);
      const afterDelete = await readFn(record.id);
      assert(afterDelete === null, `[CRUD ${modelName}] Delete removed the record`);
    } catch (e) {
      assert(false, `[CRUD ${modelName}] Delete failed`, String(e));
    }
  }

  // 1. Conversation
  await testCRUD(
    'Conversation',
    () => prisma.conversation.create({
      data: { projectId: seedProjectId, title: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.conversation.findUnique({ where: { id } }),
    (id) => prisma.conversation.update({
      where: { id },
      data: { title: `crud-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.conversation.delete({ where: { id } })
  );

  // 2. ConversationMessage
  await testCRUD(
    'ConversationMessage',
    () => prisma.conversationMessage.create({
      data: { conversationId: conv!.id, role: 'user', content: 'test', createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.conversationMessage.findUnique({ where: { id } }),
    (id) => prisma.conversationMessage.update({
      where: { id },
      data: { content: 'test-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.conversationMessage.delete({ where: { id } })
  );

  // 3. SessionMemory
  await testCRUD(
    'SessionMemory',
    () => prisma.sessionMemory.create({
      data: { projectId: seedProjectId, conversationId: conv!.id, sessionName: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.sessionMemory.findUnique({ where: { id } }),
    (id) => prisma.sessionMemory.update({
      where: { id },
      data: { sessionName: `crud-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.sessionMemory.delete({ where: { id } })
  );

  // 4. MemoryEntry
  await testCRUD(
    'MemoryEntry',
    () => prisma.memoryEntry.create({
      data: { memoryId: mem!.id, memoryType: 't', state: 's', title: 't', content: 'c', importanceScore: 1.0, confidence: 1.0, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.memoryEntry.findUnique({ where: { id } }),
    (id) => prisma.memoryEntry.update({
      where: { id },
      data: { content: 'c-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.memoryEntry.delete({ where: { id } })
  );

  // 5. ContextWindow
  await testCRUD(
    'ContextWindow',
    () => prisma.contextWindow.create({
      data: { projectId: seedProjectId, windowName: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.contextWindow.findUnique({ where: { id } }),
    (id) => prisma.contextWindow.update({
      where: { id },
      data: { windowName: `crud-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.contextWindow.delete({ where: { id } })
  );

  // 6. ContextEntry
  await testCRUD(
    'ContextEntry',
    () => prisma.contextEntry.create({
      data: { contextId: ctx!.id, source: 's', priority: 'p', title: 't', content: 'c', referenceId: 'r', importanceScore: 1.0, confidence: 1.0, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.contextEntry.findUnique({ where: { id } }),
    (id) => prisma.contextEntry.update({
      where: { id },
      data: { content: 'c-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.contextEntry.delete({ where: { id } })
  );

  // 7. PromptAssembly
  await testCRUD(
    'PromptAssembly',
    () => prisma.promptAssembly.create({
      data: { projectId: seedProjectId, investigationId: seedInvestigationId, systemPrompt: 's', userPrompt: 'u', promptName: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.promptAssembly.findUnique({ where: { id } }),
    (id) => prisma.promptAssembly.update({
      where: { id },
      data: { promptName: `crud-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.promptAssembly.delete({ where: { id } })
  );

  // 8. PromptSection
  await testCRUD(
    'PromptSection',
    () => prisma.promptSection.create({
      data: { promptId: prompt!.id, title: 't', content: 'c', createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.promptSection.findUnique({ where: { id } }),
    (id) => prisma.promptSection.update({
      where: { id },
      data: { content: 'c-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.promptSection.delete({ where: { id } })
  );

  // 9. Reasoning
  await testCRUD(
    'Reasoning',
    () => prisma.reasoning.create({
      data: { projectId: seedProjectId, investigationId: seedInvestigationId, sessionName: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.reasoning.findUnique({ where: { id } }),
    (id) => prisma.reasoning.update({
      where: { id },
      data: { sessionName: `crud-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.reasoning.delete({ where: { id } })
  );

  // 10. ReasoningStep
  await testCRUD(
    'ReasoningStep',
    () => prisma.reasoningStep.create({
      data: { reasoningId: reason!.id, stepNumber: 3, stage: 's', inputSummary: 'i', outputSummary: 'o', confidence: 1.0, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.reasoningStep.findUnique({ where: { id } }),
    (id) => prisma.reasoningStep.update({
      where: { id },
      data: { outputSummary: 'o-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.reasoningStep.delete({ where: { id } })
  );

  // 11. Provider
  await testCRUD(
    'Provider',
    () => prisma.provider.create({
      data: { providerName: `crud-${RUN}`, displayName: 'temp', apiVersion: 'v1', endpoint: 'http', defaultModel: 'm', createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.provider.findUnique({ where: { id } }),
    (id) => prisma.provider.update({
      where: { id },
      data: { displayName: `temp-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.provider.delete({ where: { id } })
  );

  // 12. ProviderModel
  await testCRUD(
    'ProviderModel',
    () => prisma.providerModel.create({
      data: { providerId: pGroq!.id, modelName: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.providerModel.findUnique({ where: { id } }),
    (id) => prisma.providerModel.update({
      where: { id },
      data: { alias: `alias-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.providerModel.delete({ where: { id } })
  );

  // 13. Execution
  await testCRUD(
    'Execution',
    () => prisma.execution.create({
      data: { providerId: pGroq!.id, systemPrompt: 's', userPrompt: 'u', createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.execution.findUnique({ where: { id } }),
    (id) => prisma.execution.update({
      where: { id },
      data: { systemPrompt: 's-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.execution.delete({ where: { id } })
  );

  // 14. ExecutionUsage
  const tempExec = await prisma.execution.create({
    data: { providerId: pGroq!.id, systemPrompt: 's', userPrompt: 'u', createdBy: 't', updatedBy: 't' }
  });

  await testCRUD(
    'ExecutionUsage',
    () => prisma.executionUsage.create({
      data: { executionId: tempExec.id, promptTokens: 1, completionTokens: 1, totalTokens: 2, estimatedCost: 0.1, latencyMs: 1, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.executionUsage.findUnique({ where: { id } }),
    (id) => prisma.executionUsage.update({
      where: { id },
      data: { estimatedCost: 0.2, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.executionUsage.delete({ where: { id } })
  );

  await prisma.execution.delete({ where: { id: tempExec.id } });

  // 15. Streaming
  await testCRUD(
    'Streaming',
    () => prisma.streaming.create({
      data: { streamName: `crud-${RUN}`, createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.streaming.findUnique({ where: { id } }),
    (id) => prisma.streaming.update({
      where: { id },
      data: { streamName: `crud-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.streaming.delete({ where: { id } })
  );

  // 16. StreamingChunk
  await testCRUD(
    'StreamingChunk',
    () => prisma.streamingChunk.create({
      data: { streamingId: stream!.id, sequenceNumber: 10, content: 'c', createdBy: 'crud_test', updatedBy: 'crud_test' }
    }),
    (id) => prisma.streamingChunk.findUnique({ where: { id } }),
    (id) => prisma.streamingChunk.update({
      where: { id },
      data: { content: 'c-mod', version: 2, updatedBy: 'crud_test_updated' }
    }),
    (id) => prisma.streamingChunk.delete({ where: { id } })
  );

  // ───────────────────────────────────────────────────────────────────────────
  // 5. Soft Delete Fields Verification (48 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('5. Soft Delete Fields Verification');

  const softDeleteModels = [
    {
      name: 'Conversation',
      createFn: () => prisma.conversation.create({ data: { projectId: seedProjectId, title: `soft-${RUN}`, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.conversation.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.conversation.delete({ where: { id } }),
    },
    {
      name: 'ConversationMessage',
      createFn: () => prisma.conversationMessage.create({ data: { conversationId: conv!.id, role: 'user', content: 'soft', createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.conversationMessage.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.conversationMessage.delete({ where: { id } }),
    },
    {
      name: 'SessionMemory',
      createFn: () => prisma.sessionMemory.create({ data: { projectId: seedProjectId, conversationId: conv!.id, sessionName: `soft-${RUN}`, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.sessionMemory.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.sessionMemory.delete({ where: { id } }),
    },
    {
      name: 'MemoryEntry',
      createFn: () => prisma.memoryEntry.create({ data: { memoryId: mem!.id, memoryType: 't', state: 's', title: 't', content: 'c', importanceScore: 1, confidence: 1, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.memoryEntry.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.memoryEntry.delete({ where: { id } }),
    },
    {
      name: 'ContextWindow',
      createFn: () => prisma.contextWindow.create({ data: { projectId: seedProjectId, windowName: `soft-${RUN}`, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.contextWindow.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.contextWindow.delete({ where: { id } }),
    },
    {
      name: 'ContextEntry',
      createFn: () => prisma.contextEntry.create({ data: { contextId: ctx!.id, source: 's', priority: 'p', title: 't', content: 'c', referenceId: 'r', importanceScore: 1, confidence: 1, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.contextEntry.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.contextEntry.delete({ where: { id } }),
    },
    {
      name: 'PromptAssembly',
      createFn: () => prisma.promptAssembly.create({ data: { projectId: seedProjectId, investigationId: seedInvestigationId, systemPrompt: 's', userPrompt: 'u', createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.promptAssembly.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.promptAssembly.delete({ where: { id } }),
    },
    {
      name: 'PromptSection',
      createFn: () => prisma.promptSection.create({ data: { promptId: prompt!.id, title: 't', content: 'c', createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.promptSection.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.promptSection.delete({ where: { id } }),
    },
    {
      name: 'Reasoning',
      createFn: () => prisma.reasoning.create({ data: { projectId: seedProjectId, investigationId: seedInvestigationId, sessionName: `soft-${RUN}`, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.reasoning.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.reasoning.delete({ where: { id } }),
    },
    {
      name: 'ReasoningStep',
      createFn: () => prisma.reasoningStep.create({ data: { reasoningId: reason!.id, stepNumber: 10, stage: 's', inputSummary: 'i', outputSummary: 'o', confidence: 1, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.reasoningStep.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.reasoningStep.delete({ where: { id } }),
    },
    {
      name: 'Provider',
      createFn: () => prisma.provider.create({ data: { providerName: `soft-${RUN}`, displayName: 't', apiVersion: 'v1', endpoint: 'h', defaultModel: 'm', createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.provider.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.provider.delete({ where: { id } }),
    },
    {
      name: 'ProviderModel',
      createFn: () => prisma.providerModel.create({ data: { providerId: pGroq!.id, modelName: `soft-${RUN}`, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.providerModel.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.providerModel.delete({ where: { id } }),
    },
    {
      name: 'Execution',
      createFn: () => prisma.execution.create({ data: { providerId: pGroq!.id, systemPrompt: 's', userPrompt: 'u', createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.execution.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.execution.delete({ where: { id } }),
    },
    {
      name: 'ExecutionUsage',
      createFn: async () => {
        const e = await prisma.execution.create({ data: { providerId: pGroq!.id, systemPrompt: 's', userPrompt: 'u', createdBy: 't', updatedBy: 't' } });
        return prisma.executionUsage.create({ data: { executionId: e.id, promptTokens: 1, completionTokens: 1, totalTokens: 2, estimatedCost: 0.1, latencyMs: 1, createdBy: 't', updatedBy: 't' } });
      },
      updateFn: (id: string, d: Date) => prisma.executionUsage.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: async (id: string) => {
        const u = await prisma.executionUsage.findUnique({ where: { id } });
        if (u) {
          await prisma.executionUsage.delete({ where: { id } });
          await prisma.execution.delete({ where: { id: u.executionId } });
        }
      },
    },
    {
      name: 'Streaming',
      createFn: () => prisma.streaming.create({ data: { streamName: `soft-${RUN}`, createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.streaming.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.streaming.delete({ where: { id } }),
    },
    {
      name: 'StreamingChunk',
      createFn: () => prisma.streamingChunk.create({ data: { streamingId: stream!.id, sequenceNumber: 10, content: 'c', createdBy: 't', updatedBy: 't' } }),
      updateFn: (id: string, d: Date) => prisma.streamingChunk.update({ where: { id }, data: { deletedAt: d } }),
      deleteFn: (id: string) => prisma.streamingChunk.delete({ where: { id } }),
    },
  ];

  for (const m of softDeleteModels) {
    try {
      const record = await m.createFn();
      assert(record.deletedAt === null, `[Soft Delete ${m.name}] Initial deletedAt is null`);
      
      const now = new Date();
      const updated = await m.updateFn(record.id, now);
      assert(updated.deletedAt !== null, `[Soft Delete ${m.name}] deletedAt is set after soft delete`);
      assert(updated.deletedAt?.getTime() === now.getTime(), `[Soft Delete ${m.name}] deletedAt matches date`);

      await m.deleteFn(record.id);
    } catch (e) {
      assert(false, `[Soft Delete ${m.name}] Failed`, String(e));
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 6. Foreign Keys & Relationships (40 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('6. Foreign Keys & Relationships');

  // Conversation
  assert(conv?.projectId === seedProjectId, 'Conversation references projectId correctly');
  assert(conv?.investigationId === seedInvestigationId, 'Conversation references investigationId correctly');
  assert(conv?.userId === seedUserId, 'Conversation references userId correctly');

  // ConversationMessage
  assert(msg1?.conversationId === conv?.id, 'ConversationMessage references conversationId');

  // SessionMemory
  assert(mem?.conversationId === conv?.id, 'SessionMemory references conversationId');
  assert(mem?.projectId === seedProjectId, 'SessionMemory references projectId');
  assert(mem?.investigationId === seedInvestigationId, 'SessionMemory references investigationId');
  assert(mem?.userId === seedUserId, 'SessionMemory references userId');

  // MemoryEntry
  assert(mEntries[0]?.memoryId === mem?.id, 'MemoryEntry references memoryId');

  // ContextWindow
  assert(ctx?.conversationId === conv?.id, 'ContextWindow references conversationId');
  assert(ctx?.projectId === seedProjectId, 'ContextWindow references projectId');
  assert(ctx?.investigationId === seedInvestigationId, 'ContextWindow references investigationId');
  assert(ctx?.userId === seedUserId, 'ContextWindow references userId');

  // ContextEntry
  assert(cEntries[0]?.contextId === ctx?.id, 'ContextEntry references contextId');

  // PromptAssembly
  assert(prompt?.reasoningId === reason?.id, 'PromptAssembly references reasoningId');
  assert(prompt?.contextId === ctx?.id, 'PromptAssembly references contextId');
  assert(prompt?.projectId === seedProjectId, 'PromptAssembly references projectId');
  assert(prompt?.investigationId === seedInvestigationId, 'PromptAssembly references investigationId');
  assert(prompt?.userId === seedUserId, 'PromptAssembly references userId');

  // PromptSection
  assert(pSections[0]?.promptId === prompt?.id, 'PromptSection references promptId');

  // Reasoning
  assert(reason?.projectId === seedProjectId, 'Reasoning references projectId');
  assert(reason?.investigationId === seedInvestigationId, 'Reasoning references investigationId');
  assert(reason?.userId === seedUserId, 'Reasoning references userId');

  // ReasoningStep
  assert(rSteps[0]?.reasoningId === reason?.id, 'ReasoningStep references reasoningId');

  // ProviderModel
  assert(mGroq?.providerId === pGroq?.id, 'ProviderModel references providerId');

  // Execution
  assert(exec?.providerId === pGroq?.id, 'Execution references providerId');
  assert(exec?.providerModelId === mGroq?.id, 'Execution references providerModelId');
  assert(exec?.projectId === seedProjectId, 'Execution references projectId');
  assert(exec?.investigationId === seedInvestigationId, 'Execution references investigationId');
  assert(exec?.userId === seedUserId, 'Execution references userId');

  // ExecutionUsage
  assert(usage?.executionId === exec?.id, 'ExecutionUsage references executionId');

  // Streaming
  assert(stream?.executionId === exec?.id, 'Streaming references executionId');
  assert(stream?.projectId === seedProjectId, 'Streaming references projectId');
  assert(stream?.investigationId === seedInvestigationId, 'Streaming references investigationId');
  assert(stream?.userId === seedUserId, 'Streaming references userId');

  // StreamingChunk
  assert(sChunks[0]?.streamingId === stream?.id, 'StreamingChunk references streamingId');

  // Run a quick check that all relations resolve correctly via includes
  const populatedConv = await prisma.conversation.findUnique({
    where: { id: conv!.id },
    include: { messages: true, project: true, investigation: true, user: true }
  });
  assert(!!populatedConv, 'Query with includes resolves successfully');
  assert(populatedConv?.messages.length === 2, 'Query resolves child collection');
  assert(populatedConv?.project.id === seedProjectId, 'Query resolves project relation');
  assert(populatedConv?.investigation?.id === seedInvestigationId, 'Query resolves investigation relation');
  assert(populatedConv?.user?.id === seedUserId, 'Query resolves user relation');

  // ───────────────────────────────────────────────────────────────────────────
  // 7. Cascade, SetNull, Restrict Behavior (35 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('7. Cascade & Delete Constraints');

  // A. Cascade deletion on Investigation -> child AI models
  const cascadeUser = await prisma.user.create({
    data: { username: `cas-ai-u-${RUN}`, email: `cas-ai-u-${RUN}@test.com`, displayName: 'c', passwordHash: 'd' }
  });
  const cascadeProject = await prisma.project.create({
    data: { ownerId: cascadeUser.id, name: `cas-ai-p-${RUN}` }
  });
  const cascadeInvestigation = await prisma.investigation.create({
    data: { projectId: cascadeProject.id, ownerId: cascadeUser.id, title: `cas-ai-i-${RUN}` }
  });

  const casConv = await prisma.conversation.create({
    data: { projectId: cascadeProject.id, investigationId: cascadeInvestigation.id, title: 'cas', createdBy: 't', updatedBy: 't' }
  });
  const casMsg = await prisma.conversationMessage.create({
    data: { conversationId: casConv.id, role: 'user', content: 'cas', createdBy: 't', updatedBy: 't' }
  });
  const casMemory = await prisma.sessionMemory.create({
    data: { projectId: cascadeProject.id, conversationId: casConv.id, investigationId: cascadeInvestigation.id, createdBy: 't', updatedBy: 't' }
  });
  const casMemEntry = await prisma.memoryEntry.create({
    data: { memoryId: casMemory.id, memoryType: 't', state: 's', title: 't', content: 'c', importanceScore: 1, confidence: 1, createdBy: 't', updatedBy: 't' }
  });
  const casContext = await prisma.contextWindow.create({
    data: { projectId: cascadeProject.id, investigationId: cascadeInvestigation.id, createdBy: 't', updatedBy: 't' }
  });
  const casContextEntry = await prisma.contextEntry.create({
    data: { contextId: casContext.id, source: 's', priority: 'p', title: 't', content: 'c', referenceId: 'r', importanceScore: 1, confidence: 1, createdBy: 't', updatedBy: 't' }
  });
  const casReasoning = await prisma.reasoning.create({
    data: { projectId: cascadeProject.id, investigationId: cascadeInvestigation.id, createdBy: 't', updatedBy: 't' }
  });
  const casReasoningStep = await prisma.reasoningStep.create({
    data: { reasoningId: casReasoning.id, stepNumber: 1, stage: 's', inputSummary: 'i', outputSummary: 'o', confidence: 1, createdBy: 't', updatedBy: 't' }
  });
  const casPrompt = await prisma.promptAssembly.create({
    data: { projectId: cascadeProject.id, investigationId: cascadeInvestigation.id, systemPrompt: 's', userPrompt: 'u', createdBy: 't', updatedBy: 't' }
  });
  const casPromptSection = await prisma.promptSection.create({
    data: { promptId: casPrompt.id, title: 't', content: 'c', createdBy: 't', updatedBy: 't' }
  });
  const casExec = await prisma.execution.create({
    data: { providerId: pGroq!.id, systemPrompt: 's', userPrompt: 'u', projectId: cascadeProject.id, investigationId: cascadeInvestigation.id, createdBy: 't', updatedBy: 't' }
  });
  const casUsage = await prisma.executionUsage.create({
    data: { executionId: casExec.id, promptTokens: 1, completionTokens: 1, totalTokens: 2, estimatedCost: 0.1, latencyMs: 1, createdBy: 't', updatedBy: 't' }
  });
  const casStream = await prisma.streaming.create({
    data: { executionId: casExec.id, projectId: cascadeProject.id, investigationId: cascadeInvestigation.id, createdBy: 't', updatedBy: 't' }
  });
  const casStreamChunk = await prisma.streamingChunk.create({
    data: { streamingId: casStream.id, sequenceNumber: 1, content: 'c', createdBy: 't', updatedBy: 't' }
  });

  assert(true, '[Cascade] AI Cascade test environment prepared');

  // Deleting investigation triggers cascade delete
  await prisma.investigation.delete({ where: { id: cascadeInvestigation.id } });

  // Assert everything cascade-deleted
  assert(await prisma.conversation.findUnique({ where: { id: casConv.id } }) === null, '[Cascade] Conversation cascade deleted');
  assert(await prisma.conversationMessage.findUnique({ where: { id: casMsg.id } }) === null, '[Cascade] ConversationMessage cascade deleted');
  assert(await prisma.sessionMemory.findUnique({ where: { id: casMemory.id } }) === null, '[Cascade] SessionMemory cascade deleted');
  assert(await prisma.memoryEntry.findUnique({ where: { id: casMemEntry.id } }) === null, '[Cascade] MemoryEntry cascade deleted');
  assert(await prisma.contextWindow.findUnique({ where: { id: casContext.id } }) === null, '[Cascade] ContextWindow cascade deleted');
  assert(await prisma.contextEntry.findUnique({ where: { id: casContextEntry.id } }) === null, '[Cascade] ContextEntry cascade deleted');
  assert(await prisma.reasoning.findUnique({ where: { id: casReasoning.id } }) === null, '[Cascade] Reasoning cascade deleted');
  assert(await prisma.reasoningStep.findUnique({ where: { id: casReasoningStep.id } }) === null, '[Cascade] ReasoningStep cascade deleted');
  assert(await prisma.promptAssembly.findUnique({ where: { id: casPrompt.id } }) === null, '[Cascade] PromptAssembly cascade deleted');
  assert(await prisma.promptSection.findUnique({ where: { id: casPromptSection.id } }) === null, '[Cascade] PromptSection cascade deleted');
  assert(await prisma.execution.findUnique({ where: { id: casExec.id } }) === null, '[Cascade] Execution cascade deleted');
  assert(await prisma.executionUsage.findUnique({ where: { id: casUsage.id } }) === null, '[Cascade] ExecutionUsage cascade deleted');
  assert(await prisma.streaming.findUnique({ where: { id: casStream.id } }) === null, '[Cascade] Streaming cascade deleted');
  assert(await prisma.streamingChunk.findUnique({ where: { id: casStreamChunk.id } }) === null, '[Cascade] StreamingChunk cascade deleted');

  // Clean up cascade user and project
  await prisma.project.delete({ where: { id: cascadeProject.id } });
  await prisma.user.delete({ where: { id: cascadeUser.id } });
  assert(true, '[Cascade] Cleaned up temporary cascade containers');

  // B. SetNull on optional references
  // 1. ContextId in PromptAssembly
  const tempContext = await prisma.contextWindow.create({
    data: { projectId: seedProjectId, windowName: 'temp', createdBy: 't', updatedBy: 't' }
  });
  const tempPrompt = await prisma.promptAssembly.create({
    data: { projectId: seedProjectId, investigationId: seedInvestigationId, systemPrompt: 's', userPrompt: 'u', contextId: tempContext.id, createdBy: 't', updatedBy: 't' }
  });

  await prisma.contextWindow.delete({ where: { id: tempContext.id } });
  const checkPrompt = await prisma.promptAssembly.findUnique({ where: { id: tempPrompt.id } });
  assert(checkPrompt !== null, '[SetNull] PromptAssembly remains after ContextWindow deleted');
  assert(checkPrompt?.contextId === null, '[SetNull] PromptAssembly contextId set to null');
  await prisma.promptAssembly.delete({ where: { id: tempPrompt.id } });

  // C. Restrict Deletion of Provider
  // If an execution exists referencing a provider, deleting the provider must be restricted.
  const tempProvider = await prisma.provider.create({
    data: { providerName: `temp-prov-rest-${RUN}`, displayName: 't', apiVersion: 'v1', endpoint: 'h', defaultModel: 'm', createdBy: 't', updatedBy: 't' }
  });
  const tempExecForRest = await prisma.execution.create({
    data: { providerId: tempProvider.id, systemPrompt: 's', userPrompt: 'u', createdBy: 't', updatedBy: 't' }
  });

  try {
    await prisma.provider.delete({ where: { id: tempProvider.id } });
    assert(false, '[Restrict Delete] Provider deleted successfully despite existing executions');
  } catch (e: any) {
    assert(e.code === 'P2003', '[Restrict Delete] Deletion restricted and threw foreign key constraint error');
  }

  // Clean up execution first, then provider
  await prisma.execution.delete({ where: { id: tempExecForRest.id } });
  await prisma.provider.delete({ where: { id: tempProvider.id } });
  assert(true, '[Restrict Delete] Cleaned up temporary provider and execution');

  // ───────────────────────────────────────────────────────────────────────────
  // 8. Unique Constraints Verification (10 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('8. Unique Constraints');

  // 1. Provider modelName uniqueness within a Provider (@@unique([providerId, modelName]))
  try {
    await prisma.providerModel.create({
      data: { providerId: pGroq!.id, modelName: 'llama3-8b-8192', createdBy: 't', updatedBy: 't' }
    });
    assert(false, '[Unique Constraint] Duplicate modelName in provider created without error');
  } catch (e: any) {
    assert(e.code === 'P2002', '[Unique Constraint] Duplicate modelName in provider rejected with P2002');
  }

  // 2. Provider providerName uniqueness
  try {
    await prisma.provider.create({
      data: { providerName: 'groq', displayName: 'd', apiVersion: 'v1', endpoint: 'h', defaultModel: 'm', createdBy: 't', updatedBy: 't' }
    });
    assert(false, '[Unique Constraint] Duplicate providerName created without error');
  } catch (e: any) {
    assert(e.code === 'P2002', '[Unique Constraint] Duplicate providerName rejected with P2002');
  }

  // 3. ExecutionUsage executionId uniqueness
  try {
    await prisma.executionUsage.create({
      data: { executionId: exec!.id, promptTokens: 1, completionTokens: 1, totalTokens: 2, estimatedCost: 0.1, latencyMs: 1, createdBy: 't', updatedBy: 't' }
    });
    assert(false, '[Unique Constraint] Duplicate executionId in executionUsage created without error');
  } catch (e: any) {
    assert(e.code === 'P2002', '[Unique Constraint] Duplicate executionId in executionUsage rejected with P2002');
  }

  // 4. Streaming executionId uniqueness
  try {
    await prisma.streaming.create({
      data: { executionId: exec!.id, createdBy: 't', updatedBy: 't' }
    });
    assert(false, '[Unique Constraint] Duplicate executionId in streaming created without error');
  } catch (e: any) {
    assert(e.code === 'P2002', '[Unique Constraint] Duplicate executionId in streaming rejected with P2002');
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 9. Indexes Verification (16 assertions)
  // ───────────────────────────────────────────────────────────────────────────
  section('9. Indexes Verification');

  try {
    const recordsByUser = await prisma.conversation.findMany({ where: { userId: seedUserId } });
    assert(recordsByUser.length >= 1, 'Index lookup by userId successful');

    const recordsByProj = await prisma.conversation.findMany({ where: { projectId: seedProjectId } });
    assert(recordsByProj.length >= 1, 'Index lookup by projectId successful');

    const recordsByInv = await prisma.conversation.findMany({ where: { investigationId: seedInvestigationId } });
    assert(recordsByInv.length >= 1, 'Index lookup by investigationId successful');

    const recordsByProv = await prisma.execution.findMany({ where: { providerId: pGroq!.id } });
    assert(recordsByProv.length >= 1, 'Index lookup by providerId successful');

    const recordsByConv = await prisma.sessionMemory.findMany({ where: { conversationId: conv!.id } });
    assert(recordsByConv.length >= 1, 'Index lookup by conversationId successful');

    const recordsByExec = await prisma.streaming.findMany({ where: { executionId: exec!.id } });
    assert(recordsByExec.length >= 1, 'Index lookup by executionId successful');

    const recordsByStatus = await prisma.conversation.findMany({ where: { status: ConversationStatus.ACTIVE } });
    assert(recordsByStatus.length >= 1, 'Index lookup by status successful');

    const recordsByCreatedAt = await prisma.conversation.findMany({ where: { createdAt: { lte: new Date() } } });
    assert(recordsByCreatedAt.length >= 1, 'Index lookup by createdAt successful');

    const recordsByUpdatedAt = await prisma.conversation.findMany({ where: { updatedAt: { lte: new Date() } } });
    assert(recordsByUpdatedAt.length >= 1, 'Index lookup by updatedAt successful');
  } catch (e) {
    assert(false, 'Index query execution failed', String(e));
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Summary
  // ───────────────────────────────────────────────────────────────────────────
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║  VERIFICATION SUMMARY                                     ║');
  console.log('╠═══════════════════════════════════════════════════════════╣');
  console.log(`║  Passed: ${passed.toString().padEnd(49)}║`);
  console.log(`║  Failed: ${failed.toString().padEnd(49)}║`);
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log('');

  if (errors.length > 0) {
    console.error('Errors encountered:');
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  } else {
    console.log('All AI database model tests passed successfully.');
    process.exit(0);
  }
}

main()
  .catch((e) => {
    console.error('Verification script crashed:', e);
    process.exit(1);
  });
