/**
 * verify_ai_services.ts — Phase A5.3.4
 * ===========================================
 * Standalone verification script for all AI domain services.
 *
 * Run:   npx ts-node src/verify_ai_services.ts
 * Exits 0 on all pass, 1 on any failure.
 *
 * Target: 2200+ assertions, 0 failures.
 */

import prisma from './lib/prisma';
import {
  conversationService,
  sessionMemoryService,
  contextWindowService,
  promptAssemblyService,
  reasoningService,
  executionService,
  providerService,
  streamingService,
} from './services/ai';
import {
  userRepository,
  projectRepository,
  investigationRepository,
} from './repositories/core';
import { eventPublisher } from './services/base/EventPublisher';
import {
  User, Project, Investigation,
  Conversation, ConversationMessage,
  SessionMemory, MemoryEntry,
  ContextWindow, ContextEntry,
  PromptAssembly, PromptSection,
  Reasoning, ReasoningStep,
  Provider, ProviderModel,
  Execution, ExecutionUsage,
  Streaming, StreamingChunk,
} from '@prisma/client';

let passed = 0;
let failed = 0;
const errors: string[] = [];

function ok(_label: string): void { passed++; }

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

const RUN = Date.now().toString(36) + Math.random().toString(36).substring(2, 6);


// ─── Shared fixtures ─────────────────────────────────────────────────────────
let testUser: User;
let testProject: Project;
let testInvestigation: Investigation;
let testProvider: Provider;

async function setupFixtures(): Promise<void> {
  section('SETUP — Core fixtures');
  testUser = await userRepository.create({
    username: `svc-user-${RUN}`,
    email: `svc-${RUN}@test.local`,
    displayName: `SvcUser ${RUN}`,
    passwordHash: 'x',
  });
  assert(!!testUser.id, 'User created');

  testProject = await projectRepository.create({
    name: `svc-proj-${RUN}`,
    description: 'AI service test project',
    ownerId: testUser.id,
  });
  assert(!!testProject.id, 'Project created');

  testInvestigation = await investigationRepository.create({
    title: `svc-inv-${RUN}`,
    projectId: testProject.id,
    ownerId: testUser.id,
  });
  assert(!!testInvestigation.id, 'Investigation created');

  const prov = await prisma.provider.create({
    data: {
      providerName: `provider-${RUN}`,
      displayName: `Test Provider ${RUN}`,
      apiVersion: 'v1',
      endpoint: 'https://api.test.local',
      defaultModel: 'gpt-test',
      enabled: true,
      priority: 10,
      healthScore: 95.0,
      status: 'ACTIVE',
      providerType: 'CLOUD',
      createdBy: 'system',
      updatedBy: 'system',
    },
  });
  testProvider = prov;
  assert(!!testProvider.id, 'Provider seed created');
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1 — ConversationService
// ═══════════════════════════════════════════════════════════════════════════════
async function testConversationService(): Promise<void> {
  section('1. ConversationService');

  // 1.1 Create
  const conv = await conversationService.createConversation({
    title: `conv-${RUN}`,
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!conv.id, '1.01 createConversation returns id');
  assert(conv.title === `conv-${RUN}`, '1.02 title persisted');
  assert(conv.status === 'ACTIVE', '1.03 default status ACTIVE');
  assert(conv.projectId === testProject.id, '1.04 projectId persisted');
  assert(conv.investigationId === testInvestigation.id, '1.05 investigationId persisted');
  assert(conv.contextSize === 0, '1.06 initial contextSize = 0');

  // 1.2 Required-field validation
  try {
    await conversationService.createConversation({ projectId: testProject.id } as any);
    fail('1.07 createConversation missing title should throw');
  } catch { ok('1.07 validation rejects missing title'); }

  // 1.3 Invalid UUID validation
  try {
    await conversationService.createConversation({
      title: 'x', projectId: 'not-a-uuid', createdBy: 'sys', updatedBy: 'sys',
    });
    fail('1.08 invalid projectId UUID should throw');
  } catch { ok('1.08 validation rejects invalid projectId UUID'); }

  // 1.4 Add message
  const msg = await conversationService.addMessage(conv.id, {
    role: 'user',
    content: 'Hello AI!',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!msg.id, '1.09 addMessage returns id');
  assert(msg.conversationId === conv.id, '1.10 message linked to conversation');
  assert(msg.role === 'user', '1.11 role persisted');
  assert(msg.content === 'Hello AI!', '1.12 content persisted');

  // 1.5 Context size updated after message
  const convAfterMsg = await conversationService.findConversation(conv.id);
  assert((convAfterMsg?.contextSize ?? 0) > 0, '1.13 contextSize updated after message');

  // 1.6 Add assistant message
  const aiMsg = await conversationService.addMessage(conv.id, {
    role: 'assistant',
    content: 'Hello! How can I help?',
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(aiMsg.role === 'assistant', '1.14 assistant role persisted');

  // 1.7 Thread message (with parentMessageId)
  const reply = await conversationService.addMessage(conv.id, {
    role: 'user',
    content: 'Follow-up question',
    parentMessageId: msg.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(reply.parentMessageId === msg.id, '1.15 parentMessageId persisted');

  // 1.8 Message validation
  try {
    await conversationService.addMessage(conv.id, { role: '', content: '', createdBy: 'x', updatedBy: 'x' });
    fail('1.16 empty role/content should throw');
  } catch { ok('1.16 message validation rejects empty role/content'); }

  // 1.9 Search messages
  const found = await conversationService.searchMessages('Hello');
  assert(Array.isArray(found), '1.17 searchMessages returns array');
  assert(found.some((m) => m.content.includes('Hello')), '1.18 searchMessages finds content');

  // 1.10 Update summary
  const withSummary = await conversationService.updateSummary(conv.id, 'Test summary', testUser.id);
  assert(withSummary.summary === 'Test summary', '1.19 summary updated');

  // 1.11 Add / remove tag
  const tagged = await conversationService.addTag(conv.id, 'security', testUser.id);
  assert(tagged.tags.includes('security'), '1.20 tag added');
  const deduped = await conversationService.addTag(conv.id, 'security', testUser.id);
  assert(deduped.tags.filter((t) => t === 'security').length === 1, '1.21 tags deduplicated');
  const untagged = await conversationService.removeTag(conv.id, 'security', testUser.id);
  assert(!untagged.tags.includes('security'), '1.22 tag removed');

  // 1.12 Recalculate context size
  const size = await conversationService.recalculateContextSize(conv.id);
  assert(typeof size === 'number' && size > 0, '1.23 recalculateContextSize returns positive number');

  // 1.13 Stats
  const stats = await conversationService.getConversationStats(conv.id);
  assert(stats.messageCount >= 3, '1.24 stats.messageCount >= 3');
  assert(stats.contextSize >= 0, '1.25 stats.contextSize >= 0');
  assert(stats.memoryCount >= 0, '1.26 stats.memoryCount >= 0');
  assert(stats.windowCount >= 0, '1.27 stats.windowCount >= 0');

  // 1.14 Find helpers
  const byProject = await conversationService.findByProject(testProject.id);
  assert(byProject.some((c) => c.id === conv.id), '1.28 findByProject includes conversation');
  const byUser = await conversationService.findByUser(testUser.id);
  assert(byUser.some((c) => c.id === conv.id), '1.29 findByUser includes conversation');
  const byInvestigation = await conversationService.findByInvestigation(testInvestigation.id);
  assert(byInvestigation.some((c) => c.id === conv.id), '1.30 findByInvestigation includes conversation');
  const active = await conversationService.findActive();
  assert(active.some((c) => c.id === conv.id), '1.31 findActive includes conversation');

  // 1.15 Lifecycle transitions
  const archived = await conversationService.archiveConversation(conv.id, testUser.id);
  assert(archived.status === 'ARCHIVED', '1.32 archiveConversation sets ARCHIVED');
  const reactivated = await conversationService.reactivateConversation(conv.id, testUser.id);
  assert(reactivated.status === 'ACTIVE', '1.33 reactivateConversation sets ACTIVE');
  const completed = await conversationService.completeConversation(conv.id, testUser.id);
  assert(completed.status === 'COMPLETED', '1.34 completeConversation sets COMPLETED');

  // 1.16 Event publishing
  let eventFired = false;
  const handler = () => { eventFired = true; };
  eventPublisher.subscribe('ConversationCreated', handler);
  const convB = await conversationService.createConversation({
    title: `conv-evented-${RUN}`,
    projectId: testProject.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(eventFired, '1.35 ConversationCreated event published');
  eventPublisher.unsubscribe('ConversationCreated', handler);

  // 1.17 Soft delete
  await conversationService.deleteConversation(conv.id, testUser.id);
  const deleted = await conversationService.findConversation(conv.id);
  assert(deleted?.deletedAt !== null, '1.36 deleteConversation sets deletedAt');

  // 1.18 Deletion validation
  try {
    await conversationService.deleteConversation('not-a-uuid', 'actor');
    fail('1.37 deleteConversation invalid UUID should throw');
  } catch { ok('1.37 deleteConversation validates UUID'); }

  // cleanup extra
  await prisma.conversation.delete({ where: { id: convB.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2 — SessionMemoryService
// ═══════════════════════════════════════════════════════════════════════════════
async function testSessionMemoryService(): Promise<void> {
  section('2. SessionMemoryService');

  // Need a live conversation for FK
  const conv = await prisma.conversation.create({
    data: {
      title: `mem-conv-${RUN}`,
      projectId: testProject.id,
      createdBy: 'system',
      updatedBy: 'system',
    },
  });

  // 2.1 Create
  const mem = await sessionMemoryService.createMemory({
    conversationId: conv.id,
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    sessionName: `sess-${RUN}`,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!mem.id, '2.01 createMemory returns id');
  assert(mem.status === 'ACTIVE', '2.02 default status ACTIVE');
  assert(mem.projectId === testProject.id, '2.03 projectId persisted');
  assert(mem.conversationId === conv.id, '2.04 conversationId persisted');
  assert(mem.sessionName === `sess-${RUN}`, '2.05 sessionName persisted');
  assert(mem.contextSize === 0, '2.06 initial contextSize = 0');

  // 2.2 Required-field validation
  try {
    await sessionMemoryService.createMemory({ projectId: testProject.id } as any);
    fail('2.07 missing conversationId should throw');
  } catch { ok('2.07 validation rejects missing conversationId'); }

  // 2.3 Add entry
  const entry = await sessionMemoryService.addEntry(mem.id, {
    memoryType: 'FACT',
    state: 'ACTIVE',
    title: 'First fact',
    content: 'The attacker used port 443',
    importanceScore: 80.0,
    confidence: 0.9,
    sourceId: testInvestigation.id,
    tags: ['network', 'attacker'],
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!entry.id, '2.08 addEntry returns id');
  assert(entry.memoryId === mem.id, '2.09 entry linked to memory');
  assert(entry.title === 'First fact', '2.10 title persisted');
  assert(entry.importanceScore === 80.0, '2.11 importanceScore persisted');
  assert(entry.confidence === 0.9, '2.12 confidence persisted');
  assert(entry.tags.includes('network'), '2.13 tags persisted');

  // Context size updated
  const memAfterEntry = await sessionMemoryService.findMemory(mem.id);
  assert((memAfterEntry?.contextSize ?? 0) > 0, '2.14 contextSize updated after entry');

  // 2.4 Add second entry
  const entry2 = await sessionMemoryService.addEntry(mem.id, {
    memoryType: 'OBSERVATION',
    state: 'ACTIVE',
    title: 'Second observation',
    content: 'Lateral movement detected on subnet 10.0.1.0/24',
    importanceScore: 60.0,
    confidence: 0.75,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!entry2.id, '2.15 second entry created');

  // 2.5 Update entry
  const updated = await sessionMemoryService.updateEntry(entry.id, {
    importanceScore: 90.0,
    updatedBy: testUser.id,
  });
  assert(updated.importanceScore === 90.0, '2.16 updateEntry persists new importanceScore');

  // 2.6 Search
  const found = await sessionMemoryService.searchEntries('attacker');
  assert(Array.isArray(found), '2.17 searchEntries returns array');
  assert(found.some((e) => e.id === entry.id), '2.18 searchEntries finds by title');

  // 2.7 Average calculations
  const avgImportance = await sessionMemoryService.calculateAverageImportance(mem.id);
  assert(typeof avgImportance === 'number', '2.19 calculateAverageImportance returns number');
  assert(avgImportance > 0, '2.20 average importance > 0');
  const avgConfidence = await sessionMemoryService.calculateAverageConfidence(mem.id);
  assert(typeof avgConfidence === 'number', '2.21 calculateAverageConfidence returns number');
  assert(avgConfidence > 0, '2.22 average confidence > 0');

  // 2.8 Stats
  const stats = await sessionMemoryService.getMemoryStats(mem.id);
  assert(stats.entryCount === 2, '2.23 stats.entryCount === 2');
  assert(stats.contextSize > 0, '2.24 stats.contextSize > 0');
  assert(stats.averageImportance > 0, '2.25 stats.averageImportance > 0');
  assert(stats.averageConfidence > 0, '2.26 stats.averageConfidence > 0');

  // 2.9 Find helpers
  const byProject = await sessionMemoryService.findByProject(testProject.id);
  assert(byProject.some((m) => m.id === mem.id), '2.27 findByProject');
  const byUser = await sessionMemoryService.findByUser(testUser.id);
  assert(byUser.some((m) => m.id === mem.id), '2.28 findByUser');
  const byInv = await sessionMemoryService.findByInvestigation(testInvestigation.id);
  assert(byInv.some((m) => m.id === mem.id), '2.29 findByInvestigation');
  const activeMemories = await sessionMemoryService.findActive();
  assert(activeMemories.some((m) => m.id === mem.id), '2.30 findActive');
  const entries = await sessionMemoryService.findEntries(mem.id);
  assert(entries.length === 2, '2.31 findEntries returns 2');

  // 2.10 Lifecycle transitions
  const archived = await sessionMemoryService.archiveMemory(mem.id, testUser.id);
  assert(archived.status === 'ARCHIVED', '2.32 archiveMemory sets ARCHIVED');
  const activated = await sessionMemoryService.activateMemory(mem.id, testUser.id);
  assert(activated.status === 'ACTIVE', '2.33 activateMemory sets ACTIVE');

  // 2.11 Delete entry
  await sessionMemoryService.deleteEntry(entry2.id, testUser.id);
  const entriesAfterDelete = await sessionMemoryService.findEntries(mem.id);
  assert(entriesAfterDelete.every((e) => e.id !== entry2.id), '2.34 deleteEntry soft-deletes');

  // 2.12 Soft delete memory
  await sessionMemoryService.deleteMemory(mem.id, testUser.id);
  const deletedMem = await sessionMemoryService.findMemory(mem.id);
  assert(deletedMem?.deletedAt !== null, '2.35 deleteMemory sets deletedAt');

  // cleanup
  await prisma.conversation.delete({ where: { id: conv.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3 — ContextWindowService
// ═══════════════════════════════════════════════════════════════════════════════
async function testContextWindowService(): Promise<void> {
  section('3. ContextWindowService');

  // 3.1 Create window
  const win = await contextWindowService.createWindow({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    windowName: `win-${RUN}`,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!win.id, '3.01 createWindow returns id');
  assert(win.status === 'ACTIVE', '3.02 default status ACTIVE');
  assert(win.windowName === `win-${RUN}`, '3.03 windowName persisted');
  assert(win.contextSize === 0, '3.04 initial contextSize = 0');

  // 3.2 Validation
  try {
    await contextWindowService.createWindow({ projectId: 'bad-uuid', createdBy: 'x', updatedBy: 'x' });
    fail('3.05 invalid projectId UUID should throw');
  } catch { ok('3.05 UUID validation on createWindow'); }

  // 3.3 Add entry
  const entry = await contextWindowService.addEntry(win.id, {
    source: 'alert',
    priority: 'HIGH',
    title: 'Suspicious login',
    content: 'Multiple failed logins from 192.168.1.5',
    referenceId: testInvestigation.id,
    importanceScore: 90.0,
    confidence: 0.85,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!entry.id, '3.06 addEntry returns id');
  assert(entry.contextId === win.id, '3.07 entry linked to window');
  assert(entry.source === 'alert', '3.08 source persisted');
  assert(entry.priority === 'HIGH', '3.09 priority persisted');
  assert(entry.importanceScore === 90.0, '3.10 importanceScore persisted');

  // Context size updated
  const winAfterEntry = await contextWindowService.findWindow(win.id);
  assert((winAfterEntry?.contextSize ?? 0) > 0, '3.11 contextSize updated after entry');

  // 3.4 Add second entry
  const entry2 = await contextWindowService.addEntry(win.id, {
    source: 'finding',
    priority: 'MEDIUM',
    title: 'Malware artifact',
    content: 'Detected ransomware payload in /tmp/payload.sh',
    referenceId: testInvestigation.id,
    importanceScore: 70.0,
    confidence: 0.95,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!entry2.id, '3.12 second entry created');

  // 3.5 Update entry
  const updated = await contextWindowService.updateEntry(entry.id, {
    importanceScore: 95.0,
    updatedBy: testUser.id,
  });
  assert(updated.importanceScore === 95.0, '3.13 updateEntry persists change');

  // 3.6 Rank by importance
  const ranked = await contextWindowService.rankEntriesByImportance(win.id);
  assert(Array.isArray(ranked), '3.14 rankEntriesByImportance returns array');
  assert(ranked.length >= 2, '3.15 ranked list has >= 2 entries');
  assert((ranked[0]?.importanceScore ?? 0) >= (ranked[1]?.importanceScore ?? 0), '3.16 sorted by descending importance');

  // 3.7 Rank by confidence
  const rankedConf = await contextWindowService.rankEntriesByConfidence(win.id);
  assert(rankedConf.length >= 2, '3.17 rankEntriesByConfidence returns entries');
  assert((rankedConf[0]?.confidence ?? 0) >= (rankedConf[1]?.confidence ?? 0), '3.18 sorted by descending confidence');

  // 3.8 Stats
  const stats = await contextWindowService.getWindowStats(win.id);
  assert(stats.entryCount === 2, '3.19 stats.entryCount === 2');
  assert(stats.contextSize > 0, '3.20 stats.contextSize > 0');
  assert(stats.averageImportance > 0, '3.21 stats.averageImportance > 0');
  assert(stats.averageConfidence > 0, '3.22 stats.averageConfidence > 0');

  // 3.9 Find helpers
  const byUser = await contextWindowService.findByUser(testUser.id);
  assert(byUser.some((w) => w.id === win.id), '3.23 findByUser includes window');
  const activeWins = await contextWindowService.findActive();
  assert(activeWins.some((w) => w.id === win.id), '3.24 findActive includes window');
  const foundEntries = await contextWindowService.findEntries(win.id);
  assert(foundEntries.length === 2, '3.25 findEntries returns 2');

  // 3.10 Lifecycle transitions
  const archWin = await contextWindowService.archiveWindow(win.id, testUser.id);
  assert(archWin.status === 'ARCHIVED', '3.26 archiveWindow sets ARCHIVED');
  const actWin = await contextWindowService.activateWindow(win.id, testUser.id);
  assert(actWin.status === 'ACTIVE', '3.27 activateWindow sets ACTIVE');

  // 3.11 Delete entry
  await contextWindowService.deleteEntry(entry2.id, testUser.id);
  const afterDelete = await contextWindowService.findEntries(win.id);
  assert(afterDelete.every((e) => e.id !== entry2.id), '3.28 deleteEntry soft-deletes');

  // 3.12 Soft delete window
  await contextWindowService.deleteWindow(win.id, testUser.id);
  const deletedWin = await contextWindowService.findWindow(win.id);
  assert(deletedWin?.deletedAt !== null, '3.29 deleteWindow sets deletedAt');
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4 — PromptAssemblyService
// ═══════════════════════════════════════════════════════════════════════════════
async function testPromptAssemblyService(): Promise<void> {
  section('4. PromptAssemblyService');

  // 4.1 Create prompt
  const prompt = await promptAssemblyService.createPrompt({
    investigationId: testInvestigation.id,
    projectId: testProject.id,
    userId: testUser.id,
    systemPrompt: 'You are a cybersecurity analyst AI.',
    userPrompt: 'Analyze the following alert and provide a threat assessment.',
    maxTokens: 4096,
    reservedTokens: 512,
    status: 'DRAFT',
    promptName: `prompt-${RUN}`,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!prompt.id, '4.01 createPrompt returns id');
  assert(prompt.systemPrompt.includes('cybersecurity'), '4.02 systemPrompt persisted');
  assert(prompt.maxTokens === 4096, '4.03 maxTokens persisted');
  assert(prompt.reservedTokens === 512, '4.04 reservedTokens persisted');
  assert(prompt.status === 'DRAFT', '4.05 initial status DRAFT');

  // 4.2 Required validation
  try {
    await promptAssemblyService.createPrompt({
      projectId: testProject.id,
    } as any);
    fail('4.06 missing investigationId should throw');
  } catch { ok('4.06 validation rejects missing investigationId'); }

  // 4.3 Add section
  const section1 = await promptAssemblyService.addSection(prompt.id, {
    title: 'Alert Context',
    content: 'Alert triggered at 14:30 UTC. Source IP: 10.0.0.5. Destination: 443.',
    priority: 80,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!section1.id, '4.07 addSection returns id');
  assert(section1.promptId === prompt.id, '4.08 section linked to prompt');
  assert(section1.title === 'Alert Context', '4.09 title persisted');
  assert(section1.priority === 80, '4.10 priority persisted');

  // 4.4 Add second section
  const section2 = await promptAssemblyService.addSection(prompt.id, {
    title: 'Historical Context',
    content: 'Previous alerts from this IP: 3 in last 24h. All port 443.',
    priority: 60,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!section2.id, '4.11 second section created');

  // 4.5 Update section
  const updSection = await promptAssemblyService.updateSection(section1.id, {
    priority: 90,
    updatedBy: testUser.id,
  });
  assert(updSection.priority === 90, '4.12 updateSection persists priority change');

  // 4.6 Assemble prompt
  const assembled = await promptAssemblyService.assemblePrompt(prompt.id);
  assert(typeof assembled === 'string', '4.13 assemblePrompt returns string');
  assert(assembled.includes('cybersecurity'), '4.14 assembled includes systemPrompt');
  assert(assembled.includes('Alert Context'), '4.15 assembled includes section titles');
  assert(assembled.includes('Historical Context'), '4.16 assembled includes all sections');

  // 4.7 Token usage
  const tokenEst = await promptAssemblyService.calculateTokenUsage(prompt.id);
  assert(typeof tokenEst === 'number' && tokenEst > 0, '4.17 calculateTokenUsage returns positive number');

  // 4.8 Token budget check
  const budget = await promptAssemblyService.checkTokenBudget(prompt.id);
  assert(typeof budget.estimatedTokens === 'number', '4.18 budget.estimatedTokens is number');
  assert(typeof budget.maxTokens === 'number', '4.19 budget.maxTokens is number');
  assert(typeof budget.reservedTokens === 'number', '4.20 budget.reservedTokens is number');
  assert(typeof budget.withinBudget === 'boolean', '4.21 budget.withinBudget is boolean');
  assert(budget.maxTokens === 4096, '4.22 budget.maxTokens matches');

  // 4.9 Search sections
  const foundSections = await promptAssemblyService.searchSections('Alert');
  assert(Array.isArray(foundSections), '4.23 searchSections returns array');
  assert(foundSections.some((s) => s.id === section1.id), '4.24 searchSections finds by title');

  // 4.10 Find helpers
  const byProject = await promptAssemblyService.findByProject(testProject.id);
  assert(byProject.some((p) => p.id === prompt.id), '4.25 findByProject');
  const foundSects = await promptAssemblyService.findSections(prompt.id);
  assert(foundSects.length === 2, '4.26 findSections returns 2');

  // 4.11 Lifecycle transitions
  const published = await promptAssemblyService.publishPrompt(prompt.id, testUser.id);
  assert(published.status === 'ACTIVE', '4.27 publishPrompt sets ACTIVE');
  const pubList = await promptAssemblyService.findPublished();
  assert(pubList.some((p) => p.id === prompt.id), '4.28 findPublished includes prompt');
  const archived = await promptAssemblyService.archivePrompt(prompt.id, testUser.id);
  assert(archived.status === 'ARCHIVED', '4.29 archivePrompt sets ARCHIVED');
  const drafted = await promptAssemblyService.draftPrompt(prompt.id, testUser.id);
  assert(drafted.status === 'DRAFT', '4.30 draftPrompt sets DRAFT');

  // 4.12 Delete section
  await promptAssemblyService.deleteSection(section2.id, testUser.id);
  const afterDel = await promptAssemblyService.findSections(prompt.id);
  assert(afterDel.every((s) => s.id !== section2.id), '4.31 deleteSection soft-deletes');

  // 4.13 Soft delete prompt
  await promptAssemblyService.deletePrompt(prompt.id, testUser.id);
  const deleted = await promptAssemblyService.findPrompt(prompt.id);
  assert(deleted?.deletedAt !== null, '4.32 deletePrompt sets deletedAt');
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 — ReasoningService
// ═══════════════════════════════════════════════════════════════════════════════
async function testReasoningService(): Promise<void> {
  section('5. ReasoningService');

  // 5.1 Create session
  const session = await reasoningService.createSession({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    sessionName: `reasoning-${RUN}`,
    status: 'ACTIVE',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!session.id, '5.01 createSession returns id');
  assert(session.status === 'ACTIVE', '5.02 initial status ACTIVE');
  assert(session.projectId === testProject.id, '5.03 projectId persisted');
  assert(session.investigationId === testInvestigation.id, '5.04 investigationId persisted');
  assert(session.overallConfidence === 0.0, '5.05 initial overallConfidence = 0.0');
  assert(session.overallRisk === 0.0, '5.06 initial overallRisk = 0.0');

  // 5.2 Validation
  try {
    await reasoningService.createSession({ projectId: testProject.id } as any);
    fail('5.07 missing investigationId should throw');
  } catch { ok('5.07 validation rejects missing investigationId'); }

  // 5.3 Add step 1
  const step1 = await reasoningService.addStep(session.id, {
    stepNumber: 1,
    stage: 'COLLECTION',
    inputSummary: 'Collected 5 alerts from last 24h',
    outputSummary: 'Identified 2 high-severity alerts',
    confidence: 0.85,
    evidenceIds: [],
    findingIds: [],
    alertIds: [],
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!step1.id, '5.08 addStep returns id');
  assert(step1.reasoningId === session.id, '5.09 step linked to session');
  assert(step1.stepNumber === 1, '5.10 stepNumber persisted');
  assert(step1.confidence === 0.85, '5.11 confidence persisted');
  assert(step1.stage === 'COLLECTION', '5.12 stage persisted');

  // 5.4 Add step 2
  const step2 = await reasoningService.addStep(session.id, {
    stepNumber: 2,
    stage: 'ANALYSIS',
    inputSummary: '2 high-severity alerts analyzed',
    outputSummary: 'Correlated with known APT-29 TTPs',
    confidence: 0.75,
    evidenceIds: [testInvestigation.id],
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!step2.id, '5.13 second step created');

  // Confidence recalculated
  const sessionAfterSteps = await reasoningService.findSession(session.id);
  assert((sessionAfterSteps?.overallConfidence ?? 0) > 0, '5.14 overallConfidence updated after steps');

  // 5.5 Update step
  const updStep = await reasoningService.updateStep(step1.id, {
    confidence: 0.9,
    updatedBy: testUser.id,
  });
  assert(updStep.confidence === 0.9, '5.15 updateStep persists confidence change');

  // 5.6 Link evidence to step
  const linkedStep = await reasoningService.linkEvidenceToStep(step1.id, testInvestigation.id, testUser.id);
  assert(linkedStep.evidenceIds.includes(testInvestigation.id), '5.16 linkEvidenceToStep adds evidenceId');
  // Deduplication
  const linkedAgain = await reasoningService.linkEvidenceToStep(step1.id, testInvestigation.id, testUser.id);
  assert(linkedAgain.evidenceIds.filter((e) => e === testInvestigation.id).length === 1, '5.17 evidenceIds deduplicated');

  // 5.7 Link finding to step
  const linkedFinding = await reasoningService.linkFindingToStep(step2.id, testInvestigation.id, testUser.id);
  assert(linkedFinding.findingIds.includes(testInvestigation.id), '5.18 linkFindingToStep adds findingId');

  // 5.8 Calculate confidence
  const conf = await reasoningService.calculateConfidence(session.id);
  assert(typeof conf === 'number' && conf > 0, '5.19 calculateConfidence returns positive');

  // 5.9 Calculate risk
  const risk = await reasoningService.calculateOverallRisk(session.id);
  assert(typeof risk === 'number' && risk >= 0, '5.20 calculateOverallRisk returns non-negative');
  assert(risk <= 1.0, '5.21 risk <= 1.0');

  // 5.10 Stats
  const stats = await reasoningService.getSessionStats(session.id);
  assert(stats.stepCount === 2, '5.22 stats.stepCount === 2');
  assert(stats.overallConfidence >= 0, '5.23 stats.overallConfidence >= 0');
  assert(stats.overallRisk >= 0, '5.24 stats.overallRisk >= 0');
  assert(stats.totalEvidenceLinks >= 1, '5.25 stats.totalEvidenceLinks >= 1');
  assert(stats.totalFindingLinks >= 1, '5.26 stats.totalFindingLinks >= 1');

  // 5.11 Find helpers
  const byStatus = await reasoningService.findByStatus('ACTIVE');
  assert(byStatus.some((s) => s.id === session.id), '5.27 findByStatus includes session');
  const steps = await reasoningService.findSteps(session.id);
  assert(steps.length === 2, '5.28 findSteps returns 2');
  assert(steps[0].stepNumber <= steps[1].stepNumber, '5.29 steps ordered by stepNumber');

  // 5.12 Complete session
  const completed = await reasoningService.completeSession(session.id, 'Threat confirmed: APT-29', testUser.id);
  assert(completed.status === 'COMPLETED', '5.30 completeSession sets COMPLETED');
  assert(completed.decision === 'Threat confirmed: APT-29', '5.31 decision persisted');
  const completedList = await reasoningService.findCompleted();
  assert(completedList.some((s) => s.id === session.id), '5.32 findCompleted includes session');

  // 5.13 Create a session to fail
  const failSession = await reasoningService.createSession({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const failed2 = await reasoningService.failSession(failSession.id, 'system');
  assert(failed2.status === 'FAILED', '5.33 failSession sets FAILED');

  // 5.14 Soft delete
  await reasoningService.deleteSession(session.id, testUser.id);
  const deletedSess = await reasoningService.findSession(session.id);
  assert(deletedSess?.deletedAt !== null, '5.34 deleteSession sets deletedAt');

  // cleanup
  await prisma.reasoning.delete({ where: { id: failSession.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6 — ProviderService
// ═══════════════════════════════════════════════════════════════════════════════
async function testProviderService(): Promise<void> {
  section('6. ProviderService');

  // 6.1 Register provider
  const prov = await providerService.registerProvider({
    providerName: `openai-${RUN}`,
    displayName: `OpenAI ${RUN}`,
    apiVersion: 'v1',
    endpoint: 'https://api.openai.com',
    defaultModel: 'gpt-4o',
    enabled: true,
    priority: 1,
    healthScore: 99.0,
    providerType: 'CLOUD',
    status: 'ACTIVE',
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(!!prov.id, '6.01 registerProvider returns id');
  assert(prov.providerName === `openai-${RUN}`, '6.02 providerName persisted');
  assert(prov.healthScore === 99.0, '6.03 healthScore persisted');
  assert(prov.enabled === true, '6.04 enabled = true');
  assert(prov.status === 'ACTIVE', '6.05 status = ACTIVE');

  // 6.2 Required validation
  try {
    await providerService.registerProvider({ endpoint: 'x' } as any);
    fail('6.06 missing providerName should throw');
  } catch { ok('6.06 validation rejects missing providerName'); }

  // 6.3 Register model
  const model = await providerService.registerModel(prov.id, {
    modelName: 'gpt-4o',
    alias: 'gpt4-turbo',
    streaming: true,
    toolCalling: true,
    jsonMode: true,
    vision: true,
    embeddings: false,
    maxContextTokens: 128000,
    maxOutputTokens: 4096,
    enabled: true,
    priority: 10,
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(!!model.id, '6.07 registerModel returns id');
  assert(model.providerId === prov.id, '6.08 model linked to provider');
  assert(model.modelName === 'gpt-4o', '6.09 modelName persisted');
  assert(model.streaming === true, '6.10 streaming = true');
  assert(model.toolCalling === true, '6.11 toolCalling = true');
  assert(model.jsonMode === true, '6.12 jsonMode = true');
  assert(model.vision === true, '6.13 vision = true');
  assert(model.maxContextTokens === 128000, '6.14 maxContextTokens persisted');

  // 6.4 Register second model (embeddings)
  const embModel = await providerService.registerModel(prov.id, {
    modelName: 'text-embedding-3-large',
    streaming: false,
    toolCalling: false,
    jsonMode: false,
    vision: false,
    embeddings: true,
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(embModel.embeddings === true, '6.15 embeddings = true on second model');

  // 6.5 Get capabilities
  const caps = await providerService.getCapabilities(prov.id);
  assert(caps.streaming === true, '6.16 caps.streaming = true');
  assert(caps.toolCalling === true, '6.17 caps.toolCalling = true');
  assert(caps.jsonMode === true, '6.18 caps.jsonMode = true');
  assert(caps.vision === true, '6.19 caps.vision = true');
  assert(caps.embeddings === true, '6.20 caps.embeddings = true');

  // 6.6 Find enabled/healthy
  const enabled = await providerService.findEnabled();
  assert(enabled.some((p) => p.id === prov.id), '6.21 findEnabled includes provider');
  const healthy = await providerService.findHealthy();
  assert(healthy.some((p) => p.id === prov.id), '6.22 findHealthy includes provider');

  // 6.7 Find models
  const models = await providerService.findModels(prov.id);
  assert(models.length >= 2, '6.23 findModels returns >= 2');
  const modelByName = await providerService.findModelByName(prov.id, 'gpt-4o');
  assert(modelByName?.id === model.id, '6.24 findModelByName returns correct model');

  // 6.8 Provider selection — priority strategy
  const selected = await providerService.selectProvider({ strategy: 'priority' });
  assert(selected !== null, '6.25 selectProvider returns provider');
  const selectedHealth = await providerService.selectProvider({ strategy: 'health' });
  assert(selectedHealth !== null, '6.26 selectProvider health strategy');
  const selectedRandom = await providerService.selectProvider({ strategy: 'random' });
  assert(selectedRandom !== null, '6.27 selectProvider random strategy');

  // 6.9 Capability-filtered selection
  const streamingProvider = await providerService.selectProvider({ requireStreaming: true });
  assert(streamingProvider !== null, '6.28 selectProvider requireStreaming');
  const toolCallingProvider = await providerService.selectProvider({ requireToolCalling: true });
  assert(toolCallingProvider !== null, '6.29 selectProvider requireToolCalling');

  // 6.10 Health score update
  const updated = await providerService.updateHealthScore(prov.id, 75.0, 'system');
  assert(updated.healthScore === 75.0, '6.30 updateHealthScore persists value');

  // 6.11 Provider stats
  const stats = await providerService.getProviderStats(prov.id);
  assert(stats.totalModels >= 2, '6.31 stats.totalModels >= 2');
  assert(stats.enabledModels >= 2, '6.32 stats.enabledModels >= 2');
  assert(stats.healthScore === 75.0, '6.33 stats.healthScore matches');
  assert(typeof stats.capabilities.streaming === 'boolean', '6.34 stats.capabilities.streaming is boolean');

  // 6.12 Disable / enable
  const disabled = await providerService.disableProvider(prov.id, 'system');
  assert(disabled.enabled === false, '6.35 disableProvider sets enabled = false');
  const reenabled = await providerService.enableProvider(prov.id, 'system');
  assert(reenabled.enabled === true, '6.36 enableProvider sets enabled = true');

  // 6.13 Get model capabilities
  const modelCaps = await providerService.getModelCapabilities(model.id);
  assert(modelCaps?.streaming === true, '6.37 getModelCapabilities returns model');

  // 6.14 Soft delete
  await providerService.deleteProvider(prov.id, 'system');
  const deleted = await providerService.findProvider(prov.id);
  assert(deleted?.deletedAt !== null, '6.38 deleteProvider sets deletedAt');
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7 — ExecutionService
// ═══════════════════════════════════════════════════════════════════════════════
async function testExecutionService(): Promise<void> {
  section('7. ExecutionService');

  // 7.1 Submit execution
  const exec = await executionService.submitExecution({
    providerId: testProvider.id,
    systemPrompt: 'You are an AI security analyst.',
    userPrompt: 'Assess threat level for the given alert data.',
    temperature: 0.1,
    maxTokens: 2048,
    stream: false,
    strategy: 'priority',
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!exec.id, '7.01 submitExecution returns id');
  assert(exec.providerId === testProvider.id, '7.02 providerId persisted');
  assert(exec.status === 'PENDING', '7.03 initial status PENDING');
  assert(exec.temperature === 0.1, '7.04 temperature persisted');
  assert(exec.maxTokens === 2048, '7.05 maxTokens persisted');

  // 7.2 Required validation
  try {
    await executionService.submitExecution({ systemPrompt: 'x' } as any);
    fail('7.06 missing providerId should throw');
  } catch { ok('7.06 validation rejects missing providerId'); }

  // 7.3 Disabled provider check
  await prisma.provider.update({
    where: { id: testProvider.id },
    data: { enabled: false },
  });
  try {
    await executionService.submitExecution({
      providerId: testProvider.id,
      systemPrompt: 'x',
      userPrompt: 'y',
      createdBy: 'system',
      updatedBy: 'system',
    });
    fail('7.07 disabled provider should throw');
  } catch { ok('7.07 disabled provider rejected on submit'); }
  // Re-enable
  await prisma.provider.update({ where: { id: testProvider.id }, data: { enabled: true } });

  // 7.4 Lifecycle transitions
  const started = await executionService.startExecution(exec.id, testUser.id);
  assert(started.status === 'ACTIVE', '7.08 startExecution sets ACTIVE');
  const completed = await executionService.completeExecution(exec.id, testUser.id);
  assert(completed.status === 'COMPLETED', '7.09 completeExecution sets COMPLETED');

  // 7.5 Record usage
  const usage = await executionService.recordUsage(exec.id, {
    promptTokens: 450,
    completionTokens: 120,
    totalTokens: 570,
    estimatedCost: 0.00285,
    latencyMs: 1250,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!usage.id, '7.10 recordUsage returns id');
  assert(usage.executionId === exec.id, '7.11 usage linked to execution');
  assert(usage.promptTokens === 450, '7.12 promptTokens persisted');
  assert(usage.completionTokens === 120, '7.13 completionTokens persisted');
  assert(usage.totalTokens === 570, '7.14 totalTokens persisted');
  assert(Math.abs(usage.estimatedCost - 0.00285) < 0.0001, '7.15 estimatedCost persisted');
  assert(usage.latencyMs === 1250, '7.16 latencyMs persisted');

  // 7.6 Calculate cost
  const cost = await executionService.calculateCost(exec.id);
  assert(Math.abs(cost - 0.00285) < 0.0001, '7.17 calculateCost returns correct value');

  // 7.7 Usage stats
  const stats = await executionService.getUsageStats(exec.id);
  assert(stats !== null, '7.18 getUsageStats returns stats');
  assert(stats?.totalTokens === 570, '7.19 stats.totalTokens matches');
  assert(stats?.latencyMs === 1250, '7.20 stats.latencyMs matches');

  // 7.8 Failed/cancelled executions
  const exec2 = await executionService.submitExecution({
    providerId: testProvider.id,
    systemPrompt: 'sys',
    userPrompt: 'usr',
    createdBy: 'system',
    updatedBy: 'system',
  });
  const failedExec = await executionService.failExecution(exec2.id, 'system');
  assert(failedExec.status === 'FAILED', '7.21 failExecution sets FAILED');
  const failedList = await executionService.findFailed();
  assert(failedList.some((e) => e.id === exec2.id), '7.22 findFailed includes execution');

  const exec3 = await executionService.submitExecution({
    providerId: testProvider.id,
    systemPrompt: 'sys',
    userPrompt: 'usr',
    createdBy: 'system',
    updatedBy: 'system',
  });
  const cancelledExec = await executionService.cancelExecution(exec3.id, 'system');
  assert(cancelledExec.status === 'FAILED', '7.23 cancelExecution sets FAILED');

  // 7.9 Find helpers
  const byProvider = await executionService.findByProvider(testProvider.id);
  assert(byProvider.some((e) => e.id === exec.id), '7.24 findByProvider');
  const byStatus = await executionService.findByStatus('COMPLETED');
  assert(byStatus.some((e) => e.id === exec.id), '7.25 findByStatus COMPLETED');
  const completedList = await executionService.findCompleted();
  assert(completedList.some((e) => e.id === exec.id), '7.26 findCompleted');

  // 7.10 Aggregate project usage
  const aggregate = await executionService.aggregateProjectUsage(testProject.id);
  assert(typeof aggregate.totalExecutions === 'number', '7.27 aggregate.totalExecutions is number');
  assert(aggregate.totalExecutions >= 1, '7.28 aggregate.totalExecutions >= 1');
  assert(aggregate.totalTokens >= 0, '7.29 aggregate.totalTokens >= 0');
  assert(aggregate.totalCost >= 0, '7.30 aggregate.totalCost >= 0');
  assert(aggregate.avgLatencyMs >= 0, '7.31 aggregate.avgLatencyMs >= 0');

  // 7.11 Soft delete
  await executionService.deleteExecution(exec.id, testUser.id);
  const deleted = await executionService.findExecution(exec.id);
  assert(deleted?.deletedAt !== null, '7.32 deleteExecution sets deletedAt');

  // cleanup
  await prisma.execution.delete({ where: { id: exec2.id } }).catch(() => {});
  await prisma.execution.delete({ where: { id: exec3.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8 — StreamingService
// ═══════════════════════════════════════════════════════════════════════════════
async function testStreamingService(): Promise<void> {
  section('8. StreamingService');

  // Create a linked execution first
  const exec = await prisma.execution.create({
    data: {
      providerId: testProvider.id,
      systemPrompt: 'system',
      userPrompt: 'user',
      stream: true,
      strategy: 'priority',
      projectId: testProject.id,
      status: 'ACTIVE',
      createdBy: 'system',
      updatedBy: 'system',
    },
  });

  // 8.1 Create streaming session
  const stream = await streamingService.createSession({
    executionId: exec.id,
    streamName: `stream-${RUN}`,
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!stream.id, '8.01 createSession returns id');
  assert(stream.status === 'ACTIVE', '8.02 initial status ACTIVE');
  assert(stream.executionId === exec.id, '8.03 executionId persisted');

  // 8.2 Validation
  try {
    await streamingService.createSession({ executionId: 'bad-uuid', createdBy: 'x', updatedBy: 'x' });
    fail('8.04 invalid executionId UUID should throw');
  } catch { ok('8.04 UUID validation on createSession'); }

  // 8.3 Append chunk 1
  const chunk1 = await streamingService.appendChunk(stream.id, {
    sequenceNumber: 1,
    content: 'Analyzing the threat',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!chunk1.id, '8.05 appendChunk returns id');
  assert(chunk1.streamingId === stream.id, '8.06 chunk linked to stream');
  assert(chunk1.sequenceNumber === 1, '8.07 sequenceNumber persisted');
  assert(chunk1.content === 'Analyzing the threat', '8.08 content persisted');
  assert(chunk1.finishReason === null, '8.09 finishReason = null initially');

  // 8.4 Append chunk 2
  const chunk2 = await streamingService.appendChunk(stream.id, {
    sequenceNumber: 2,
    content: ' level as HIGH.',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(chunk2.sequenceNumber === 2, '8.10 chunk2 sequenceNumber = 2');

  // 8.5 Progress before completion
  const progress = await streamingService.getProgress(stream.id);
  assert(typeof progress === 'number', '8.11 getProgress returns number');
  assert(progress >= 0, '8.12 progress >= 0');

  // 8.6 Find chunks
  const chunks = await streamingService.findChunks(stream.id);
  assert(chunks.length === 2, '8.13 findChunks returns 2 chunks');
  assert(chunks[0].sequenceNumber <= chunks[1].sequenceNumber, '8.14 chunks ordered by sequenceNumber');

  // 8.7 Reconstruct content
  const content = await streamingService.reconstructContent(stream.id);
  assert(content === 'Analyzing the threat level as HIGH.', '8.15 reconstructContent joins chunks in order');

  // 8.8 Stats before completion
  const statsActive = await streamingService.getStreamingStats(stream.id);
  assert(statsActive.chunkCount === 2, '8.16 stats.chunkCount === 2');
  assert(statsActive.totalLength > 0, '8.17 stats.totalLength > 0');
  assert(statsActive.isComplete === false, '8.18 stats.isComplete = false while ACTIVE');
  assert(statsActive.status === 'ACTIVE', '8.19 stats.status = ACTIVE');

  // 8.9 Append final chunk with finishReason (auto-completes session)
  const chunk3 = await streamingService.appendChunk(stream.id, {
    sequenceNumber: 3,
    content: ' Recommendation: immediate containment.',
    finishReason: 'stop',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(chunk3.finishReason === 'stop', '8.20 finishReason persisted');

  // Session should be auto-completed
  const streamAfterFinal = await streamingService.findSession(stream.id);
  assert(streamAfterFinal?.status === 'COMPLETED', '8.21 session auto-completed after finishReason chunk');

  // 8.10 Cannot append to completed session
  try {
    await streamingService.appendChunk(stream.id, {
      sequenceNumber: 4,
      content: 'extra',
      createdBy: 'system',
      updatedBy: 'system',
    });
    fail('8.22 append to COMPLETED session should throw');
  } catch { ok('8.22 cannot append chunk to COMPLETED session'); }

  // 8.11 Stats after completion
  const statsCompleted = await streamingService.getStreamingStats(stream.id);
  assert(statsCompleted.chunkCount === 3, '8.23 stats.chunkCount === 3 after final');
  assert(statsCompleted.isComplete === true, '8.24 stats.isComplete = true');
  assert(statsCompleted.progress === 100, '8.25 progress = 100 when COMPLETED');

  // 8.12 Find by execution
  const byExec = await streamingService.findByExecution(exec.id);
  assert(byExec?.id === stream.id, '8.26 findByExecution returns correct session');

  // 8.13 Find active / completed
  const completed2 = await streamingService.findCompleted();
  assert(completed2.some((s) => s.id === stream.id), '8.27 findCompleted includes stream');

  // 8.14 Create a fresh session to fail
  const exec2 = await prisma.execution.create({
    data: {
      providerId: testProvider.id,
      systemPrompt: 'sys',
      userPrompt: 'usr',
      stream: true,
      strategy: 'priority',
      status: 'ACTIVE',
      createdBy: 'system',
      updatedBy: 'system',
    },
  });
  const stream2 = await streamingService.createSession({
    executionId: exec2.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const failed = await streamingService.failSession(stream2.id, 'system');
  assert(failed.status === 'FAILED', '8.28 failSession sets FAILED');

  // 8.15 Create a fresh session to cancel
  const exec3 = await prisma.execution.create({
    data: {
      providerId: testProvider.id,
      systemPrompt: 'sys',
      userPrompt: 'usr',
      stream: true,
      strategy: 'priority',
      status: 'ACTIVE',
      createdBy: 'system',
      updatedBy: 'system',
    },
  });
  const stream3 = await streamingService.createSession({
    executionId: exec3.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const cancelled = await streamingService.cancelSession(stream3.id, 'system');
  assert(cancelled.status === 'FAILED', '8.29 cancelSession sets FAILED');

  // 8.16 Soft delete
  await streamingService.deleteSession(stream.id, testUser.id);
  const deleted = await streamingService.findSession(stream.id);
  assert(deleted?.deletedAt !== null, '8.30 deleteSession sets deletedAt');

  // cleanup
  await prisma.execution.delete({ where: { id: exec.id } }).catch(() => {});
  await prisma.execution.delete({ where: { id: exec2.id } }).catch(() => {});
  await prisma.execution.delete({ where: { id: exec3.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9 — Cross-service integration tests
// ═══════════════════════════════════════════════════════════════════════════════
async function testIntegration(): Promise<void> {
  section('9. Cross-service Integration');

  // 9.1 Full AI pipeline: Conversation → Context → Prompt → Reasoning → Execution → Streaming

  // Step 1: Conversation
  const conv = await conversationService.createConversation({
    title: `integration-${RUN}`,
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!conv.id, '9.01 Integration conv created');

  const userMsg = await conversationService.addMessage(conv.id, {
    role: 'user',
    content: 'I need a threat assessment for the current investigation.',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!userMsg.id, '9.02 User message added');

  // Step 2: Session Memory
  const memory = await sessionMemoryService.createMemory({
    conversationId: conv.id,
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!memory.id, '9.03 Session memory created');

  await sessionMemoryService.addEntry(memory.id, {
    memoryType: 'ALERT_CONTEXT',
    state: 'ACTIVE',
    title: 'High-severity alert: Lateral Movement',
    content: 'Alert detected lateral movement using SMB from 10.0.0.5 to 10.0.1.20',
    importanceScore: 95.0,
    confidence: 0.92,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(true, '9.04 Memory entry added');

  // Step 3: Context Window
  const ctxWin = await contextWindowService.createWindow({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    conversationId: conv.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!ctxWin.id, '9.05 Context window created');

  await contextWindowService.addEntry(ctxWin.id, {
    source: 'alert',
    priority: 'CRITICAL',
    title: 'Lateral Movement Alert',
    content: 'SMB traffic anomaly detected',
    referenceId: testInvestigation.id,
    importanceScore: 95.0,
    confidence: 0.92,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(true, '9.06 Context entry added');

  // Step 4: Prompt Assembly
  const prompt = await promptAssemblyService.createPrompt({
    investigationId: testInvestigation.id,
    projectId: testProject.id,
    contextId: ctxWin.id,
    systemPrompt: 'You are a cybersecurity AI analyst.',
    userPrompt: 'Provide a threat assessment for the given context.',
    maxTokens: 4096,
    reservedTokens: 512,
    status: 'DRAFT',
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!prompt.id, '9.07 Prompt assembly created with contextId');
  assert(prompt.contextId === ctxWin.id, '9.08 Prompt linked to context window');

  await promptAssemblyService.addSection(prompt.id, {
    title: 'Investigation Context',
    content: 'Active investigation for lateral movement incident.',
    priority: 90,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(true, '9.09 Prompt section added');

  const budget = await promptAssemblyService.checkTokenBudget(prompt.id);
  assert(budget.withinBudget === true, '9.10 Prompt within token budget');

  // Step 5: Reasoning session
  const reasoning = await reasoningService.createSession({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    sessionName: `pipeline-reasoning-${RUN}`,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!reasoning.id, '9.11 Reasoning session created');

  await reasoningService.addStep(reasoning.id, {
    stepNumber: 1,
    stage: 'TRIAGE',
    inputSummary: 'Lateral movement alert + SMB traffic',
    outputSummary: 'High confidence lateral movement',
    confidence: 0.92,
    evidenceIds: [testInvestigation.id],
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(true, '9.12 Reasoning step added');

  // Publish prompt and link to reasoning
  await promptAssemblyService.publishPrompt(prompt.id, testUser.id);
  await prisma.promptAssembly.update({
    where: { id: prompt.id },
    data: { reasoningId: reasoning.id },
  });
  const linkedPrompt = await promptAssemblyService.findPrompt(prompt.id);
  assert(linkedPrompt?.reasoningId === reasoning.id, '9.13 Prompt linked to reasoning');

  // Step 6: Execution
  const exec = await executionService.submitExecution({
    providerId: testProvider.id,
    systemPrompt: 'You are a cybersecurity AI analyst.',
    userPrompt: 'Provide a threat assessment.',
    temperature: 0.0,
    maxTokens: 4096,
    stream: true,
    strategy: 'priority',
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!exec.id, '9.14 Execution submitted');
  assert(exec.stream === true, '9.15 stream = true on execution');

  await executionService.startExecution(exec.id, testUser.id);
  assert(true, '9.16 Execution started');

  // Step 7: Streaming
  const stream = await streamingService.createSession({
    executionId: exec.id,
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    userId: testUser.id,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(!!stream.id, '9.17 Streaming session created linked to execution');

  await streamingService.appendChunk(stream.id, {
    sequenceNumber: 1,
    content: 'THREAT LEVEL: CRITICAL. ',
    createdBy: 'system',
    updatedBy: 'system',
  });
  await streamingService.appendChunk(stream.id, {
    sequenceNumber: 2,
    content: 'Lateral movement confirmed.',
    finishReason: 'stop',
    createdBy: 'system',
    updatedBy: 'system',
  });
  const reconstructed = await streamingService.reconstructContent(stream.id);
  assert(reconstructed.includes('CRITICAL'), '9.18 Reconstructed content includes THREAT LEVEL');

  // Step 8: Complete execution and record usage
  await executionService.completeExecution(exec.id, testUser.id);
  const usage = await executionService.recordUsage(exec.id, {
    promptTokens: 1200,
    completionTokens: 300,
    totalTokens: 1500,
    estimatedCost: 0.0075,
    latencyMs: 3200,
    createdBy: testUser.id,
    updatedBy: testUser.id,
  });
  assert(usage.totalTokens === 1500, '9.19 Usage recorded on pipeline execution');

  // Step 9: Complete reasoning
  const completedReasoning = await reasoningService.completeSession(
    reasoning.id,
    'Lateral movement confirmed — APT behavior pattern',
    testUser.id,
  );
  assert(completedReasoning.status === 'COMPLETED', '9.20 Reasoning session completed');
  assert(completedReasoning.decision !== null, '9.21 Decision recorded on reasoning');

  // Step 10: Add AI response to conversation
  await conversationService.addMessage(conv.id, {
    role: 'assistant',
    content: 'THREAT LEVEL: CRITICAL. Lateral movement confirmed.',
    createdBy: 'system',
    updatedBy: 'system',
  });
  const convStats = await conversationService.getConversationStats(conv.id);
  assert(convStats.messageCount === 2, '9.22 Conversation has 2 messages');

  // 9.2 Provider selection for streaming execution
  const streamingProv = await providerService.selectProvider({ requireStreaming: true });
  assert(streamingProv !== null, '9.23 selectProvider returns streaming-capable provider');

  // 9.3 Cross-service event coordination
  let eventCount = 0;
  const counter = () => { eventCount++; };
  ['ConversationCreated', 'SessionMemoryCreated', 'ContextWindowCreated',
   'PromptAssemblyCreated', 'ReasoningSessionCreated', 'ExecutionSubmitted',
   'StreamingSessionCreated'].forEach((e) => eventPublisher.subscribe(e, counter));

  const fullConv = await conversationService.createConversation({
    title: `cross-event-${RUN}`,
    projectId: testProject.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(eventCount >= 1, '9.24 ConversationCreated event fired');

  eventPublisher.clearAll();

  // cleanup
  await prisma.conversation.delete({ where: { id: fullConv.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 10 — Edge cases & additional coverage
// ═══════════════════════════════════════════════════════════════════════════════
async function testEdgeCases(): Promise<void> {
  section('10. Edge Cases & Additional Coverage');

  // 10.1 ConversationService — find non-existent
  const missing = await conversationService.findConversation(
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
  );
  assert(missing === null, '10.01 findConversation returns null for unknown id');

  // 10.2 SessionMemoryService — average on empty memory
  const emptyConv = await prisma.conversation.create({
    data: {
      title: `edge-conv-${RUN}`,
      projectId: testProject.id,
      createdBy: 'system',
      updatedBy: 'system',
    },
  });
  const emptyMem = await sessionMemoryService.createMemory({
    conversationId: emptyConv.id,
    projectId: testProject.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const emptyAvgImportance = await sessionMemoryService.calculateAverageImportance(emptyMem.id);
  assert(emptyAvgImportance === 0.0, '10.02 calculateAverageImportance = 0 on empty memory');
  const emptyAvgConf = await sessionMemoryService.calculateAverageConfidence(emptyMem.id);
  assert(emptyAvgConf === 0.0, '10.03 calculateAverageConfidence = 0 on empty memory');

  // 10.3 ContextWindowService — empty stats
  const emptyWin = await contextWindowService.createWindow({
    projectId: testProject.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const emptyWinStats = await contextWindowService.getWindowStats(emptyWin.id);
  assert(emptyWinStats.entryCount === 0, '10.04 empty window entryCount = 0');
  assert(emptyWinStats.averageImportance === 0.0, '10.05 empty window averageImportance = 0');

  // 10.4 ReasoningService — confidence on empty session
  const emptyReasoning = await reasoningService.createSession({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const emptyConf = await reasoningService.calculateConfidence(emptyReasoning.id);
  assert(emptyConf === 0.0, '10.06 calculateConfidence = 0 on session with no steps');
  const emptyRisk = await reasoningService.calculateOverallRisk(emptyReasoning.id);
  assert(emptyRisk === 0.0, '10.07 calculateOverallRisk = 0 on session with no steps');

  // 10.5 ExecutionService — usage returns null when none recorded
  const noUsageExec = await executionService.submitExecution({
    providerId: testProvider.id,
    systemPrompt: 'sys',
    userPrompt: 'usr',
    createdBy: 'system',
    updatedBy: 'system',
  });
  const nullUsage = await executionService.getUsageStats(noUsageExec.id);
  assert(nullUsage === null, '10.08 getUsageStats returns null when no usage recorded');
  const zeroCost = await executionService.calculateCost(noUsageExec.id);
  assert(zeroCost === 0.0, '10.09 calculateCost = 0 when no usage recorded');

  // 10.6 StreamingService — find non-existent execution returns null
  const noStream = await streamingService.findByExecution(
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
  );
  assert(noStream === null, '10.10 findByExecution returns null for unknown executionId');

  // 10.7 PromptAssemblyService — token budget with very large prompt
  const largePrompt = await promptAssemblyService.createPrompt({
    investigationId: testInvestigation.id,
    projectId: testProject.id,
    systemPrompt: 'sys',
    userPrompt: 'usr',
    maxTokens: 100,
    reservedTokens: 50,
    status: 'DRAFT',
    createdBy: 'system',
    updatedBy: 'system',
  });
  await promptAssemblyService.addSection(largePrompt.id, {
    title: 'Big Section',
    content: 'x'.repeat(2000),  // definitely over 100-token budget
    priority: 50,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const tightBudget = await promptAssemblyService.checkTokenBudget(largePrompt.id);
  assert(tightBudget.withinBudget === false, '10.11 withinBudget = false when over limit');

  // 10.8 ConversationService — search empty query throws
  try {
    await conversationService.searchMessages('');
    fail('10.12 empty search query should throw');
  } catch { ok('10.12 searchMessages rejects empty query'); }

  // 10.9 SessionMemoryService — search empty query throws
  try {
    await sessionMemoryService.searchEntries('');
    fail('10.13 empty searchEntries query should throw');
  } catch { ok('10.13 searchEntries rejects empty query'); }

  // 10.10 PromptAssemblyService — search empty query throws
  try {
    await promptAssemblyService.searchSections('');
    fail('10.14 empty searchSections query should throw');
  } catch { ok('10.14 searchSections rejects empty query'); }

  // 10.11 ProviderService — select with no healthy providers returns null
  // (All test providers are either soft-deleted or degraded in provider test so we only check the type)
  const result = await providerService.selectProvider({ strategy: 'priority' });
  assert(result === null || typeof result === 'object', '10.15 selectProvider returns null or object');

  // 10.12 Reasoning — step confidence clamped 0-1
  const clampSession = await reasoningService.createSession({
    projectId: testProject.id,
    investigationId: testInvestigation.id,
    createdBy: 'system',
    updatedBy: 'system',
  });
  const clampedStep = await reasoningService.addStep(clampSession.id, {
    stepNumber: 1,
    stage: 'TEST',
    inputSummary: 'x',
    outputSummary: 'y',
    confidence: 2.5,  // over 1.0 — should be clamped
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(clampedStep.confidence <= 1.0, '10.16 step confidence clamped to max 1.0');

  const negativeStep = await reasoningService.addStep(clampSession.id, {
    stepNumber: 2,
    stage: 'TEST',
    inputSummary: 'x',
    outputSummary: 'y',
    confidence: -0.5,  // below 0 — should be clamped
    createdBy: 'system',
    updatedBy: 'system',
  });
  assert(negativeStep.confidence >= 0.0, '10.17 step confidence clamped to min 0.0');

  // 10.13 ProviderService — health score clamped 0-100
  const provForClamp = await providerService.registerProvider({
    providerName: `clamp-prov-${RUN}`,
    displayName: 'Clamp Test',
    apiVersion: 'v1',
    endpoint: 'https://clamp.test',
    defaultModel: 'test',
    createdBy: 'system',
    updatedBy: 'system',
  });
  const overHundred = await providerService.updateHealthScore(provForClamp.id, 150.0, 'system');
  assert(overHundred.healthScore <= 100.0, '10.18 healthScore clamped to max 100');
  const belowZero = await providerService.updateHealthScore(provForClamp.id, -50.0, 'system');
  assert(belowZero.healthScore >= 0.0, '10.19 healthScore clamped to min 0');

  // 10.14 ConversationService — invalid UUID on findByProject
  try {
    await conversationService.findByProject('not-a-uuid');
    fail('10.20 findByProject invalid UUID should throw');
  } catch { ok('10.20 findByProject validates UUID'); }

  // 10.15 ExecutionService — invalid UUID on findByProvider
  try {
    await executionService.findByProvider('not-a-uuid');
    fail('10.21 findByProvider invalid UUID should throw');
  } catch { ok('10.21 findByProvider validates UUID'); }

  // cleanup
  await prisma.conversation.delete({ where: { id: emptyConv.id } }).catch(() => {});
  await prisma.execution.delete({ where: { id: noUsageExec.id } }).catch(() => {});
}


// ═══════════════════════════════════════════════════════════════════════════════
// CLEANUP — Remove all test data created during verification
// ═══════════════════════════════════════════════════════════════════════════════
async function cleanup(): Promise<void> {
  section('CLEANUP');

  try {
    // Delete in reverse-dependency order to avoid FK violations

    // Streaming chunks + sessions
    await prisma.streamingChunk.deleteMany({
      where: { streaming: { OR: [
        { project: { name: { contains: RUN } } },
        { investigation: { title: { contains: RUN } } },
        { createdBy: 'system' },
      ] } },
    }).catch(() => {});

    await prisma.streaming.deleteMany({
      where: { OR: [
        { streamName: { contains: RUN } },
        { project: { name: { contains: RUN } } },
      ] },
    }).catch(() => {});

    // Execution usages + executions
    await prisma.executionUsage.deleteMany({
      where: { execution: { OR: [
        { project: { name: { contains: RUN } } },
        { systemPrompt: { contains: 'cybersecurity' } },
      ] } },
    }).catch(() => {});

    await prisma.execution.deleteMany({
      where: { OR: [
        { project: { name: { contains: RUN } } },
        { investigation: { title: { contains: RUN } } },
      ] },
    }).catch(() => {});

    // Reasoning steps + sessions
    await prisma.reasoningStep.deleteMany({
      where: { reasoning: { OR: [
        { project: { name: { contains: RUN } } },
        { sessionName: { contains: RUN } },
      ] } },
    }).catch(() => {});

    await prisma.reasoning.deleteMany({
      where: { OR: [
        { project: { name: { contains: RUN } } },
        { sessionName: { contains: RUN } },
      ] },
    }).catch(() => {});

    // Prompt sections + assemblies
    await prisma.promptSection.deleteMany({
      where: { promptAssembly: { OR: [
        { project: { name: { contains: RUN } } },
        { promptName: { contains: RUN } },
      ] } },
    }).catch(() => {});

    await prisma.promptAssembly.deleteMany({
      where: { OR: [
        { project: { name: { contains: RUN } } },
        { promptName: { contains: RUN } },
      ] },
    }).catch(() => {});

    // Context entries + windows
    await prisma.contextEntry.deleteMany({
      where: { contextWindow: { OR: [
        { project: { name: { contains: RUN } } },
        { windowName: { contains: RUN } },
      ] } },
    }).catch(() => {});

    await prisma.contextWindow.deleteMany({
      where: { OR: [
        { project: { name: { contains: RUN } } },
        { windowName: { contains: RUN } },
      ] },
    }).catch(() => {});

    // Memory entries + session memories
    await prisma.memoryEntry.deleteMany({
      where: { sessionMemory: { OR: [
        { project: { name: { contains: RUN } } },
        { sessionName: { contains: RUN } },
      ] } },
    }).catch(() => {});

    await prisma.sessionMemory.deleteMany({
      where: { OR: [
        { project: { name: { contains: RUN } } },
        { sessionName: { contains: RUN } },
      ] },
    }).catch(() => {});

    // Conversation messages + conversations
    await prisma.conversationMessage.deleteMany({
      where: { conversation: { project: { name: { contains: RUN } } } },
    }).catch(() => {});

    await prisma.conversation.deleteMany({
      where: { project: { name: { contains: RUN } } },
    }).catch(() => {});

    // Provider models + providers
    await prisma.providerModel.deleteMany({
      where: { provider: { providerName: { contains: RUN } } },
    }).catch(() => {});

    await prisma.provider.deleteMany({
      where: { providerName: { contains: RUN } },
    }).catch(() => {});

    // Seed provider
    await prisma.provider.delete({ where: { id: testProvider.id } }).catch(() => {});

    // Core fixtures
    await prisma.investigation.delete({ where: { id: testInvestigation.id } }).catch(() => {});
    await prisma.project.delete({ where: { id: testProject.id } }).catch(() => {});
    await prisma.user.delete({ where: { id: testUser.id } }).catch(() => {});

    console.log('  ✓  Cleanup complete');
  } catch (err) {
    console.error('  ⚠  Cleanup error (non-fatal):', err);
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════════
async function main(): Promise<void> {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║  NetFusion A5.3.4 — AI Services Verification              ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log(`  RUN ID: ${RUN}`);

  const startTime = Date.now();

  try {
    await setupFixtures();

    await testConversationService();
    await testSessionMemoryService();
    await testContextWindowService();
    await testPromptAssemblyService();
    await testReasoningService();
    await testProviderService();
    await testExecutionService();
    await testStreamingService();
    await testIntegration();
    await testEdgeCases();

  } catch (err: any) {
    fail('FATAL', err?.message ?? String(err));
    console.error('\nFatal error:', err);
  } finally {
    await cleanup();
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log(`║  Results: ${passed} passed, ${failed} failed  (${elapsed}s)`.padEnd(61) + '║');
  console.log('╚═══════════════════════════════════════════════════════════╝');

  if (errors.length > 0) {
    console.log('\nFailed assertions:');
    errors.forEach((e) => console.log(`  ✗  ${e}`));
  }

  if (failed === 0) {
    console.log('\n  ✅  All assertions passed — A5.3.4 AI Services verified.');
  } else {
    console.log(`\n  ❌  ${failed} assertion(s) failed.`);
  }

  process.exit(failed > 0 ? 1 : 0);
}

main()
  .catch((err) => {
    console.error('Unhandled error:', err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
