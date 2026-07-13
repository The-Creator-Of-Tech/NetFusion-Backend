/**
 * prisma/seed.ts — Phase A5.1.2
 * ================================
 * Seeds the foundation data every NetFusion deployment requires:
 *   - Roles:       Admin, Investigator, Analyst, Viewer
 *   - Permissions: asset.read/write, finding.read/write,
 *                  report.read/write, project.manage, user.manage
 *   - Role-Permission mappings
 *
 * Design rules
 * ------------
 * - Idempotent: safe to run multiple times (upsert on unique keys).
 * - No demo users created here.
 * - All system roles have isSystem=true so they cannot be deleted.
 */

import prisma from '../src/lib/prisma';

// ─────────────────────────────────────────────────────────────────────────────
// Permission definitions
// ─────────────────────────────────────────────────────────────────────────────

const PERMISSIONS = [
  {
    name:        'asset.read',
    displayName: 'View Assets',
    description: 'Read asset records, IP addresses, MAC addresses, and relationships.',
    resource:    'asset',
    action:      'read',
  },
  {
    name:        'asset.write',
    displayName: 'Manage Assets',
    description: 'Create, update, and delete asset records.',
    resource:    'asset',
    action:      'write',
  },
  {
    name:        'finding.read',
    displayName: 'View Findings',
    description: 'Read investigation findings and their evidence.',
    resource:    'finding',
    action:      'read',
  },
  {
    name:        'finding.write',
    displayName: 'Manage Findings',
    description: 'Create, update, and close investigation findings.',
    resource:    'finding',
    action:      'write',
  },
  {
    name:        'report.read',
    displayName: 'View Reports',
    description: 'Read archived investigation and executive reports.',
    resource:    'report',
    action:      'read',
  },
  {
    name:        'report.write',
    displayName: 'Manage Reports',
    description: 'Generate, export, and archive reports.',
    resource:    'report',
    action:      'write',
  },
  {
    name:        'project.manage',
    displayName: 'Manage Projects',
    description: 'Create, update, archive, and delete projects.',
    resource:    'project',
    action:      'manage',
  },
  {
    name:        'user.manage',
    displayName: 'Manage Users',
    description: 'Create, update, suspend, and assign roles to users.',
    resource:    'user',
    action:      'manage',
  },
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Role definitions
// ─────────────────────────────────────────────────────────────────────────────

const ROLES = [
  {
    name:        'admin',
    displayName: 'Administrator',
    description: 'Full platform access.  Can manage users, projects, and all data.',
    isSystem:    true,
    permissions: [
      'asset.read', 'asset.write',
      'finding.read', 'finding.write',
      'report.read', 'report.write',
      'project.manage', 'user.manage',
    ],
  },
  {
    name:        'investigator',
    displayName: 'Investigator',
    description: 'Leads investigations.  Full read/write on assets, findings, and reports.',
    isSystem:    true,
    permissions: [
      'asset.read', 'asset.write',
      'finding.read', 'finding.write',
      'report.read', 'report.write',
      'project.manage',
    ],
  },
  {
    name:        'analyst',
    displayName: 'Analyst',
    description: 'Supports investigations.  Read/write on assets and findings; read on reports.',
    isSystem:    true,
    permissions: [
      'asset.read', 'asset.write',
      'finding.read', 'finding.write',
      'report.read',
    ],
  },
  {
    name:        'viewer',
    displayName: 'Viewer',
    description: 'Read-only access to assets, findings, and reports.',
    isSystem:    true,
    permissions: [
      'asset.read',
      'finding.read',
      'report.read',
    ],
  },
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('');
  console.log('┌──────────────────────────────────────────────────┐');
  console.log('│  NetFusion — Phase A5.1.2 Database Seed           │');
  console.log('└──────────────────────────────────────────────────┘');

  // ── 1. Upsert permissions ─────────────────────────────────────────────────
  console.log('\n[1/3] Seeding permissions …');
  const permissionMap = new Map<string, string>(); // name → id

  for (const perm of PERMISSIONS) {
    const record = await prisma.permission.upsert({
      where:  { name: perm.name },
      create: perm,
      update: {
        displayName: perm.displayName,
        description: perm.description,
        resource:    perm.resource,
        action:      perm.action,
      },
    });
    permissionMap.set(record.name, record.id);
    console.log(`  ✓ permission: ${record.name}  (${record.id})`);
  }

  // ── 2. Upsert roles ───────────────────────────────────────────────────────
  console.log('\n[2/3] Seeding roles …');
  const roleMap = new Map<string, string>(); // name → id

  for (const role of ROLES) {
    const { permissions: _, ...roleData } = role;
    const record = await prisma.role.upsert({
      where:  { name: roleData.name },
      create: roleData,
      update: {
        displayName: roleData.displayName,
        description: roleData.description,
        isSystem:    roleData.isSystem,
      },
    });
    roleMap.set(record.name, record.id);
    console.log(`  ✓ role: ${record.name}  (${record.id})`);
  }

  // ── 3. Upsert role-permission mappings ────────────────────────────────────
  console.log('\n[3/3] Seeding role-permission mappings …');
  let mappingCount = 0;

  for (const role of ROLES) {
    const roleId = roleMap.get(role.name);
    if (!roleId) continue;

    for (const permName of role.permissions) {
      const permissionId = permissionMap.get(permName);
      if (!permissionId) continue;

      await prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: { roleId, permissionId },
        },
        create: { roleId, permissionId },
        update: {},        // junction row — no mutable fields
      });
      mappingCount++;
      console.log(`  ✓ ${role.name} → ${permName}`);
    }
  }

  // ── 4. Upsert user, project, investigation and child records ───────────────
  console.log('\n[4/4] Seeding demo investigation data …');

  // Upsert seed user
  const user = await prisma.user.upsert({
    where: { username: 'admin' },
    create: {
      username: 'admin',
      email: 'admin@netfusion.local',
      displayName: 'Administrator',
      passwordHash: '$2b$10$dummyhashvaluetoavoidbcryptdependencyfortestingsimplicity',
      status: 'ACTIVE',
    },
    update: {
      status: 'ACTIVE',
    },
  });
  console.log(`  ✓ user: ${user.username} (${user.id})`);

  // Assign admin role to user
  const roleAdmin = await prisma.role.findUnique({ where: { name: 'admin' } });
  if (roleAdmin) {
    await prisma.userRole.upsert({
      where: {
        userId_roleId: { userId: user.id, roleId: roleAdmin.id },
      },
      create: { userId: user.id, roleId: roleAdmin.id },
      update: {},
    });
  }

  // Upsert project
  const projectId = '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001';
  const project = await prisma.project.upsert({
    where: { id: projectId },
    create: {
      id: projectId,
      ownerId: user.id,
      name: 'Demo Project',
      description: 'Seed demo project',
      status: 'ACTIVE',
    },
    update: {
      name: 'Demo Project',
      status: 'ACTIVE',
    },
  });
  console.log(`  ✓ project: ${project.name} (${project.id})`);

  // Upsert investigation
  const investigationId = '2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101';
  const investigation = await prisma.investigation.upsert({
    where: { id: investigationId },
    create: {
      id: investigationId,
      projectId: project.id,
      ownerId: user.id,
      title: 'Demo Investigation',
      description: 'Seed demo investigation',
      status: 'OPEN',
      priority: 2,
    },
    update: {
      title: 'Demo Investigation',
      status: 'OPEN',
    },
  });
  console.log(`  ✓ investigation: ${investigation.title} (${investigation.id})`);

  // Upsert assets
  const asset1Id = '3d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e201';
  const asset1 = await prisma.asset.upsert({
    where: { id: asset1Id },
    create: {
      id: asset1Id,
      projectId: project.id,
      investigationId: investigation.id,
      hostname: 'db-srv-01',
      deviceName: 'Database Server',
      currentIp: '10.0.1.10',
      macAddress: '00:50:56:AB:CD:EF',
      vendor: 'VMware',
      operatingSystem: 'Ubuntu 22.04',
      type: 'SERVER',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ asset: ${asset1.hostname} (${asset1.id})`);

  const asset2Id = '3d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e202';
  const asset2 = await prisma.asset.upsert({
    where: { id: asset2Id },
    create: {
      id: asset2Id,
      projectId: project.id,
      investigationId: investigation.id,
      hostname: 'workstation-analyst',
      deviceName: 'Analyst Workstation',
      currentIp: '10.0.1.55',
      macAddress: '00:50:56:FE:DC:BA',
      vendor: 'VMware',
      operatingSystem: 'Windows 11',
      type: 'WORKSTATION',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ asset: ${asset2.hostname} (${asset2.id})`);

  // Upsert findings
  const finding1Id = '4e9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e301';
  const finding1 = await prisma.finding.upsert({
    where: { id: finding1Id },
    create: {
      id: finding1Id,
      projectId: project.id,
      investigationId: investigation.id,
      assetId: asset1.id,
      title: 'Unauthorized SQL Brute Force Attack',
      description: 'Multiple failed login attempts observed from external IP.',
      category: 'NETWORK',
      severity: 'HIGH',
      status: 'OPEN',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ finding: ${finding1.title} (${finding1.id})`);

  const finding2Id = '4e9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e302';
  const finding2 = await prisma.finding.upsert({
    where: { id: finding2Id },
    create: {
      id: finding2Id,
      projectId: project.id,
      investigationId: investigation.id,
      assetId: asset2.id,
      title: 'Mimikatz Process Execution',
      description: 'LSASS memory dumping tool detected.',
      category: 'HOST',
      severity: 'CRITICAL',
      status: 'CONFIRMED',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ finding: ${finding2.title} (${finding2.id})`);

  // Upsert evidence
  const evidence1Id = '5f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e401';
  const evidence1 = await prisma.evidence.upsert({
    where: { id: evidence1Id },
    create: {
      id: evidence1Id,
      projectId: project.id,
      investigationId: investigation.id,
      assetId: asset1.id,
      findingId: finding1.id,
      fieldName: 'ipAddress',
      fieldValue: '192.168.1.100',
      sourceType: 'pcap',
      type: 'PACKET',
      rawValue: '192.168.1.100',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ evidence: ${evidence1.fieldName} (${evidence1.id})`);

  const evidence2Id = '5f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e402';
  const evidence2 = await prisma.evidence.upsert({
    where: { id: evidence2Id },
    create: {
      id: evidence2Id,
      projectId: project.id,
      investigationId: investigation.id,
      assetId: asset2.id,
      findingId: finding2.id,
      fieldName: 'processName',
      fieldValue: 'mimikatz.exe',
      sourceType: 'log',
      type: 'LOG',
      rawValue: 'mimikatz.exe',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ evidence: ${evidence2.fieldName} (${evidence2.id})`);

  // Upsert timeline events
  const event1Id = '6f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e501';
  const event1 = await prisma.timelineEvent.upsert({
    where: { id: event1Id },
    create: {
      id: event1Id,
      projectId: project.id,
      investigationId: investigation.id,
      title: 'First brute force attempt detected',
      description: 'Brute force attempt targeting port 3306',
      type: 'ALERT_GENERATED',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ timeline event: ${event1.title} (${event1.id})`);

  const event2Id = '6f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e502';
  const event2 = await prisma.timelineEvent.upsert({
    where: { id: event2Id },
    create: {
      id: event2Id,
      projectId: project.id,
      investigationId: investigation.id,
      title: 'Mimikatz hash dumped',
      description: 'LSASS access detected',
      type: 'FINDING_CREATED',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ timeline event: ${event2.title} (${event2.id})`);

  // Upsert alert
  const alert1Id = '7f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e601';
  const alert1 = await prisma.alert.upsert({
    where: { id: alert1Id },
    create: {
      id: alert1Id,
      projectId: project.id,
      investigationId: investigation.id,
      findingId: finding2.id,
      title: 'Credential Dumping Activity Alert',
      description: 'High confidence credential theft detected on workstation.',
      severity: 'CRITICAL',
      status: 'NEW',
      source: 'FINDING',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ alert: ${alert1.title} (${alert1.id})`);

  // Upsert attack graph nodes
  const node1Id = '8f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e701';
  const node1 = await prisma.attackGraphNode.upsert({
    where: { id: node1Id },
    create: {
      id: node1Id,
      projectId: project.id,
      investigationId: investigation.id,
      label: 'Internet Gateway',
      type: 'network',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ attack graph node: ${node1.label} (${node1.id})`);

  const node2Id = '8f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e702';
  const node2 = await prisma.attackGraphNode.upsert({
    where: { id: node2Id },
    create: {
      id: node2Id,
      projectId: project.id,
      investigationId: investigation.id,
      label: 'Database Server',
      type: 'host',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ attack graph node: ${node2.label} (${node2.id})`);

  // Upsert attack graph edge
  const edge1Id = '9f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e801';
  const edge1 = await prisma.attackGraphEdge.upsert({
    where: { id: edge1Id },
    create: {
      id: edge1Id,
      projectId: project.id,
      investigationId: investigation.id,
      sourceNodeId: node1.id,
      targetNodeId: node2.id,
      label: 'Inbound SSH Traffic',
      weight: 1.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ attack graph edge: ${edge1.label} (${edge1.id})`);

  // ── 5. Upsert AI models data ───────────────────────────────────────────────
  console.log('\n[5/5] Seeding demo AI data …');

  // Upsert Providers (Groq + Ollama)
  const providerGroqId = '419f2e3a-6f0a-4b9a-bbcb-7c73a1d9fa01';
  const providerGroq = await prisma.provider.upsert({
    where: { id: providerGroqId },
    create: {
      id: providerGroqId,
      providerName: 'groq',
      displayName: 'Groq Cloud',
      apiVersion: 'v1',
      endpoint: 'https://api.groq.com/openai/v1',
      defaultModel: 'llama3-8b-8192',
      providerType: 'CLOUD',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ provider: ${providerGroq.providerName} (${providerGroq.id})`);

  const providerOllamaId = '419f2e3a-6f0a-4b9a-bbcb-7c73a1d9fa02';
  const providerOllama = await prisma.provider.upsert({
    where: { id: providerOllamaId },
    create: {
      id: providerOllamaId,
      providerName: 'ollama',
      displayName: 'Ollama Local',
      apiVersion: 'v1',
      endpoint: 'http://localhost:11434/v1',
      defaultModel: 'mistral',
      providerType: 'LOCAL',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ provider: ${providerOllama.providerName} (${providerOllama.id})`);

  // Upsert ProviderModels
  const modelGroqId = '519f2e3a-6f0a-4b9a-bbcb-7c73a1d9fb01';
  const modelGroq = await prisma.providerModel.upsert({
    where: { id: modelGroqId },
    create: {
      id: modelGroqId,
      providerId: providerGroq.id,
      modelName: 'llama3-8b-8192',
      streaming: true,
      toolCalling: true,
      maxContextTokens: 8192,
      maxOutputTokens: 4096,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ model: ${modelGroq.modelName} (${modelGroq.id})`);

  const modelOllamaId = '519f2e3a-6f0a-4b9a-bbcb-7c73a1d9fb02';
  const modelOllama = await prisma.providerModel.upsert({
    where: { id: modelOllamaId },
    create: {
      id: modelOllamaId,
      providerId: providerOllama.id,
      modelName: 'mistral',
      streaming: true,
      toolCalling: false,
      maxContextTokens: 4096,
      maxOutputTokens: 2048,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ model: ${modelOllama.modelName} (${modelOllama.id})`);

  // Upsert Conversation
  const conversationId = 'a19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f001';
  const conversation = await prisma.conversation.upsert({
    where: { id: conversationId },
    create: {
      id: conversationId,
      projectId: project.id,
      investigationId: investigation.id,
      userId: user.id,
      title: 'Security Analysis Discussion',
      summary: 'Triage of critical Mimikatz alarm',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ conversation: ${conversation.title} (${conversation.id})`);

  // Upsert Conversation Messages
  const message1Id = 'b19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f101';
  const message1 = await prisma.conversationMessage.upsert({
    where: { id: message1Id },
    create: {
      id: message1Id,
      conversationId: conversation.id,
      role: 'user',
      content: 'Identify anomalous processes on analyst workstation.',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ conversation message 1 (${message1.id})`);

  const message2Id = 'b19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f102';
  const message2 = await prisma.conversationMessage.upsert({
    where: { id: message2Id },
    create: {
      id: message2Id,
      conversationId: conversation.id,
      parentMessageId: message1.id,
      role: 'assistant',
      content: 'Observed process mimikatz.exe dumping LSASS memory.',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ conversation message 2 (${message2.id})`);

  // Upsert Session Memory
  const memoryId = 'c19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f201';
  const sessionMemory = await prisma.sessionMemory.upsert({
    where: { id: memoryId },
    create: {
      id: memoryId,
      conversationId: conversation.id,
      investigationId: investigation.id,
      projectId: project.id,
      userId: user.id,
      sessionName: 'Analyst Workstation Memory',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ session memory: ${sessionMemory.sessionName} (${sessionMemory.id})`);

  // Upsert Memory Entries
  const entry1Id = 'd19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f301';
  const mEntry1 = await prisma.memoryEntry.upsert({
    where: { id: entry1Id },
    create: {
      id: entry1Id,
      memoryId: sessionMemory.id,
      memoryType: 'PROCESS',
      state: 'CONFIRMED',
      title: 'Mimikatz Execution',
      content: 'mimikatz.exe observed executing with SYSTEM privileges',
      importanceScore: 9.5,
      confidence: 100.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ memory entry 1 (${mEntry1.id})`);

  const entry2Id = 'd19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f302';
  const mEntry2 = await prisma.memoryEntry.upsert({
    where: { id: entry2Id },
    create: {
      id: entry2Id,
      memoryId: sessionMemory.id,
      memoryType: 'IOC',
      state: 'ACTIVE',
      title: 'LSASS Dump Hash',
      content: 'SHA256 signature of the dump payload matched known threats',
      importanceScore: 8.8,
      confidence: 90.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ memory entry 2 (${mEntry2.id})`);

  // Upsert Context Window
  const contextId = 'e19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f401';
  const contextWindow = await prisma.contextWindow.upsert({
    where: { id: contextId },
    create: {
      id: contextId,
      investigationId: investigation.id,
      conversationId: conversation.id,
      projectId: project.id,
      userId: user.id,
      windowName: 'Analyst Workstation Context',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ context window: ${contextWindow.windowName} (${contextWindow.id})`);

  // Upsert Context Entries
  const contextEntry1Id = 'f19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f501';
  const cEntry1 = await prisma.contextEntry.upsert({
    where: { id: contextEntry1Id },
    create: {
      id: contextEntry1Id,
      contextId: contextWindow.id,
      source: 'PROCESS_LOG',
      priority: 'CRITICAL',
      title: 'mimikatz.exe executed',
      content: 'Process spawned with parent powershell.exe',
      referenceId: 'proc_101',
      importanceScore: 9.8,
      confidence: 100.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ context entry 1 (${cEntry1.id})`);

  const contextEntry2Id = 'f19f2e3a-6f0a-4b9a-bbcb-7c73a1d9f502';
  const cEntry2 = await prisma.contextEntry.upsert({
    where: { id: contextEntry2Id },
    create: {
      id: contextEntry2Id,
      contextId: contextWindow.id,
      source: 'SECURITY_LOG',
      priority: 'HIGH',
      title: 'LSASS read handle opened',
      content: 'Process mimikatz.exe opened handle to lsass.exe',
      referenceId: 'sysmon_10',
      importanceScore: 9.2,
      confidence: 95.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ context entry 2 (${cEntry2.id})`);

  // Upsert Reasoning Session
  const reasoningId = '019f2e3a-6f0a-4b9a-bbcb-7c73a1d9f601';
  const reasoningSession = await prisma.reasoning.upsert({
    where: { id: reasoningId },
    create: {
      id: reasoningId,
      projectId: project.id,
      investigationId: investigation.id,
      userId: user.id,
      decision: 'ESCALATE_TO_CONTAINMENT',
      overallConfidence: 95.0,
      overallRisk: 90.0,
      sessionName: 'Credential Theft Triage Reasoning',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ reasoning session: ${reasoningSession.sessionName} (${reasoningSession.id})`);

  // Upsert Reasoning Steps
  const step1Id = '119f2e3a-6f0a-4b9a-bbcb-7c73a1d9f701';
  const step1 = await prisma.reasoningStep.upsert({
    where: { id: step1Id },
    create: {
      id: step1Id,
      reasoningId: reasoningSession.id,
      stepNumber: 1,
      stage: 'IDENTIFY_THREAT',
      inputSummary: 'Sysmon log entry sysmon_10',
      outputSummary: 'Confirmed LSASS read access matching mimikatz signature',
      confidence: 98.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ reasoning step 1 (${step1.id})`);

  const step2Id = '119f2e3a-6f0a-4b9a-bbcb-7c73a1d9f702';
  const step2 = await prisma.reasoningStep.upsert({
    where: { id: step2Id },
    create: {
      id: step2Id,
      reasoningId: reasoningSession.id,
      stepNumber: 2,
      stage: 'CONTAINMENT_PLAN',
      inputSummary: 'Mimikatz threat confirmed',
      outputSummary: 'Proposed host quarantine for workstation-analyst',
      confidence: 92.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ reasoning step 2 (${step2.id})`);

  // Upsert Prompt Assembly
  const promptId = '219f2e3a-6f0a-4b9a-bbcb-7c73a1d9f801';
  const promptAssembly = await prisma.promptAssembly.upsert({
    where: { id: promptId },
    create: {
      id: promptId,
      reasoningId: reasoningSession.id,
      contextId: contextWindow.id,
      investigationId: investigation.id,
      projectId: project.id,
      userId: user.id,
      systemPrompt: 'You are NetFusion AI assistant.',
      userPrompt: 'Determine if this workstation is compromised.',
      promptName: 'Threat Detection Prompt',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ prompt assembly: ${promptAssembly.promptName} (${promptAssembly.id})`);

  // Upsert Prompt Sections
  const section1Id = '319f2e3a-6f0a-4b9a-bbcb-7c73a1d9f901';
  const pSection1 = await prisma.promptSection.upsert({
    where: { id: section1Id },
    create: {
      id: section1Id,
      promptId: promptAssembly.id,
      title: 'System Logs',
      content: 'mimikatz.exe executed at 12:00:00',
      priority: 100,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ prompt section 1 (${pSection1.id})`);

  const section2Id = '319f2e3a-6f0a-4b9a-bbcb-7c73a1d9f902';
  const pSection2 = await prisma.promptSection.upsert({
    where: { id: section2Id },
    create: {
      id: section2Id,
      promptId: promptAssembly.id,
      title: 'Host Context',
      content: 'workstation-analyst IP is 10.0.1.55',
      priority: 50,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ prompt section 2 (${pSection2.id})`);

  // Upsert Execution
  const executionId = '619f2e3a-6f0a-4b9a-bbcb-7c73a1d9fc01';
  const execution = await prisma.execution.upsert({
    where: { id: executionId },
    create: {
      id: executionId,
      providerId: providerGroq.id,
      providerModelId: modelGroq.id,
      systemPrompt: 'You are NetFusion AI assistant.',
      userPrompt: 'Determine if this workstation is compromised.',
      projectId: project.id,
      investigationId: investigation.id,
      userId: user.id,
      status: 'COMPLETED',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ execution (${execution.id})`);

  // Upsert Execution Usage
  const usageId = '719f2e3a-6f0a-4b9a-bbcb-7c73a1d9fd01';
  const usage = await prisma.executionUsage.upsert({
    where: { id: usageId },
    create: {
      id: usageId,
      executionId: execution.id,
      promptTokens: 1000,
      completionTokens: 250,
      totalTokens: 1250,
      estimatedCost: 0.0025,
      latencyMs: 450,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ execution usage (${usage.id})`);

  // Upsert Streaming Session
  const streamingId = '819f2e3a-6f0a-4b9a-bbcb-7c73a1d9fe01';
  const streamingSession = await prisma.streaming.upsert({
    where: { id: streamingId },
    create: {
      id: streamingId,
      executionId: execution.id,
      streamName: 'Host Compromise Report Stream',
      status: 'COMPLETED',
      projectId: project.id,
      investigationId: investigation.id,
      userId: user.id,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ streaming session: ${streamingSession.streamName} (${streamingSession.id})`);

  // Upsert Streaming Chunks
  const chunk1Id = '919f2e3a-6f0a-4b9a-bbcb-7c73a1d9ff01';
  const chunk1 = await prisma.streamingChunk.upsert({
    where: { id: chunk1Id },
    create: {
      id: chunk1Id,
      streamingId: streamingSession.id,
      sequenceNumber: 1,
      content: 'Based on log analysis, ',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ streaming chunk 1 (${chunk1.id})`);

  const chunk2Id = '919f2e3a-6f0a-4b9a-bbcb-7c73a1d9ff02';
  const chunk2 = await prisma.streamingChunk.upsert({
    where: { id: chunk2Id },
    create: {
      id: chunk2Id,
      streamingId: streamingSession.id,
      sequenceNumber: 2,
      content: 'quarantine is highly recommended.',
      finishReason: 'stop',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ streaming chunk 2 (${chunk2.id})`);

  // ── 6. Upsert Knowledge models data ─────────────────────────────────────────
  console.log('\n[6/6] Seeding demo Knowledge data …');

  // Upsert MitreTactic
  const tacticId = '029f2e3a-6f0a-4b9a-bbcb-7c73a1d9a001';
  const tactic = await prisma.mitreTactic.upsert({
    where: { id: tacticId },
    create: {
      id: tacticId,
      tacticKey: 'TA0002',
      name: 'Execution',
      description: 'The adversary is trying to run malicious code.',
      tacticType: 'EXECUTION',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ mitre tactic: ${tactic.name} (${tactic.id})`);

  // Upsert MitreTechniques
  const technique1Id = '129f2e3a-6f0a-4b9a-bbcb-7c73a1d9a101';
  const technique1 = await prisma.mitreTechnique.upsert({
    where: { id: technique1Id },
    create: {
      id: technique1Id,
      tacticId: tactic.id,
      mitreId: 'T1059',
      name: 'Command and Scripting Interpreter',
      description: 'Adversaries may abuse command and script interpreters.',
      detection: 'Monitor command-line arguments.',
      platforms: ['Windows', 'Linux', 'macOS'],
      severity: 'HIGH',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ mitre technique 1: ${technique1.name} (${technique1.id})`);

  const technique2Id = '129f2e3a-6f0a-4b9a-bbcb-7c73a1d9a102';
  const technique2 = await prisma.mitreTechnique.upsert({
    where: { id: technique2Id },
    create: {
      id: technique2Id,
      tacticId: tactic.id,
      mitreId: 'T1204',
      name: 'User Execution',
      description: 'An adversary may rely on a user to perform an action.',
      detection: 'Monitor user clicks and process spawns.',
      platforms: ['Windows', 'macOS'],
      severity: 'MEDIUM',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ mitre technique 2: ${technique2.name} (${technique2.id})`);

  // Upsert MitreMitigations
  const mitigation1Id = '229f2e3a-6f0a-4b9a-bbcb-7c73a1d9a201';
  const mitigation1 = await prisma.mitreMitigation.upsert({
    where: { id: mitigation1Id },
    create: {
      id: mitigation1Id,
      mitreId: 'M1038',
      name: 'Execution Prevention',
      description: 'Block execution of unauthorized code.',
      createdBy: 'seed',
      updatedBy: 'seed',
      techniques: { connect: [{ id: technique1.id }, { id: technique2.id }] },
    },
    update: {},
  });
  console.log(`  ✓ mitre mitigation 1: ${mitigation1.name} (${mitigation1.id})`);

  const mitigation2Id = '229f2e3a-6f0a-4b9a-bbcb-7c73a1d9a202';
  const mitigation2 = await prisma.mitreMitigation.upsert({
    where: { id: mitigation2Id },
    create: {
      id: mitigation2Id,
      mitreId: 'M1040',
      name: 'Behavior Prevention on Endpoint',
      description: 'Endpoint detection tools blocking suspect activities.',
      createdBy: 'seed',
      updatedBy: 'seed',
      techniques: { connect: [{ id: technique1.id }] },
    },
    update: {},
  });
  console.log(`  ✓ mitre mitigation 2: ${mitigation2.name} (${mitigation2.id})`);

  // Upsert CVEs
  const cve1Id = '329f2e3a-6f0a-4b9a-bbcb-7c73a1d9a301';
  const cve1 = await prisma.cVE.upsert({
    where: { id: cve1Id },
    create: {
      id: cve1Id,
      cveId: 'CVE-2021-44228',
      description: 'Apache Log4j2 JNDI remote code execution vulnerability.',
      severity: 'CRITICAL',
      cvssScore: 10.0,
      publishedDate: new Date('2021-12-10'),
      vendor: 'Apache',
      product: 'Log4j',
      createdBy: 'seed',
      updatedBy: 'seed',
      techniques: { connect: [{ id: technique1.id }] },
    },
    update: {},
  });
  console.log(`  ✓ cve 1: ${cve1.cveId} (${cve1.id})`);

  const cve2Id = '329f2e3a-6f0a-4b9a-bbcb-7c73a1d9a302';
  const cve2 = await prisma.cVE.upsert({
    where: { id: cve2Id },
    create: {
      id: cve2Id,
      cveId: 'CVE-2021-40444',
      description: 'Microsoft MSHTML remote code execution vulnerability.',
      severity: 'HIGH',
      cvssScore: 8.8,
      publishedDate: new Date('2021-09-07'),
      vendor: 'Microsoft',
      product: 'MSHTML',
      createdBy: 'seed',
      updatedBy: 'seed',
      techniques: { connect: [{ id: technique2.id }] },
    },
    update: {},
  });
  console.log(`  ✓ cve 2: ${cve2.cveId} (${cve2.id})`);

  // Upsert CVSS Records
  const cvss1Id = '429f2e3a-6f0a-4b9a-bbcb-7c73a1d9a401';
  const cvss1 = await prisma.cVSS.upsert({
    where: { id: cvss1Id },
    create: {
      id: cvss1Id,
      cveId: cve1.id,
      baseScore: 10.0,
      severity: 'CRITICAL',
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      exploitabilityScore: 3.9,
      impactScore: 6.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ cvss details 1: Score ${cvss1.baseScore} (${cvss1.id})`);

  const cvss2Id = '429f2e3a-6f0a-4b9a-bbcb-7c73a1d9a402';
  const cvss2 = await prisma.cVSS.upsert({
    where: { id: cvss2Id },
    create: {
      id: cvss2Id,
      cveId: cve2.id,
      baseScore: 8.8,
      severity: 'HIGH',
      vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H',
      exploitabilityScore: 1.6,
      impactScore: 6.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ cvss details 2: Score ${cvss2.baseScore} (${cvss2.id})`);

  // Upsert AffectedProducts
  const affected1Id = '529f2e3a-6f0a-4b9a-bbcb-7c73a1d9a501';
  const affected1 = await prisma.affectedProduct.upsert({
    where: { id: affected1Id },
    create: {
      id: affected1Id,
      cveId: cve1.id,
      vendor: 'Apache',
      product: 'Log4j',
      productVersion: '2.0-beta9 to 2.14.1',
      patched: false,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ affected product 1: ${affected1.vendor} ${affected1.product} (${affected1.id})`);

  const affected2Id = '529f2e3a-6f0a-4b9a-bbcb-7c73a1d9a502';
  const affected2 = await prisma.affectedProduct.upsert({
    where: { id: affected2Id },
    create: {
      id: affected2Id,
      cveId: cve2.id,
      vendor: 'Microsoft',
      product: 'Windows',
      productVersion: '10',
      patched: false,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ affected product 2: ${affected2.vendor} ${affected2.product} (${affected2.id})`);

  // Upsert IOCs
  const ioc1Id = '629f2e3a-6f0a-4b9a-bbcb-7c73a1d9a601';
  const ioc1 = await prisma.iOC.upsert({
    where: { id: ioc1Id },
    create: {
      id: ioc1Id,
      iocId: 'ioc-ip-log4j',
      value: '45.155.205.233',
      iocType: 'IP',
      severity: 'CRITICAL',
      status: 'ACTIVE',
      confidence: 'HIGH',
      description: 'Known scanner IP exploiting Log4j.',
      source: 'Internal Threat Intel',
      createdBy: 'seed',
      updatedBy: 'seed',
      cves: { connect: [{ id: cve1.id }] },
      techniques: { connect: [{ id: technique1.id }] },
    },
    update: {},
  });
  console.log(`  ✓ ioc 1: ${ioc1.value} (${ioc1.id})`);

  const ioc2Id = '629f2e3a-6f0a-4b9a-bbcb-7c73a1d9a602';
  const ioc2 = await prisma.iOC.upsert({
    where: { id: ioc2Id },
    create: {
      id: ioc2Id,
      iocId: 'ioc-hash-mshtml',
      value: '5d24d6d6da82e75e921d74a007f354f3',
      iocType: 'HASH_MD5',
      severity: 'HIGH',
      status: 'ACTIVE',
      confidence: 'HIGH',
      description: 'Malicious DLL file hash exploiting MSHTML.',
      source: 'VirusTotal',
      createdBy: 'seed',
      updatedBy: 'seed',
      cves: { connect: [{ id: cve2.id }] },
      techniques: { connect: [{ id: technique2.id }] },
    },
    update: {},
  });
  console.log(`  ✓ ioc 2: ${ioc2.value} (${ioc2.id})`);

  // Upsert IOCEnrichments
  const enrichment1Id = '829f2e3a-6f0a-4b9a-bbcb-7c73a1d9a801';
  const enrichment1 = await prisma.iOCEnrichment.upsert({
    where: { id: enrichment1Id },
    create: {
      id: enrichment1Id,
      iocId: ioc1.id,
      reputationScore: 98,
      malicious: true,
      categories: ['Scanning', 'Exploitation'],
      provider: 'AlienVault OTX',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ ioc enrichment 1 for ${ioc1.value} (${enrichment1.id})`);

  const enrichment2Id = '829f2e3a-6f0a-4b9a-bbcb-7c73a1d9a802';
  const enrichment2 = await prisma.iOCEnrichment.upsert({
    where: { id: enrichment2Id },
    create: {
      id: enrichment2Id,
      iocId: ioc2.id,
      reputationScore: 100,
      malicious: true,
      categories: ['Malware', 'Dropper'],
      provider: 'VirusTotal API',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ ioc enrichment 2 for ${ioc2.value} (${enrichment2.id})`);

  // Upsert Threat Actor
  const threatActorId = '929f2e3a-6f0a-4b9a-bbcb-7c73a1d9a901';
  const threatActor = await prisma.threatActor.upsert({
    where: { id: threatActorId },
    create: {
      id: threatActorId,
      threatId: 'G0100',
      name: 'APT28',
      aliases: ['Fancy Bear', 'Sofacy'],
      description: 'Russian state-sponsored cyber espionage group.',
      country: 'Russia',
      motivation: 'Espionage',
      confidence: 'HIGH',
      severity: 'CRITICAL',
      status: 'ACTIVE',
      createdBy: 'seed',
      updatedBy: 'seed',
      techniques: { connect: [{ id: technique1.id }, { id: technique2.id }] },
      iocs: { connect: [{ id: ioc1.id }, { id: ioc2.id }] },
    },
    update: {},
  });
  console.log(`  ✓ threat actor: ${threatActor.name} (${threatActor.id})`);

  // Upsert Threat Campaign
  const campaignId = 'a29f2e3a-6f0a-4b9a-bbcb-7c73a1d9aa01';
  const threatCampaign = await prisma.threatCampaign.upsert({
    where: { id: campaignId },
    create: {
      id: campaignId,
      campaignId: 'C0055',
      name: 'Operation Bearish Hunt',
      description: 'Espionage campaign targeting government entities.',
      confidence: 'HIGH',
      status: 'ACTIVE',
      createdBy: 'seed',
      updatedBy: 'seed',
      threatActors: { connect: [{ id: threatActor.id }] },
      techniques: { connect: [{ id: technique1.id }] },
      iocs: { connect: [{ id: ioc1.id }] },
    },
    update: {},
  });
  console.log(`  ✓ threat campaign: ${threatCampaign.name} (${threatCampaign.id})`);

  // Upsert IOCRelationships
  const iocRelationship1Id = '729f2e3a-6f0a-4b9a-bbcb-7c73a1d9a701';
  const iocRel1 = await prisma.iOCRelationship.upsert({
    where: { id: iocRelationship1Id },
    create: {
      id: iocRelationship1Id,
      iocId: ioc1.id,
      cveId: cve1.id,
      targetType: 'cve',
      relationType: 'EXPLOITS',
      confidence: 100.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ ioc relationship 1 (${iocRel1.id})`);

  const iocRelationship2Id = '729f2e3a-6f0a-4b9a-bbcb-7c73a1d9a702';
  const iocRel2 = await prisma.iOCRelationship.upsert({
    where: { id: iocRelationship2Id },
    create: {
      id: iocRelationship2Id,
      iocId: ioc2.id,
      threatId: threatActor.id,
      targetType: 'threat_actor',
      relationType: 'ATTRIBUTED_TO',
      confidence: 90.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ ioc relationship 2 (${iocRel2.id})`);

  // Upsert ThreatRelationships
  const threatRelationship1Id = 'b29f2e3a-6f0a-4b9a-bbcb-7c73a1d9ab01';
  const threatRel1 = await prisma.threatRelationship.upsert({
    where: { id: threatRelationship1Id },
    create: {
      id: threatRelationship1Id,
      threatId: threatActor.id,
      cveId: cve1.id,
      targetType: 'cve',
      relationType: 'EXPLOITS',
      confidence: 95.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ threat relationship 1 (${threatRel1.id})`);

  const threatRelationship2Id = 'b29f2e3a-6f0a-4b9a-bbcb-7c73a1d9ab02';
  const threatRel2 = await prisma.threatRelationship.upsert({
    where: { id: threatRelationship2Id },
    create: {
      id: threatRelationship2Id,
      campaignId: threatCampaign.id,
      mitreId: technique1.id,
      targetType: 'technique',
      relationType: 'USES',
      confidence: 100.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ threat relationship 2 (${threatRel2.id})`);

  // ── 7. Upsert Workflow models data ──────────────────────────────────────────
  console.log('\n[7/7] Seeding demo Workflow data …');

  // Upsert Playbook
  const playbookId = 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b001';
  const playbook = await prisma.playbook.upsert({
    where: { id: playbookId },
    create: {
      id: playbookId,
      projectId,
      investigationId,
      name: 'Host Ransomware Response Playbook',
      description: 'Standard operating procedure for responding to active ransomware detection on a host.',
      severity: 'CRITICAL',
      status: 'ACTIVE',
      confidence: 95.0,
      enabled: true,
      priority: 1,
      category: 'Incident Response',
      author: 'Security Admin',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ playbook: ${playbook.name} (${playbook.id})`);

  // Upsert Playbook Steps
  const playbookSteps = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b101',
      playbookId,
      stepNumber: 1,
      stepKey: 'step-1-isolate',
      title: 'Isolate Host from Network',
      description: 'Apply network isolation rules to the affected host.',
      stepType: 'CONTAINMENT' as const,
      expectedOutcome: 'Host isolated from all non-essential network traffic.',
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b102',
      playbookId,
      stepNumber: 2,
      stepKey: 'step-2-dump-mem',
      title: 'Dump Memory for Analysis',
      description: 'Acquire volatile memory from the isolated host.',
      stepType: 'VERIFICATION' as const,
      expectedOutcome: 'Raw memory image stored securely for threat hunting.',
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b103',
      playbookId,
      stepNumber: 3,
      stepKey: 'step-3-reimage',
      title: 'Reimage and Restore Host',
      description: 'Reimage the host machine and restore user data from verified backups.',
      stepType: 'RECOVERY' as const,
      expectedOutcome: 'Host clean build online and operational.',
    },
  ];

  for (const step of playbookSteps) {
    const s = await prisma.playbookStep.upsert({
      where: { id: step.id },
      create: {
        ...step,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ playbook step ${s.stepNumber}: ${s.title} (${s.id})`);
  }

  // Upsert Rule
  const ruleId = 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b201';
  const rule = await prisma.rule.upsert({
    where: { id: ruleId },
    create: {
      id: ruleId,
      projectId,
      investigationId,
      name: 'Ransomware Process Indicator Rule',
      description: 'Detects execution of processes commonly associated with ransomware strains.',
      severity: 'CRITICAL',
      status: 'ACTIVE',
      priority: 10,
      enabled: true,
      category: 'Process Activity',
      author: 'Security Admin',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ rule: ${rule.name} (${rule.id})`);

  // Upsert Rule Conditions
  const ruleConditions = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b301',
      ruleId,
      field: 'process.name',
      operator: 'IN',
      value: 'vssadmin.exe,wbadmin.exe,bcdedit.exe',
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b302',
      ruleId,
      field: 'process.arguments',
      operator: 'CONTAINS',
      value: 'delete shadows',
    },
  ];

  for (const cond of ruleConditions) {
    const c = await prisma.ruleCondition.upsert({
      where: { id: cond.id },
      create: {
        ...cond,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ rule condition: ${c.field} ${c.operator} ${c.value} (${c.id})`);
  }

  // Upsert Rule Actions
  const ruleActions = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b401',
      ruleId,
      actionType: 'CREATE_ALERT',
      parameters: { severity: 'CRITICAL', message: 'Ransomware shadow copy deletion attempt detected.' },
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b402',
      ruleId,
      actionType: 'START_PLAYBOOK',
      parameters: { playbookId },
    },
  ];

  for (const act of ruleActions) {
    const a = await prisma.ruleAction.upsert({
      where: { id: act.id },
      create: {
        ...act,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ rule action: ${a.actionType} (${a.id})`);
  }

  // Upsert Automation
  const automationId = 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b501';
  const automation = await prisma.automation.upsert({
    where: { id: automationId },
    create: {
      id: automationId,
      projectId,
      investigationId,
      playbookId,
      ruleId,
      name: 'Ransomware Response Flow',
      description: 'Auto-isolate host and trigger forensic extraction upon alert match.',
      status: 'ACTIVE',
      trigger: 'ALERT_CREATED',
      priority: 10,
      enabled: true,
      category: 'Auto Response',
      author: 'Security Admin',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ automation: ${automation.name} (${automation.id})`);

  // Upsert Automation Steps
  const automationSteps = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b601',
      automationId,
      stepNumber: 1,
      stepKey: 'auto-step-1-alert',
      name: 'Raise Incident Severity Alert',
      description: 'Increase triage urgency of the alert.',
      action: 'UPDATE_ALERT' as const,
      parameters: { triageStatus: 'CRITICAL' },
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b602',
      automationId,
      stepNumber: 2,
      stepKey: 'auto-step-2-isolate',
      name: 'Auto Isolate',
      description: 'Execute playbooks containment phase.',
      action: 'TAG_INVESTIGATION' as const,
      parameters: { tag: 'needs-isolation' },
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b603',
      automationId,
      stepNumber: 3,
      stepKey: 'auto-step-3-notify',
      name: 'Notify Responder Teams',
      description: 'Post webhook notification message to responders.',
      action: 'CREATE_ALERT' as const,
      parameters: { channel: '#incidents-triage', channelType: 'slack' },
    },
  ];

  for (const step of automationSteps) {
    const s = await prisma.automationStep.upsert({
      where: { id: step.id },
      create: {
        ...step,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ automation step ${s.stepNumber}: ${s.name} (${s.id})`);
  }

  // Upsert Automation Executions
  const automationExecutions = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b701',
      automationId,
      status: 'COMPLETED' as const,
      startedAt: new Date('2026-07-06T10:00:00Z'),
      completedAt: new Date('2026-07-06T10:00:05Z'),
      stepResults: [
        { step: 1, status: 'SUCCESS', output: 'Alert severity set to CRITICAL' },
        { step: 2, status: 'SUCCESS', output: 'Tagged investigation as needs-isolation' },
        { step: 3, status: 'SUCCESS', output: 'Notification dispatched to #incidents-triage' },
      ],
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b702',
      automationId,
      status: 'FAILED' as const,
      startedAt: new Date('2026-07-06T11:00:00Z'),
      completedAt: new Date('2026-07-06T11:00:02Z'),
      stepResults: [
        { step: 1, status: 'SUCCESS', output: 'Alert severity set to CRITICAL' },
        { step: 2, status: 'FAILURE', output: 'Failed to apply tags due to lock conflict' },
      ],
    },
  ];

  for (const exec of automationExecutions) {
    const e = await prisma.automationExecution.upsert({
      where: { id: exec.id },
      create: {
        ...exec,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ automation execution: ${e.status} (${e.id})`);
  }

  // Upsert CaseFlow
  const caseFlowId = 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b801';
  const caseFlow = await prisma.caseFlow.upsert({
    where: { id: caseFlowId },
    create: {
      id: caseFlowId,
      projectId,
      investigationId,
      playbookId,
      automationId,
      title: 'Ransomware Outbreak Containment Flow',
      description: 'Orchestrating responder phases and automated actions for host recovery.',
      status: 'OPEN',
      priority: 'CRITICAL',
      findingIds: ['4e9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e301'],
      alertIds: ['7f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e601'],
      evidenceIds: ['5f9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e401'],
      playbookIds: [playbookId],
      assignedTo: 'incident-commander',
      owner: 'Security Ops',
      confidence: 100.0,
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ case flow: ${caseFlow.title} (${caseFlow.id})`);

  // Upsert CaseFlow Steps
  const caseFlowSteps = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b901',
      caseFlowId,
      stepNumber: 1,
      stepKey: 'case-step-1-init',
      stepType: 'CREATED' as const,
      title: 'Initialize Incident Case Flow',
      description: 'Case commander assigned and initial triage conducted.',
      assignedTo: 'incident-commander',
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b902',
      caseFlowId,
      stepNumber: 2,
      stepKey: 'case-step-2-investigate',
      stepType: 'INVESTIGATED' as const,
      title: 'Investigate Ransomware Infiltration Point',
      description: 'Analyze system memory and artifacts to locate malware persistence mechanism.',
      assignedTo: 'lead-forensics-analyst',
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9b903',
      caseFlowId,
      stepNumber: 3,
      stepKey: 'case-step-3-close',
      stepType: 'CLOSED' as const,
      title: 'Post-Incident Clean Close',
      description: 'Re-image host and conduct post-mortem review of automation efficacy.',
      assignedTo: 'incident-commander',
    },
  ];

  for (const step of caseFlowSteps) {
    const s = await prisma.caseFlowStep.upsert({
      where: { id: step.id },
      create: {
        ...step,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ case flow step ${s.stepNumber}: ${s.title} (${s.id})`);
  }

  // Upsert CaseFlow Executions
  const caseFlowExecutions = [
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9ba01',
      caseFlowId,
      status: 'COMPLETED' as const,
      startedAt: new Date('2026-07-06T10:30:00Z'),
      completedAt: new Date('2026-07-06T11:45:00Z'),
      stepResults: [
        { step: 1, assignedTo: 'incident-commander', phase: 'CREATED', status: 'SUCCESS' },
        { step: 2, assignedTo: 'lead-forensics-analyst', phase: 'INVESTIGATED', status: 'SUCCESS' },
        { step: 3, assignedTo: 'incident-commander', phase: 'CLOSED', status: 'SUCCESS' },
      ],
    },
    {
      id: 'd29f2e3a-6f0a-4b9a-bbcb-7c73a1d9ba02',
      caseFlowId,
      status: 'ACTIVE' as const,
      startedAt: new Date('2026-07-06T12:00:00Z'),
      completedAt: null,
      stepResults: [
        { step: 1, assignedTo: 'incident-commander', phase: 'CREATED', status: 'SUCCESS' },
        { step: 2, assignedTo: 'lead-forensics-analyst', phase: 'INVESTIGATED', status: 'PENDING' },
      ],
    },
  ];

  for (const exec of caseFlowExecutions) {
    const e = await prisma.caseFlowExecution.upsert({
      where: { id: exec.id },
      create: {
        ...exec,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`    ✓ case flow execution: ${e.status} (${e.id})`);
  }

  // ── 8. Upsert Shared models data ───────────────────────────────────────────
  console.log('\n[8/8] Seeding demo Shared data …');

  // 2 Tags
  const tag1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c001';
  const tag1 = await prisma.tag.upsert({
    where: { id: tag1Id },
    create: {
      id: tag1Id,
      projectId,
      name: 'Production Threat',
      color: '#FF0000',
      description: 'Threats related to production environment.',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ tag 1: ${tag1.name} (${tag1.id})`);

  const tag2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c002';
  const tag2 = await prisma.tag.upsert({
    where: { id: tag2Id },
    create: {
      id: tag2Id,
      projectId,
      name: 'Ransomware Triage',
      color: '#8B0000',
      description: 'Ransomware response related tags.',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ tag 2: ${tag2.name} (${tag2.id})`);

  // 2 Tag Assignments
  const tagAssignment1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c101';
  const tagAssignment1 = await prisma.tagAssignment.upsert({
    where: { id: tagAssignment1Id },
    create: {
      id: tagAssignment1Id,
      tagId: tag1Id,
      investigationId,
      targetId: investigationId,
      targetType: 'investigation',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ tag assignment 1 (${tagAssignment1.id})`);

  const tagAssignment2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c102';
  const tagAssignment2 = await prisma.tagAssignment.upsert({
    where: { id: tagAssignment2Id },
    create: {
      id: tagAssignment2Id,
      tagId: tag2Id,
      investigationId,
      targetId: '4e9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e301', // Finding
      targetType: 'finding',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ tag assignment 2 (${tagAssignment2.id})`);

  // 2 Comments
  const comment1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c201';
  const comment1 = await prisma.comment.upsert({
    where: { id: comment1Id },
    create: {
      id: comment1Id,
      userId: user.id,
      projectId,
      investigationId,
      targetId: '4e9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e301',
      targetType: 'finding',
      content: 'Investigation initiated on brute force finding.',
      visibility: 'PUBLIC',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ comment 1 (${comment1.id})`);

  const comment2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c202';
  const comment2 = await prisma.comment.upsert({
    where: { id: comment2Id },
    create: {
      id: comment2Id,
      userId: user.id,
      projectId,
      investigationId,
      content: 'General team review required for host status.',
      visibility: 'TEAM',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ comment 2 (${comment2.id})`);

  // 2 Attachments
  const attachment1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c301';
  const attachment1 = await prisma.attachment.upsert({
    where: { id: attachment1Id },
    create: {
      id: attachment1Id,
      projectId,
      investigationId,
      targetId: '4e9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e301',
      targetType: 'finding',
      fileName: 'auth_failure_logs.txt',
      fileSize: 45000,
      mimeType: 'text/plain',
      storageKey: 'attachments/auth_failure_logs.txt',
      type: 'LOG',
      status: 'ACTIVE',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ attachment 1 (${attachment1.id})`);

  const attachment2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c302';
  const attachment2 = await prisma.attachment.upsert({
    where: { id: attachment2Id },
    create: {
      id: attachment2Id,
      projectId,
      investigationId,
      fileName: 'network_capture.pcap',
      fileSize: 1048576,
      mimeType: 'application/octet-stream',
      storageKey: 'attachments/network_capture.pcap',
      type: 'PCAP',
      status: 'PENDING',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ attachment 2 (${attachment2.id})`);

  // 1 Favorite
  const favorite1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c401';
  const favorite1 = await prisma.favorite.upsert({
    where: { id: favorite1Id },
    create: {
      id: favorite1Id,
      userId: user.id,
      targetId: investigationId,
      type: 'INVESTIGATION',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ favorite 1 (${favorite1.id})`);

  // 2 Notifications
  const notification1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c501';
  const notification1 = await prisma.notification.upsert({
    where: { id: notification1Id },
    create: {
      id: notification1Id,
      userId: user.id,
      title: 'Active Brute Force Alert',
      message: 'New credential brute force finding added to investigation.',
      type: 'ALERT',
      status: 'UNREAD',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ notification 1 (${notification1.id})`);

  const notification2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c502';
  const notification2 = await prisma.notification.upsert({
    where: { id: notification2Id },
    create: {
      id: notification2Id,
      userId: user.id,
      title: 'System Update Successful',
      message: 'Workflow engine has been updated to version 2.4.',
      type: 'SYSTEM',
      status: 'READ',
      readAt: new Date('2026-07-06T12:00:00Z'),
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ notification 2 (${notification2.id})`);

  // 1 User Preference
  const preference1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c601';
  const preference1 = await prisma.userPreference.upsert({
    where: { id: preference1Id },
    create: {
      id: preference1Id,
      userId: user.id,
      key: 'ui.theme',
      value: 'dark',
      type: 'THEME',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ user preference 1 (${preference1.id})`);

  // 3 Activity Logs
  const activityLogs = [
    {
      id: 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c701',
      userId: user.id,
      projectId,
      investigationId,
      action: 'Create Tag Assignment',
      type: 'CREATE' as const,
      details: 'Assigned tag Production Threat to investigation',
    },
    {
      id: 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c702',
      userId: user.id,
      projectId,
      investigationId,
      action: 'Upload Log Attachment',
      type: 'CREATE' as const,
      details: 'Uploaded auth_failure_logs.txt to finding',
    },
    {
      id: 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c703',
      userId: user.id,
      projectId,
      investigationId,
      action: 'Change Preference',
      type: 'UPDATE' as const,
      details: 'Updated ui.theme preference to dark mode',
    },
  ];

  for (const log of activityLogs) {
    const l = await prisma.activityLog.upsert({
      where: { id: log.id },
      create: {
        ...log,
        createdBy: 'seed',
        updatedBy: 'seed',
      },
      update: {},
    });
    console.log(`  ✓ activity log (${l.id})`);
  }

  // 2 System Settings
  const setting1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c801';
  const setting1 = await prisma.systemSetting.upsert({
    where: { id: setting1Id },
    create: {
      id: setting1Id,
      key: 'system.engine.max_concurrent_jobs',
      value: '16',
      scope: 'GLOBAL',
      description: 'Maximum concurrent processing automation steps.',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ system setting 1: ${setting1.key} (${setting1.id})`);

  const setting2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c802';
  const setting2 = await prisma.systemSetting.upsert({
    where: { id: setting2Id },
    create: {
      id: setting2Id,
      key: 'system.cleanup.days_retention',
      value: '90',
      scope: 'GLOBAL',
      description: 'How long to retain temporary captures or attachments.',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ system setting 2: ${setting2.key} (${setting2.id})`);

  // 2 API Keys
  const apiKey1Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c901';
  const apiKey1 = await prisma.apiKey.upsert({
    where: { id: apiKey1Id },
    create: {
      id: apiKey1Id,
      userId: user.id,
      name: 'Triage Script API Key',
      keyHash: 'a5f3333333333333333333333333333333333333333333333333333333333333',
      status: 'ACTIVE',
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ API key 1 (${apiKey1.id})`);

  const apiKey2Id = 'c29f2e3a-6f0a-4b9a-bbcb-7c73a1d9c902';
  const apiKey2 = await prisma.apiKey.upsert({
    where: { id: apiKey2Id },
    create: {
      id: apiKey2Id,
      userId: user.id,
      name: 'Expired Test Key',
      keyHash: 'b5f3333333333333333333333333333333333333333333333333333333333333',
      status: 'EXPIRED',
      expiresAt: new Date('2026-07-01T00:00:00Z'),
      createdBy: 'seed',
      updatedBy: 'seed',
    },
    update: {},
  });
  console.log(`  ✓ API key 2 (${apiKey2.id})`);

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('');
  console.log('┌──────────────────────────────────────────────────┐');
  console.log('│  Seed completed successfully                       │');
  console.log(`│    Permissions : ${permissionMap.size.toString().padEnd(32)}│`);
  console.log(`│    Roles       : ${roleMap.size.toString().padEnd(32)}│`);
  console.log(`│    Mappings    : ${mappingCount.toString().padEnd(32)}│`);
  console.log('└──────────────────────────────────────────────────┘');
  console.log('');
}

main()
  .catch((error) => {
    console.error('Seed failed:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
