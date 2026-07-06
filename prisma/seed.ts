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
