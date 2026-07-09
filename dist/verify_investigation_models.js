"use strict";
/**
 * verify_investigation_models.ts — Phase A5.1.3
 * ==================================================
 * Standalone verification script that checks every requirement
 * of the Investigation Database Models phase against the live database.
 *
 * Run:
 *   npx ts-node src/verify_investigation_models.ts
 *
 * Exits 0 if all checks pass, 1 on any failure.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const prisma_1 = __importDefault(require("./lib/prisma"));
const client_1 = require("@prisma/client");
let passed = 0;
let failed = 0;
const errors = [];
function ok(label) {
    passed++;
    console.log(`  ✓  ${label}`);
}
function fail(label, detail) {
    failed++;
    const msg = detail ? `${label} — ${detail}` : label;
    errors.push(msg);
    console.log(`  ✗  ${msg}`);
}
function assert(condition, label, detail) {
    condition ? ok(label) : fail(label, detail);
}
function section(title) {
    console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 60 - title.length))}`);
}
// Helper to generate unique suffixes
const RUN = Date.now().toString(36) + Math.random().toString(36).substr(2, 4);
async function main() {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║  NetFusion A5.1.3 — Investigation Models Verification     ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    // ───────────────────────────────────────────────────────────────────────────
    // 1. Schema Validation & Connectivity
    // ───────────────────────────────────────────────────────────────────────────
    section('1. Schema Validation & Connectivity');
    try {
        await prisma_1.default.$queryRaw `SELECT 1`;
        assert(true, 'Database connection established');
    }
    catch (e) {
        assert(false, 'Database connection failed', String(e));
    }
    const models = [
        { name: 'asset', countFn: () => prisma_1.default.asset.count() },
        { name: 'evidence', countFn: () => prisma_1.default.evidence.count() },
        { name: 'timelineEvent', countFn: () => prisma_1.default.timelineEvent.count() },
        { name: 'finding', countFn: () => prisma_1.default.finding.count() },
        { name: 'alert', countFn: () => prisma_1.default.alert.count() },
        { name: 'attackGraphNode', countFn: () => prisma_1.default.attackGraphNode.count() },
        { name: 'attackGraphEdge', countFn: () => prisma_1.default.attackGraphEdge.count() },
        { name: 'note', countFn: () => prisma_1.default.note.count() },
        { name: 'report', countFn: () => prisma_1.default.report.count() },
    ];
    for (const m of models) {
        try {
            const count = await m.countFn();
            assert(true, `Table "${m.name}" is accessible (row count: ${count})`);
        }
        catch (e) {
            assert(false, `Table "${m.name}" is NOT accessible`, String(e));
        }
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 2. Seed Data Verification
    // ───────────────────────────────────────────────────────────────────────────
    section('2. Seed Data Verification');
    const seedProjectId = '1d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e001';
    const seedProject = await prisma_1.default.project.findUnique({ where: { id: seedProjectId } });
    assert(!!seedProject, 'Seeded project exists');
    assert(seedProject?.name === 'Demo Project', 'Seeded project name matches');
    const seedInvestigationId = '2d9f2e3a-6f0a-4b9a-bbcb-7c73a1d9e101';
    const seedInvestigation = await prisma_1.default.investigation.findUnique({ where: { id: seedInvestigationId } });
    assert(!!seedInvestigation, 'Seeded investigation exists');
    assert(seedInvestigation?.title === 'Demo Investigation', 'Seeded investigation title matches');
    const seedAssets = await prisma_1.default.asset.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedAssets.length === 2, `Seeded exactly 2 assets (found ${seedAssets.length})`);
    assert(seedAssets.some(a => a.hostname === 'db-srv-01'), 'Seeded asset "db-srv-01" exists');
    assert(seedAssets.some(a => a.hostname === 'workstation-analyst'), 'Seeded asset "workstation-analyst" exists');
    const seedFindings = await prisma_1.default.finding.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedFindings.length === 2, `Seeded exactly 2 findings (found ${seedFindings.length})`);
    assert(seedFindings.some(f => f.title === 'Unauthorized SQL Brute Force Attack'), 'Seeded finding 1 exists');
    assert(seedFindings.some(f => f.title === 'Mimikatz Process Execution'), 'Seeded finding 2 exists');
    const seedEvidence = await prisma_1.default.evidence.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedEvidence.length === 2, `Seeded exactly 2 evidence records (found ${seedEvidence.length})`);
    assert(seedEvidence.some(e => e.fieldName === 'ipAddress'), 'Seeded evidence "ipAddress" exists');
    assert(seedEvidence.some(e => e.fieldName === 'processName'), 'Seeded evidence "processName" exists');
    const seedEvents = await prisma_1.default.timelineEvent.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedEvents.length === 2, `Seeded exactly 2 timeline events (found ${seedEvents.length})`);
    assert(seedEvents.some(e => e.title === 'First brute force attempt detected'), 'Seeded event 1 exists');
    assert(seedEvents.some(e => e.title === 'Mimikatz hash dumped'), 'Seeded event 2 exists');
    const seedAlerts = await prisma_1.default.alert.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedAlerts.length === 1, `Seeded exactly 1 alert (found ${seedAlerts.length})`);
    assert(seedAlerts[0]?.title === 'Credential Dumping Activity Alert', 'Seeded alert title matches');
    const seedNodes = await prisma_1.default.attackGraphNode.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedNodes.length === 2, `Seeded exactly 2 attack graph nodes (found ${seedNodes.length})`);
    assert(seedNodes.some(n => n.label === 'Internet Gateway'), 'Seeded node "Internet Gateway" exists');
    assert(seedNodes.some(n => n.label === 'Database Server'), 'Seeded node "Database Server" exists');
    const seedEdges = await prisma_1.default.attackGraphEdge.findMany({ where: { investigationId: seedInvestigationId } });
    assert(seedEdges.length === 1, `Seeded exactly 1 attack graph edge (found ${seedEdges.length})`);
    assert(seedEdges[0]?.label === 'Inbound SSH Traffic', 'Seeded edge label matches');
    // ───────────────────────────────────────────────────────────────────────────
    // 3. Enum Mappings Verification
    // ───────────────────────────────────────────────────────────────────────────
    section('3. Enum Mappings Verification');
    // Test AssetType (10 values)
    const assetTypes = Object.values(client_1.AssetType);
    assert(assetTypes.length === 10, `AssetType contains 10 values`);
    for (const val of assetTypes) {
        try {
            const tempAsset = await prisma_1.default.asset.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    hostname: `temp-${val}-${RUN}`,
                    type: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempAsset.type === val, `AssetType.${val} saved successfully`);
            await prisma_1.default.asset.delete({ where: { id: tempAsset.id } });
        }
        catch (e) {
            assert(false, `AssetType.${val} failed to save`, String(e));
        }
    }
    // Test FindingSeverity (5 values)
    const findingSeverities = Object.values(client_1.FindingSeverity);
    assert(findingSeverities.length === 5, `FindingSeverity contains 5 values`);
    for (const val of findingSeverities) {
        try {
            const tempFinding = await prisma_1.default.finding.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    title: `temp-${val}-${RUN}`,
                    severity: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempFinding.severity === val, `FindingSeverity.${val} saved successfully`);
            await prisma_1.default.finding.delete({ where: { id: tempFinding.id } });
        }
        catch (e) {
            assert(false, `FindingSeverity.${val} failed to save`, String(e));
        }
    }
    // Test FindingStatus (6 values)
    const findingStatuses = Object.values(client_1.FindingStatus);
    assert(findingStatuses.length === 6, `FindingStatus contains 6 values`);
    for (const val of findingStatuses) {
        try {
            const tempFinding = await prisma_1.default.finding.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    title: `temp-${val}-${RUN}`,
                    status: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempFinding.status === val, `FindingStatus.${val} saved successfully`);
            await prisma_1.default.finding.delete({ where: { id: tempFinding.id } });
        }
        catch (e) {
            assert(false, `FindingStatus.${val} failed to save`, String(e));
        }
    }
    // Test AlertSeverity (5 values)
    const alertSeverities = Object.values(client_1.AlertSeverity);
    assert(alertSeverities.length === 5, `AlertSeverity contains 5 values`);
    for (const val of alertSeverities) {
        try {
            const tempAlert = await prisma_1.default.alert.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    title: `temp-${val}-${RUN}`,
                    severity: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempAlert.severity === val, `AlertSeverity.${val} saved successfully`);
            await prisma_1.default.alert.delete({ where: { id: tempAlert.id } });
        }
        catch (e) {
            assert(false, `AlertSeverity.${val} failed to save`, String(e));
        }
    }
    // Test AlertStatus (7 values)
    const alertStatuses = Object.values(client_1.AlertStatus);
    assert(alertStatuses.length === 7, `AlertStatus contains 7 values`);
    for (const val of alertStatuses) {
        try {
            const tempAlert = await prisma_1.default.alert.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    title: `temp-${val}-${RUN}`,
                    status: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempAlert.status === val, `AlertStatus.${val} saved successfully`);
            await prisma_1.default.alert.delete({ where: { id: tempAlert.id } });
        }
        catch (e) {
            assert(false, `AlertStatus.${val} failed to save`, String(e));
        }
    }
    // Test TimelineEventType (17 values)
    const timelineEventTypes = Object.values(client_1.TimelineEventType);
    assert(timelineEventTypes.length === 17, `TimelineEventType contains 17 values`);
    for (const val of timelineEventTypes) {
        try {
            const tempEvent = await prisma_1.default.timelineEvent.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    title: `temp-${val}-${RUN}`,
                    type: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempEvent.type === val, `TimelineEventType.${val} saved successfully`);
            await prisma_1.default.timelineEvent.delete({ where: { id: tempEvent.id } });
        }
        catch (e) {
            assert(false, `TimelineEventType.${val} failed to save`, String(e));
        }
    }
    // Test EvidenceType (10 values)
    const evidenceTypes = Object.values(client_1.EvidenceType);
    assert(evidenceTypes.length === 10, `EvidenceType contains 10 values`);
    for (const val of evidenceTypes) {
        try {
            const tempEvidence = await prisma_1.default.evidence.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    fieldName: 'temp',
                    fieldValue: 'temp',
                    sourceType: 'temp',
                    type: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempEvidence.type === val, `EvidenceType.${val} saved successfully`);
            await prisma_1.default.evidence.delete({ where: { id: tempEvidence.id } });
        }
        catch (e) {
            assert(false, `EvidenceType.${val} failed to save`, String(e));
        }
    }
    // Test ReportStatus (4 values)
    const reportStatuses = Object.values(client_1.ReportStatus);
    assert(reportStatuses.length === 4, `ReportStatus contains 4 values`);
    for (const val of reportStatuses) {
        try {
            const tempReport = await prisma_1.default.report.create({
                data: {
                    projectId: seedProjectId,
                    investigationId: seedInvestigationId,
                    title: `temp-${val}-${RUN}`,
                    content: 'content',
                    status: val,
                    createdBy: 'verify',
                    updatedBy: 'verify',
                }
            });
            assert(tempReport.status === val, `ReportStatus.${val} saved successfully`);
            await prisma_1.default.report.delete({ where: { id: tempReport.id } });
        }
        catch (e) {
            assert(false, `ReportStatus.${val} failed to save`, String(e));
        }
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 4. CRUD Operations & Common Fields (9 models)
    // ───────────────────────────────────────────────────────────────────────────
    section('4. CRUD Operations & Common Fields');
    // Helper for model verification
    async function testCRUD(modelName, createFn, readFn, updateFn, deleteFn) {
        // CREATE
        let record;
        try {
            record = await createFn();
            assert(!!record.id, `[CRUD ${modelName}] Record created successfully`);
            assert(record.createdBy === 'crud_test', `[CRUD ${modelName}] createdBy field verified`);
            assert(record.updatedBy === 'crud_test', `[CRUD ${modelName}] updatedBy field verified`);
            assert(record.version === 1, `[CRUD ${modelName}] version starts at 1`);
        }
        catch (e) {
            assert(false, `[CRUD ${modelName}] Create failed`, String(e));
            return;
        }
        // READ
        try {
            const fetched = await readFn(record.id);
            assert(!!fetched, `[CRUD ${modelName}] Read retrieved record successfully`);
            assert(fetched?.createdBy === 'crud_test', `[CRUD ${modelName}] Read verified createdBy`);
            assert(fetched?.version === 1, `[CRUD ${modelName}] Read verified version`);
        }
        catch (e) {
            assert(false, `[CRUD ${modelName}] Read failed`, String(e));
        }
        // UPDATE
        const initialTime = record.updatedAt.getTime();
        // Wait briefly to ensure timestamp shifts
        await new Promise(r => setTimeout(r, 100));
        try {
            const updated = await updateFn(record.id);
            assert(updated.version === 2, `[CRUD ${modelName}] Update incremented version to 2`);
            assert(updated.updatedBy === 'crud_test_updated', `[CRUD ${modelName}] Update modified updatedBy`);
            assert(updated.updatedAt.getTime() > initialTime, `[CRUD ${modelName}] Update updated updatedAt timestamp`);
        }
        catch (e) {
            assert(false, `[CRUD ${modelName}] Update failed`, String(e));
        }
        // DELETE
        try {
            await deleteFn(record.id);
            const afterDelete = await readFn(record.id);
            assert(afterDelete === null, `[CRUD ${modelName}] Delete removed the record`);
        }
        catch (e) {
            assert(false, `[CRUD ${modelName}] Delete failed`, String(e));
        }
    }
    // 1. Asset CRUD
    await testCRUD('Asset', () => prisma_1.default.asset.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            hostname: `crud-asset-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.asset.findUnique({ where: { id } }), (id) => prisma_1.default.asset.update({
        where: { id },
        data: { hostname: `crud-asset-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.asset.delete({ where: { id } }));
    // 2. Evidence CRUD
    await testCRUD('Evidence', () => prisma_1.default.evidence.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            fieldName: 'ip',
            fieldValue: `192.168.1.1-${RUN}`,
            sourceType: 'manual',
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.evidence.findUnique({ where: { id } }), (id) => prisma_1.default.evidence.update({
        where: { id },
        data: { fieldValue: `192.168.1.2-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.evidence.delete({ where: { id } }));
    // 3. TimelineEvent CRUD
    await testCRUD('TimelineEvent', () => prisma_1.default.timelineEvent.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            title: `crud-event-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.timelineEvent.findUnique({ where: { id } }), (id) => prisma_1.default.timelineEvent.update({
        where: { id },
        data: { description: 'event description', version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.timelineEvent.delete({ where: { id } }));
    // 4. Finding CRUD
    await testCRUD('Finding', () => prisma_1.default.finding.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            title: `crud-finding-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.finding.findUnique({ where: { id } }), (id) => prisma_1.default.finding.update({
        where: { id },
        data: { description: 'finding description', version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.finding.delete({ where: { id } }));
    // 5. Alert CRUD
    await testCRUD('Alert', () => prisma_1.default.alert.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            title: `crud-alert-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.alert.findUnique({ where: { id } }), (id) => prisma_1.default.alert.update({
        where: { id },
        data: { description: 'alert description', version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.alert.delete({ where: { id } }));
    // 6. AttackGraphNode CRUD
    await testCRUD('AttackGraphNode', () => prisma_1.default.attackGraphNode.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            label: `crud-node-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.attackGraphNode.findUnique({ where: { id } }), (id) => prisma_1.default.attackGraphNode.update({
        where: { id },
        data: { type: 'server', version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.attackGraphNode.delete({ where: { id } }));
    // 7. AttackGraphEdge CRUD
    // We need nodes for the edge
    const srcNode = await prisma_1.default.attackGraphNode.create({
        data: { projectId: seedProjectId, investigationId: seedInvestigationId, label: 'src', createdBy: 't', updatedBy: 't' }
    });
    const dstNode = await prisma_1.default.attackGraphNode.create({
        data: { projectId: seedProjectId, investigationId: seedInvestigationId, label: 'dst', createdBy: 't', updatedBy: 't' }
    });
    await testCRUD('AttackGraphEdge', () => prisma_1.default.attackGraphEdge.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            sourceNodeId: srcNode.id,
            targetNodeId: dstNode.id,
            label: `crud-edge-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.attackGraphEdge.findUnique({ where: { id } }), (id) => prisma_1.default.attackGraphEdge.update({
        where: { id },
        data: { label: `crud-edge-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.attackGraphEdge.delete({ where: { id } }));
    await prisma_1.default.attackGraphNode.deleteMany({ where: { id: { in: [srcNode.id, dstNode.id] } } });
    // 8. Note CRUD
    await testCRUD('Note', () => prisma_1.default.note.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            content: `crud-note-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.note.findUnique({ where: { id } }), (id) => prisma_1.default.note.update({
        where: { id },
        data: { content: `crud-note-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.note.delete({ where: { id } }));
    // 9. Report CRUD
    await testCRUD('Report', () => prisma_1.default.report.create({
        data: {
            projectId: seedProjectId,
            investigationId: seedInvestigationId,
            title: `crud-report-${RUN}`,
            content: `content-${RUN}`,
            createdBy: 'crud_test',
            updatedBy: 'crud_test',
            version: 1,
        }
    }), (id) => prisma_1.default.report.findUnique({ where: { id } }), (id) => prisma_1.default.report.update({
        where: { id },
        data: { content: `content-mod-${RUN}`, version: 2, updatedBy: 'crud_test_updated' }
    }), (id) => prisma_1.default.report.delete({ where: { id } }));
    // ───────────────────────────────────────────────────────────────────────────
    // 5. Soft Delete Fields Verification (9 models)
    // ───────────────────────────────────────────────────────────────────────────
    section('5. Soft Delete Fields Verification');
    const softDeleteModels = [
        {
            name: 'Asset',
            createFn: () => prisma_1.default.asset.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, hostname: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.asset.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.asset.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.asset.delete({ where: { id } }),
        },
        {
            name: 'Evidence',
            createFn: () => prisma_1.default.evidence.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, fieldName: 'soft', fieldValue: 'soft', sourceType: 't', createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.evidence.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.evidence.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.evidence.delete({ where: { id } }),
        },
        {
            name: 'TimelineEvent',
            createFn: () => prisma_1.default.timelineEvent.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, title: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.timelineEvent.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.timelineEvent.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.timelineEvent.delete({ where: { id } }),
        },
        {
            name: 'Finding',
            createFn: () => prisma_1.default.finding.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, title: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.finding.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.finding.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.finding.delete({ where: { id } }),
        },
        {
            name: 'Alert',
            createFn: () => prisma_1.default.alert.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, title: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.alert.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.alert.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.alert.delete({ where: { id } }),
        },
        {
            name: 'AttackGraphNode',
            createFn: () => prisma_1.default.attackGraphNode.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, label: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.attackGraphNode.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.attackGraphNode.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.attackGraphNode.delete({ where: { id } }),
        },
        {
            name: 'AttackGraphEdge',
            createFn: async () => {
                const s = await prisma_1.default.attackGraphNode.create({ data: { projectId: seedProjectId, investigationId: seedInvestigationId, label: 's', createdBy: 't', updatedBy: 't' } });
                const t = await prisma_1.default.attackGraphNode.create({ data: { projectId: seedProjectId, investigationId: seedInvestigationId, label: 't', createdBy: 't', updatedBy: 't' } });
                return prisma_1.default.attackGraphEdge.create({
                    data: { projectId: seedProjectId, investigationId: seedInvestigationId, sourceNodeId: s.id, targetNodeId: t.id, label: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
                });
            },
            updateFn: (id, d) => prisma_1.default.attackGraphEdge.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.attackGraphEdge.findUnique({ where: { id } }),
            deleteFn: async (id) => {
                const edge = await prisma_1.default.attackGraphEdge.findUnique({ where: { id } });
                if (edge) {
                    await prisma_1.default.attackGraphEdge.delete({ where: { id } });
                    await prisma_1.default.attackGraphNode.deleteMany({ where: { id: { in: [edge.sourceNodeId, edge.targetNodeId] } } });
                }
            },
        },
        {
            name: 'Note',
            createFn: () => prisma_1.default.note.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, content: `soft-${RUN}`, createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.note.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.note.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.note.delete({ where: { id } }),
        },
        {
            name: 'Report',
            createFn: () => prisma_1.default.report.create({
                data: { projectId: seedProjectId, investigationId: seedInvestigationId, title: `soft-${RUN}`, content: 'content', createdBy: 't', updatedBy: 't' }
            }),
            updateFn: (id, d) => prisma_1.default.report.update({ where: { id }, data: { deletedAt: d } }),
            readFn: (id) => prisma_1.default.report.findUnique({ where: { id } }),
            deleteFn: (id) => prisma_1.default.report.delete({ where: { id } }),
        },
    ];
    for (const m of softDeleteModels) {
        try {
            const record = await m.createFn();
            assert(record.deletedAt === null, `[Soft Delete ${m.name}] Initial deletedAt is null`);
            const now = new Date();
            const updated = await m.updateFn(record.id, now);
            assert(updated.deletedAt !== null, `[Soft Delete ${m.name}] deletedAt is set after soft delete`);
            assert(updated.deletedAt?.getTime() === now.getTime(), `[Soft Delete ${m.name}] deletedAt matches date object`);
            await m.deleteFn(record.id);
        }
        catch (e) {
            assert(false, `[Soft Delete ${m.name}] Verification failed`, String(e));
        }
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 6. Foreign Keys & Relationships
    // ───────────────────────────────────────────────────────────────────────────
    section('6. Foreign Keys & Relationships');
    // Test Asset -> Project & Investigation
    const asset = seedAssets[0];
    assert(asset?.projectId === seedProjectId, 'Asset resolves projectId correctly');
    assert(asset?.investigationId === seedInvestigationId, 'Asset resolves investigationId correctly');
    // Test Evidence -> Asset & Finding
    const evidence = seedEvidence.find(e => e.assetId !== null);
    assert(!!evidence, 'Evidence with asset exists');
    if (evidence) {
        assert(evidence.projectId === seedProjectId, 'Evidence resolves projectId correctly');
        assert(evidence.investigationId === seedInvestigationId, 'Evidence resolves investigationId correctly');
        assert(evidence.assetId !== null, 'Evidence contains assetId');
        assert(evidence.findingId !== null, 'Evidence contains findingId');
    }
    // Test Finding -> Asset
    const finding = seedFindings.find(f => f.assetId !== null);
    assert(!!finding, 'Finding with asset exists');
    if (finding) {
        assert(finding.projectId === seedProjectId, 'Finding resolves projectId');
        assert(finding.investigationId === seedInvestigationId, 'Finding resolves investigationId');
        assert(finding.assetId !== null, 'Finding contains assetId');
    }
    // Test Alert -> Finding
    const alert = seedAlerts[0];
    assert(alert?.projectId === seedProjectId, 'Alert resolves projectId');
    assert(alert?.investigationId === seedInvestigationId, 'Alert resolves investigationId');
    assert(alert?.findingId !== null, 'Alert contains findingId');
    // Test AttackGraphEdge -> Nodes
    const edge = seedEdges[0];
    assert(edge?.projectId === seedProjectId, 'AttackGraphEdge resolves projectId');
    assert(edge?.investigationId === seedInvestigationId, 'AttackGraphEdge resolves investigationId');
    assert(edge?.sourceNodeId !== null, 'AttackGraphEdge has sourceNodeId');
    assert(edge?.targetNodeId !== null, 'AttackGraphEdge has targetNodeId');
    // ───────────────────────────────────────────────────────────────────────────
    // 7. Cascade Behavior (Deep Cascade Tests)
    // ───────────────────────────────────────────────────────────────────────────
    section('7. Cascade Behavior');
    // Create temporary project and investigation to test cascade deletes
    const tempUser = await prisma_1.default.user.create({
        data: {
            username: `cascade-u-${RUN}`,
            email: `cascade-u-${RUN}@test.com`,
            displayName: 'Cascade test',
            passwordHash: 'dummy',
        }
    });
    const tempProject = await prisma_1.default.project.create({
        data: {
            ownerId: tempUser.id,
            name: `cascade-p-${RUN}`,
        }
    });
    const tempInvestigation = await prisma_1.default.investigation.create({
        data: {
            projectId: tempProject.id,
            ownerId: tempUser.id,
            title: `cascade-i-${RUN}`,
        }
    });
    // Create child items for this temp investigation (1 of each)
    const cAsset = await prisma_1.default.asset.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, hostname: 'cas', createdBy: 't', updatedBy: 't' }
    });
    const cFinding = await prisma_1.default.finding.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, title: 'cas', assetId: cAsset.id, createdBy: 't', updatedBy: 't' }
    });
    const cEvidence = await prisma_1.default.evidence.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, fieldName: 'cas', fieldValue: 'cas', sourceType: 't', assetId: cAsset.id, findingId: cFinding.id, createdBy: 't', updatedBy: 't' }
    });
    const cEvent = await prisma_1.default.timelineEvent.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, title: 'cas', createdBy: 't', updatedBy: 't' }
    });
    const cAlert = await prisma_1.default.alert.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, title: 'cas', findingId: cFinding.id, createdBy: 't', updatedBy: 't' }
    });
    const cNode1 = await prisma_1.default.attackGraphNode.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, label: 'cas1', createdBy: 't', updatedBy: 't' }
    });
    const cNode2 = await prisma_1.default.attackGraphNode.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, label: 'cas2', createdBy: 't', updatedBy: 't' }
    });
    const cEdge = await prisma_1.default.attackGraphEdge.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, sourceNodeId: cNode1.id, targetNodeId: cNode2.id, label: 'cas', createdBy: 't', updatedBy: 't' }
    });
    const cNote = await prisma_1.default.note.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, content: 'cas', createdBy: 't', updatedBy: 't' }
    });
    const cReport = await prisma_1.default.report.create({
        data: { projectId: tempProject.id, investigationId: tempInvestigation.id, title: 'cas', content: 'cas', createdBy: 't', updatedBy: 't' }
    });
    // Verify they all exist
    assert(true, '[Cascade] All child entities created for temp investigation');
    // Hard-delete tempInvestigation
    await prisma_1.default.investigation.delete({ where: { id: tempInvestigation.id } });
    // Assert that investigation is gone
    const fetchInvestigation = await prisma_1.default.investigation.findUnique({ where: { id: tempInvestigation.id } });
    assert(fetchInvestigation === null, '[Cascade] Temp investigation deleted');
    // Assert that ALL child records are deleted by cascade
    assert(await prisma_1.default.asset.findUnique({ where: { id: cAsset.id } }) === null, '[Cascade] Asset deleted');
    assert(await prisma_1.default.finding.findUnique({ where: { id: cFinding.id } }) === null, '[Cascade] Finding deleted');
    assert(await prisma_1.default.evidence.findUnique({ where: { id: cEvidence.id } }) === null, '[Cascade] Evidence deleted');
    assert(await prisma_1.default.timelineEvent.findUnique({ where: { id: cEvent.id } }) === null, '[Cascade] TimelineEvent deleted');
    assert(await prisma_1.default.alert.findUnique({ where: { id: cAlert.id } }) === null, '[Cascade] Alert deleted');
    assert(await prisma_1.default.attackGraphNode.findUnique({ where: { id: cNode1.id } }) === null, '[Cascade] AttackGraphNode 1 deleted');
    assert(await prisma_1.default.attackGraphNode.findUnique({ where: { id: cNode2.id } }) === null, '[Cascade] AttackGraphNode 2 deleted');
    assert(await prisma_1.default.attackGraphEdge.findUnique({ where: { id: cEdge.id } }) === null, '[Cascade] AttackGraphEdge deleted');
    assert(await prisma_1.default.note.findUnique({ where: { id: cNote.id } }) === null, '[Cascade] Note deleted');
    assert(await prisma_1.default.report.findUnique({ where: { id: cReport.id } }) === null, '[Cascade] Report deleted');
    // Clean up user and project
    await prisma_1.default.project.delete({ where: { id: tempProject.id } });
    await prisma_1.default.user.delete({ where: { id: tempUser.id } });
    assert(true, '[Cascade] Cleaned up temporary cascade test containers');
    // Test setNull behavior:
    // If an Asset is deleted, its related Finding should have assetId set to null (instead of cascade deletion).
    const assetForNull = await prisma_1.default.asset.create({
        data: { projectId: seedProjectId, investigationId: seedInvestigationId, hostname: `nulltest-${RUN}`, createdBy: 't', updatedBy: 't' }
    });
    const findingForNull = await prisma_1.default.finding.create({
        data: { projectId: seedProjectId, investigationId: seedInvestigationId, title: 'nulltest', assetId: assetForNull.id, createdBy: 't', updatedBy: 't' }
    });
    await prisma_1.default.asset.delete({ where: { id: assetForNull.id } });
    const refetchedFinding = await prisma_1.default.finding.findUnique({ where: { id: findingForNull.id } });
    assert(refetchedFinding !== null, '[onDelete SetNull] Finding remains after Asset is deleted');
    assert(refetchedFinding?.assetId === null, '[onDelete SetNull] Finding assetId set to null');
    await prisma_1.default.finding.delete({ where: { id: findingForNull.id } });
    // ───────────────────────────────────────────────────────────────────────────
    // 8. Unique Constraints Verification
    // ───────────────────────────────────────────────────────────────────────────
    section('8. Unique Constraints');
    // Test RolePermission unique constraint [roleId, permissionId]
    const adminRole = await prisma_1.default.role.findUnique({ where: { name: 'admin' } });
    const assetReadPerm = await prisma_1.default.permission.findUnique({ where: { name: 'asset.read' } });
    if (adminRole && assetReadPerm) {
        try {
            await prisma_1.default.rolePermission.create({
                data: {
                    roleId: adminRole.id,
                    permissionId: assetReadPerm.id
                }
            });
            assert(false, '[Unique Constraint] rolePermission duplicate created without error');
        }
        catch (e) {
            // Prisma error for unique constraint violation is P2002
            assert(e.code === 'P2002', '[Unique Constraint] rolePermission duplicate rejected with P2002 error code');
        }
    }
    // Test UserRole unique constraint [userId, roleId]
    const seedUser = await prisma_1.default.user.findUnique({ where: { username: 'admin' } });
    if (seedUser && adminRole) {
        try {
            await prisma_1.default.userRole.create({
                data: {
                    userId: seedUser.id,
                    roleId: adminRole.id
                }
            });
            assert(false, '[Unique Constraint] userRole duplicate created without error');
        }
        catch (e) {
            assert(e.code === 'P2002', '[Unique Constraint] userRole duplicate rejected with P2002 error code');
        }
    }
    // Test User username uniqueness
    try {
        await prisma_1.default.user.create({
            data: {
                username: 'admin',
                email: 'other@test.com',
                displayName: 'Other',
                passwordHash: 'dummy'
            }
        });
        assert(false, '[Unique Constraint] Duplicate user username created without error');
    }
    catch (e) {
        assert(e.code === 'P2002', '[Unique Constraint] Duplicate user username rejected with P2002');
    }
    // Test User email uniqueness
    try {
        await prisma_1.default.user.create({
            data: {
                username: 'otheradmin',
                email: 'admin@netfusion.local',
                displayName: 'Other',
                passwordHash: 'dummy'
            }
        });
        assert(false, '[Unique Constraint] Duplicate user email created without error');
    }
    catch (e) {
        assert(e.code === 'P2002', '[Unique Constraint] Duplicate user email rejected with P2002');
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 9. Indexes Verification
    // ───────────────────────────────────────────────────────────────────────────
    section('9. Indexes Verification');
    // Verify we can retrieve records filtered by each index field successfully
    try {
        const assetsByProj = await prisma_1.default.asset.findMany({ where: { projectId: seedProjectId } });
        assert(assetsByProj.length >= 2, 'Index lookup by projectId works');
        const assetsByInv = await prisma_1.default.asset.findMany({ where: { investigationId: seedInvestigationId } });
        assert(assetsByInv.length >= 2, 'Index lookup by investigationId works');
        const findingsByAsset = await prisma_1.default.finding.findMany({ where: { assetId: seedAssets[0].id } });
        assert(findingsByAsset.length >= 1, 'Index lookup by assetId works');
        const evidenceByFinding = await prisma_1.default.evidence.findMany({ where: { findingId: seedFindings[0].id } });
        assert(evidenceByFinding.length >= 1, 'Index lookup by findingId works');
        const findingsBySeverity = await prisma_1.default.finding.findMany({ where: { severity: client_1.FindingSeverity.HIGH } });
        assert(findingsBySeverity.length >= 1, 'Index lookup by severity works');
        const findingsByStatus = await prisma_1.default.finding.findMany({ where: { status: client_1.FindingStatus.OPEN } });
        assert(findingsByStatus.length >= 1, 'Index lookup by status works');
        const assetsByCreatedAt = await prisma_1.default.asset.findMany({ where: { createdAt: { lte: new Date() } } });
        assert(assetsByCreatedAt.length >= 2, 'Index lookup by createdAt works');
        const assetsByUpdatedAt = await prisma_1.default.asset.findMany({ where: { updatedAt: { lte: new Date() } } });
        assert(assetsByUpdatedAt.length >= 2, 'Index lookup by updatedAt works');
    }
    catch (e) {
        assert(false, 'Index lookups failed', String(e));
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
    }
    else {
        console.log('All tests passed successfully.');
        process.exit(0);
    }
}
main()
    .catch((e) => {
    console.error('Verification script crashed:', e);
    process.exit(1);
});
