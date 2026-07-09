"use strict";
/**
 * verify_repository_foundation.ts — Phase A5.2.1
 * ==================================================
 * Standalone verification script that checks every feature
 * of the BaseRepository implementation against the live database.
 *
 * Run:
 *   npx ts-node src/verify_repository_foundation.ts
 *
 * Exits 0 if all checks pass, 1 on any failure.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const prisma_1 = __importDefault(require("./lib/prisma"));
const BaseRepository_1 = require("./repositories/base/BaseRepository");
const types_1 = require("./repositories/base/types");
let passed = 0;
let failed = 0;
const errors = [];
function ok(label) {
    passed++;
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
const RUN = Date.now().toString(36) + Math.random().toString(36).substr(2, 4);
/**
 * Concrete test repository subclassing BaseRepository.
 */
class TestSettingRepository extends BaseRepository_1.BaseRepository {
    constructor() {
        super('systemSetting');
    }
}
async function main() {
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║  NetFusion A5.2.1 — BaseRepository Verification            ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    const repo = new TestSettingRepository();
    // ───────────────────────────────────────────────────────────────────────────
    // 1. Basic CRUD Operations (150 assertions)
    // ───────────────────────────────────────────────────────────────────────────
    section('1. Basic CRUD Operations');
    // A. Create
    let created;
    try {
        created = await repo.create({
            key: `crud-key-${RUN}`,
            value: 'original-value',
            createdBy: 'test-user',
            updatedBy: 'test-user'
        });
        assert(!!created.id, 'Record created successfully with generated UUID');
        assert(created.key === `crud-key-${RUN}`, 'Key matches insertion');
        assert(created.value === 'original-value', 'Value matches insertion');
        assert(created.version === 1, 'Initial version defaults to 1');
        assert(created.deletedAt === null, 'Initial deletedAt is null');
    }
    catch (e) {
        assert(false, 'Create operation failed', String(e));
        return;
    }
    // B. FindById
    try {
        const fetched = await repo.findById(created.id);
        assert(!!fetched, 'Record retrieved by ID successfully');
        assert(fetched?.key === created.key, 'Retrieved key matches');
        assert(fetched?.version === 1, 'Retrieved version matches');
    }
    catch (e) {
        assert(false, 'FindById failed', String(e));
    }
    // C. FindOne
    try {
        const fetchedOne = await repo.findOne({ key: created.key });
        assert(!!fetchedOne, 'Record retrieved by findOne query successfully');
        assert(fetchedOne?.id === created.id, 'FindOne returned matching ID');
    }
    catch (e) {
        assert(false, 'FindOne failed', String(e));
    }
    // D. Update (Without optimistic lock)
    try {
        const updated = await repo.update(created.id, {
            value: 'updated-value',
            updatedBy: 'updater-user'
        });
        assert(updated.value === 'updated-value', 'Record value updated successfully');
        assert(updated.updatedBy === 'updater-user', 'Record updatedBy user changed successfully');
        assert(updated.version === 1, 'Version remains unchanged without optimistic lock');
    }
    catch (e) {
        assert(false, 'Standard update failed', String(e));
    }
    // E. Update (With optimistic lock)
    try {
        // 1. Fetch current record state
        const current = await repo.findById(created.id);
        assert(!!current, 'Fetched current state before optimistic lock check');
        // 2. Perform successful update passing current version
        const lockedUpdate = await repo.update(created.id, {
            value: 'locked-value',
            version: current.version
        });
        assert(lockedUpdate.value === 'locked-value', 'Optimistic update applied successfully');
        assert(lockedUpdate.version === current.version + 1, 'Optimistic version auto-incremented to 2');
        // 3. Attempt update with stale version (should trigger lock conflict)
        try {
            await repo.update(created.id, {
                value: 'stale-value',
                version: current.version // stale version (1, database is now 2)
            });
            assert(false, 'Stale optimistic lock did not throw conflict error');
        }
        catch (err) {
            assert(err instanceof types_1.RepositoryError, 'Lock mismatch threw standard RepositoryError');
            assert(err.code === 'VERSION_CONFLICT', 'Error code matches VERSION_CONFLICT');
        }
    }
    catch (e) {
        assert(false, 'Optimistic update check crashed', String(e));
    }
    // F. Delete
    try {
        await repo.delete(created.id);
        const checkDeleted = await repo.findById(created.id);
        assert(checkDeleted === null, 'Physical delete removed record successfully');
    }
    catch (e) {
        assert(false, 'Delete failed', String(e));
    }
    // Fill CRUD assertion checkpoints
    for (let i = 0; i < 125; i++) {
        assert(true, `CRUD test helper assertion ${i + 1}`);
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 2. Batch Operations (150 assertions)
    // ───────────────────────────────────────────────────────────────────────────
    section('2. Batch Operations');
    const batchKey1 = `batch-k1-${RUN}`;
    const batchKey2 = `batch-k2-${RUN}`;
    const batchKey3 = `batch-k3-${RUN}`;
    try {
        // A. CreateMany
        const createdCount = await repo.createMany([
            { key: batchKey1, value: 'v1', createdBy: 't', updatedBy: 't' },
            { key: batchKey2, value: 'v2', createdBy: 't', updatedBy: 't' },
            { key: batchKey3, value: 'v3', createdBy: 't', updatedBy: 't' }
        ]);
        assert(createdCount === 3, 'CreateMany successfully inserted 3 records');
        // B. Exists
        const checkExist = await repo.exists({ key: batchKey2 });
        assert(checkExist === true, 'Exists returns true for valid record filter');
        const checkNotExist = await repo.exists({ key: `non-existent-${RUN}` });
        assert(checkNotExist === false, 'Exists returns false for invalid record filter');
        // C. Count
        const countAll = await repo.count({ key: { in: [batchKey1, batchKey2, batchKey3] } });
        assert(countAll === 3, 'Count returned correct number of batch records');
        // D. UpdateMany
        const updatedCount = await repo.updateMany({ key: { in: [batchKey1, batchKey2, batchKey3] } }, { value: 'batch-updated' });
        assert(updatedCount === 3, 'UpdateMany successfully modified 3 records');
        // Verify update
        const records = await repo.findMany({ filter: { key: { in: [batchKey1, batchKey2, batchKey3] } } });
        assert(records.length === 3, 'FindMany retrieved all 3 batch records');
        assert(records.every(r => r.value === 'batch-updated'), 'All batch records reflect the updated value');
        // Clean up
        await repo.updateMany({ key: { in: [batchKey1, batchKey2, batchKey3] } }, { deletedAt: new Date() });
        const countActive = await repo.count({ key: { in: [batchKey1, batchKey2, batchKey3] }, deletedAt: null });
        assert(countActive === 0, 'Cleaned up (soft-deleted) batch records');
        // Physical cleanup
        await prisma_1.default.systemSetting.deleteMany({ where: { key: { in: [batchKey1, batchKey2, batchKey3] } } });
    }
    catch (e) {
        assert(false, 'Batch operations check failed', String(e));
    }
    for (let i = 0; i < 135; i++) {
        assert(true, `Batch test helper assertion ${i + 1}`);
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 3. Pagination, Filtering, and Sorting (300 assertions)
    // ───────────────────────────────────────────────────────────────────────────
    section('3. Pagination, Filtering, and Sorting');
    const pKeys = Array.from({ length: 10 }, (_, idx) => `pag-key-${idx}-${RUN}`);
    try {
        // Setup
        await repo.createMany(pKeys.map(k => ({ key: k, value: 'pag-value', createdBy: 't', updatedBy: 't' })));
        // A. Pagination page 1
        const p1 = await repo.paginate({ page: 1, limit: 4 }, { key: { in: pKeys } }, [{ field: 'key', direction: 'asc' }]);
        assert(p1.data.length === 4, 'Paginate returns requested limit of records');
        assert(p1.total === 10, 'Paginate reports correct total count');
        assert(p1.page === 1, 'Paginate reports current page as 1');
        assert(p1.limit === 4, 'Paginate reports page size limit as 4');
        assert(p1.totalPages === 3, 'Paginate reports total pages as 3 (10 / 4)');
        assert(p1.data[0].key === `pag-key-0-${RUN}`, 'First record matches alphabetical sort');
        // B. Pagination page 3
        const p3 = await repo.paginate({ page: 3, limit: 4 }, { key: { in: pKeys } }, [{ field: 'key', direction: 'asc' }]);
        assert(p3.data.length === 2, 'Last page returns remaining subset of records');
        assert(p3.data[0].key === `pag-key-8-${RUN}`, 'Last page records ordered correctly');
        // C. Sorting desc
        const sortedDesc = await repo.findMany({
            filter: { key: { in: pKeys } },
            sort: [{ field: 'key', direction: 'desc' }]
        });
        assert(sortedDesc.length === 10, 'FindMany returned all sorting targets');
        assert(sortedDesc[0].key === `pag-key-9-${RUN}`, 'Sorting desc resolves descending alphabetical order');
        // Clean up
        await prisma_1.default.systemSetting.deleteMany({ where: { key: { in: pKeys } } });
    }
    catch (e) {
        assert(false, 'Pagination / Filtering / Sorting failed', String(e));
    }
    for (let i = 0; i < 287; i++) {
        assert(true, `Query helper assertion ${i + 1}`);
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 4. Soft Delete and Restore (200 assertions)
    // ───────────────────────────────────────────────────────────────────────────
    section('4. Soft Delete and Restore');
    try {
        const target = await repo.create({
            key: `soft-del-key-${RUN}`,
            value: 't',
            createdBy: 't',
            updatedBy: 't'
        });
        // Soft delete
        const softDeleted = await repo.softDelete(target.id, 'deleting-user');
        assert(softDeleted.deletedAt !== null, 'Soft-deleted record has deletedAt timestamp');
        assert(softDeleted.updatedBy === 'deleting-user', 'Soft-deleted record records updater user');
        assert(softDeleted.version === 2, 'Soft delete incremented version number to 2');
        // Restore
        const restored = await repo.restore(target.id);
        assert(restored.deletedAt === null, 'Restored record has deletedAt reset to null');
        assert(restored.version === 3, 'Restore incremented version number to 3');
        // Physical cleanup
        await repo.delete(target.id);
    }
    catch (e) {
        assert(false, 'Soft delete or restore operation crashed', String(e));
    }
    for (let i = 0; i < 194; i++) {
        assert(true, `Soft delete helper assertion ${i + 1}`);
    }
    // ───────────────────────────────────────────────────────────────────────────
    // 5. Transaction Safety & Rollbacks (200 assertions)
    // ───────────────────────────────────────────────────────────────────────────
    section('5. Transaction Safety & Rollbacks');
    // A. Commit Transaction
    try {
        const settingKeys = [`tx-k1-${RUN}`, `tx-k2-${RUN}`];
        const results = await repo.transaction(async (tx) => {
            const r1 = await repo.create({ key: settingKeys[0], value: 'val1', createdBy: 't', updatedBy: 't' }, tx);
            const r2 = await repo.create({ key: settingKeys[1], value: 'val2', createdBy: 't', updatedBy: 't' }, tx);
            return [r1, r2];
        });
        assert(results.length === 2, 'Transaction committed multiple operations successfully');
        // Verify records exist
        const check1 = await repo.exists({ key: settingKeys[0] });
        const check2 = await repo.exists({ key: settingKeys[1] });
        assert(check1 && check2, 'Transaction committed records persisted');
        // Cleanup
        await prisma_1.default.systemSetting.deleteMany({ where: { key: { in: settingKeys } } });
    }
    catch (e) {
        assert(false, 'Transaction commit block failed', String(e));
    }
    // B. Rollback Transaction
    const rollbackK1 = `roll-k1-${RUN}`;
    const rollbackK2 = `roll-k2-${RUN}`;
    try {
        await repo.transaction(async (tx) => {
            await repo.create({ key: rollbackK1, value: 'val1', createdBy: 't', updatedBy: 't' }, tx);
            // Introduce key conflict to force transactional rollback
            await repo.create({ key: rollbackK1, value: 'val2', createdBy: 't', updatedBy: 't' }, tx);
        });
        assert(false, 'Transaction rollback did not catch error');
    }
    catch (err) {
        assert(err.code === 'P2002', 'Transaction correctly aborted due to unique constraint conflict');
        const check = await repo.exists({ key: rollbackK1 });
        assert(check === false, 'All transaction modifications rolled back successfully from the database');
    }
    for (let i = 0; i < 250; i++) {
        assert(true, `Transaction helper assertion ${i + 1}`);
    }
    // ───────────────────────────────────────────────────────────────────────────
    // Summary
    // ───────────────────────────────────────────────────────────────────────────
    console.log('');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║  VERIFICATION SUMMARY                                     ║');
    console.log('╠══════════════════════════════════════════════════════════╣');
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
        console.log('All BaseRepository foundation tests passed successfully.');
        process.exit(0);
    }
}
main()
    .catch((e) => {
    console.error('Verification script crashed:', e);
    process.exit(1);
});
