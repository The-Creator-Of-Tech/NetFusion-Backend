"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.connect = connect;
exports.disconnect = disconnect;
exports.health = health;
exports.transaction = transaction;
exports.reset = reset;
const prisma_1 = __importDefault(require("./prisma"));
/**
 * Connect to the database.
 */
async function connect() {
    await prisma_1.default.$connect();
}
/**
 * Disconnect from the database.
 */
async function disconnect() {
    await prisma_1.default.$disconnect();
}
/**
 * Check the database health and responsiveness.
 */
async function health() {
    const start = Date.now();
    await prisma_1.default.$queryRaw `SELECT 1`;
    const latencyMs = Date.now() - start;
    return {
        status: 'healthy',
        latencyMs,
    };
}
/**
 * Execute operations inside a database transaction.
 */
async function transaction(fn) {
    return await prisma_1.default.$transaction(fn);
}
/**
 * Reset the database (development only).
 * Truncates or deletes all records in tables.
 */
async function reset() {
    if (process.env.NODE_ENV === 'production') {
        throw new Error('Database reset is disabled in production.');
    }
    // Clear system_health records
    try {
        await prisma_1.default.$executeRawUnsafe('TRUNCATE TABLE "system_health" CASCADE;');
    }
    catch (error) {
        try {
            await prisma_1.default.$executeRawUnsafe('DELETE FROM "system_health";');
        }
        catch (innerError) {
            // Ignore if database/table is not initialized
        }
    }
}
