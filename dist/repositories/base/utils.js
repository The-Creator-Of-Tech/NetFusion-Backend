"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildPaginationArgs = buildPaginationArgs;
exports.buildSortArgs = buildSortArgs;
exports.buildFilterArgs = buildFilterArgs;
exports.executeSafely = executeSafely;
const client_1 = require("@prisma/client");
const types_1 = require("./types");
/**
 * Converts a RepositoryPagination object into Prisma's skip/take parameters.
 */
function buildPaginationArgs(p) {
    if (!p)
        return {};
    const page = Math.max(1, p.page);
    const limit = Math.max(1, p.limit);
    return {
        skip: (page - 1) * limit,
        take: limit,
    };
}
/**
 * Converts a RepositorySort array into Prisma's orderBy structure.
 */
function buildSortArgs(sorts) {
    if (!sorts || sorts.length === 0)
        return undefined;
    return sorts.map((s) => ({
        [s.field]: s.direction,
    }));
}
/**
 * Parses RepositoryFilter into query clauses.
 * Strips out undefined or null keys to avoid prisma criteria matches unless desired.
 */
function buildFilterArgs(filter) {
    if (!filter)
        return {};
    const prismaFilter = {};
    for (const [key, value] of Object.entries(filter)) {
        if (value !== undefined) {
            prismaFilter[key] = value;
        }
    }
    return prismaFilter;
}
/**
 * Wraps database execution blocks to capture and map native errors to RepositoryErrors.
 */
async function executeSafely(fn) {
    try {
        return await fn();
    }
    catch (error) {
        if (error instanceof types_1.RepositoryError) {
            throw error;
        }
        if (error instanceof client_1.Prisma.PrismaClientKnownRequestError) {
            throw new types_1.RepositoryError(`Database query failed: ${error.message}`, error.code, error);
        }
        throw new types_1.RepositoryError(error?.message || 'An unexpected database error occurred', 'UNKNOWN', error);
    }
}
