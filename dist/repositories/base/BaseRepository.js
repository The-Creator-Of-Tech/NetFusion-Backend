"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseRepository = void 0;
const prisma_1 = __importDefault(require("../../lib/prisma"));
const types_1 = require("./types");
const utils_1 = require("./utils");
/**
 * Generic BaseRepository class providing core database operations using Prisma.
 */
class BaseRepository {
    /**
     * @param modelKey The key corresponding to the model in the Prisma Client (e.g. 'user', 'project')
     */
    constructor(modelKey) {
        this.modelKey = modelKey;
    }
    /**
     * Dynamically retrieves the Prisma delegate for this model.
     * Leverages transaction-scoped client if provided, otherwise defaults to the standard prisma client.
     */
    getDelegate(tx) {
        const client = tx || prisma_1.default;
        const delegate = client[this.modelKey];
        if (!delegate) {
            throw new types_1.RepositoryError(`Prisma delegate for key "${this.modelKey}" is not defined.`);
        }
        return delegate;
    }
    /**
     * Inserts a single record.
     */
    async create(data, tx) {
        return (0, utils_1.executeSafely)(() => this.getDelegate(tx).create({ data }));
    }
    /**
     * Batch inserts multiple records. Returns the count of created records.
     */
    async createMany(data, tx) {
        const result = await (0, utils_1.executeSafely)(() => this.getDelegate(tx).createMany({ data }));
        return result.count;
    }
    /**
     * Retrieves a record by its UUID.
     */
    async findById(id, tx) {
        return (0, utils_1.executeSafely)(() => this.getDelegate(tx).findUnique({ where: { id } }));
    }
    /**
     * Finds the first record matching filter parameters.
     */
    async findOne(filter, tx) {
        const where = (0, utils_1.buildFilterArgs)(filter);
        return (0, utils_1.executeSafely)(() => this.getDelegate(tx).findFirst({ where }));
    }
    /**
     * Retrieves all records matching query options (filters, sorting, offsets, limit, inclusion).
     */
    async findMany(options, tx) {
        const where = (0, utils_1.buildFilterArgs)(options?.filter);
        const orderBy = (0, utils_1.buildSortArgs)(options?.sort);
        return (0, utils_1.executeSafely)(() => this.getDelegate(tx).findMany({
            where,
            ...(orderBy && { orderBy }),
            ...(options?.offset !== undefined && { skip: options.offset }),
            ...(options?.limit !== undefined && { take: options.limit }),
            ...(options?.include && { include: options.include }),
        }));
    }
    /**
     * Updates a record by ID. Supports optimistic concurrency version checking if version is present.
     */
    async update(id, data, tx) {
        return (0, utils_1.executeSafely)(async () => {
            const anyData = data;
            const hasVersion = anyData && typeof anyData.version === 'number';
            if (hasVersion) {
                const currentVersion = anyData.version;
                const updatedData = { ...anyData, version: currentVersion + 1 };
                try {
                    return await this.getDelegate(tx).update({
                        where: { id, version: currentVersion },
                        data: updatedData,
                    });
                }
                catch (error) {
                    if (error.code === 'P2025') {
                        throw new types_1.RepositoryError(`Optimistic lock failure: Record not found or version mismatch for ID "${id}" (version: ${currentVersion})`, 'VERSION_CONFLICT', error);
                    }
                    throw error;
                }
            }
            return this.getDelegate(tx).update({
                where: { id },
                data,
            });
        });
    }
    /**
     * Updates multiple records matching filters. Returns the count of updated records.
     */
    async updateMany(filter, data, tx) {
        const where = (0, utils_1.buildFilterArgs)(filter);
        const result = await (0, utils_1.executeSafely)(() => this.getDelegate(tx).updateMany({ where, data }));
        return result.count;
    }
    /**
     * Performs hard physical delete on a record by its UUID.
     */
    async delete(id, tx) {
        return (0, utils_1.executeSafely)(() => this.getDelegate(tx).delete({ where: { id } }));
    }
    /**
     * Sets `deletedAt` to current timestamp, records deletion user, and increments version.
     */
    async softDelete(id, deletedBy, tx) {
        return (0, utils_1.executeSafely)(async () => {
            const record = await this.getDelegate(tx).findUnique({ where: { id } });
            if (!record) {
                throw new types_1.RepositoryError(`Record not found for soft delete: "${id}"`, 'NOT_FOUND');
            }
            const currentVersion = typeof record.version === 'number' ? record.version : undefined;
            const hasUpdatedBy = 'updatedBy' in record;
            const updateData = {
                deletedAt: new Date(),
                ...(hasUpdatedBy && { updatedBy: deletedBy }),
                ...(currentVersion !== undefined && { version: currentVersion + 1 }),
            };
            return this.getDelegate(tx).update({
                where: { id },
                data: updateData,
            });
        });
    }
    /**
     * Restores a soft-deleted record by setting `deletedAt` to null and incrementing version.
     */
    async restore(id, tx) {
        return (0, utils_1.executeSafely)(async () => {
            const record = await this.getDelegate(tx).findUnique({ where: { id } });
            if (!record) {
                throw new types_1.RepositoryError(`Record not found for restore: "${id}"`, 'NOT_FOUND');
            }
            const currentVersion = typeof record.version === 'number' ? record.version : undefined;
            const updateData = {
                deletedAt: null,
                ...(currentVersion !== undefined && { version: currentVersion + 1 }),
            };
            return this.getDelegate(tx).update({
                where: { id },
                data: updateData,
            });
        });
    }
    /**
     * Counts records matching filters.
     */
    async count(filter, tx) {
        const where = (0, utils_1.buildFilterArgs)(filter);
        return (0, utils_1.executeSafely)(() => this.getDelegate(tx).count({ where }));
    }
    /**
     * Returns true if at least one record matches filter requirements.
     */
    async exists(filter, tx) {
        const total = await this.count(filter, tx);
        return total > 0;
    }
    /**
     * Paginates records with pagination, filters, sort specification, and structural inclusions.
     */
    async paginate(pagination, filter, sort, include, tx) {
        return (0, utils_1.executeSafely)(async () => {
            const where = (0, utils_1.buildFilterArgs)(filter);
            const orderBy = (0, utils_1.buildSortArgs)(sort);
            const { skip, take } = (0, utils_1.buildPaginationArgs)(pagination);
            const total = await this.getDelegate(tx).count({ where });
            const data = await this.getDelegate(tx).findMany({
                where,
                ...(orderBy && { orderBy }),
                ...(skip !== undefined && { skip }),
                ...(take !== undefined && { take }),
                ...(include && { include }),
            });
            const limit = pagination.limit;
            const totalPages = Math.ceil(total / limit);
            return {
                data,
                total,
                page: pagination.page,
                limit,
                totalPages,
            };
        });
    }
    /**
     * Initiates a database transaction.
     */
    async transaction(fn) {
        return prisma_1.default.$transaction(fn);
    }
}
exports.BaseRepository = BaseRepository;
