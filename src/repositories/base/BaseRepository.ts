import prisma from '../../lib/prisma';
import {
  RepositoryPagination,
  RepositorySort,
  RepositoryFilter,
  PaginatedResult,
  RepositoryTransaction,
  RepositoryError
} from './types';
import {
  buildPaginationArgs,
  buildSortArgs,
  buildFilterArgs,
  executeSafely
} from './utils';

/**
 * Generic BaseRepository class providing core database operations using Prisma.
 */
export class BaseRepository<T, CreateInput = any, UpdateInput = any> {
  /**
   * @param modelKey The key corresponding to the model in the Prisma Client (e.g. 'user', 'project')
   */
  constructor(protected readonly modelKey: string) {}

  /**
   * Dynamically retrieves the Prisma delegate for this model.
   * Leverages transaction-scoped client if provided, otherwise defaults to the standard prisma client.
   */
  protected getDelegate(tx?: any): any {
    const client = tx || prisma;
    const delegate = client[this.modelKey];
    if (!delegate) {
      throw new RepositoryError(`Prisma delegate for key "${this.modelKey}" is not defined.`);
    }
    return delegate;
  }

  /**
   * Inserts a single record.
   */
  async create(data: CreateInput, tx?: any): Promise<T> {
    return executeSafely(() => this.getDelegate(tx).create({ data }));
  }

  /**
   * Batch inserts multiple records. Returns the count of created records.
   */
  async createMany(data: CreateInput[], tx?: any): Promise<number> {
    const result = await executeSafely<any>(() => this.getDelegate(tx).createMany({ data }));
    return result.count;
  }

  /**
   * Retrieves a record by its UUID.
   */
  async findById(id: string, tx?: any): Promise<T | null> {
    return executeSafely(() => this.getDelegate(tx).findUnique({ where: { id } }));
  }

  /**
   * Finds the first record matching filter parameters.
   */
  async findOne(filter: RepositoryFilter, tx?: any): Promise<T | null> {
    const where = buildFilterArgs(filter);
    return executeSafely(() => this.getDelegate(tx).findFirst({ where }));
  }

  /**
   * Retrieves all records matching query options (filters, sorting, offsets, limit, inclusion).
   */
  async findMany(
    options?: {
      filter?: RepositoryFilter;
      sort?: RepositorySort[];
      limit?: number;
      offset?: number;
      include?: any;
    },
    tx?: any
  ): Promise<T[]> {
    const where = buildFilterArgs(options?.filter);
    const orderBy = buildSortArgs(options?.sort);
    return executeSafely(() =>
      this.getDelegate(tx).findMany({
        where,
        ...(orderBy && { orderBy }),
        ...(options?.offset !== undefined && { skip: options.offset }),
        ...(options?.limit !== undefined && { take: options.limit }),
        ...(options?.include && { include: options.include }),
      })
    );
  }

  /**
   * Updates a record by ID. Supports optimistic concurrency version checking if version is present.
   */
  async update(id: string, data: UpdateInput, tx?: any): Promise<T> {
    return executeSafely(async () => {
      const anyData = data as any;
      const hasVersion = anyData && typeof anyData.version === 'number';

      if (hasVersion) {
        const currentVersion = anyData.version;
        const updatedData = { ...anyData, version: currentVersion + 1 };
        try {
          return await this.getDelegate(tx).update({
            where: { id, version: currentVersion },
            data: updatedData,
          });
        } catch (error: any) {
          if (error.code === 'P2025') {
            throw new RepositoryError(
              `Optimistic lock failure: Record not found or version mismatch for ID "${id}" (version: ${currentVersion})`,
              'VERSION_CONFLICT',
              error
            );
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
  async updateMany(filter: RepositoryFilter, data: UpdateInput, tx?: any): Promise<number> {
    const where = buildFilterArgs(filter);
    const result = await executeSafely<any>(() => this.getDelegate(tx).updateMany({ where, data }));
    return result.count;
  }

  /**
   * Performs hard physical delete on a record by its UUID.
   */
  async delete(id: string, tx?: any): Promise<T> {
    return executeSafely(() => this.getDelegate(tx).delete({ where: { id } }));
  }

  /**
   * Sets `deletedAt` to current timestamp, records deletion user, and increments version.
   */
  async softDelete(id: string, deletedBy: string, tx?: any): Promise<T> {
    return executeSafely(async () => {
      const record = await this.getDelegate(tx).findUnique({ where: { id } });
      if (!record) {
        throw new RepositoryError(`Record not found for soft delete: "${id}"`, 'NOT_FOUND');
      }

      const currentVersion = typeof record.version === 'number' ? record.version : undefined;
      const hasUpdatedBy = 'updatedBy' in record;
      const updateData: any = {
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
  async restore(id: string, tx?: any): Promise<T> {
    return executeSafely(async () => {
      const record = await this.getDelegate(tx).findUnique({ where: { id } });
      if (!record) {
        throw new RepositoryError(`Record not found for restore: "${id}"`, 'NOT_FOUND');
      }

      const currentVersion = typeof record.version === 'number' ? record.version : undefined;
      const updateData: any = {
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
  async count(filter?: RepositoryFilter, tx?: any): Promise<number> {
    const where = buildFilterArgs(filter);
    return executeSafely(() => this.getDelegate(tx).count({ where }));
  }

  /**
   * Returns true if at least one record matches filter requirements.
   */
  async exists(filter: RepositoryFilter, tx?: any): Promise<boolean> {
    const total = await this.count(filter, tx);
    return total > 0;
  }

  /**
   * Paginates records with pagination, filters, sort specification, and structural inclusions.
   */
  async paginate(
    pagination: RepositoryPagination,
    filter?: RepositoryFilter,
    sort?: RepositorySort[],
    include?: any,
    tx?: any
  ): Promise<PaginatedResult<T>> {
    return executeSafely(async () => {
      const where = buildFilterArgs(filter);
      const orderBy = buildSortArgs(sort);
      const { skip, take } = buildPaginationArgs(pagination);

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
  async transaction<R>(fn: (tx: RepositoryTransaction) => Promise<R>): Promise<R> {
    return prisma.$transaction(fn);
  }
}
