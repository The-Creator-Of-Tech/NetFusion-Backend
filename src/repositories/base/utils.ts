import { Prisma } from '@prisma/client';
import { RepositoryPagination, RepositorySort, RepositoryFilter, RepositoryError } from './types';

/**
 * Converts a RepositoryPagination object into Prisma's skip/take parameters.
 */
export function buildPaginationArgs(p?: RepositoryPagination): { skip?: number; take?: number } {
  if (!p) return {};
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
export function buildSortArgs(sorts?: RepositorySort[]): Record<string, 'asc' | 'desc'>[] | undefined {
  if (!sorts || sorts.length === 0) return undefined;
  return sorts.map((s) => ({
    [s.field]: s.direction,
  }));
}

/**
 * Parses RepositoryFilter into query clauses.
 * Strips out undefined or null keys to avoid prisma criteria matches unless desired.
 */
export function buildFilterArgs(filter?: RepositoryFilter): Record<string, any> {
  if (!filter) return {};
  const prismaFilter: Record<string, any> = {};

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
export async function executeSafely<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error: any) {
    if (error instanceof RepositoryError) {
      throw error;
    }

    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      throw new RepositoryError(
        `Database query failed: ${error.message}`,
        error.code,
        error
      );
    }

    throw new RepositoryError(
      error?.message || 'An unexpected database error occurred',
      'UNKNOWN',
      error
    );
  }
}
