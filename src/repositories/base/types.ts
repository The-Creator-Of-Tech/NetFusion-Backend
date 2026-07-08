import { Prisma } from '@prisma/client';

/**
 * Custom Error class representing errors thrown inside the repository layer.
 */
export class RepositoryError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
    public readonly originalError?: any
  ) {
    super(message);
    this.name = 'RepositoryError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Pagination input parameters.
 */
export interface RepositoryPagination {
  page: number; // 1-indexed
  limit: number;
}

/**
 * Platform-agnostic filtering representation.
 */
export type RepositoryFilter = Record<string, any>;

/**
 * Sorting specification.
 */
export interface RepositorySort {
  field: string;
  direction: 'asc' | 'desc';
}

/**
 * Standard operation response container.
 */
export interface RepositoryResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Standard response structure for paginated requests.
 */
export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

/**
 * Interface mapping to Prisma's TransactionClient for transactional queries.
 */
export type RepositoryTransaction = Prisma.TransactionClient;
