import prisma from './prisma';

/**
 * Connect to the database.
 */
export async function connect(): Promise<void> {
  await prisma.$connect();
}

/**
 * Disconnect from the database.
 */
export async function disconnect(): Promise<void> {
  await prisma.$disconnect();
}

/**
 * Check the database health and responsiveness.
 */
export async function health(): Promise<{ status: string; latencyMs: number }> {
  const start = Date.now();
  await prisma.$queryRaw`SELECT 1`;
  const latencyMs = Date.now() - start;
  return {
    status: 'healthy',
    latencyMs,
  };
}

/**
 * Execute operations inside a database transaction.
 */
export async function transaction<T>(fn: (tx: any) => Promise<T>): Promise<T> {
  return await prisma.$transaction(fn);
}

/**
 * Reset the database (development only).
 * Truncates or deletes all records in tables.
 */
export async function reset(): Promise<void> {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Database reset is disabled in production.');
  }

  // Clear system_health records
  try {
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "system_health" CASCADE;');
  } catch (error) {
    try {
      await prisma.$executeRawUnsafe('DELETE FROM "system_health";');
    } catch (innerError) {
      // Ignore if database/table is not initialized
    }
  }
}
