import prisma from './lib/prisma';
import * as db from './lib/database';
import { PrismaClient } from '@prisma/client';

async function runVerification() {
  console.log('====================================================');
  console.log('Starting NetFusion Database Foundation Verification...');
  console.log('====================================================');

  let assertions = 0;
  let failures = 0;

  function assert(expr: boolean, message: string) {
    assertions++;
    if (expr) {
      console.log(`[PASS] ${message}`);
    } else {
      failures++;
      console.error(`[FAIL] ${message}`);
    }
  }

  try {
    // ---------------------------------------------------------------------------
    // 1. Singleton Behavior
    // ---------------------------------------------------------------------------
    console.log('\nVerifying Prisma Client singleton behavior...');
    assert(prisma instanceof PrismaClient, 'Imported client is an instance of PrismaClient');
    
    // Resolve module dynamically or check global variable
    const clientRef1 = prisma;
    const clientRef2 = globalThis.prismaGlobal;
    assert(clientRef1 === clientRef2, 'Client references the same global singleton instance');

    // ---------------------------------------------------------------------------
    // 2. Database Connection & Health Checks
    // ---------------------------------------------------------------------------
    console.log('\nVerifying database connection & health check...');
    await db.connect();
    console.log('Successfully connected to PostgreSQL database.');

    const healthStatus = await db.health();
    assert(healthStatus.status === 'healthy', 'Health check status is "healthy"');
    assert(typeof healthStatus.latencyMs === 'number' && healthStatus.latencyMs >= 0, `Latency is a valid number: ${healthStatus.latencyMs}ms`);

    // ---------------------------------------------------------------------------
    // 3. Transaction Helper Check
    // ---------------------------------------------------------------------------
    console.log('\nVerifying transaction helper...');
    const result = await db.transaction(async (tx) => {
      // Create a test record inside transaction
      return await tx.systemHealth.create({
        data: {
          status: 'TRANSACTION_VERIFICATION',
        },
      });
    });

    assert(result && typeof result.id === 'string', 'Transaction created record successfully');
    
    // Query record back from database
    const fetched = await prisma.systemHealth.findUnique({
      where: { id: result.id },
    });
    assert(fetched !== null && fetched.status === 'TRANSACTION_VERIFICATION', 'Querying record outside transaction succeeds');

    // ---------------------------------------------------------------------------
    // 4. Reset Helper Check
    // ---------------------------------------------------------------------------
    console.log('\nVerifying database reset helper...');
    await db.reset();
    const count = await prisma.systemHealth.count();
    assert(count === 0, 'Database reset successfully truncated the database');

    // ---------------------------------------------------------------------------
    // Finalization
    // ---------------------------------------------------------------------------
    await db.disconnect();
    console.log('\nSuccessfully disconnected from PostgreSQL.');

  } catch (error) {
    failures++;
    console.error('Fatal error during database verification:', error);
  }

  console.log('====================================================');
  console.log(`Verification completed with ${failures} failure(s) across ${assertions} assertions.`);
  console.log('====================================================');

  if (failures === 0) {
    console.log('ALL VERIFICATIONS PASSED');
    process.exit(0);
  } else {
    console.error('DATABASE FOUNDATION VERIFICATION FAILED');
    process.exit(1);
  }
}

runVerification();
