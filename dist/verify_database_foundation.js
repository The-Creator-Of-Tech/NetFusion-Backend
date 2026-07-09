"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const prisma_1 = __importDefault(require("./lib/prisma"));
const db = __importStar(require("./lib/database"));
const client_1 = require("@prisma/client");
async function runVerification() {
    console.log('====================================================');
    console.log('Starting NetFusion Database Foundation Verification...');
    console.log('====================================================');
    let assertions = 0;
    let failures = 0;
    function assert(expr, message) {
        assertions++;
        if (expr) {
            console.log(`[PASS] ${message}`);
        }
        else {
            failures++;
            console.error(`[FAIL] ${message}`);
        }
    }
    try {
        // ---------------------------------------------------------------------------
        // 1. Singleton Behavior
        // ---------------------------------------------------------------------------
        console.log('\nVerifying Prisma Client singleton behavior...');
        assert(prisma_1.default instanceof client_1.PrismaClient, 'Imported client is an instance of PrismaClient');
        // Resolve module dynamically or check global variable
        const clientRef1 = prisma_1.default;
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
        const fetched = await prisma_1.default.systemHealth.findUnique({
            where: { id: result.id },
        });
        assert(fetched !== null && fetched.status === 'TRANSACTION_VERIFICATION', 'Querying record outside transaction succeeds');
        // ---------------------------------------------------------------------------
        // 4. Reset Helper Check
        // ---------------------------------------------------------------------------
        console.log('\nVerifying database reset helper...');
        await db.reset();
        const count = await prisma_1.default.systemHealth.count();
        assert(count === 0, 'Database reset successfully truncated the database');
        // ---------------------------------------------------------------------------
        // Finalization
        // ---------------------------------------------------------------------------
        await db.disconnect();
        console.log('\nSuccessfully disconnected from PostgreSQL.');
    }
    catch (error) {
        failures++;
        console.error('Fatal error during database verification:', error);
    }
    console.log('====================================================');
    console.log(`Verification completed with ${failures} failure(s) across ${assertions} assertions.`);
    console.log('====================================================');
    if (failures === 0) {
        console.log('ALL VERIFICATIONS PASSED');
        process.exit(0);
    }
    else {
        console.error('DATABASE FOUNDATION VERIFICATION FAILED');
        process.exit(1);
    }
}
runVerification();
