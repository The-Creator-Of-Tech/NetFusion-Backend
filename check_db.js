const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  const sessions = await prisma.captureSession.findMany();
  console.log("=== CAPTURE SESSIONS IN SQLite DB ===");
  console.log(sessions.map(s => ({
    id: s.id,
    projectId: s.projectId,
    captureId: s.captureId,
    packetCount: s.packetCount
  })));
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
