-- CreateTable
CREATE TABLE "ScanRun" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "captureId" TEXT,
    "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" DATETIME,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "packetCount" INTEGER NOT NULL DEFAULT 0,
    "summary" TEXT,
    "findings" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "captureSessionId" TEXT,
    CONSTRAINT "ScanRun_captureSessionId_fkey" FOREIGN KEY ("captureSessionId") REFERENCES "CaptureSession" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "CaptureSession" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "captureId" TEXT,
    "packetCount" INTEGER NOT NULL DEFAULT 0,
    "analysis" TEXT,
    "timeline" TEXT,
    "alerts" TEXT,
    "iocs" TEXT,
    "correlations" TEXT,
    "mitre" TEXT,
    "riskRanking" TEXT,
    "attackStory" TEXT,
    "investigationPlan" TEXT,
    "executiveReport" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "ReportArchive" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "reportType" TEXT NOT NULL,
    "reportData" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "archivedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
