-- CreateTable
CREATE TABLE "PcapInvestigation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "summary" TEXT,
    "alerts" TEXT,
    "iocs" TEXT,
    "timeline" TEXT,
    "mitre" TEXT,
    "riskRanking" TEXT,
    "attackStory" TEXT,
    "investigationPlan" TEXT,
    "executiveReport" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "NmapScan" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "profile" TEXT NOT NULL DEFAULT 'quick',
    "resultJson" TEXT,
    "rawOutput" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
