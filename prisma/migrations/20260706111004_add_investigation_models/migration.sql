-- CreateEnum
CREATE TYPE "AssetType" AS ENUM ('SERVER', 'WORKSTATION', 'ROUTER', 'SWITCH', 'FIREWALL', 'MOBILE', 'IOT', 'CLOUD', 'UNKNOWN', 'OTHER');

-- CreateEnum
CREATE TYPE "FindingSeverity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'CONFIRMED', 'SUPPRESSED', 'FALSE_POSITIVE', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "AlertSeverity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "AlertStatus" AS ENUM ('NEW', 'OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'CLOSED', 'SUPPRESSED');

-- CreateEnum
CREATE TYPE "TimelineEventType" AS ENUM ('OBSERVED', 'IDENTITY_MATCH', 'IDENTITY_CREATED', 'RELATIONSHIP_CREATED', 'RELATIONSHIP_UPDATED', 'EVIDENCE_ADDED', 'HISTORY_CREATED', 'ALERT_GENERATED', 'FINDING_CREATED', 'MITRE_MAPPED', 'ATTACK_PATTERN', 'ATTACK_CHAIN', 'BLAST_RADIUS', 'LATERAL_MOVEMENT', 'PIVOT', 'CHOKE_POINT', 'MANUAL_ACTION');

-- CreateEnum
CREATE TYPE "EvidenceType" AS ENUM ('PACKET', 'LOG', 'FILE', 'REGISTRY', 'PROCESS', 'IOC', 'ARTIFACT', 'METRIC', 'USER_INPUT', 'OTHER');

-- CreateEnum
CREATE TYPE "ReportStatus" AS ENUM ('DRAFT', 'READY', 'PUBLISHED', 'ARCHIVED');

-- CreateTable
CREATE TABLE "assets" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "macAddress" TEXT,
    "hostname" TEXT,
    "deviceName" TEXT,
    "vendor" TEXT,
    "operatingSystem" TEXT,
    "currentIp" TEXT,
    "currentStatus" TEXT,
    "type" "AssetType" NOT NULL DEFAULT 'UNKNOWN',
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "assets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidence" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "assetId" UUID,
    "findingId" UUID,
    "fieldName" TEXT NOT NULL,
    "fieldValue" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL,
    "type" "EvidenceType" NOT NULL DEFAULT 'OTHER',
    "rawValue" TEXT,
    "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" INTEGER NOT NULL DEFAULT 100,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "timeline_events" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "type" "TimelineEventType" NOT NULL DEFAULT 'OBSERVED',
    "eventTimestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "timeline_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "assetId" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "category" TEXT NOT NULL DEFAULT 'OTHER',
    "severity" "FindingSeverity" NOT NULL DEFAULT 'MEDIUM',
    "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alerts" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "findingId" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" "AlertSeverity" NOT NULL DEFAULT 'MEDIUM',
    "status" "AlertStatus" NOT NULL DEFAULT 'NEW',
    "source" TEXT NOT NULL DEFAULT 'FINDING',
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 100.0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "alerts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "attack_graph_nodes" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "label" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'host',
    "x" DOUBLE PRECISION,
    "y" DOUBLE PRECISION,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "attack_graph_nodes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "attack_graph_edges" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "sourceNodeId" UUID NOT NULL,
    "targetNodeId" UUID NOT NULL,
    "label" TEXT,
    "weight" DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "attack_graph_edges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notes" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "title" TEXT,
    "content" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "notes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reports" (
    "id" UUID NOT NULL,
    "projectId" UUID NOT NULL,
    "investigationId" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'SUMMARY',
    "status" "ReportStatus" NOT NULL DEFAULT 'DRAFT',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "reports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "assets_investigationId_idx" ON "assets"("investigationId");

-- CreateIndex
CREATE INDEX "assets_projectId_idx" ON "assets"("projectId");

-- CreateIndex
CREATE INDEX "assets_createdAt_idx" ON "assets"("createdAt");

-- CreateIndex
CREATE INDEX "assets_updatedAt_idx" ON "assets"("updatedAt");

-- CreateIndex
CREATE INDEX "evidence_investigationId_idx" ON "evidence"("investigationId");

-- CreateIndex
CREATE INDEX "evidence_projectId_idx" ON "evidence"("projectId");

-- CreateIndex
CREATE INDEX "evidence_assetId_idx" ON "evidence"("assetId");

-- CreateIndex
CREATE INDEX "evidence_findingId_idx" ON "evidence"("findingId");

-- CreateIndex
CREATE INDEX "evidence_createdAt_idx" ON "evidence"("createdAt");

-- CreateIndex
CREATE INDEX "evidence_updatedAt_idx" ON "evidence"("updatedAt");

-- CreateIndex
CREATE INDEX "timeline_events_investigationId_idx" ON "timeline_events"("investigationId");

-- CreateIndex
CREATE INDEX "timeline_events_projectId_idx" ON "timeline_events"("projectId");

-- CreateIndex
CREATE INDEX "timeline_events_createdAt_idx" ON "timeline_events"("createdAt");

-- CreateIndex
CREATE INDEX "timeline_events_updatedAt_idx" ON "timeline_events"("updatedAt");

-- CreateIndex
CREATE INDEX "findings_investigationId_idx" ON "findings"("investigationId");

-- CreateIndex
CREATE INDEX "findings_projectId_idx" ON "findings"("projectId");

-- CreateIndex
CREATE INDEX "findings_assetId_idx" ON "findings"("assetId");

-- CreateIndex
CREATE INDEX "findings_severity_idx" ON "findings"("severity");

-- CreateIndex
CREATE INDEX "findings_status_idx" ON "findings"("status");

-- CreateIndex
CREATE INDEX "findings_createdAt_idx" ON "findings"("createdAt");

-- CreateIndex
CREATE INDEX "findings_updatedAt_idx" ON "findings"("updatedAt");

-- CreateIndex
CREATE INDEX "alerts_investigationId_idx" ON "alerts"("investigationId");

-- CreateIndex
CREATE INDEX "alerts_projectId_idx" ON "alerts"("projectId");

-- CreateIndex
CREATE INDEX "alerts_findingId_idx" ON "alerts"("findingId");

-- CreateIndex
CREATE INDEX "alerts_severity_idx" ON "alerts"("severity");

-- CreateIndex
CREATE INDEX "alerts_status_idx" ON "alerts"("status");

-- CreateIndex
CREATE INDEX "alerts_createdAt_idx" ON "alerts"("createdAt");

-- CreateIndex
CREATE INDEX "alerts_updatedAt_idx" ON "alerts"("updatedAt");

-- CreateIndex
CREATE INDEX "attack_graph_nodes_investigationId_idx" ON "attack_graph_nodes"("investigationId");

-- CreateIndex
CREATE INDEX "attack_graph_nodes_projectId_idx" ON "attack_graph_nodes"("projectId");

-- CreateIndex
CREATE INDEX "attack_graph_nodes_createdAt_idx" ON "attack_graph_nodes"("createdAt");

-- CreateIndex
CREATE INDEX "attack_graph_nodes_updatedAt_idx" ON "attack_graph_nodes"("updatedAt");

-- CreateIndex
CREATE INDEX "attack_graph_edges_investigationId_idx" ON "attack_graph_edges"("investigationId");

-- CreateIndex
CREATE INDEX "attack_graph_edges_projectId_idx" ON "attack_graph_edges"("projectId");

-- CreateIndex
CREATE INDEX "attack_graph_edges_sourceNodeId_idx" ON "attack_graph_edges"("sourceNodeId");

-- CreateIndex
CREATE INDEX "attack_graph_edges_targetNodeId_idx" ON "attack_graph_edges"("targetNodeId");

-- CreateIndex
CREATE INDEX "attack_graph_edges_createdAt_idx" ON "attack_graph_edges"("createdAt");

-- CreateIndex
CREATE INDEX "attack_graph_edges_updatedAt_idx" ON "attack_graph_edges"("updatedAt");

-- CreateIndex
CREATE INDEX "notes_investigationId_idx" ON "notes"("investigationId");

-- CreateIndex
CREATE INDEX "notes_projectId_idx" ON "notes"("projectId");

-- CreateIndex
CREATE INDEX "notes_createdAt_idx" ON "notes"("createdAt");

-- CreateIndex
CREATE INDEX "notes_updatedAt_idx" ON "notes"("updatedAt");

-- CreateIndex
CREATE INDEX "reports_investigationId_idx" ON "reports"("investigationId");

-- CreateIndex
CREATE INDEX "reports_projectId_idx" ON "reports"("projectId");

-- CreateIndex
CREATE INDEX "reports_status_idx" ON "reports"("status");

-- CreateIndex
CREATE INDEX "reports_createdAt_idx" ON "reports"("createdAt");

-- CreateIndex
CREATE INDEX "reports_updatedAt_idx" ON "reports"("updatedAt");

-- AddForeignKey
ALTER TABLE "assets" ADD CONSTRAINT "assets_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "assets" ADD CONSTRAINT "assets_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "timeline_events" ADD CONSTRAINT "timeline_events_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "timeline_events" ADD CONSTRAINT "timeline_events_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attack_graph_nodes" ADD CONSTRAINT "attack_graph_nodes_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attack_graph_nodes" ADD CONSTRAINT "attack_graph_nodes_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attack_graph_edges" ADD CONSTRAINT "attack_graph_edges_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attack_graph_edges" ADD CONSTRAINT "attack_graph_edges_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attack_graph_edges" ADD CONSTRAINT "attack_graph_edges_sourceNodeId_fkey" FOREIGN KEY ("sourceNodeId") REFERENCES "attack_graph_nodes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "attack_graph_edges" ADD CONSTRAINT "attack_graph_edges_targetNodeId_fkey" FOREIGN KEY ("targetNodeId") REFERENCES "attack_graph_nodes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notes" ADD CONSTRAINT "notes_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notes" ADD CONSTRAINT "notes_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "projects"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
