-- CreateTable
CREATE TABLE "Asset" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "deviceType" TEXT,
    "vendor" TEXT,
    "os" TEXT,
    "osVersion" TEXT,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" REAL NOT NULL DEFAULT 0.0,
    "riskScore" REAL NOT NULL DEFAULT 0.0,
    "isManaged" BOOLEAN NOT NULL DEFAULT false,
    "notes" TEXT,
    "metadata" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "AssetHostname" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "confidence" REAL NOT NULL DEFAULT 1.0,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT,
    CONSTRAINT "AssetHostname_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetIPAddress" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "isCurrent" BOOLEAN NOT NULL DEFAULT true,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT,
    CONSTRAINT "AssetIPAddress_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetMAC" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "macAddress" TEXT NOT NULL,
    "isCurrent" BOOLEAN NOT NULL DEFAULT true,
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "vendor" TEXT,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT,
    CONSTRAINT "AssetMAC_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetSSID" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "ssid" TEXT NOT NULL,
    "isCurrent" BOOLEAN NOT NULL DEFAULT true,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT,
    CONSTRAINT "AssetSSID_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetPort" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "protocol" TEXT NOT NULL DEFAULT 'tcp',
    "service" TEXT,
    "state" TEXT NOT NULL DEFAULT 'open',
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AssetPort_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetService" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "protocol" TEXT,
    "port" INTEGER,
    "confidence" REAL NOT NULL DEFAULT 1.0,
    CONSTRAINT "AssetService_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetTag" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "tag" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AssetTag_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetFieldEvidence" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "fieldName" TEXT NOT NULL,
    "fieldValue" TEXT NOT NULL,
    "confidence" REAL NOT NULL DEFAULT 1.0,
    "sourceType" TEXT,
    "sourceId" TEXT,
    "packetNumber" INTEGER,
    "captureId" TEXT,
    "observedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" TEXT,
    CONSTRAINT "AssetFieldEvidence_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AssetRelationship" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "sourceId" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "relationshipType" TEXT NOT NULL,
    "confidence" REAL NOT NULL DEFAULT 1.0,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" TEXT,
    CONSTRAINT "AssetRelationship_sourceId_fkey" FOREIGN KEY ("sourceId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AssetRelationship_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "Relationship" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "sourceAssetId" TEXT NOT NULL,
    "targetAssetId" TEXT NOT NULL,
    "relationshipType" TEXT NOT NULL,
    "protocol" TEXT NOT NULL,
    "port" INTEGER,
    "direction" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "state" TEXT NOT NULL DEFAULT 'NEW',
    "relationshipKey" TEXT,
    "packetCount" INTEGER NOT NULL DEFAULT 0,
    "byteCount" INTEGER NOT NULL DEFAULT 0,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confidence" REAL NOT NULL DEFAULT 0.0,
    "lastEvidenceId" TEXT,
    "engineVersion" TEXT,
    "metadata" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "RelationshipEvidence" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "relationshipId" TEXT NOT NULL,
    "evidenceId" TEXT NOT NULL,
    "captureId" TEXT,
    "packetNumber" INTEGER,
    "sourceType" TEXT,
    "observedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "RelationshipEvidence_relationshipId_fkey" FOREIGN KEY ("relationshipId") REFERENCES "Relationship" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "RelationshipHistory" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "relationshipId" TEXT NOT NULL,
    "relationshipKey" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "sourceAssetId" TEXT NOT NULL,
    "targetAssetId" TEXT NOT NULL,
    "relationshipType" TEXT NOT NULL,
    "protocol" TEXT NOT NULL,
    "port" INTEGER,
    "eventType" TEXT NOT NULL,
    "changedFields" TEXT NOT NULL,
    "changeReason" TEXT NOT NULL,
    "previousSnapshot" TEXT,
    "currentSnapshot" TEXT NOT NULL,
    "sequenceNumber" INTEGER NOT NULL DEFAULT 0,
    "parentEventId" TEXT,
    "occurredAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "summary" TEXT,
    "engineVersion" TEXT,
    "metadata" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "Asset_projectId_idx" ON "Asset"("projectId");

-- CreateIndex
CREATE INDEX "Asset_riskScore_idx" ON "Asset"("riskScore");

-- CreateIndex
CREATE INDEX "Asset_lastSeen_idx" ON "Asset"("lastSeen");

-- CreateIndex
CREATE INDEX "Asset_projectId_lastSeen_idx" ON "Asset"("projectId", "lastSeen");

-- CreateIndex
CREATE INDEX "Asset_projectId_riskScore_idx" ON "Asset"("projectId", "riskScore");

-- CreateIndex
CREATE INDEX "AssetHostname_assetId_idx" ON "AssetHostname"("assetId");

-- CreateIndex
CREATE INDEX "AssetHostname_hostname_idx" ON "AssetHostname"("hostname");

-- CreateIndex
CREATE UNIQUE INDEX "AssetHostname_assetId_hostname_key" ON "AssetHostname"("assetId", "hostname");

-- CreateIndex
CREATE INDEX "AssetIPAddress_assetId_idx" ON "AssetIPAddress"("assetId");

-- CreateIndex
CREATE INDEX "AssetIPAddress_ipAddress_idx" ON "AssetIPAddress"("ipAddress");

-- CreateIndex
CREATE INDEX "AssetIPAddress_isCurrent_idx" ON "AssetIPAddress"("isCurrent");

-- CreateIndex
CREATE UNIQUE INDEX "AssetIPAddress_assetId_ipAddress_key" ON "AssetIPAddress"("assetId", "ipAddress");

-- CreateIndex
CREATE INDEX "AssetMAC_assetId_idx" ON "AssetMAC"("assetId");

-- CreateIndex
CREATE INDEX "AssetMAC_macAddress_idx" ON "AssetMAC"("macAddress");

-- CreateIndex
CREATE INDEX "AssetMAC_isCurrent_idx" ON "AssetMAC"("isCurrent");

-- CreateIndex
CREATE UNIQUE INDEX "AssetMAC_assetId_macAddress_key" ON "AssetMAC"("assetId", "macAddress");

-- CreateIndex
CREATE INDEX "AssetSSID_assetId_idx" ON "AssetSSID"("assetId");

-- CreateIndex
CREATE INDEX "AssetSSID_ssid_idx" ON "AssetSSID"("ssid");

-- CreateIndex
CREATE UNIQUE INDEX "AssetSSID_assetId_ssid_key" ON "AssetSSID"("assetId", "ssid");

-- CreateIndex
CREATE INDEX "AssetPort_assetId_idx" ON "AssetPort"("assetId");

-- CreateIndex
CREATE INDEX "AssetPort_port_idx" ON "AssetPort"("port");

-- CreateIndex
CREATE INDEX "AssetPort_protocol_idx" ON "AssetPort"("protocol");

-- CreateIndex
CREATE INDEX "AssetPort_state_idx" ON "AssetPort"("state");

-- CreateIndex
CREATE UNIQUE INDEX "AssetPort_assetId_port_protocol_key" ON "AssetPort"("assetId", "port", "protocol");

-- CreateIndex
CREATE INDEX "AssetService_assetId_idx" ON "AssetService"("assetId");

-- CreateIndex
CREATE INDEX "AssetService_name_idx" ON "AssetService"("name");

-- CreateIndex
CREATE INDEX "AssetService_port_idx" ON "AssetService"("port");

-- CreateIndex
CREATE INDEX "AssetTag_assetId_idx" ON "AssetTag"("assetId");

-- CreateIndex
CREATE INDEX "AssetTag_tag_idx" ON "AssetTag"("tag");

-- CreateIndex
CREATE UNIQUE INDEX "AssetTag_assetId_tag_key" ON "AssetTag"("assetId", "tag");

-- CreateIndex
CREATE INDEX "AssetFieldEvidence_assetId_idx" ON "AssetFieldEvidence"("assetId");

-- CreateIndex
CREATE INDEX "AssetFieldEvidence_assetId_fieldName_idx" ON "AssetFieldEvidence"("assetId", "fieldName");

-- CreateIndex
CREATE INDEX "AssetFieldEvidence_fieldName_idx" ON "AssetFieldEvidence"("fieldName");

-- CreateIndex
CREATE INDEX "AssetFieldEvidence_captureId_idx" ON "AssetFieldEvidence"("captureId");

-- CreateIndex
CREATE INDEX "AssetFieldEvidence_sourceType_sourceId_idx" ON "AssetFieldEvidence"("sourceType", "sourceId");

-- CreateIndex
CREATE INDEX "AssetFieldEvidence_observedAt_idx" ON "AssetFieldEvidence"("observedAt");

-- CreateIndex
CREATE INDEX "AssetRelationship_sourceId_idx" ON "AssetRelationship"("sourceId");

-- CreateIndex
CREATE INDEX "AssetRelationship_targetId_idx" ON "AssetRelationship"("targetId");

-- CreateIndex
CREATE INDEX "AssetRelationship_relationshipType_idx" ON "AssetRelationship"("relationshipType");

-- CreateIndex
CREATE UNIQUE INDEX "AssetRelationship_sourceId_targetId_relationshipType_key" ON "AssetRelationship"("sourceId", "targetId", "relationshipType");

-- CreateIndex
CREATE UNIQUE INDEX "Relationship_relationshipKey_key" ON "Relationship"("relationshipKey");

-- CreateIndex
CREATE INDEX "Relationship_projectId_idx" ON "Relationship"("projectId");

-- CreateIndex
CREATE INDEX "Relationship_sourceAssetId_idx" ON "Relationship"("sourceAssetId");

-- CreateIndex
CREATE INDEX "Relationship_targetAssetId_idx" ON "Relationship"("targetAssetId");

-- CreateIndex
CREATE INDEX "Relationship_projectId_sourceAssetId_idx" ON "Relationship"("projectId", "sourceAssetId");

-- CreateIndex
CREATE INDEX "Relationship_projectId_targetAssetId_idx" ON "Relationship"("projectId", "targetAssetId");

-- CreateIndex
CREATE INDEX "Relationship_relationshipType_idx" ON "Relationship"("relationshipType");

-- CreateIndex
CREATE INDEX "Relationship_state_idx" ON "Relationship"("state");

-- CreateIndex
CREATE INDEX "Relationship_lastSeen_idx" ON "Relationship"("lastSeen");

-- CreateIndex
CREATE INDEX "Relationship_projectId_lastSeen_idx" ON "Relationship"("projectId", "lastSeen");

-- CreateIndex
CREATE UNIQUE INDEX "Relationship_projectId_sourceAssetId_targetAssetId_relationshipType_protocol_port_key" ON "Relationship"("projectId", "sourceAssetId", "targetAssetId", "relationshipType", "protocol", "port");

-- CreateIndex
CREATE INDEX "RelationshipEvidence_relationshipId_idx" ON "RelationshipEvidence"("relationshipId");

-- CreateIndex
CREATE INDEX "RelationshipEvidence_evidenceId_idx" ON "RelationshipEvidence"("evidenceId");

-- CreateIndex
CREATE INDEX "RelationshipEvidence_captureId_idx" ON "RelationshipEvidence"("captureId");

-- CreateIndex
CREATE INDEX "RelationshipEvidence_observedAt_idx" ON "RelationshipEvidence"("observedAt");

-- CreateIndex
CREATE UNIQUE INDEX "RelationshipEvidence_relationshipId_evidenceId_key" ON "RelationshipEvidence"("relationshipId", "evidenceId");

-- CreateIndex
CREATE INDEX "RelationshipHistory_relationshipId_idx" ON "RelationshipHistory"("relationshipId");

-- CreateIndex
CREATE INDEX "RelationshipHistory_relationshipKey_idx" ON "RelationshipHistory"("relationshipKey");

-- CreateIndex
CREATE INDEX "RelationshipHistory_projectId_idx" ON "RelationshipHistory"("projectId");

-- CreateIndex
CREATE INDEX "RelationshipHistory_sourceAssetId_idx" ON "RelationshipHistory"("sourceAssetId");

-- CreateIndex
CREATE INDEX "RelationshipHistory_targetAssetId_idx" ON "RelationshipHistory"("targetAssetId");

-- CreateIndex
CREATE INDEX "RelationshipHistory_eventType_idx" ON "RelationshipHistory"("eventType");

-- CreateIndex
CREATE INDEX "RelationshipHistory_changeReason_idx" ON "RelationshipHistory"("changeReason");

-- CreateIndex
CREATE INDEX "RelationshipHistory_occurredAt_idx" ON "RelationshipHistory"("occurredAt");

-- CreateIndex
CREATE INDEX "RelationshipHistory_projectId_occurredAt_idx" ON "RelationshipHistory"("projectId", "occurredAt");

-- CreateIndex
CREATE INDEX "RelationshipHistory_relationshipId_occurredAt_idx" ON "RelationshipHistory"("relationshipId", "occurredAt");

-- CreateIndex
CREATE UNIQUE INDEX "RelationshipHistory_relationshipId_eventType_occurredAt_key" ON "RelationshipHistory"("relationshipId", "eventType", "occurredAt");
