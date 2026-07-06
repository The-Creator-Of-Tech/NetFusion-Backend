-- CreateEnum
CREATE TYPE "MitreTacticType" AS ENUM ('RECONNAISSANCE', 'RESOURCE_DEVELOPMENT', 'INITIAL_ACCESS', 'EXECUTION', 'PERSISTENCE', 'PRIVILEGE_ESCALATION', 'DEFENSE_EVASION', 'CREDENTIAL_ACCESS', 'DISCOVERY', 'LATERAL_MOVEMENT', 'COLLECTION', 'COMMAND_AND_CONTROL', 'EXFILTRATION', 'IMPACT');

-- CreateEnum
CREATE TYPE "CVESeverity" AS ENUM ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "IOCType" AS ENUM ('IP', 'DOMAIN', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256', 'EMAIL', 'FILE_PATH', 'MUTEX', 'REGISTRY_KEY');

-- CreateEnum
CREATE TYPE "IOCStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'FALSE_POSITIVE', 'SUSPICIOUS', 'REVOKED');

-- CreateEnum
CREATE TYPE "ThreatLevel" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "ThreatStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'MONITORED', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "CampaignStatus" AS ENUM ('ACTIVE', 'INACTIVE', 'COMPLETED', 'PAUSED');

-- CreateEnum
CREATE TYPE "RelationshipType" AS ENUM ('EXPLOITS', 'USES', 'ATTRIBUTED_TO', 'ASSOCIATED_WITH', 'TARGETS');

-- CreateTable
CREATE TABLE "mitre_tactics" (
    "id" UUID NOT NULL,
    "tacticKey" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "tacticType" "MitreTacticType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "mitre_tactics_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mitre_techniques" (
    "id" UUID NOT NULL,
    "tacticId" UUID,
    "mitreId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "detection" TEXT,
    "platforms" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "references" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "severity" "CVESeverity" NOT NULL DEFAULT 'MEDIUM',
    "dataSource" TEXT,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "mitre_techniques_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mitre_mitigations" (
    "id" UUID NOT NULL,
    "mitreId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "mitre_mitigations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cves" (
    "id" UUID NOT NULL,
    "cveId" TEXT NOT NULL,
    "description" TEXT,
    "severity" "CVESeverity" NOT NULL,
    "cvssScore" DOUBLE PRECISION NOT NULL,
    "publishedDate" TIMESTAMP(3),
    "modifiedDate" TIMESTAMP(3),
    "references" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "affectedPlatforms" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "exploited" BOOLEAN NOT NULL DEFAULT false,
    "patched" BOOLEAN NOT NULL DEFAULT false,
    "vendor" TEXT,
    "product" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "cves_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cvss_details" (
    "id" UUID NOT NULL,
    "cveId" UUID NOT NULL,
    "baseScore" DOUBLE PRECISION NOT NULL,
    "severity" "CVESeverity" NOT NULL,
    "vectorString" TEXT,
    "exploitabilityScore" DOUBLE PRECISION,
    "impactScore" DOUBLE PRECISION,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "cvss_details_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "affected_products" (
    "id" UUID NOT NULL,
    "cveId" UUID NOT NULL,
    "vendor" TEXT NOT NULL,
    "product" TEXT NOT NULL,
    "productVersion" TEXT,
    "patched" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "affected_products_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "iocs" (
    "id" UUID NOT NULL,
    "iocId" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "iocType" "IOCType" NOT NULL,
    "severity" "CVESeverity" NOT NULL,
    "status" "IOCStatus" NOT NULL DEFAULT 'ACTIVE',
    "confidence" TEXT NOT NULL,
    "description" TEXT,
    "source" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "malicious" BOOLEAN NOT NULL DEFAULT true,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "iocs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ioc_relationships" (
    "id" UUID NOT NULL,
    "iocId" UUID NOT NULL,
    "cveId" UUID,
    "mitreId" UUID,
    "threatId" UUID,
    "campaignId" UUID,
    "targetType" TEXT NOT NULL,
    "relationType" "RelationshipType" NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "ioc_relationships_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ioc_enrichments" (
    "id" UUID NOT NULL,
    "iocId" UUID NOT NULL,
    "reputationScore" INTEGER NOT NULL,
    "malicious" BOOLEAN NOT NULL,
    "categories" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "firstSeen" TIMESTAMP(3),
    "lastSeen" TIMESTAMP(3),
    "provider" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "ioc_enrichments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_actors" (
    "id" UUID NOT NULL,
    "threatId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "aliases" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "description" TEXT,
    "country" TEXT,
    "motivation" TEXT,
    "confidence" TEXT NOT NULL,
    "severity" "ThreatLevel" NOT NULL,
    "status" "ThreatStatus" NOT NULL DEFAULT 'ACTIVE',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "malware" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "industry" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "threat_actors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_campaigns" (
    "id" UUID NOT NULL,
    "campaignId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "startDate" TIMESTAMP(3),
    "endDate" TIMESTAMP(3),
    "confidence" TEXT NOT NULL,
    "status" "CampaignStatus" NOT NULL DEFAULT 'ACTIVE',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "threat_campaigns_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_relationships" (
    "id" UUID NOT NULL,
    "threatId" UUID,
    "campaignId" UUID,
    "cveId" UUID,
    "mitreId" UUID,
    "iocId" UUID,
    "targetCampaignId" UUID,
    "targetType" TEXT NOT NULL,
    "relationType" "RelationshipType" NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "updatedBy" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "metadata" JSONB,

    CONSTRAINT "threat_relationships_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_ActorTechniques" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_CampaignTechniques" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_TechniqueMitigations" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_CVETechniques" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_CVEIOCs" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_IOCTechniques" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_IOCActors" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_IOCCampaigns" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateTable
CREATE TABLE "_ActorCampaigns" (
    "A" UUID NOT NULL,
    "B" UUID NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "mitre_tactics_tacticKey_key" ON "mitre_tactics"("tacticKey");

-- CreateIndex
CREATE INDEX "mitre_tactics_createdAt_idx" ON "mitre_tactics"("createdAt");

-- CreateIndex
CREATE INDEX "mitre_tactics_updatedAt_idx" ON "mitre_tactics"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "mitre_techniques_mitreId_key" ON "mitre_techniques"("mitreId");

-- CreateIndex
CREATE INDEX "mitre_techniques_mitreId_idx" ON "mitre_techniques"("mitreId");

-- CreateIndex
CREATE INDEX "mitre_techniques_severity_idx" ON "mitre_techniques"("severity");

-- CreateIndex
CREATE INDEX "mitre_techniques_createdAt_idx" ON "mitre_techniques"("createdAt");

-- CreateIndex
CREATE INDEX "mitre_techniques_updatedAt_idx" ON "mitre_techniques"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "mitre_mitigations_mitreId_key" ON "mitre_mitigations"("mitreId");

-- CreateIndex
CREATE INDEX "mitre_mitigations_mitreId_idx" ON "mitre_mitigations"("mitreId");

-- CreateIndex
CREATE INDEX "mitre_mitigations_createdAt_idx" ON "mitre_mitigations"("createdAt");

-- CreateIndex
CREATE INDEX "mitre_mitigations_updatedAt_idx" ON "mitre_mitigations"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "cves_cveId_key" ON "cves"("cveId");

-- CreateIndex
CREATE INDEX "cves_cveId_idx" ON "cves"("cveId");

-- CreateIndex
CREATE INDEX "cves_severity_idx" ON "cves"("severity");

-- CreateIndex
CREATE INDEX "cves_createdAt_idx" ON "cves"("createdAt");

-- CreateIndex
CREATE INDEX "cves_updatedAt_idx" ON "cves"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "cvss_details_cveId_key" ON "cvss_details"("cveId");

-- CreateIndex
CREATE INDEX "cvss_details_cveId_idx" ON "cvss_details"("cveId");

-- CreateIndex
CREATE INDEX "cvss_details_severity_idx" ON "cvss_details"("severity");

-- CreateIndex
CREATE INDEX "cvss_details_createdAt_idx" ON "cvss_details"("createdAt");

-- CreateIndex
CREATE INDEX "cvss_details_updatedAt_idx" ON "cvss_details"("updatedAt");

-- CreateIndex
CREATE INDEX "affected_products_cveId_idx" ON "affected_products"("cveId");

-- CreateIndex
CREATE INDEX "affected_products_createdAt_idx" ON "affected_products"("createdAt");

-- CreateIndex
CREATE INDEX "affected_products_updatedAt_idx" ON "affected_products"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "iocs_iocId_key" ON "iocs"("iocId");

-- CreateIndex
CREATE INDEX "iocs_iocId_idx" ON "iocs"("iocId");

-- CreateIndex
CREATE INDEX "iocs_severity_idx" ON "iocs"("severity");

-- CreateIndex
CREATE INDEX "iocs_status_idx" ON "iocs"("status");

-- CreateIndex
CREATE INDEX "iocs_createdAt_idx" ON "iocs"("createdAt");

-- CreateIndex
CREATE INDEX "iocs_updatedAt_idx" ON "iocs"("updatedAt");

-- CreateIndex
CREATE INDEX "ioc_relationships_iocId_idx" ON "ioc_relationships"("iocId");

-- CreateIndex
CREATE INDEX "ioc_relationships_cveId_idx" ON "ioc_relationships"("cveId");

-- CreateIndex
CREATE INDEX "ioc_relationships_mitreId_idx" ON "ioc_relationships"("mitreId");

-- CreateIndex
CREATE INDEX "ioc_relationships_threatId_idx" ON "ioc_relationships"("threatId");

-- CreateIndex
CREATE INDEX "ioc_relationships_campaignId_idx" ON "ioc_relationships"("campaignId");

-- CreateIndex
CREATE INDEX "ioc_relationships_createdAt_idx" ON "ioc_relationships"("createdAt");

-- CreateIndex
CREATE INDEX "ioc_relationships_updatedAt_idx" ON "ioc_relationships"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ioc_enrichments_iocId_key" ON "ioc_enrichments"("iocId");

-- CreateIndex
CREATE INDEX "ioc_enrichments_iocId_idx" ON "ioc_enrichments"("iocId");

-- CreateIndex
CREATE INDEX "ioc_enrichments_createdAt_idx" ON "ioc_enrichments"("createdAt");

-- CreateIndex
CREATE INDEX "ioc_enrichments_updatedAt_idx" ON "ioc_enrichments"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "threat_actors_threatId_key" ON "threat_actors"("threatId");

-- CreateIndex
CREATE INDEX "threat_actors_threatId_idx" ON "threat_actors"("threatId");

-- CreateIndex
CREATE INDEX "threat_actors_severity_idx" ON "threat_actors"("severity");

-- CreateIndex
CREATE INDEX "threat_actors_status_idx" ON "threat_actors"("status");

-- CreateIndex
CREATE INDEX "threat_actors_createdAt_idx" ON "threat_actors"("createdAt");

-- CreateIndex
CREATE INDEX "threat_actors_updatedAt_idx" ON "threat_actors"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "threat_campaigns_campaignId_key" ON "threat_campaigns"("campaignId");

-- CreateIndex
CREATE INDEX "threat_campaigns_campaignId_idx" ON "threat_campaigns"("campaignId");

-- CreateIndex
CREATE INDEX "threat_campaigns_status_idx" ON "threat_campaigns"("status");

-- CreateIndex
CREATE INDEX "threat_campaigns_createdAt_idx" ON "threat_campaigns"("createdAt");

-- CreateIndex
CREATE INDEX "threat_campaigns_updatedAt_idx" ON "threat_campaigns"("updatedAt");

-- CreateIndex
CREATE INDEX "threat_relationships_threatId_idx" ON "threat_relationships"("threatId");

-- CreateIndex
CREATE INDEX "threat_relationships_campaignId_idx" ON "threat_relationships"("campaignId");

-- CreateIndex
CREATE INDEX "threat_relationships_cveId_idx" ON "threat_relationships"("cveId");

-- CreateIndex
CREATE INDEX "threat_relationships_mitreId_idx" ON "threat_relationships"("mitreId");

-- CreateIndex
CREATE INDEX "threat_relationships_iocId_idx" ON "threat_relationships"("iocId");

-- CreateIndex
CREATE INDEX "threat_relationships_createdAt_idx" ON "threat_relationships"("createdAt");

-- CreateIndex
CREATE INDEX "threat_relationships_updatedAt_idx" ON "threat_relationships"("updatedAt");

-- CreateIndex
CREATE UNIQUE INDEX "_ActorTechniques_AB_unique" ON "_ActorTechniques"("A", "B");

-- CreateIndex
CREATE INDEX "_ActorTechniques_B_index" ON "_ActorTechniques"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_CampaignTechniques_AB_unique" ON "_CampaignTechniques"("A", "B");

-- CreateIndex
CREATE INDEX "_CampaignTechniques_B_index" ON "_CampaignTechniques"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_TechniqueMitigations_AB_unique" ON "_TechniqueMitigations"("A", "B");

-- CreateIndex
CREATE INDEX "_TechniqueMitigations_B_index" ON "_TechniqueMitigations"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_CVETechniques_AB_unique" ON "_CVETechniques"("A", "B");

-- CreateIndex
CREATE INDEX "_CVETechniques_B_index" ON "_CVETechniques"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_CVEIOCs_AB_unique" ON "_CVEIOCs"("A", "B");

-- CreateIndex
CREATE INDEX "_CVEIOCs_B_index" ON "_CVEIOCs"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_IOCTechniques_AB_unique" ON "_IOCTechniques"("A", "B");

-- CreateIndex
CREATE INDEX "_IOCTechniques_B_index" ON "_IOCTechniques"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_IOCActors_AB_unique" ON "_IOCActors"("A", "B");

-- CreateIndex
CREATE INDEX "_IOCActors_B_index" ON "_IOCActors"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_IOCCampaigns_AB_unique" ON "_IOCCampaigns"("A", "B");

-- CreateIndex
CREATE INDEX "_IOCCampaigns_B_index" ON "_IOCCampaigns"("B");

-- CreateIndex
CREATE UNIQUE INDEX "_ActorCampaigns_AB_unique" ON "_ActorCampaigns"("A", "B");

-- CreateIndex
CREATE INDEX "_ActorCampaigns_B_index" ON "_ActorCampaigns"("B");

-- AddForeignKey
ALTER TABLE "mitre_techniques" ADD CONSTRAINT "mitre_techniques_tacticId_fkey" FOREIGN KEY ("tacticId") REFERENCES "mitre_tactics"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cvss_details" ADD CONSTRAINT "cvss_details_cveId_fkey" FOREIGN KEY ("cveId") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_cveId_fkey" FOREIGN KEY ("cveId") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_relationships" ADD CONSTRAINT "ioc_relationships_iocId_fkey" FOREIGN KEY ("iocId") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_relationships" ADD CONSTRAINT "ioc_relationships_cveId_fkey" FOREIGN KEY ("cveId") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_relationships" ADD CONSTRAINT "ioc_relationships_mitreId_fkey" FOREIGN KEY ("mitreId") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_relationships" ADD CONSTRAINT "ioc_relationships_threatId_fkey" FOREIGN KEY ("threatId") REFERENCES "threat_actors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_relationships" ADD CONSTRAINT "ioc_relationships_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "threat_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_enrichments" ADD CONSTRAINT "ioc_enrichments_iocId_fkey" FOREIGN KEY ("iocId") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_relationships" ADD CONSTRAINT "threat_relationships_threatId_fkey" FOREIGN KEY ("threatId") REFERENCES "threat_actors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_relationships" ADD CONSTRAINT "threat_relationships_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "threat_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_relationships" ADD CONSTRAINT "threat_relationships_cveId_fkey" FOREIGN KEY ("cveId") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_relationships" ADD CONSTRAINT "threat_relationships_mitreId_fkey" FOREIGN KEY ("mitreId") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_relationships" ADD CONSTRAINT "threat_relationships_iocId_fkey" FOREIGN KEY ("iocId") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_relationships" ADD CONSTRAINT "threat_relationships_targetCampaignId_fkey" FOREIGN KEY ("targetCampaignId") REFERENCES "threat_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ActorTechniques" ADD CONSTRAINT "_ActorTechniques_A_fkey" FOREIGN KEY ("A") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ActorTechniques" ADD CONSTRAINT "_ActorTechniques_B_fkey" FOREIGN KEY ("B") REFERENCES "threat_actors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CampaignTechniques" ADD CONSTRAINT "_CampaignTechniques_A_fkey" FOREIGN KEY ("A") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CampaignTechniques" ADD CONSTRAINT "_CampaignTechniques_B_fkey" FOREIGN KEY ("B") REFERENCES "threat_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_TechniqueMitigations" ADD CONSTRAINT "_TechniqueMitigations_A_fkey" FOREIGN KEY ("A") REFERENCES "mitre_mitigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_TechniqueMitigations" ADD CONSTRAINT "_TechniqueMitigations_B_fkey" FOREIGN KEY ("B") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CVETechniques" ADD CONSTRAINT "_CVETechniques_A_fkey" FOREIGN KEY ("A") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CVETechniques" ADD CONSTRAINT "_CVETechniques_B_fkey" FOREIGN KEY ("B") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CVEIOCs" ADD CONSTRAINT "_CVEIOCs_A_fkey" FOREIGN KEY ("A") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_CVEIOCs" ADD CONSTRAINT "_CVEIOCs_B_fkey" FOREIGN KEY ("B") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_IOCTechniques" ADD CONSTRAINT "_IOCTechniques_A_fkey" FOREIGN KEY ("A") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_IOCTechniques" ADD CONSTRAINT "_IOCTechniques_B_fkey" FOREIGN KEY ("B") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_IOCActors" ADD CONSTRAINT "_IOCActors_A_fkey" FOREIGN KEY ("A") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_IOCActors" ADD CONSTRAINT "_IOCActors_B_fkey" FOREIGN KEY ("B") REFERENCES "threat_actors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_IOCCampaigns" ADD CONSTRAINT "_IOCCampaigns_A_fkey" FOREIGN KEY ("A") REFERENCES "iocs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_IOCCampaigns" ADD CONSTRAINT "_IOCCampaigns_B_fkey" FOREIGN KEY ("B") REFERENCES "threat_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ActorCampaigns" ADD CONSTRAINT "_ActorCampaigns_A_fkey" FOREIGN KEY ("A") REFERENCES "threat_actors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_ActorCampaigns" ADD CONSTRAINT "_ActorCampaigns_B_fkey" FOREIGN KEY ("B") REFERENCES "threat_campaigns"("id") ON DELETE CASCADE ON UPDATE CASCADE;
