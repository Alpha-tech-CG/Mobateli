-- CreateEnum
CREATE TYPE "InfraCategory" AS ENUM ('ports', 'ssh', 'firewall', 'bruteforce', 'docker', 'updates');

-- CreateTable
CREATE TABLE "servers" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "provider" TEXT,
    "environment" TEXT NOT NULL DEFAULT 'production',
    "agentTokenHash" TEXT NOT NULL,
    "hostname" TEXT,
    "os" TEXT,
    "agentVersion" TEXT,
    "securityScore" INTEGER,
    "lastReport" JSONB,
    "lastReportAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "servers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "server_findings" (
    "id" UUID NOT NULL,
    "serverId" UUID NOT NULL,
    "category" "InfraCategory" NOT NULL,
    "checkId" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" TEXT NOT NULL,
    "detail" TEXT NOT NULL,
    "recommendation" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "server_findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "servers_agentTokenHash_key" ON "servers"("agentTokenHash");

-- CreateIndex
CREATE INDEX "servers_organizationId_idx" ON "servers"("organizationId");

-- CreateIndex
CREATE INDEX "server_findings_serverId_idx" ON "server_findings"("serverId");

-- AddForeignKey
ALTER TABLE "servers" ADD CONSTRAINT "servers_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "server_findings" ADD CONSTRAINT "server_findings_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;
