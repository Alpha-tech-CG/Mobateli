-- AlterEnum
ALTER TYPE "InfraCategory" ADD VALUE 'secrets';
ALTER TYPE "InfraCategory" ADD VALUE 'network';
ALTER TYPE "InfraCategory" ADD VALUE 'admin';
ALTER TYPE "InfraCategory" ADD VALUE 'http';
ALTER TYPE "InfraCategory" ADD VALUE 'daemon';

-- AlterTable
ALTER TABLE "server_findings" ADD COLUMN "evidence" TEXT,
ADD COLUMN "verifyCommand" TEXT,
ADD COLUMN "exploitScenario" TEXT,
ADD COLUMN "exposure" TEXT;

-- AlterTable
ALTER TABLE "servers" ADD COLUMN "previousScore" INTEGER,
ADD COLUMN "analysis" JSONB,
ADD COLUMN "rescanRequestedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "server_risk_acceptances" (
    "id" UUID NOT NULL,
    "serverId" UUID NOT NULL,
    "checkId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "justification" TEXT NOT NULL,
    "acceptedById" UUID,
    "expiresAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "server_risk_acceptances_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "server_scans" (
    "id" UUID NOT NULL,
    "serverId" UUID NOT NULL,
    "score" INTEGER NOT NULL,
    "critical" INTEGER NOT NULL,
    "high" INTEGER NOT NULL,
    "total" INTEGER NOT NULL,
    "resolved" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "introduced" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "server_scans_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "server_risk_acceptances_serverId_checkId_key" ON "server_risk_acceptances"("serverId", "checkId");

-- CreateIndex
CREATE INDEX "server_scans_serverId_createdAt_idx" ON "server_scans"("serverId", "createdAt");

-- AddForeignKey
ALTER TABLE "server_risk_acceptances" ADD CONSTRAINT "server_risk_acceptances_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "server_scans" ADD CONSTRAINT "server_scans_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "servers"("id") ON DELETE CASCADE ON UPDATE CASCADE;
