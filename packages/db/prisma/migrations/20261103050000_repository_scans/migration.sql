-- AlterTable
ALTER TABLE "repositories" ADD COLUMN "autoScan" BOOLEAN NOT NULL DEFAULT true;

-- CreateTable
CREATE TABLE "repository_scans" (
    "id" UUID NOT NULL,
    "repositoryId" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "trigger" TEXT NOT NULL DEFAULT 'manual',
    "status" TEXT NOT NULL DEFAULT 'queued',
    "phase" TEXT,
    "ref" TEXT,
    "commitSha" TEXT,
    "filesScanned" INTEGER NOT NULL DEFAULT 0,
    "riskScore" INTEGER,
    "decision" TEXT,
    "summary" JSONB,
    "result" JSONB,
    "error" TEXT,
    "requestedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),

    CONSTRAINT "repository_scans_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "repository_scans_repositoryId_createdAt_idx" ON "repository_scans"("repositoryId", "createdAt");

-- CreateIndex
CREATE INDEX "repository_scans_organizationId_createdAt_idx" ON "repository_scans"("organizationId", "createdAt");

-- AddForeignKey
ALTER TABLE "repository_scans" ADD CONSTRAINT "repository_scans_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;
