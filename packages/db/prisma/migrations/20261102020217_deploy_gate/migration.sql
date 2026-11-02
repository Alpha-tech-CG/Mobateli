-- CreateEnum
CREATE TYPE "DeployDecision" AS ENUM ('authorized', 'warning', 'blocked', 'requires_approval');

-- CreateTable
CREATE TABLE "deploy_checks" (
    "id" UUID NOT NULL,
    "repositoryId" UUID NOT NULL,
    "externalId" TEXT NOT NULL,
    "provider" TEXT NOT NULL DEFAULT 'vercel',
    "target" TEXT,
    "commitSha" TEXT,
    "decision" "DeployDecision" NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "deploy_checks_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "deploy_checks_repositoryId_idx" ON "deploy_checks"("repositoryId");

-- CreateIndex
CREATE UNIQUE INDEX "deploy_checks_provider_externalId_key" ON "deploy_checks"("provider", "externalId");

-- AddForeignKey
ALTER TABLE "deploy_checks" ADD CONSTRAINT "deploy_checks_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;
