-- AlterEnum
ALTER TYPE "FeedbackVerdict" ADD VALUE 'accepted_risk';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "FindingStatus" ADD VALUE 'accepted_risk';
ALTER TYPE "FindingStatus" ADD VALUE 'suppressed';

-- AlterTable
ALTER TABLE "dependencies" ADD COLUMN     "exceptionId" UUID;

-- AlterTable
ALTER TABLE "finding_feedback" ADD COLUMN     "category" TEXT,
ADD COLUMN     "expiresAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "findings" ADD COLUMN     "assurance" TEXT,
ADD COLUMN     "confidence" TEXT,
ADD COLUMN     "details" JSONB,
ADD COLUMN     "exceptionId" UUID;

-- AlterTable
ALTER TABLE "pull_requests" ADD COLUMN     "baseBranch" TEXT;

-- CreateTable
CREATE TABLE "finding_exceptions" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "repositoryId" UUID,
    "orgWide" BOOLEAN NOT NULL DEFAULT false,
    "ruleId" TEXT,
    "pathGlob" TEXT,
    "riskType" TEXT,
    "dependency" TEXT,
    "dependencyVersion" TEXT,
    "branch" TEXT,
    "environment" TEXT,
    "reason" TEXT NOT NULL,
    "ticketUrl" TEXT,
    "requestedById" UUID NOT NULL,
    "approvedById" UUID,
    "approvedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "revokedById" UUID,
    "remindedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "finding_exceptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rule_feedback" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "ruleId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "note" TEXT,
    "findingId" UUID,
    "pullRequestId" UUID,
    "repositoryId" UUID,
    "language" TEXT,
    "filePath" TEXT,
    "fileType" TEXT,
    "userId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "rule_feedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "rule_settings" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "ruleId" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "setById" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "rule_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "block_contests" (
    "id" UUID NOT NULL,
    "pullRequestId" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "reason" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'open',
    "resolution" TEXT,
    "resolvedById" UUID,
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "block_contests_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "finding_exceptions_organizationId_idx" ON "finding_exceptions"("organizationId");

-- CreateIndex
CREATE INDEX "finding_exceptions_repositoryId_idx" ON "finding_exceptions"("repositoryId");

-- CreateIndex
CREATE INDEX "rule_feedback_organizationId_ruleId_idx" ON "rule_feedback"("organizationId", "ruleId");

-- CreateIndex
CREATE UNIQUE INDEX "rule_settings_organizationId_ruleId_key" ON "rule_settings"("organizationId", "ruleId");

-- CreateIndex
CREATE INDEX "block_contests_pullRequestId_idx" ON "block_contests"("pullRequestId");

-- AddForeignKey
ALTER TABLE "finding_exceptions" ADD CONSTRAINT "finding_exceptions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_exceptions" ADD CONSTRAINT "finding_exceptions_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rule_feedback" ADD CONSTRAINT "rule_feedback_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "rule_settings" ADD CONSTRAINT "rule_settings_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "block_contests" ADD CONSTRAINT "block_contests_pullRequestId_fkey" FOREIGN KEY ("pullRequestId") REFERENCES "pull_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

