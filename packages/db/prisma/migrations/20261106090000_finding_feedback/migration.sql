-- CreateEnum
CREATE TYPE "FeedbackVerdict" AS ENUM ('false_positive', 'confirmed');

-- AlterTable
ALTER TABLE "findings" ADD COLUMN "fingerprint" TEXT;

-- CreateIndex
CREATE INDEX "findings_fingerprint_idx" ON "findings"("fingerprint");

-- CreateTable
CREATE TABLE "finding_feedback" (
    "id" UUID NOT NULL,
    "repositoryId" UUID NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "ruleId" TEXT,
    "filePath" TEXT,
    "verdict" "FeedbackVerdict" NOT NULL,
    "note" TEXT,
    "userId" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "finding_feedback_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "finding_feedback_repositoryId_fingerprint_key" ON "finding_feedback"("repositoryId", "fingerprint");

-- CreateIndex
CREATE INDEX "finding_feedback_repositoryId_ruleId_idx" ON "finding_feedback"("repositoryId", "ruleId");

-- AddForeignKey
ALTER TABLE "finding_feedback" ADD CONSTRAINT "finding_feedback_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;
