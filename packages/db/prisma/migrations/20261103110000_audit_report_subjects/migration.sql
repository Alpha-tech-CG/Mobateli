-- AlterTable
ALTER TABLE "audit_reports" ADD COLUMN "kind" TEXT NOT NULL DEFAULT 'organization',
ADD COLUMN "subjectId" UUID,
ADD COLUMN "subjectLabel" TEXT;

-- CreateIndex
CREATE INDEX "audit_reports_subjectId_idx" ON "audit_reports"("subjectId");
