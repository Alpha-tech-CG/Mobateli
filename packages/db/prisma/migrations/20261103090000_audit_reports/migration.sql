-- CreateTable
CREATE TABLE "audit_reports" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "generatedById" UUID,
    "sha256" TEXT NOT NULL,
    "signerFingerprint" TEXT NOT NULL,
    "filters" JSONB NOT NULL,
    "summary" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_reports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "audit_reports_organizationId_createdAt_idx" ON "audit_reports"("organizationId", "createdAt");

-- AddForeignKey
ALTER TABLE "audit_reports" ADD CONSTRAINT "audit_reports_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
