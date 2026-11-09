-- AlterTable
ALTER TABLE "secret_findings" ADD COLUMN "severity" "Severity" NOT NULL DEFAULT 'high';

-- CreateTable
CREATE TABLE "finding_suppressions" (
    "id" UUID NOT NULL,
    "repositoryId" UUID NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "reason" TEXT,
    "createdById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "finding_suppressions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "finding_suppressions_repositoryId_fingerprint_key" ON "finding_suppressions"("repositoryId", "fingerprint");

-- AddForeignKey
ALTER TABLE "finding_suppressions" ADD CONSTRAINT "finding_suppressions_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;
