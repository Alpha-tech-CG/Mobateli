-- AlterEnum
ALTER TYPE "InfraCategory" ADD VALUE 'backups';

-- CreateTable
CREATE TABLE "backup_jobs" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "serverId" UUID,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "frequencyHours" INTEGER NOT NULL DEFAULT 24,
    "tokenHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "backup_jobs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_runs" (
    "id" UUID NOT NULL,
    "jobId" UUID NOT NULL,
    "finishedAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL,
    "sizeBytes" DOUBLE PRECISION,
    "durationSeconds" INTEGER,
    "sha256" TEXT,
    "encrypted" BOOLEAN NOT NULL,
    "encryptionAlgorithm" TEXT,
    "inTransit" TEXT,
    "keyLocation" TEXT NOT NULL DEFAULT 'unknown',
    "signed" BOOLEAN NOT NULL DEFAULT false,
    "storageProvider" TEXT,
    "storageLocation" TEXT NOT NULL DEFAULT 'unknown',
    "immutable" BOOLEAN,
    "versioning" BOOLEAN,
    "separateAccount" BOOLEAN,
    "retentionDays" INTEGER,
    "integrityCheckedAt" TIMESTAMP(3),
    "integrityOk" BOOLEAN,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "backup_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "backup_restore_tests" (
    "id" UUID NOT NULL,
    "jobId" UUID NOT NULL,
    "engine" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3) NOT NULL,
    "durationSeconds" INTEGER NOT NULL,
    "result" TEXT NOT NULL,
    "restoredTables" INTEGER,
    "restoredRecords" DOUBLE PRECISION,
    "detail" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "backup_restore_tests_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "backup_jobs_tokenHash_key" ON "backup_jobs"("tokenHash");

-- CreateIndex
CREATE INDEX "backup_jobs_organizationId_idx" ON "backup_jobs"("organizationId");

-- CreateIndex
CREATE INDEX "backup_runs_jobId_finishedAt_idx" ON "backup_runs"("jobId", "finishedAt");

-- CreateIndex
CREATE INDEX "backup_restore_tests_jobId_completedAt_idx" ON "backup_restore_tests"("jobId", "completedAt");

-- AddForeignKey
ALTER TABLE "backup_jobs" ADD CONSTRAINT "backup_jobs_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_jobs" ADD CONSTRAINT "backup_jobs_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "servers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_runs" ADD CONSTRAINT "backup_runs_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "backup_jobs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "backup_restore_tests" ADD CONSTRAINT "backup_restore_tests_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "backup_jobs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
