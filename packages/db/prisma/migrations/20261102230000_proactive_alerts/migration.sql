-- AlterEnum
ALTER TYPE "InfraCategory" ADD VALUE 'tls';

-- AlterTable
ALTER TABLE "servers" ADD COLUMN "silentAlertedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "backup_jobs" ADD COLUMN "lateAlertedAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "linear_connections" ADD COLUMN "webhookSecretEncrypted" TEXT;

-- AlterTable
ALTER TABLE "remediation_issues" ADD COLUMN "status" TEXT NOT NULL DEFAULT 'open',
ADD COLUMN "closedAt" TIMESTAMP(3);
