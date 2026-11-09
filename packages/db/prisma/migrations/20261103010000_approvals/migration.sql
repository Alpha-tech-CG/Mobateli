-- CreateTable
CREATE TABLE "approval_requests" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "repositoryId" UUID,
    "kind" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "detail" JSONB NOT NULL,
    "dedupeKey" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "requestedById" UUID,
    "decidedById" UUID,
    "decidedAt" TIMESTAMP(3),
    "reason" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "approval_requests_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "approval_requests_organizationId_status_idx" ON "approval_requests"("organizationId", "status");

-- CreateIndex
CREATE INDEX "approval_requests_dedupeKey_idx" ON "approval_requests"("dedupeKey");

-- AddForeignKey
ALTER TABLE "approval_requests" ADD CONSTRAINT "approval_requests_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AlterTable
ALTER TABLE "gitlab_connections" ADD COLUMN "baseUrl" TEXT NOT NULL DEFAULT 'https://gitlab.com',
ADD COLUMN "apiTokenEncrypted" TEXT;
