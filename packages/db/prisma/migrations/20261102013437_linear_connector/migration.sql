-- CreateTable
CREATE TABLE "linear_connections" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "apiKeyEncrypted" TEXT NOT NULL,
    "teamId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "linear_connections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remediation_issues" (
    "id" UUID NOT NULL,
    "pullRequestId" UUID NOT NULL,
    "provider" TEXT NOT NULL DEFAULT 'linear',
    "externalId" TEXT NOT NULL,
    "identifier" TEXT,
    "url" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "remediation_issues_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "linear_connections_organizationId_key" ON "linear_connections"("organizationId");

-- CreateIndex
CREATE INDEX "remediation_issues_pullRequestId_idx" ON "remediation_issues"("pullRequestId");

-- CreateIndex
CREATE UNIQUE INDEX "remediation_issues_pullRequestId_provider_key" ON "remediation_issues"("pullRequestId", "provider");

-- AddForeignKey
ALTER TABLE "linear_connections" ADD CONSTRAINT "linear_connections_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_issues" ADD CONSTRAINT "remediation_issues_pullRequestId_fkey" FOREIGN KEY ("pullRequestId") REFERENCES "pull_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;
