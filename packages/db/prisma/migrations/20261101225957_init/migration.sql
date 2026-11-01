-- CreateEnum
CREATE TYPE "Role" AS ENUM ('owner', 'admin', 'security_manager', 'developer', 'auditor', 'viewer');

-- CreateEnum
CREATE TYPE "ScmProvider" AS ENUM ('github', 'gitlab');

-- CreateEnum
CREATE TYPE "ProtectionLevel" AS ENUM ('observe', 'warn', 'block');

-- CreateEnum
CREATE TYPE "PullRequestStatus" AS ENUM ('pending', 'analyzing', 'passed', 'warning', 'blocked', 'escalated');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('info', 'low', 'medium', 'high', 'critical');

-- CreateEnum
CREATE TYPE "FindingType" AS ENUM ('secret', 'dependency', 'sast', 'config', 'auth', 'prompt_injection');

-- CreateEnum
CREATE TYPE "FindingStatus" AS ENUM ('open', 'acknowledged', 'resolved', 'false_positive');

-- CreateEnum
CREATE TYPE "DependencyRisk" AS ENUM ('low', 'medium', 'high', 'critical');

-- CreateEnum
CREATE TYPE "PolicyAction" AS ENUM ('allow', 'warn', 'block', 'require_approval');

-- CreateEnum
CREATE TYPE "ActorType" AS ENUM ('user', 'ai_agent', 'system');

-- CreateTable
CREATE TABLE "organizations" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "plan" TEXT NOT NULL DEFAULT 'free',
    "region" TEXT NOT NULL DEFAULT 'eu',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'developer',
    "mfaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "mfaSecret" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "repositories" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "provider" "ScmProvider" NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "defaultBranch" TEXT NOT NULL DEFAULT 'main',
    "protectionLevel" "ProtectionLevel" NOT NULL DEFAULT 'observe',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "repositories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pull_requests" (
    "id" UUID NOT NULL,
    "repositoryId" UUID NOT NULL,
    "externalId" TEXT NOT NULL,
    "number" INTEGER NOT NULL,
    "title" TEXT NOT NULL,
    "author" TEXT NOT NULL,
    "aiGenerated" BOOLEAN NOT NULL DEFAULT false,
    "riskScore" INTEGER,
    "status" "PullRequestStatus" NOT NULL DEFAULT 'pending',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "pull_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL,
    "pullRequestId" UUID NOT NULL,
    "type" "FindingType" NOT NULL,
    "severity" "Severity" NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "filePath" TEXT,
    "line" INTEGER,
    "ruleId" TEXT,
    "remediation" TEXT,
    "status" "FindingStatus" NOT NULL DEFAULT 'open',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dependencies" (
    "id" UUID NOT NULL,
    "pullRequestId" UUID NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT NOT NULL,
    "trustScore" INTEGER,
    "riskLevel" "DependencyRisk" NOT NULL DEFAULT 'low',
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dependencies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "secret_findings" (
    "id" UUID NOT NULL,
    "pullRequestId" UUID NOT NULL,
    "secretType" TEXT NOT NULL,
    "location" TEXT NOT NULL,
    "maskedPreview" TEXT NOT NULL,
    "status" "FindingStatus" NOT NULL DEFAULT 'open',
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "secret_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "policies" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "repositoryId" UUID,
    "rule" TEXT NOT NULL,
    "action" "PolicyAction" NOT NULL,
    "severityThreshold" "Severity" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "actorType" "ActorType" NOT NULL,
    "actorId" TEXT,
    "action" TEXT NOT NULL,
    "resourceType" TEXT NOT NULL,
    "resourceId" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "users_organizationId_idx" ON "users"("organizationId");

-- CreateIndex
CREATE INDEX "repositories_organizationId_idx" ON "repositories"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "repositories_provider_externalId_key" ON "repositories"("provider", "externalId");

-- CreateIndex
CREATE INDEX "pull_requests_repositoryId_idx" ON "pull_requests"("repositoryId");

-- CreateIndex
CREATE UNIQUE INDEX "pull_requests_repositoryId_externalId_key" ON "pull_requests"("repositoryId", "externalId");

-- CreateIndex
CREATE INDEX "findings_pullRequestId_idx" ON "findings"("pullRequestId");

-- CreateIndex
CREATE INDEX "dependencies_pullRequestId_idx" ON "dependencies"("pullRequestId");

-- CreateIndex
CREATE INDEX "secret_findings_pullRequestId_idx" ON "secret_findings"("pullRequestId");

-- CreateIndex
CREATE INDEX "policies_organizationId_idx" ON "policies"("organizationId");

-- CreateIndex
CREATE INDEX "audit_events_organizationId_createdAt_idx" ON "audit_events"("organizationId", "createdAt");

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repositories" ADD CONSTRAINT "repositories_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pull_requests" ADD CONSTRAINT "pull_requests_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_pullRequestId_fkey" FOREIGN KEY ("pullRequestId") REFERENCES "pull_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependencies" ADD CONSTRAINT "dependencies_pullRequestId_fkey" FOREIGN KEY ("pullRequestId") REFERENCES "pull_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "secret_findings" ADD CONSTRAINT "secret_findings_pullRequestId_fkey" FOREIGN KEY ("pullRequestId") REFERENCES "pull_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policies" ADD CONSTRAINT "policies_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policies" ADD CONSTRAINT "policies_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
