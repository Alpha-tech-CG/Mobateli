-- CreateEnum
CREATE TYPE "AgentPermission" AS ENUM ('read_repo', 'modify_file', 'install_dependency', 'run_shell', 'network_access', 'modify_secrets', 'deploy_production', 'delete_files');

-- CreateEnum
CREATE TYPE "AgentDecision" AS ENUM ('allow', 'deny', 'require_approval');

-- CreateTable
CREATE TABLE "agent_policies" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "repositoryId" UUID,
    "permission" "AgentPermission" NOT NULL,
    "decision" "AgentDecision" NOT NULL,
    "allowlist" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agent_policies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "agent_policies_organizationId_idx" ON "agent_policies"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "agent_policies_organizationId_repositoryId_permission_key" ON "agent_policies"("organizationId", "repositoryId", "permission");

-- AddForeignKey
ALTER TABLE "agent_policies" ADD CONSTRAINT "agent_policies_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_policies" ADD CONSTRAINT "agent_policies_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;
