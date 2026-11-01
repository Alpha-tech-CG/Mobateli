-- AlterTable
ALTER TABLE "repositories" ADD COLUMN     "installationId" BIGINT;

-- CreateTable
CREATE TABLE "github_installations" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "installationId" BIGINT NOT NULL,
    "accountLogin" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "github_installations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "github_installations_installationId_key" ON "github_installations"("installationId");

-- CreateIndex
CREATE INDEX "github_installations_organizationId_idx" ON "github_installations"("organizationId");

-- AddForeignKey
ALTER TABLE "github_installations" ADD CONSTRAINT "github_installations_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
