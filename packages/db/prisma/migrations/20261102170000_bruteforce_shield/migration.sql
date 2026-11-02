-- CreateTable
CREATE TABLE "auth_throttles" (
    "key" TEXT NOT NULL,
    "failures" INTEGER NOT NULL DEFAULT 0,
    "windowStart" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lockedUntil" TIMESTAMP(3),
    "lockouts" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "auth_throttles_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "bruteforce_policies" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "endpoint" TEXT NOT NULL,
    "maxAttempts" INTEGER NOT NULL,
    "windowSeconds" INTEGER NOT NULL,
    "lockoutSeconds" INTEGER NOT NULL,
    "strategy" TEXT NOT NULL DEFAULT 'progressive',
    "applyTo" TEXT[] DEFAULT ARRAY['ip', 'account']::TEXT[],
    "captchaAfter" INTEGER,
    "alertAfter" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "bruteforce_policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bruteforce_targets" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "origin" TEXT NOT NULL,
    "environment" TEXT NOT NULL DEFAULT 'staging',
    "verificationToken" TEXT NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "bruteforce_targets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bruteforce_tests" (
    "id" UUID NOT NULL,
    "targetId" UUID NOT NULL,
    "testType" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL,
    "blockedAfter" INTEGER,
    "scope" TEXT,
    "result" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "evidence" JSONB NOT NULL,
    "createdById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "bruteforce_tests_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "bruteforce_policies_organizationId_endpoint_key" ON "bruteforce_policies"("organizationId", "endpoint");

-- CreateIndex
CREATE UNIQUE INDEX "bruteforce_targets_organizationId_origin_key" ON "bruteforce_targets"("organizationId", "origin");

-- CreateIndex
CREATE INDEX "bruteforce_tests_targetId_idx" ON "bruteforce_tests"("targetId");

-- AddForeignKey
ALTER TABLE "bruteforce_policies" ADD CONSTRAINT "bruteforce_policies_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "bruteforce_targets" ADD CONSTRAINT "bruteforce_targets_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "bruteforce_tests" ADD CONSTRAINT "bruteforce_tests_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "bruteforce_targets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
