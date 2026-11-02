-- CreateTable
CREATE TABLE "gitlab_connections" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "gitlab_connections_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "gitlab_connections_organizationId_key" ON "gitlab_connections"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "gitlab_connections_tokenHash_key" ON "gitlab_connections"("tokenHash");

-- AddForeignKey
ALTER TABLE "gitlab_connections" ADD CONSTRAINT "gitlab_connections_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
