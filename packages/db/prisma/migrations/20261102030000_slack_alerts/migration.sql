-- CreateTable
CREATE TABLE "slack_connections" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "webhookUrlEncrypted" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "slack_connections_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "slack_connections_organizationId_key" ON "slack_connections"("organizationId");

-- AddForeignKey
ALTER TABLE "slack_connections" ADD CONSTRAINT "slack_connections_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
