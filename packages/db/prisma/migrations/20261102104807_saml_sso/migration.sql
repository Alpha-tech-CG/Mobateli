-- CreateTable
CREATE TABLE "saml_connections" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "idpEntityId" TEXT NOT NULL,
    "idpSsoUrl" TEXT NOT NULL,
    "idpCert" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "saml_connections_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "saml_connections_organizationId_key" ON "saml_connections"("organizationId");

-- AddForeignKey
ALTER TABLE "saml_connections" ADD CONSTRAINT "saml_connections_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
