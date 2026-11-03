-- CreateTable
CREATE TABLE "platform_settings" (
    "key" TEXT NOT NULL,
    "valueEncrypted" TEXT NOT NULL,
    "updatedById" UUID,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "platform_settings_pkey" PRIMARY KEY ("key")
);
