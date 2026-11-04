-- Proof of acceptance of the terms (CGU/CGV, privacy policy, DPA) at signup.
ALTER TABLE "users" ADD COLUMN "termsAcceptedAt" TIMESTAMP(3);
ALTER TABLE "users" ADD COLUMN "termsVersion" TEXT;
