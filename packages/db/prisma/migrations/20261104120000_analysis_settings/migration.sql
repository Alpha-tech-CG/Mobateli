-- Analysis parameters: organization defaults + per-repository overrides.
-- Validated by @codegate/shared analysisSettingsSchema; NULL means defaults.
ALTER TABLE "organizations" ADD COLUMN "analysisSettings" JSONB;
ALTER TABLE "repositories" ADD COLUMN "analysisSettings" JSONB;
