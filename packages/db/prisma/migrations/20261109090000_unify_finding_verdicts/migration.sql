-- One store for the team's verdicts on alerts: "finding_feedback".
--
-- "finding_suppressions" keyed a false positive on rule + file, which hid
-- every later alert of that rule in the file, including new real ones.
-- Verdicts are now keyed on rule + file + flagged code (see
-- apps/api/src/analysis/fingerprint.ts). The old keys cannot be converted
-- (the flagged code was never stored), so they are kept for the record
-- under a "legacy:" fingerprint that matches no new alert: those alerts
-- show again until a reviewer gives their verdict once more.

INSERT INTO "finding_feedback" ("id", "repositoryId", "fingerprint", "ruleId", "filePath", "verdict", "note", "userId", "createdAt", "updatedAt")
SELECT
    s."id",
    s."repositoryId",
    'legacy:' || s."fingerprint",
    NULLIF(split_part(s."fingerprint", '|', 1), ''),
    NULLIF(substr(s."fingerprint", length(split_part(s."fingerprint", '|', 1)) + 2), ''),
    'false_positive',
    s."reason",
    s."createdById",
    s."createdAt",
    s."createdAt"
FROM "finding_suppressions" s
ON CONFLICT ("repositoryId", "fingerprint") DO NOTHING;

-- DropTable
DROP TABLE "finding_suppressions";
