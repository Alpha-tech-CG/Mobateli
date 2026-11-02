import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateBackup, type RunFacts } from "./backup.js";

const now = new Date("2026-11-02T12:00:00Z");
const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000);

const ideal: RunFacts = {
  finishedAt: hoursAgo(9),
  status: "success",
  sha256: "a".repeat(64),
  encrypted: true,
  encryptionAlgorithm: "AES-256-GCM",
  inTransit: "tls1.3",
  keyLocation: "external_kms",
  signed: true,
  storageLocation: "offsite",
  immutable: true,
  versioning: true,
  separateAccount: true,
  retentionDays: 90,
  integrityCheckedAt: hoursAgo(8),
  integrityOk: true,
};
const restored = { completedAt: hoursAgo(72), result: "success", durationSeconds: 252 };

test("§5.5 healthy backup ⇒ 100, healthy, ransomware ready", () => {
  const e = evaluateBackup({ frequencyHours: 24 }, ideal, restored, now);
  assert.equal(e.score, 100);
  assert.equal(e.status, "healthy");
  assert.equal(e.ransomwareReady, true);
  assert.ok(e.checks.every((c) => c.ok));
});

test("no run at all ⇒ critical", () => {
  const e = evaluateBackup({ frequencyHours: 24 }, null, null, now);
  assert.equal(e.status, "critical");
  assert.equal(e.checks[0]!.id, "exists");
});

test("missing backup is detected from freshness (1.5 × frequency)", () => {
  const ok = evaluateBackup({ frequencyHours: 24 }, { ...ideal, finishedAt: hoursAgo(30) }, restored, now);
  assert.equal(ok.checks.find((c) => c.id === "freshness")!.ok, true);
  const late = evaluateBackup({ frequencyHours: 24 }, { ...ideal, finishedAt: hoursAgo(37) }, restored, now);
  assert.equal(late.checks.find((c) => c.id === "freshness")!.ok, false);
  assert.equal(late.status, "critical");
});

test("plaintext backup on the prod server with key nowhere ⇒ critical, not ransomware ready", () => {
  const e = evaluateBackup(
    { frequencyHours: 24 },
    {
      ...ideal,
      encrypted: false,
      encryptionAlgorithm: null,
      storageLocation: "same_server",
      immutable: false,
      separateAccount: false,
      retentionDays: 7,
    },
    null,
    now,
  );
  const failed = Object.fromEntries(e.checks.filter((c) => !c.ok).map((c) => [c.id, c.severity]));
  assert.equal(failed.encryption_at_rest, "critical");
  assert.equal(failed.isolation, "high");
  assert.equal(failed.retention, "high");
  assert.equal(failed.restore_test, "high");
  assert.equal(e.ransomwareReady, false);
  assert.equal(e.status, "critical");
});

test("key on the same server is flagged high", () => {
  const e = evaluateBackup({ frequencyHours: 24 }, { ...ideal, keyLocation: "same_server" }, restored, now);
  assert.equal(e.checks.find((c) => c.id === "key_isolation")!.severity, "high");
  assert.equal(e.ransomwareReady, false);
});

test("integrity mismatch and failed restore are critical", () => {
  const e = evaluateBackup(
    { frequencyHours: 24 },
    { ...ideal, integrityOk: false },
    { ...restored, result: "failed" },
    now,
  );
  const sev = Object.fromEntries(e.checks.filter((c) => !c.ok).map((c) => [c.id, c.severity]));
  assert.equal(sev.integrity_verified, "critical");
  assert.equal(sev.restore_test, "critical");
});

test("§5.5 uploads example: no restore test ⇒ attention", () => {
  const e = evaluateBackup({ frequencyHours: 24 }, ideal, null, now);
  assert.equal(e.status, "attention");
  assert.equal(e.score, 88);
});
