import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveEnforcement } from "./policy.js";
import { buildPrComment, CODEGATE_COMMENT_MARKER } from "./explainer.js";
import type { AnalysisResult } from "./types.js";

function result(partial: Partial<AnalysisResult>): AnalysisResult {
  return {
    findings: [],
    secrets: [],
    dependencies: [],
    riskScore: 0,
    decision: "allow",
    status: "passed",
    ...partial,
  };
}

const blockVerdict = result({
  secrets: [{ secretType: "stripe", location: "a:1", maskedPreview: "x", severity: "critical" }],
  riskScore: 85,
  decision: "block",
  status: "blocked",
});

test("block protection + block verdict ⇒ failure, blocked", () => {
  const e = resolveEnforcement(blockVerdict, "block", []);
  assert.equal(e.conclusion, "failure");
  assert.equal(e.blocked, true);
});

test("observe protection never blocks, even on a block verdict", () => {
  const e = resolveEnforcement(blockVerdict, "observe", []);
  assert.equal(e.blocked, false);
  assert.equal(e.conclusion, "neutral");
});

test("warn protection reports as neutral, not failure", () => {
  const e = resolveEnforcement(blockVerdict, "warn", []);
  assert.equal(e.blocked, false);
  assert.equal(e.conclusion, "neutral");
});

test("clean result ⇒ success", () => {
  const e = resolveEnforcement(result({}), "block", []);
  assert.equal(e.conclusion, "success");
  assert.equal(e.blocked, false);
});

test("a policy can escalate a non-block verdict to a block", () => {
  const highOnly = result({
    findings: [{ type: "sast", severity: "high", title: "x", description: "y" }],
    riskScore: 20,
    decision: "fix",
    status: "warning",
  });
  // No policy: warn/neutral.
  assert.equal(resolveEnforcement(highOnly, "block", []).blocked, false);
  // Policy: block at >= high.
  const e = resolveEnforcement(highOnly, "block", [
    { action: "block", severityThreshold: "high" },
  ]);
  assert.equal(e.blocked, true);
  assert.equal(e.conclusion, "failure");
});

test("PR comment carries the upsert marker", () => {
  const body = buildPrComment(blockVerdict);
  assert.ok(body.startsWith(CODEGATE_COMMENT_MARKER));
  assert.ok(body.includes("CodeGate"));
});

test("observe mode: informational notes only ⇒ green check", () => {
  const r = resolveEnforcement(
    {
      findings: [{ type: "config", severity: "info", title: "Fichier sensible modifié : ci.yml", description: "x" }],
      secrets: [],
      dependencies: [],
      riskScore: 0,
      decision: "allow",
      status: "passed",
    },
    "observe",
    [],
  );
  assert.equal(r.conclusion, "success");
  assert.equal(r.title, "Aucun risque détecté");
});
