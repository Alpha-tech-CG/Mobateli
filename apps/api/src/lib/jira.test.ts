import { test } from "node:test";
import assert from "node:assert/strict";
import { buildJiraIssue } from "./jira.js";
import type { AnalysisResult } from "../analysis/types.js";

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

test("buildJiraIssue produces a summary and an ADF description", () => {
  const issue = buildJiraIssue({
    repository: "acme/app",
    prNumber: 7,
    prTitle: "Add login",
    result: result({
      riskScore: 85,
      decision: "block",
      secrets: [{ secretType: "stripe_secret_key", location: "config.ts:3", maskedPreview: "sk…xyz", severity: "critical" }],
      findings: [{ type: "sast", severity: "high", title: "SQL concat", description: "Injection.", ruleId: "SQL" }],
    }),
  });

  assert.match(issue.summary, /\[CodeGate\].*acme\/app PR #7/);
  // Valid ADF root.
  assert.equal(issue.description.type, "doc");
  assert.equal((issue.description as { version?: number }).version, 1);
  assert.ok(Array.isArray(issue.description.content) && issue.description.content.length >= 3);
  const text = JSON.stringify(issue.description);
  assert.match(text, /stripe_secret_key/);
  assert.match(text, /85\/100/);
  assert.match(text, /preuve d'audit/);
});
