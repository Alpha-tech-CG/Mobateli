import { test } from "node:test";
import assert from "node:assert/strict";
import { shouldCreateRemediation, buildRemediationIssue } from "./linear.js";
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

test("shouldCreateRemediation: block verdict or secret or high+ ⇒ true", () => {
  assert.equal(shouldCreateRemediation(result({ decision: "block" })), true);
  assert.equal(
    shouldCreateRemediation(
      result({ secrets: [{ secretType: "x", location: "a:1", maskedPreview: "y", severity: "critical" }] }),
    ),
    true,
  );
  assert.equal(
    shouldCreateRemediation(
      result({ findings: [{ type: "sast", severity: "high", title: "t", description: "d" }] }),
    ),
    true,
  );
});

test("shouldCreateRemediation: clean or low ⇒ false", () => {
  assert.equal(shouldCreateRemediation(result({})), false);
  assert.equal(
    shouldCreateRemediation(
      result({ findings: [{ type: "config", severity: "low", title: "t", description: "d" }] }),
    ),
    false,
  );
});

test("buildRemediationIssue produces a titled, sectioned body", () => {
  const r = result({
    riskScore: 85,
    decision: "block",
    secrets: [{ secretType: "stripe_secret_key", location: "config.ts:3", maskedPreview: "sk_l…xyz", severity: "critical" }],
    findings: [
      {
        type: "sast",
        severity: "high",
        title: "Requête SQL concaténée",
        description: "Injection SQL possible.",
        filePath: "db.ts",
        line: 10,
        ruleId: "SQL_STRING_CONCAT",
        remediation: "Requêtes paramétrées.",
      },
    ],
  });
  const issue = buildRemediationIssue({
    repository: "zlat/demo",
    prNumber: 7,
    prTitle: "Add login",
    result: r,
  });
  assert.match(issue.title, /\[CodeGate\].*zlat\/demo PR #7/);
  assert.match(issue.description, /Score de risque :\*\* 85\/100/);
  assert.match(issue.description, /stripe_secret_key/);
  assert.match(issue.description, /SQL/);
  assert.match(issue.description, /preuve d'audit/);
});
