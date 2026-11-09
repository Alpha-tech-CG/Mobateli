import { test } from "node:test";
import assert from "node:assert/strict";
import { findOwnReport } from "./github-feedback.js";
import { CODEGATE_COMMENT_MARKER } from "../analysis/explainer.js";

test("findOwnReport only picks a report posted by this App", () => {
  const report = `${CODEGATE_COMMENT_MARKER}\n## CodeGate`;
  const comments = [
    { id: 1, body: "LGTM", performed_via_github_app: null },
    // Another CodeGate App on the same repo (e.g. production) — not ours.
    { id: 2, body: report, performed_via_github_app: { id: 5587730 } },
    { id: 3, body: report, performed_via_github_app: { id: 5609367 } },
  ];
  assert.equal(findOwnReport(comments, 5609367)?.id, 3);
  // No report of ours yet → create a new one, never overwrite the other App's.
  assert.equal(findOwnReport(comments.slice(0, 2), 5609367), undefined);
  // A human quoting the marker isn't ours either.
  assert.equal(findOwnReport([{ id: 4, body: report }], 5609367), undefined);
});
