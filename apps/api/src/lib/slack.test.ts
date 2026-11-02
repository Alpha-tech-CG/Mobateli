import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSlackAlert } from "./slack.js";

test("buildSlackAlert produces text + blocks with repo and detail", () => {
  const msg = buildSlackAlert({
    title: "Pull request bloquée",
    severity: "critical",
    repository: "zlat/demo",
    detail: "PR #7 — risque 85/100",
    url: "https://app.codegate.dev/pr/7",
  });
  assert.match(msg.text, /CodeGate/);
  assert.match(msg.text, /zlat\/demo/);
  assert.ok(Array.isArray(msg.blocks) && msg.blocks.length >= 3);
  const json = JSON.stringify(msg.blocks);
  assert.match(json, /zlat\/demo/);
  assert.match(json, /PR #7/);
  assert.match(json, /critical/);
  // The action button carries the link when provided.
  assert.match(json, /app\.codegate\.dev/);
});

test("buildSlackAlert omits the action block when no url", () => {
  const msg = buildSlackAlert({
    title: "Test",
    severity: "info",
    repository: "x/y",
    detail: "d",
  });
  assert.ok(!JSON.stringify(msg.blocks).includes('"actions"'));
});
