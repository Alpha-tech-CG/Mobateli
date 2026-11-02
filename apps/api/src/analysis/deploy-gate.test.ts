import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateDeployGate, type DeployGateInput } from "./deploy-gate.js";

const clean: DeployGateInput = {
  openSecrets: 0,
  criticalFindings: 0,
  highFindings: 0,
  criticalDependencies: 0,
  latestPrBlocked: false,
};

test("clean posture ⇒ authorized", () => {
  assert.equal(evaluateDeployGate(clean, "block").decision, "authorized");
});

test("exposed secret ⇒ blocked under block protection", () => {
  const r = evaluateDeployGate({ ...clean, openSecrets: 1 }, "block");
  assert.equal(r.decision, "blocked");
});

test("critical risk under observe ⇒ warning, never blocked", () => {
  const r = evaluateDeployGate({ ...clean, criticalFindings: 2 }, "observe");
  assert.equal(r.decision, "warning");
});

test("high findings under block ⇒ requires_approval", () => {
  const r = evaluateDeployGate({ ...clean, highFindings: 3 }, "block");
  assert.equal(r.decision, "requires_approval");
});

test("high findings under warn ⇒ warning", () => {
  const r = evaluateDeployGate({ ...clean, highFindings: 3 }, "warn");
  assert.equal(r.decision, "warning");
});

test("blocked latest PR ⇒ blocked under block protection", () => {
  const r = evaluateDeployGate({ ...clean, latestPrBlocked: true }, "block");
  assert.equal(r.decision, "blocked");
});
