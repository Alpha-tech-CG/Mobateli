import { test } from "node:test";
import assert from "node:assert/strict";
import {
  firstBlocked,
  gradeEnumeration,
  gradeLockout,
  isBlocked,
  type Observation,
} from "./bruteforce.js";
import { nextThrottleState, RULES } from "../lib/throttle.js";
import { runLockoutProbe } from "../lib/bruteforce-runner.js";

const obs = (attempt: number, status: number, body = "", ms = 100, retryAfter: string | null = null): Observation => ({
  attempt,
  status,
  ms,
  body,
  retryAfter,
});

// ── CodeGate's own lockout ──

test("throttle: locks on the 5th failure in the window, then escalates", () => {
  const t0 = new Date("2026-11-02T10:00:00Z");
  let state = null;
  for (let i = 1; i <= 4; i++) {
    const r = nextThrottleState(state, RULES.loginAccount, t0);
    assert.equal(r.locked, false);
    state = r.state;
  }
  const fifth = nextThrottleState(state, RULES.loginAccount, t0);
  assert.equal(fifth.locked, true);
  assert.equal(fifth.state.lockedUntil!.getTime() - t0.getTime(), 300_000);

  // Second lockout doubles (progressive), capped at 1h.
  let s2 = fifth.state;
  let last = fifth;
  for (let i = 0; i < 5; i++) {
    last = nextThrottleState(s2, RULES.loginAccount, t0);
    s2 = last.state;
  }
  assert.equal(last.state.lockedUntil!.getTime() - t0.getTime(), 600_000);
});

test("throttle: failures outside the window are forgotten", () => {
  const t0 = new Date("2026-11-02T10:00:00Z");
  const first = nextThrottleState(null, RULES.loginAccount, t0).state;
  const later = new Date(t0.getTime() + 11 * 60_000);
  assert.equal(nextThrottleState({ ...first, failures: 4 }, RULES.loginAccount, later).state.failures, 1);
});

// ── Grading ──

test("blocked responses: 429, Retry-After, lock wording", () => {
  assert.ok(isBlocked(obs(1, 429)));
  assert.ok(isBlocked(obs(1, 401, "", 1, "300")));
  assert.ok(isBlocked(obs(1, 401, '{"error":"too_many_attempts"}')));
  assert.ok(isBlocked(obs(1, 403, "compte verrouillé")));
  assert.ok(!isBlocked(obs(1, 401, '{"error":"invalid_credentials"}')));
});

test("lockout grading vs policy", () => {
  assert.equal(gradeLockout(null, 12, null, null).result, "fail");
  assert.equal(gradeLockout(6, 6, 5, "account").result, "pass");
  assert.equal(gradeLockout(11, 11, 5, "account").result, "warn");
  assert.equal(gradeLockout(4, 4, 5, "ip").result, "warn");
});

test("enumeration: identical responses pass, different messages fail", () => {
  const same = [obs(1, 401, '{"error":"invalid_credentials"}'), obs(3, 401, '{"error":"invalid_credentials"}')];
  assert.equal(gradeEnumeration(same, same).result, "pass");
  const leaky = gradeEnumeration(same, [obs(2, 404, '{"error":"user_not_found"}')]);
  assert.equal(leaky.result, "fail");
  assert.equal(leaky.signals.length, 2);
  const slow = same.map((o) => ({ ...o, ms: 450 }));
  assert.equal(gradeEnumeration(slow, same).result, "warn");
});

// ── Runner against a fake endpoint (no network) ──

test("lockout probe stops at the first blocked response", async () => {
  let calls = 0;
  const fakeFetch = (async () => {
    calls++;
    return calls < 6
      ? new Response('{"error":"invalid_credentials"}', { status: 401 })
      : new Response('{"error":"too_many_attempts"}', { status: 429, headers: { "retry-after": "300" } });
  }) as typeof fetch;
  const probe = { origin: "https://app.example.com", endpoint: "/api/login", emailField: "email", passwordField: "password" };
  const out = await runLockoutProbe(probe, "qa@example.com", 12, isBlocked, fakeFetch);
  assert.equal(out.length, 6);
  assert.equal(firstBlocked(out), 6);
});
