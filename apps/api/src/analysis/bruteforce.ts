/**
 * BruteForce Shield grading (extension §4, US03). Pure functions: the runner
 * collects HTTP observations, these decide what they mean.
 */

export interface Observation {
  attempt: number;
  status: number;
  ms: number;
  /** Lowercased, truncated response body (never stored with secrets). */
  body: string;
  retryAfter: string | null;
}

export type TestResult = "pass" | "warn" | "fail";

const BLOCK_PATTERN =
  /too[ _-]?many|rate[ _-]?limit|locked|lockout|temporarily blocked|try again later|trop de tentatives|verrouill|captcha|turnstile|hcaptcha|recaptcha/;

/** Did the target refuse this attempt because of anti brute force? */
export function isBlocked(o: Pick<Observation, "status" | "body" | "retryAfter">): boolean {
  if (o.status === 429 || o.status === 423) return true;
  if (o.retryAfter) return true;
  return o.status >= 400 && BLOCK_PATTERN.test(o.body);
}

export function firstBlocked(observations: Observation[]): number | null {
  const hit = observations.find((o) => isBlocked(o));
  return hit ? hit.attempt : null;
}

/**
 * Grade a lockout test. `blockedAfter` is the attempt number that was refused
 * (so failures tolerated = blockedAfter - 1). Compared to the org policy when
 * one exists, else to the §4.4 baseline of 5 failures.
 */
export function gradeLockout(
  blockedAfter: number | null,
  attempts: number,
  policyMax: number | null,
  scope: "account" | "ip" | null,
): { result: TestResult; summary: string } {
  const expected = policyMax ?? 5;
  if (blockedAfter === null) {
    return {
      result: "fail",
      summary: `Aucun blocage après ${attempts} échecs consécutifs : l'endpoint est exposé au brute force (CWE-307).`,
    };
  }
  const tolerated = blockedAfter - 1;
  const by = scope === "account" ? "par compte" : scope === "ip" ? "par IP uniquement" : "";
  if (tolerated > expected) {
    return {
      result: "warn",
      summary: `Blocage ${by} après ${tolerated} échecs, au-delà de la politique (${expected}).`,
    };
  }
  if (scope === "ip") {
    return {
      result: "warn",
      summary: `Blocage après ${tolerated} échecs, mais par IP uniquement : une attaque distribuée sur un compte passe (OWASP recommande un compteur par compte).`,
    };
  }
  return {
    result: "pass",
    summary: `Blocage ${by} après ${tolerated} échec${tolerated > 1 ? "s" : ""}, conforme à la politique (${expected}).`,
  };
}

const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length ? s[Math.floor(s.length / 2)]! : 0;
};

/** Strip volatile parts (ids, timestamps, numbers) before comparing bodies. */
export function normalizeBody(body: string): string {
  return body
    .replace(/"(request_?id|trace_?id|timestamp|time|date)"\s*:\s*"[^"]*"/g, "")
    .replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, "<uuid>")
    .replace(/\d+/g, "<n>")
    .trim();
}

/**
 * Account enumeration (§4.3): compare responses for the existing test account
 * vs. a non-existent one. Different status/body, or a stable timing gap,
 * reveals whether an account exists.
 */
export function gradeEnumeration(
  existing: Observation[],
  missing: Observation[],
): { result: TestResult; summary: string; signals: string[] } {
  const signals: string[] = [];
  const statusesA = new Set(existing.map((o) => o.status));
  const statusesB = new Set(missing.map((o) => o.status));
  if ([...statusesA].join() !== [...statusesB].join()) {
    signals.push(`codes HTTP différents (${[...statusesA].join("/")} vs ${[...statusesB].join("/")})`);
  }
  const bodiesA = new Set(existing.map((o) => normalizeBody(o.body)));
  const bodiesB = new Set(missing.map((o) => normalizeBody(o.body)));
  if ([...bodiesA].sort().join("|") !== [...bodiesB].sort().join("|")) {
    signals.push("messages d'erreur différents");
  }
  const gap = median(existing.map((o) => o.ms)) - median(missing.map((o) => o.ms));
  if (Math.abs(gap) >= 150) {
    signals.push(`écart de temps de réponse de ${Math.round(Math.abs(gap))} ms`);
  }

  if (!signals.length) {
    return {
      result: "pass",
      summary: "Réponses identiques pour un compte existant et inexistant : pas d'énumération détectée.",
      signals,
    };
  }
  const onlyTiming = signals.length === 1 && signals[0]!.startsWith("écart");
  return {
    result: onlyTiming ? "warn" : "fail",
    summary: `L'endpoint révèle si un compte existe : ${signals.join(", ")}.`,
    signals,
  };
}
