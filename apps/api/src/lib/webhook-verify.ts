import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Verify a Vercel webhook signature (x-vercel-signature) — HMAC-SHA1 of the
 * raw body with the integration secret. cahier §13.4.
 */
export function verifyVercelSignature(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader) return false;
  const expected = createHmac("sha1", secret).update(rawBody).digest("hex");
  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Verify a GitHub webhook signature (X-Hub-Signature-256) against the raw
 * request body using the shared secret. Constant-time comparison.
 * cahier §13.4 — "validation stricte des webhooks par signature".
 */
export function verifyGithubSignature(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith("sha256=")) return false;

  const expected = "sha256=" + createHmac("sha256", secret).update(rawBody).digest("hex");

  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  // Lengths must match for timingSafeEqual; different length ⇒ not a match.
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
