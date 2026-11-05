import crypto from "node:crypto";
import https from "node:https";
import jwt from "jsonwebtoken";

// ---- Weak hash --------------------------------------------------------------
export function hashPassword(pw: string): string {
  return crypto.createHash("md5").update(pw).digest("hex"); // VULN: HASH
}

export function legacySignature(body: string): string {
  return crypto.createHash("sha1").update(body).digest("hex"); // VULN: HASH
}

export function etag(body: string): string {
  return crypto.createHash("sha256").update(body).digest("hex"); // SAFE: HASH
}

// ---- Weak randomness --------------------------------------------------------
export function resetToken(): string {
  return Math.random().toString(36).slice(2); // VULN: RANDOM
}

export function newSessionId(): string {
  const sessionId = Math.random().toString(36).substring(2, 15); // VULN: RANDOM
  return sessionId;
}

export function jitterMs(): number {
  return Math.floor(Math.random() * 250); // SAFE: RANDOM
}

export function apiKey(): string {
  return crypto.randomBytes(32).toString("hex"); // SAFE: RANDOM
}

// ---- JWT --------------------------------------------------------------------
export function readUser(token: string): unknown {
  return jwt.decode(token); // VULN: JWT
}

export function verifyLoose(token: string, key: string): unknown {
  return jwt.verify(token, key, { algorithms: ["none", "HS256"] }); // VULN: JWT
}

export function verifyStrict(token: string, key: string): unknown {
  return jwt.verify(token, key, { algorithms: ["RS256"] }); // SAFE: JWT
}

// ---- TLS --------------------------------------------------------------------
export const insecureAgent = new https.Agent({ rejectUnauthorized: false }); // VULN: TLS

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // VULN: TLS

export const secureAgent = new https.Agent({ rejectUnauthorized: true }); // SAFE: TLS
