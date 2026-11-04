import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Secure linking of a GitHub App installation to a CodeGate organization.
 *
 * GitHub sends the browser back with an `installation_id` that anyone can
 * forge, so it is never trusted on its own (GitHub's own guidance). Two
 * independent proofs are required:
 *  1. a signed, short-lived `state` we issued to a logged-in owner/admin —
 *     it carries the organization and binds the round trip to our user;
 *  2. a user-to-server OAuth token obtained from the one-time `code`, used
 *     to ask GitHub which installations *this GitHub user* can access.
 */

type FetchImpl = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

export interface ConnectState {
  organizationId: string;
  userId: string;
  /** Expiry, epoch milliseconds. */
  exp: number;
  nonce: string;
}

const STATE_TTL_MS = 15 * 60 * 1000;

function hmac(secret: string, payload: string): string {
  // Domain-separated so a state can never be confused with another signature.
  return createHmac("sha256", secret).update(`github-connect:${payload}`).digest("base64url");
}

export function signConnectState(
  secret: string,
  organizationId: string,
  userId: string,
  now = Date.now(),
): string {
  const state: ConnectState = {
    organizationId,
    userId,
    exp: now + STATE_TTL_MS,
    nonce: randomBytes(12).toString("base64url"),
  };
  const payload = Buffer.from(JSON.stringify(state)).toString("base64url");
  return `${payload}.${hmac(secret, payload)}`;
}

/** The decoded state, or null when tampered with, malformed or expired. */
export function verifyConnectState(
  secret: string,
  token: string | undefined,
  now = Date.now(),
): ConnectState | null {
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = Buffer.from(hmac(secret, payload));
  const given = Buffer.from(sig);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
  try {
    const state = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as ConnectState;
    if (typeof state.organizationId !== "string" || typeof state.userId !== "string") return null;
    if (typeof state.exp !== "number" || state.exp < now) return null;
    return state;
  } catch {
    return null;
  }
}

/** Exchange the one-time OAuth `code` for a user-to-server token. */
export async function exchangeOAuthCode(
  clientId: string,
  clientSecret: string,
  code: string,
  fetchImpl: FetchImpl = globalThis.fetch as unknown as FetchImpl,
): Promise<string | null> {
  const res = await fetchImpl("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
  });
  if (!res.ok) return null;
  const data = (await res.json()) as { access_token?: string };
  return data.access_token ?? null;
}

/**
 * Does this GitHub user have access to the installation? Returns its account
 * login when they do. Walks `GET /user/installations` (paginated).
 */
export async function findUserInstallation(
  userToken: string,
  installationId: number,
  fetchImpl: FetchImpl = globalThis.fetch as unknown as FetchImpl,
): Promise<{ accountLogin: string } | null> {
  for (let page = 1; page <= 10; page++) {
    const res = await fetchImpl(
      `https://api.github.com/user/installations?per_page=100&page=${page}`,
      {
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${userToken}`,
          "x-github-api-version": "2022-11-28",
        },
      },
    );
    if (!res.ok) return null;
    const data = (await res.json()) as {
      installations?: { id: number; account?: { login?: string } }[];
    };
    const list = data.installations ?? [];
    const hit = list.find((i) => i.id === installationId);
    if (hit) return { accountLogin: hit.account?.login ?? "github" };
    if (list.length < 100) return null;
  }
  return null;
}
