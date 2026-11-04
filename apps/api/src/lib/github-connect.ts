/**
 * OAuth proof for "Connecter GitHub" (routes/github.ts). GitHub sends the
 * browser back with an `installation_id` anyone can forge; the signed state
 * proves which organization started the flow, and this proves that the
 * GitHub user who installed the App can actually access that installation:
 * the one-time `code` is exchanged for a user-to-server token, then GitHub is
 * asked which installations this user can see.
 */

type FetchImpl = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;

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
