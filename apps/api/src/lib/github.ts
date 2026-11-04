import { App } from "@octokit/app";
import type { AppConfig } from "../config.js";
import { readPlatformSetting } from "./platform.js";

/**
 * GitHub App client. Authenticates as the App (JWT) and mints short-lived
 * installation tokens on demand — we never store a long-lived token
 * (cahier §10.3, principe du moindre privilège).
 *
 * The App's credentials come from the environment, or — when the operator
 * created the App from the dashboard (manifest flow) — from the encrypted
 * platform settings. Returns undefined when neither exists, so callers
 * degrade gracefully in local dev.
 */

export interface GithubAppSettings {
  appId: string;
  slug: string | null;
  privateKey: string;
  webhookSecret: string | null;
  /**
   * OAuth credentials of the App — used at "Connecter GitHub" to verify the
   * user really has access to the installation (null: not configured).
   */
  clientId: string | null;
  clientSecret: string | null;
  source: "env" | "database";
}

/** Shape stored under the `github_app` platform setting. */
export interface StoredGithubApp {
  appId: string;
  slug: string;
  privateKey: string;
  webhookSecret: string;
  clientId: string;
  clientSecret: string;
  owner: string | null;
}

export const GITHUB_APP_SETTING = "github_app";
const CACHE_MS = 60_000;

let cached: { at: number; value: GithubAppSettings | null } | undefined;
let app: { appId: string; instance: App } | undefined;

/** Forget cached credentials (after the operator created / replaced the App). */
export function resetGithubAppCache(): void {
  cached = undefined;
  app = undefined;
}

export async function getGithubSettings(config: AppConfig): Promise<GithubAppSettings | null> {
  if (config.GITHUB_APP_ID && config.GITHUB_APP_PRIVATE_KEY) {
    return {
      appId: config.GITHUB_APP_ID,
      slug: config.GITHUB_APP_SLUG ?? null,
      privateKey: config.GITHUB_APP_PRIVATE_KEY,
      webhookSecret: config.GITHUB_WEBHOOK_SECRET ?? null,
      clientId: config.GITHUB_CLIENT_ID ?? null,
      clientSecret: config.GITHUB_CLIENT_SECRET ?? null,
      source: "env",
    };
  }
  if (cached && Date.now() - cached.at < CACHE_MS) {
    return cached.value ?? (config.GITHUB_WEBHOOK_SECRET ? envSecretOnly(config) : null);
  }
  let value: GithubAppSettings | null = null;
  try {
    const stored = await readPlatformSetting<StoredGithubApp>(GITHUB_APP_SETTING, config.ENCRYPTION_KEY);
    if (stored) {
      value = {
        appId: stored.appId,
        slug: stored.slug,
        privateKey: stored.privateKey,
        webhookSecret: stored.webhookSecret,
        clientId: stored.clientId ?? null,
        clientSecret: stored.clientSecret ?? null,
        source: "database",
      };
    }
  } catch {
    value = null;
  }
  cached = { at: Date.now(), value };
  return value ?? (config.GITHUB_WEBHOOK_SECRET ? envSecretOnly(config) : null);
}

/** Webhook secret configured without App credentials (tests, partial setup). */
function envSecretOnly(config: AppConfig): GithubAppSettings {
  return {
    appId: "",
    slug: config.GITHUB_APP_SLUG ?? null,
    privateKey: "",
    webhookSecret: config.GITHUB_WEBHOOK_SECRET ?? null,
    clientId: config.GITHUB_CLIENT_ID ?? null,
    clientSecret: config.GITHUB_CLIENT_SECRET ?? null,
    source: "env",
  };
}

export async function getGithubApp(config: AppConfig): Promise<App | undefined> {
  const s = await getGithubSettings(config);
  if (!s?.appId || !s.privateKey) return undefined;
  if (!app || app.appId !== s.appId) {
    app = { appId: s.appId, instance: new App({ appId: s.appId, privateKey: s.privateKey }) };
  }
  return app.instance;
}

type InstallationOctokit = Awaited<ReturnType<App["getInstallationOctokit"]>>;

/** Octokit scoped to one installation, for repo-level API calls. */
export async function getInstallationOctokit(
  config: AppConfig,
  installationId: number,
): Promise<InstallationOctokit> {
  const gh = await getGithubApp(config);
  if (!gh) throw new Error("GitHub App not configured");
  return gh.getInstallationOctokit(installationId);
}
