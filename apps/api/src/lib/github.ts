import { App } from "@octokit/app";
import type { AppConfig } from "../config.js";

/**
 * GitHub App client. Authenticates as the App (JWT) and mints short-lived
 * installation tokens on demand — we never store a long-lived token
 * (cahier §10.3, principe du moindre privilège).
 *
 * Returns undefined when the App isn't configured, so callers degrade
 * gracefully in local dev.
 */
let app: App | undefined;

export function getGithubApp(config: AppConfig): App | undefined {
  if (!config.GITHUB_APP_ID || !config.GITHUB_APP_PRIVATE_KEY) return undefined;
  if (!app) {
    app = new App({
      appId: config.GITHUB_APP_ID,
      privateKey: config.GITHUB_APP_PRIVATE_KEY,
    });
  }
  return app;
}

type InstallationOctokit = Awaited<ReturnType<App["getInstallationOctokit"]>>;

/** Octokit scoped to one installation, for repo-level API calls. */
export async function getInstallationOctokit(
  config: AppConfig,
  installationId: number,
): Promise<InstallationOctokit> {
  const gh = getGithubApp(config);
  if (!gh) throw new Error("GitHub App not configured");
  return gh.getInstallationOctokit(installationId);
}
