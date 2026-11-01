import { getInstallationOctokit } from "./github.js";
import type { AppConfig } from "../config.js";

/**
 * Fetch a pull request's unified diff via an installation-scoped token.
 * Returns null when the App isn't configured or the call fails, so the
 * worker degrades gracefully in local dev.
 */
export async function fetchPrDiff(
  config: AppConfig,
  installationId: number,
  fullName: string,
  prNumber: number,
): Promise<string | null> {
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) return null;

  try {
    const octokit = await getInstallationOctokit(config, installationId);
    const res = await octokit.request(
      "GET /repos/{owner}/{repo}/pulls/{pull_number}",
      { owner, repo, pull_number: prNumber, mediaType: { format: "diff" } },
    );
    // With the diff media type, the body is the raw diff text.
    return res.data as unknown as string;
  } catch {
    return null;
  }
}
