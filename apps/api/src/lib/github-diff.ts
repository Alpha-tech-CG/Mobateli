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

/**
 * Read one file from the repository's DEFAULT branch (no `ref`), e.g. the
 * `.codegateignore`. Deliberately never the PR head: a pull request must not
 * be able to change the rules it is judged by. Returns null when the file is
 * absent, the App isn't configured, or the call fails.
 */
export async function fetchDefaultBranchFile(
  config: AppConfig,
  installationId: number,
  fullName: string,
  path: string,
): Promise<string | null> {
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) return null;

  try {
    const octokit = await getInstallationOctokit(config, installationId);
    const res = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", {
      owner,
      repo,
      path,
      mediaType: { format: "raw" },
    });
    // With the raw media type, the body is the file content.
    return typeof res.data === "string" ? res.data : null;
  } catch {
    return null; // 404 (no ignore file) or any API failure.
  }
}
