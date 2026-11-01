import { getInstallationOctokit } from "./github.js";
import { CODEGATE_COMMENT_MARKER } from "../analysis/explainer.js";
import type { CheckConclusion } from "../analysis/policy.js";
import type { AppConfig } from "../config.js";

/**
 * Posts CodeGate's verdict back to GitHub (cahier §5.1, §6.2): a Check Run on
 * the head commit, and a structured PR comment (upserted so we never spam the
 * thread). All calls are best-effort — failures are surfaced to the caller
 * but never corrupt the analysis already persisted.
 */

const CHECK_NAME = "CodeGate";

export async function createCheckRun(
  config: AppConfig,
  installationId: number,
  fullName: string,
  headSha: string,
  outcome: { conclusion: CheckConclusion; title: string; summary: string },
): Promise<void> {
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) return;
  const octokit = await getInstallationOctokit(config, installationId);
  await octokit.request("POST /repos/{owner}/{repo}/check-runs", {
    owner,
    repo,
    name: CHECK_NAME,
    head_sha: headSha,
    status: "completed",
    conclusion: outcome.conclusion,
    output: { title: outcome.title, summary: outcome.summary },
  });
}

export async function upsertPrComment(
  config: AppConfig,
  installationId: number,
  fullName: string,
  prNumber: number,
  body: string,
): Promise<void> {
  const [owner, repo] = fullName.split("/");
  if (!owner || !repo) return;
  const octokit = await getInstallationOctokit(config, installationId);

  // Find an existing CodeGate comment to update in place.
  const comments = await octokit.request(
    "GET /repos/{owner}/{repo}/issues/{issue_number}/comments",
    { owner, repo, issue_number: prNumber, per_page: 100 },
  );
  const existing = comments.data.find((c) =>
    (c.body ?? "").includes(CODEGATE_COMMENT_MARKER),
  );

  if (existing) {
    await octokit.request(
      "PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}",
      { owner, repo, comment_id: existing.id, body },
    );
  } else {
    await octokit.request(
      "POST /repos/{owner}/{repo}/issues/{issue_number}/comments",
      { owner, repo, issue_number: prNumber, body },
    );
  }
}
