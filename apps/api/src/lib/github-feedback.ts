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

interface IssueComment {
  id: number;
  body?: string | null;
  performed_via_github_app?: { id: number } | null;
}

/**
 * Our own previous report on the PR, if any. Matching the hidden marker alone
 * is not enough: another CodeGate App on the same repository (production next
 * to a dev App, or another tenant) writes the same marker, and we would
 * overwrite its report — seen on the first real run. The comment must also
 * have been posted by this App.
 */
export function findOwnReport(comments: IssueComment[], appId: number): IssueComment | undefined {
  return comments.find(
    (c) =>
      (c.body ?? "").includes(CODEGATE_COMMENT_MARKER) &&
      c.performed_via_github_app?.id === appId,
  );
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
  const existing = findOwnReport(
    comments.data as IssueComment[],
    Number(config.GITHUB_APP_ID),
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
