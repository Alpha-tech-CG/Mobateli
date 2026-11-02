import type { AnalysisResult } from "../analysis/types.js";
import { explainSecret, explainDependency, explainFinding } from "../analysis/explainer.js";

/**
 * Linear connector (cahier §5.7). Creates a remediation issue when a PR carries
 * real risk. Outbound only; the API key is passed in already decrypted.
 */

const LINEAR_GRAPHQL = "https://api.linear.app/graphql";

export interface LinearIssueRef {
  id: string;
  identifier: string;
  url: string;
}

/** Should a remediation ticket be opened for this analysis? */
export function shouldCreateRemediation(result: AnalysisResult): boolean {
  if (result.decision === "block") return true;
  if (result.secrets.length > 0) return true;
  if (result.findings.some((f) => f.severity === "high" || f.severity === "critical")) return true;
  if (result.dependencies.some((d) => d.riskLevel === "high" || d.riskLevel === "critical")) {
    return true;
  }
  return false;
}

/** Build the issue title + Markdown body (cahier §5.7 fields). */
export function buildRemediationIssue(params: {
  repository: string;
  prNumber: number;
  prTitle: string;
  result: AnalysisResult;
}): { title: string; description: string } {
  const { repository, prNumber, prTitle, result } = params;
  const title = `[CodeGate] Risque de sécurité — ${repository} PR #${prNumber}`;

  const lines: string[] = [];
  lines.push(`**PR :** ${repository} #${prNumber} — ${prTitle}`);
  lines.push(`**Score de risque :** ${result.riskScore}/100 — **décision : ${result.decision}**`);
  lines.push("");

  if (result.secrets.length) {
    lines.push(`### Secrets (${result.secrets.length})`);
    for (const s of result.secrets) lines.push(`- ${explainSecret(s)}`);
    lines.push("");
  }
  const riskyDeps = result.dependencies.filter((d) => d.riskLevel !== "low");
  if (riskyDeps.length) {
    lines.push(`### Dépendances à risque (${riskyDeps.length})`);
    for (const d of riskyDeps) lines.push(`- ${explainDependency(d)}`);
    lines.push("");
  }
  if (result.findings.length) {
    lines.push(`### Problèmes de code (${result.findings.length})`);
    for (const f of result.findings) lines.push(`- **[${f.severity}]** ${explainFinding(f)}`);
    lines.push("");
  }

  lines.push("---");
  lines.push("_Issue générée automatiquement par CodeGate — preuve d'audit conservée._");
  return { title, description: lines.join("\n") };
}

/** Create the issue via Linear's GraphQL API. */
export async function createLinearIssue(
  apiKey: string,
  teamId: string,
  issue: { title: string; description: string },
): Promise<LinearIssueRef> {
  const query = `
    mutation IssueCreate($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier url }
      }
    }`;

  const res = await fetch(LINEAR_GRAPHQL, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: apiKey },
    body: JSON.stringify({
      query,
      variables: { input: { teamId, title: issue.title, description: issue.description } },
    }),
  });

  if (!res.ok) throw new Error(`Linear API ${res.status}`);
  const body = (await res.json()) as {
    data?: { issueCreate?: { success: boolean; issue?: LinearIssueRef } };
    errors?: { message: string }[];
  };
  if (body.errors?.length) throw new Error(`Linear: ${body.errors[0]!.message}`);
  const created = body.data?.issueCreate;
  if (!created?.success || !created.issue) throw new Error("Linear: issueCreate failed");
  return created.issue;
}
