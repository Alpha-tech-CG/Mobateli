import type { AnalysisResult } from "../analysis/types.js";
import { explainSecret, explainDependency, explainFinding } from "../analysis/explainer.js";

/**
 * Jira Cloud connector (cahier §12.2 P3). Creates a remediation issue via the
 * REST API v3. Credentials are passed in already decrypted.
 */

export interface JiraCredentials {
  baseUrl: string;
  email: string;
  apiToken: string;
  projectKey: string;
}

export interface JiraIssueRef {
  key: string;
  url: string;
}

/** Minimal Atlassian Document Format node. */
interface AdfNode {
  type: string;
  version?: number;
  content?: AdfNode[];
  text?: string;
  attrs?: Record<string, unknown>;
}

/** Build the issue summary + ADF description (cahier §5.7 fields). */
export function buildJiraIssue(params: {
  repository: string;
  prNumber: number;
  prTitle: string;
  result: AnalysisResult;
}): { summary: string; description: AdfNode } {
  const { repository, prNumber, prTitle, result } = params;
  const summary = `[CodeGate] Risque de sécurité — ${repository} PR #${prNumber}`;

  const paragraphs: string[] = [];
  paragraphs.push(`${repository} #${prNumber} — ${prTitle}`);
  paragraphs.push(`Score de risque : ${result.riskScore}/100 — décision : ${result.decision}`);
  for (const s of result.secrets) paragraphs.push(`🔑 ${explainSecret(s)}`);
  for (const d of result.dependencies.filter((x) => x.riskLevel !== "low")) {
    paragraphs.push(`📦 ${explainDependency(d)}`);
  }
  for (const f of result.findings) paragraphs.push(`🔎 [${f.severity}] ${explainFinding(f)}`);
  paragraphs.push("Issue générée automatiquement par CodeGate — preuve d'audit conservée.");

  const description: AdfNode = {
    type: "doc",
    version: 1, // ADF requires version at the document root.
    content: paragraphs.map((text) => ({
      type: "paragraph",
      content: [{ type: "text", text }],
    })),
  };

  return { summary, description };
}

/** Create the issue via Jira REST API v3 (Basic auth: email + API token). */
export async function createJiraIssue(
  creds: JiraCredentials,
  issue: { summary: string; description: AdfNode },
): Promise<JiraIssueRef> {
  const auth = Buffer.from(`${creds.email}:${creds.apiToken}`).toString("base64");
  const base = creds.baseUrl.replace(/\/+$/, "");

  const res = await fetch(`${base}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      authorization: `Basic ${auth}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      fields: {
        project: { key: creds.projectKey },
        issuetype: { name: "Bug" },
        summary: issue.summary,
        description: issue.description,
      },
    }),
  });

  if (!res.ok) throw new Error(`Jira API ${res.status}`);
  const body = (await res.json()) as { key?: string };
  if (!body.key) throw new Error("Jira: issue create returned no key");
  return { key: body.key, url: `${base}/browse/${body.key}` };
}
