import type { FastifyInstance } from "fastify";
import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import type { Jobs } from "../lib/jobs.js";
import { getInstallationOctokit } from "../lib/github.js";
import { gitlabForOrg } from "../lib/gitlab.js";
import { looksAiGenerated } from "./webhooks.js";

const ANALYZE_ROLES = ["owner", "admin", "security_manager", "developer"] as const;

interface OpenPr {
  number: number;
  externalId: string;
  title: string;
  author: string;
  body: string;
  headSha: string | null;
  url: string;
  updatedAt: string;
}

async function listOpen(config: AppConfig, repo: RepoRow): Promise<OpenPr[]> {
  if (repo.provider === "github") {
    if (repo.installationId == null) throw new Error("github_not_installed");
    const [owner, name] = repo.name.split("/") as [string, string];
    const octokit = await getInstallationOctokit(config, Number(repo.installationId));
    const { data } = await octokit.request("GET /repos/{owner}/{repo}/pulls", {
      owner,
      repo: name,
      state: "open",
      per_page: 50,
      sort: "updated",
      direction: "desc",
    });
    return data.map((p) => ({
      number: p.number,
      externalId: String(p.id),
      title: p.title,
      author: p.user?.login ?? "unknown",
      body: p.body ?? "",
      headSha: p.head?.sha ?? null,
      url: p.html_url,
      updatedAt: p.updated_at,
    }));
  }
  const api = await gitlabForOrg(repo.organizationId, config.ENCRYPTION_KEY);
  if (!api) throw new Error("gitlab_api_not_configured");
  const mrs = await api.request<
    { iid: number; title: string; description: string | null; sha: string; web_url: string; updated_at: string; author?: { username?: string } }[]
  >(`/projects/${encodeURIComponent(repo.externalId)}/merge_requests?state=opened&per_page=50&order_by=updated_at`);
  return mrs.map((m) => ({
    number: m.iid,
    externalId: String(m.iid),
    title: m.title,
    author: m.author?.username ?? "unknown",
    body: m.description ?? "",
    headSha: m.sha,
    url: m.web_url,
    updatedAt: m.updated_at,
  }));
}

interface RepoRow {
  id: string;
  name: string;
  provider: "github" | "gitlab";
  organizationId: string;
  installationId: bigint | null;
  externalId: string;
}

const ERRORS = new Set(["github_not_installed", "gitlab_api_not_configured"]);

/**
 * Pull requests from the platform: pick a project, see its open pull / merge
 * requests and analyse one on demand — the same path as the webhook, without
 * waiting for a new push.
 */
export async function prImportRoutes(app: FastifyInstance, config: AppConfig, jobs: Jobs) {
  async function repoFor(id: string, organizationId: string): Promise<RepoRow | null> {
    return prisma.repository.findFirst({
      where: { id, organizationId },
      select: { id: true, name: true, provider: true, organizationId: true, installationId: true, externalId: true },
    });
  }

  app.get(
    "/api/v1/repositories/:id/open-pull-requests",
    { preHandler: [app.authenticate] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const repo = await repoFor(id, req.principal.organizationId);
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });
      let open: OpenPr[];
      try {
        open = await listOpen(config, repo);
      } catch (err) {
        const code = err instanceof Error && ERRORS.has(err.message) ? err.message : "provider_unreachable";
        return reply.code(409).send({ error: code });
      }
      const known = await prisma.pullRequest.findMany({
        where: { repositoryId: repo.id, externalId: { in: open.map((p) => p.externalId) } },
        select: { id: true, externalId: true, headSha: true, riskScore: true, status: true },
      });
      const byExt = new Map(known.map((k) => [k.externalId, k]));
      return {
        pullRequests: open.map((p) => {
          const k = byExt.get(p.externalId);
          return {
            number: p.number,
            title: p.title,
            author: p.author,
            url: p.url,
            updatedAt: p.updatedAt,
            analysis: k
              ? { id: k.id, riskScore: k.riskScore, status: k.status, upToDate: k.headSha === p.headSha }
              : null,
          };
        }),
      };
    },
  );

  app.post(
    "/api/v1/repositories/:id/pull-requests/:number/analyze",
    { preHandler: [app.authenticate, app.requireRole(...ANALYZE_ROLES)] },
    async (req, reply) => {
      const { id, number } = req.params as { id: string; number: string };
      const repo = await repoFor(id, req.principal.organizationId);
      if (!repo) return reply.code(404).send({ error: "repository_not_found" });
      let open: OpenPr[];
      try {
        open = await listOpen(config, repo);
      } catch (err) {
        const code = err instanceof Error && ERRORS.has(err.message) ? err.message : "provider_unreachable";
        return reply.code(409).send({ error: code });
      }
      const p = open.find((x) => x.number === Number(number));
      if (!p) return reply.code(404).send({ error: "pull_request_not_open" });

      const aiGenerated = looksAiGenerated(p.author, p.title, p.body);
      const row = await prisma.pullRequest.upsert({
        where: { repositoryId_externalId: { repositoryId: repo.id, externalId: p.externalId } },
        create: {
          repositoryId: repo.id,
          externalId: p.externalId,
          number: p.number,
          title: p.title,
          author: p.author,
          aiGenerated,
          headSha: p.headSha,
          status: "pending",
        },
        update: { title: p.title, aiGenerated, headSha: p.headSha, status: "pending" },
        select: { id: true },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "pr.analysis_requested",
        resourceType: "pull_request",
        resourceId: row.id,
        metadata: { repository: repo.name, number: p.number },
      });
      await jobs.dispatchPrAnalysis({ pullRequestId: row.id, reason: "manual_rescan" });
      return reply.code(202).send({ pullRequestId: row.id });
    },
  );
}
