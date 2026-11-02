import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Redis } from "ioredis";
import { createHash } from "node:crypto";
import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { verifyGithubSignature, verifyVercelSignature } from "../lib/webhook-verify.js";
import { claimDelivery, releaseDelivery } from "../lib/redis.js";
import { enqueuePrAnalysis } from "../queues/pr-analysis.js";
import { recordAudit } from "../lib/audit.js";
import { evaluateDeployGate } from "../analysis/deploy-gate.js";
import { notifySlack } from "../lib/notify.js";

/** Heuristic: was this PR likely opened by an AI coding agent? (cahier §5.1) */
function looksAiGenerated(authorLogin: string, title: string, body: string): boolean {
  const needles = ["cursor", "claude", "copilot", "codex", "windsurf", "devin", "[bot]"];
  const hay = `${authorLogin} ${title} ${body}`.toLowerCase();
  return needles.some((n) => hay.includes(n)) || /generated with/i.test(body);
}

async function resolveOrg(
  installationId: number,
  opts?: { autoLink?: boolean; accountLogin?: string },
): Promise<string | null> {
  const inst = await prisma.githubInstallation.findUnique({
    where: { installationId: BigInt(installationId) },
    select: { organizationId: true },
  });
  if (inst) return inst.organizationId;

  // Dev convenience: when exactly one organization exists, auto-link a new
  // installation to it so self-hosted single-org testing works without a
  // manual mapping step. Never in production (there, use a connect flow).
  if (opts?.autoLink) {
    const orgs = await prisma.organization.findMany({ select: { id: true }, take: 2 });
    if (orgs.length === 1) {
      await prisma.githubInstallation.create({
        data: {
          organizationId: orgs[0]!.id,
          installationId: BigInt(installationId),
          accountLogin: opts.accountLogin ?? "github",
        },
      });
      return orgs[0]!.id;
    }
  }
  return null;
}

type GithubRepo = { id: number; full_name: string; default_branch?: string };

async function upsertRepository(
  organizationId: string,
  installationId: number,
  repo: GithubRepo,
): Promise<string> {
  const row = await prisma.repository.upsert({
    where: { provider_externalId: { provider: "github", externalId: String(repo.id) } },
    create: {
      organizationId,
      provider: "github",
      externalId: String(repo.id),
      name: repo.full_name,
      defaultBranch: repo.default_branch ?? "main",
      installationId: BigInt(installationId),
    },
    update: {
      name: repo.full_name,
      installationId: BigInt(installationId),
      ...(repo.default_branch ? { defaultBranch: repo.default_branch } : {}),
    },
    select: { id: true },
  });
  return row.id;
}

/* eslint-disable @typescript-eslint/no-explicit-any */
async function handlePullRequest(
  req: FastifyRequest,
  payload: any,
  connection: Redis,
  devAutoLink: boolean,
): Promise<void> {
  const action: string = payload.action;
  if (!["opened", "synchronize", "reopened"].includes(action)) return;

  const installationId: number | undefined = payload.installation?.id;
  if (!installationId) return;
  const organizationId = await resolveOrg(installationId, {
    autoLink: devAutoLink,
    ...(payload.installation?.account?.login
      ? { accountLogin: payload.installation.account.login }
      : {}),
  });
  if (!organizationId) {
    req.log.warn({ installationId }, "webhook for unknown installation — skipped");
    return;
  }

  const repositoryId = await upsertRepository(organizationId, installationId, payload.repository);

  const pr = payload.pull_request;
  const aiGenerated = looksAiGenerated(pr.user?.login ?? "", pr.title ?? "", pr.body ?? "");

  const row = await prisma.pullRequest.upsert({
    where: {
      repositoryId_externalId: { repositoryId, externalId: String(pr.id) },
    },
    create: {
      repositoryId,
      externalId: String(pr.id),
      number: pr.number,
      title: pr.title ?? "",
      author: pr.user?.login ?? "unknown",
      aiGenerated,
      headSha: pr.head?.sha ?? null,
      status: "pending",
    },
    update: {
      title: pr.title ?? "",
      aiGenerated,
      headSha: pr.head?.sha ?? null,
      status: "pending",
    },
    select: { id: true },
  });

  await recordAudit({
    organizationId,
    actorType: "system",
    action: `pr.${action}`,
    resourceType: "pull_request",
    resourceId: row.id,
    metadata: { number: pr.number, aiGenerated },
  });

  await enqueuePrAnalysis(connection, {
    pullRequestId: row.id,
    reason: action as "opened" | "synchronize" | "reopened",
  });
}

async function handleInstallationRepositories(payload: any): Promise<void> {
  const installationId: number | undefined = payload.installation?.id;
  if (!installationId) return;
  const organizationId = await resolveOrg(installationId);
  if (!organizationId) return;

  for (const repo of payload.repositories_added ?? []) {
    await upsertRepository(organizationId, installationId, repo);
  }
  for (const repo of payload.repositories_removed ?? []) {
    await prisma.repository.deleteMany({
      where: { provider: "github", externalId: String(repo.id) },
    });
  }
}

async function handleGitlabMergeRequest(
  organizationId: string,
  payload: any,
  connection: Redis,
): Promise<void> {
  const attrs = payload.object_attributes ?? {};
  const action: string = attrs.action;
  if (!["open", "reopen", "update"].includes(action)) return;

  const project = payload.project ?? {};
  if (!project.id || !project.path_with_namespace) return;

  const repoRow = await prisma.repository.upsert({
    where: { provider_externalId: { provider: "gitlab", externalId: String(project.id) } },
    create: {
      organizationId,
      provider: "gitlab",
      externalId: String(project.id),
      name: project.path_with_namespace,
      defaultBranch: project.default_branch ?? "main",
    },
    update: { name: project.path_with_namespace },
    select: { id: true },
  });

  const author = payload.user?.username ?? "unknown";
  const title: string = attrs.title ?? "";
  const aiGenerated = looksAiGenerated(author, title, attrs.description ?? "");

  const row = await prisma.pullRequest.upsert({
    where: {
      repositoryId_externalId: { repositoryId: repoRow.id, externalId: String(attrs.iid) },
    },
    create: {
      repositoryId: repoRow.id,
      externalId: String(attrs.iid),
      number: attrs.iid,
      title,
      author,
      aiGenerated,
      headSha: attrs.last_commit?.id ?? null,
      status: "pending",
    },
    update: { title, aiGenerated, headSha: attrs.last_commit?.id ?? null, status: "pending" },
    select: { id: true },
  });

  await recordAudit({
    organizationId,
    actorType: "system",
    action: `pr.${action === "open" ? "opened" : action}`,
    resourceType: "pull_request",
    resourceId: row.id,
    metadata: { provider: "gitlab", iid: attrs.iid, aiGenerated },
  });

  await enqueuePrAnalysis(connection, {
    pullRequestId: row.id,
    reason: action === "open" ? "opened" : action === "reopen" ? "reopened" : "synchronize",
  });
}

async function handleVercelDeployment(
  req: FastifyRequest,
  payload: any,
  encryptionKey: string,
): Promise<void> {
  const deployment = payload.payload?.deployment ?? payload.deployment;
  const meta = deployment?.meta ?? {};
  const org: string | undefined = meta.githubCommitOrg;
  const name: string | undefined = meta.githubCommitRepo;
  const deploymentId: string | undefined = deployment?.id ?? payload.payload?.deployment?.id;
  if (!org || !name || !deploymentId) {
    req.log.warn("vercel deployment without git repo metadata — skipped");
    return;
  }
  const fullName = `${org}/${name}`;

  const repo = await prisma.repository.findFirst({
    where: { provider: "github", name: fullName },
    select: { id: true, organizationId: true, protectionLevel: true },
  });
  if (!repo) {
    req.log.warn({ fullName }, "vercel deploy for unknown repository — skipped");
    return;
  }

  // Gather the security posture of what's being shipped.
  const prWhere = { pullRequest: { repositoryId: repo.id } };
  const [openSecrets, criticalFindings, highFindings, criticalDependencies, latestPr] =
    await Promise.all([
      prisma.secretFinding.count({ where: { ...prWhere, status: "open" } }),
      prisma.finding.count({ where: { ...prWhere, severity: "critical", status: "open" } }),
      prisma.finding.count({ where: { ...prWhere, severity: "high", status: "open" } }),
      prisma.dependency.count({ where: { ...prWhere, riskLevel: "critical" } }),
      prisma.pullRequest.findFirst({
        where: { repositoryId: repo.id },
        orderBy: { createdAt: "desc" },
        select: { status: true },
      }),
    ]);

  const result = evaluateDeployGate(
    {
      openSecrets,
      criticalFindings,
      highFindings,
      criticalDependencies,
      latestPrBlocked: latestPr?.status === "blocked",
    },
    repo.protectionLevel,
  );

  await prisma.deployCheck.upsert({
    where: { provider_externalId: { provider: "vercel", externalId: deploymentId } },
    create: {
      repositoryId: repo.id,
      provider: "vercel",
      externalId: deploymentId,
      target: meta.githubCommitRef ?? deployment?.target ?? null,
      commitSha: meta.githubCommitSha ?? null,
      decision: result.decision,
      reason: result.reason,
    },
    update: { decision: result.decision, reason: result.reason },
  });

  await recordAudit({
    organizationId: repo.organizationId,
    actorType: "system",
    action: `deploy.${result.decision}`,
    resourceType: "repository",
    resourceId: repo.id,
    metadata: { deploymentId, decision: result.decision, reason: result.reason },
  });

  if (result.decision === "blocked") {
    await notifySlack(repo.organizationId, encryptionKey, {
      title: "Déploiement bloqué",
      severity: "critical",
      repository: fullName,
      detail: result.reason,
    });
  }
}

async function handleInstallationDeleted(payload: any): Promise<void> {
  const installationId: number | undefined = payload.installation?.id;
  if (!installationId) return;
  // Removes the mapping and cascades to its repositories is not automatic
  // (repos belong to the org, not the installation) — detach them instead.
  await prisma.repository.updateMany({
    where: { installationId: BigInt(installationId) },
    data: { installationId: null },
  });
  await prisma.githubInstallation.deleteMany({
    where: { installationId: BigInt(installationId) },
  });
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export async function webhookRoutes(
  app: FastifyInstance,
  config: AppConfig,
  connection: Redis,
) {
  // Capture the raw body (needed for signature verification) instead of the
  // default JSON parse. Scoped to this plugin only.
  app.addContentTypeParser(
    "application/json",
    { parseAs: "buffer" },
    (_req, body, done) => done(null, body),
  );

  app.post("/webhooks/github", async (req, reply) => {
    if (!config.GITHUB_WEBHOOK_SECRET) {
      return reply.code(503).send({ error: "github_not_configured" });
    }

    const raw = req.body as Buffer;
    const signature = req.headers["x-hub-signature-256"] as string | undefined;
    if (!verifyGithubSignature(raw, signature, config.GITHUB_WEBHOOK_SECRET)) {
      return reply.code(401).send({ error: "invalid_signature" });
    }

    const deliveryId = req.headers["x-github-delivery"] as string | undefined;
    if (deliveryId && !(await claimDelivery(connection, deliveryId))) {
      // Replay of an already-processed delivery — acknowledge and stop.
      return reply.code(200).send({ status: "duplicate" });
    }

    const event = req.headers["x-github-event"] as string | undefined;
    let payload: unknown;
    try {
      payload = JSON.parse(raw.toString("utf8"));
    } catch {
      return reply.code(400).send({ error: "invalid_json" });
    }

    const devAutoLink = config.NODE_ENV !== "production";
    try {
      switch (event) {
        case "pull_request":
          await handlePullRequest(req, payload, connection, devAutoLink);
          break;
        case "installation_repositories":
          await handleInstallationRepositories(payload);
          break;
        case "installation": {
          const action = (payload as { action?: string }).action;
          if (action === "created") {
            // Pre-link the installation (dev: to the sole org) and log its id.
            const instId = (payload as { installation?: { id?: number } }).installation?.id;
            const login = (payload as { installation?: { account?: { login?: string } } })
              .installation?.account?.login;
            if (instId) {
              const org = await resolveOrg(instId, {
                autoLink: devAutoLink,
                ...(login ? { accountLogin: login } : {}),
              });
              req.log.info({ installationId: instId, login, linked: org !== null }, "github app installed");
            }
          } else if (action === "deleted") {
            await handleInstallationDeleted(payload);
          }
          break;
        }
        default:
          // Unhandled event — acknowledge so GitHub stops retrying.
          break;
      }
    } catch (err) {
      req.log.error({ err, event }, "webhook handler error");
      // Release the idempotency claim so GitHub's retry is processed afresh.
      if (deliveryId) await releaseDelivery(connection, deliveryId);
      return reply.code(500).send({ error: "handler_error" });
    }

    return reply.code(202).send({ status: "accepted" });
  });

  app.post("/webhooks/gitlab", async (req, reply) => {
    const raw = req.body as Buffer;
    const token = req.headers["x-gitlab-token"] as string | undefined;
    if (!token) return reply.code(401).send({ error: "missing_token" });

    // Identify the org by the hash of the shared secret token.
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const conn = await prisma.gitlabConnection.findUnique({
      where: { tokenHash },
      select: { organizationId: true },
    });
    if (!conn) return reply.code(401).send({ error: "invalid_token" });

    const deliveryId = req.headers["x-gitlab-event-uuid"] as string | undefined;
    if (deliveryId && !(await claimDelivery(connection, deliveryId))) {
      return reply.code(200).send({ status: "duplicate" });
    }

    let payload: any;
    try {
      payload = JSON.parse(raw.toString("utf8"));
    } catch {
      return reply.code(400).send({ error: "invalid_json" });
    }

    try {
      if (payload.object_kind === "merge_request") {
        await handleGitlabMergeRequest(conn.organizationId, payload, connection);
      }
    } catch (err) {
      req.log.error({ err }, "gitlab webhook handler error");
      if (deliveryId) await releaseDelivery(connection, deliveryId);
      return reply.code(500).send({ error: "handler_error" });
    }

    return reply.code(202).send({ status: "accepted" });
  });

  app.post("/webhooks/vercel", async (req, reply) => {
    if (!config.VERCEL_WEBHOOK_SECRET) {
      return reply.code(503).send({ error: "vercel_not_configured" });
    }

    const raw = req.body as Buffer;
    const signature = req.headers["x-vercel-signature"] as string | undefined;
    if (!verifyVercelSignature(raw, signature, config.VERCEL_WEBHOOK_SECRET)) {
      return reply.code(401).send({ error: "invalid_signature" });
    }

    const deliveryId = req.headers["x-vercel-id"] as string | undefined;
    if (deliveryId && !(await claimDelivery(connection, deliveryId))) {
      return reply.code(200).send({ status: "duplicate" });
    }

    let payload: unknown;
    try {
      payload = JSON.parse(raw.toString("utf8"));
    } catch {
      return reply.code(400).send({ error: "invalid_json" });
    }

    try {
      if ((payload as { type?: string }).type === "deployment.created") {
        await handleVercelDeployment(req, payload, config.ENCRYPTION_KEY);
      }
    } catch (err) {
      req.log.error({ err }, "vercel webhook handler error");
      if (deliveryId) await releaseDelivery(connection, deliveryId);
      return reply.code(500).send({ error: "handler_error" });
    }

    return reply.code(202).send({ status: "accepted" });
  });
}
