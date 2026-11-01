import type { FastifyInstance, FastifyRequest } from "fastify";
import type { Redis } from "ioredis";
import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { verifyGithubSignature } from "../lib/webhook-verify.js";
import { claimDelivery, releaseDelivery } from "../lib/redis.js";
import { enqueuePrAnalysis } from "../queues/pr-analysis.js";
import { recordAudit } from "../lib/audit.js";

/** Heuristic: was this PR likely opened by an AI coding agent? (cahier §5.1) */
function looksAiGenerated(authorLogin: string, title: string, body: string): boolean {
  const needles = ["cursor", "claude", "copilot", "codex", "windsurf", "devin", "[bot]"];
  const hay = `${authorLogin} ${title} ${body}`.toLowerCase();
  return needles.some((n) => hay.includes(n)) || /generated with/i.test(body);
}

async function resolveOrg(installationId: number): Promise<string | null> {
  const inst = await prisma.githubInstallation.findUnique({
    where: { installationId: BigInt(installationId) },
    select: { organizationId: true },
  });
  return inst?.organizationId ?? null;
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
): Promise<void> {
  const action: string = payload.action;
  if (!["opened", "synchronize", "reopened"].includes(action)) return;

  const installationId: number | undefined = payload.installation?.id;
  if (!installationId) return;
  const organizationId = await resolveOrg(installationId);
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
      status: "pending",
    },
    update: {
      title: pr.title ?? "",
      aiGenerated,
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

    try {
      switch (event) {
        case "pull_request":
          await handlePullRequest(req, payload, connection);
          break;
        case "installation_repositories":
          await handleInstallationRepositories(payload);
          break;
        case "installation":
          if ((payload as { action?: string }).action === "deleted") {
            await handleInstallationDeleted(payload);
          }
          break;
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
}
