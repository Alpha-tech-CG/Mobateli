import type { FastifyInstance, FastifyRequest } from "fastify";
import { createHash, randomBytes } from "node:crypto";
import { prisma } from "@codegate/db";
import {
  backupRunReportSchema,
  backupVerifyReportSchema,
  createBackupJobSchema,
  restoreTestReportSchema,
} from "@codegate/shared";
import type { AppConfig } from "../config.js";
import { recordAudit } from "../lib/audit.js";
import { notifySlack } from "../lib/notify.js";
import { evaluateBackup, type BackupEvaluation } from "../analysis/backup.js";

const TOKEN_PREFIX = "cg_bkp_";
const MANAGE = ["owner", "admin", "security_manager"] as const;

const hashToken = (t: string) => createHash("sha256").update(t).digest("hex");
function newToken() {
  const token = TOKEN_PREFIX + randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token) };
}

const latestInclude = {
  runs: { orderBy: { finishedAt: "desc" as const }, take: 1 },
  restoreTests: { orderBy: { completedAt: "desc" as const }, take: 1 },
};

type JobWithLatest = {
  frequencyHours: number;
  runs: Parameters<typeof evaluateBackup>[1][];
  restoreTests: Parameters<typeof evaluateBackup>[2][];
};

function evaluate(job: JobWithLatest): BackupEvaluation {
  return evaluateBackup(job, job.runs[0] ?? null, job.restoreTests[0] ?? null);
}

/**
 * Backup Shield (extension §5, §8). Jobs are declared in the dashboard; the
 * backup host reports runs, integrity re-checks and isolated restore tests
 * with a per-job token. CodeGate never receives the backup data itself.
 */
export async function backupRoutes(app: FastifyInstance, config: AppConfig) {
  app.get("/api/v1/backups", { preHandler: [app.authenticate] }, async (req) => {
    const jobs = await prisma.backupJob.findMany({
      where: { organizationId: req.principal.organizationId },
      orderBy: { createdAt: "desc" },
      include: { ...latestInclude, server: { select: { name: true } } },
    });
    return {
      backups: jobs.map((j) => {
        const e = evaluate(j);
        return {
          id: j.id,
          name: j.name,
          type: j.type,
          frequencyHours: j.frequencyHours,
          server: j.server?.name ?? null,
          lastRunAt: j.runs[0]?.finishedAt ?? null,
          lastRestoreAt: j.restoreTests[0]?.completedAt ?? null,
          score: e.score,
          status: e.status,
          ransomwareReady: e.ransomwareReady,
          failedChecks: e.checks.filter((c) => !c.ok).length,
        };
      }),
    };
  });

  app.post(
    "/api/v1/backups",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const body = createBackupJobSchema.parse(req.body);
      if (body.serverId) {
        const server = await prisma.server.findFirst({
          where: { id: body.serverId, organizationId: req.principal.organizationId },
          select: { id: true },
        });
        if (!server) return reply.code(404).send({ error: "server_not_found" });
      }
      const { token, hash } = newToken();
      const job = await prisma.backupJob.create({
        data: {
          organizationId: req.principal.organizationId,
          name: body.name,
          type: body.type,
          frequencyHours: body.frequencyHours,
          serverId: body.serverId ?? null,
          tokenHash: hash,
        },
        select: { id: true, name: true, type: true, frequencyHours: true },
      });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "backup.job_created",
        resourceType: "backup_job",
        resourceId: job.id,
        metadata: { name: body.name, type: body.type },
      });
      return reply.code(201).send({ backup: job, reportToken: token });
    },
  );

  app.get("/api/v1/backups/:id", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const job = await prisma.backupJob.findFirst({
      where: { id, organizationId: req.principal.organizationId },
      include: {
        server: { select: { id: true, name: true } },
        runs: { orderBy: { finishedAt: "desc" }, take: 30 },
        restoreTests: { orderBy: { completedAt: "desc" }, take: 10 },
      },
    });
    if (!job) return reply.code(404).send({ error: "not_found" });
    const { tokenHash: _omit, ...safe } = job;
    return { backup: safe, evaluation: evaluate(job) };
  });

  // §8 "Vérifier intégrité et chiffrement": re-evaluate now from the facts.
  app.post("/api/v1/backups/:id/verify", { preHandler: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const job = await prisma.backupJob.findFirst({
      where: { id, organizationId: req.principal.organizationId },
      include: latestInclude,
    });
    if (!job) return reply.code(404).send({ error: "not_found" });
    return { evaluation: evaluate(job) };
  });

  // Restore tests run on the customer's side, in a throwaway container: the
  // API hands back the exact command (it never touches the customer's data).
  app.post(
    "/api/v1/backups/:id/restore-test",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const job = await prisma.backupJob.findFirst({
        where: { id, organizationId: req.principal.organizationId },
        select: { type: true },
      });
      if (!job) return reply.code(404).send({ error: "not_found" });
      if (job.type !== "postgres") {
        return reply.code(422).send({ error: "restore_engine_unsupported" });
      }
      return reply.code(202).send({
        command:
          "sudo codegate-backup restore-test --engine postgres --file <dump> " +
          "[--decrypt-cmd 'age -d -i /chemin/cle.txt'] --token-file /etc/codegate/backup.token",
      });
    },
  );

  app.post(
    "/api/v1/backups/:id/rotate-token",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const { token, hash } = newToken();
      const res = await prisma.backupJob.updateMany({
        where: { id, organizationId: req.principal.organizationId },
        data: { tokenHash: hash },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "backup.token_rotated",
        resourceType: "backup_job",
        resourceId: id,
      });
      return { reportToken: token };
    },
  );

  app.delete(
    "/api/v1/backups/:id",
    { preHandler: [app.authenticate, app.requireRole(...MANAGE)] },
    async (req, reply) => {
      const { id } = req.params as { id: string };
      const res = await prisma.backupJob.deleteMany({
        where: { id, organizationId: req.principal.organizationId },
      });
      if (!res.count) return reply.code(404).send({ error: "not_found" });
      await recordAudit({
        organizationId: req.principal.organizationId,
        actorType: "user",
        actorId: req.principal.userId,
        action: "backup.job_removed",
        resourceType: "backup_job",
        resourceId: id,
      });
      return reply.code(204).send();
    },
  );

  app.get("/api/v1/reports/backup", { preHandler: [app.authenticate] }, async (req) => {
    const jobs = await prisma.backupJob.findMany({
      where: { organizationId: req.principal.organizationId },
      include: latestInclude,
    });
    const rows = jobs.map((j) => ({ id: j.id, name: j.name, type: j.type, ...evaluate(j) }));
    return {
      generatedAt: new Date().toISOString(),
      recoveryScore: rows.length
        ? Math.round(rows.reduce((s, r) => s + r.score, 0) / rows.length)
        : null,
      encryptedShare: rows.length
        ? rows.filter((r) => r.checks.find((c) => c.id === "encryption_at_rest")?.ok).length / rows.length
        : null,
      restoreTestedShare: rows.length
        ? rows.filter((r) => r.checks.find((c) => c.id === "restore_test")?.ok).length / rows.length
        : null,
      backups: rows,
    };
  });

  // ── Ingestion from the backup host (bearer cg_bkp_…) ──

  async function jobFromToken(req: FastifyRequest) {
    const auth = req.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token.startsWith(TOKEN_PREFIX)) return null;
    return prisma.backupJob.findUnique({
      where: { tokenHash: hashToken(token) },
      select: { id: true, name: true, organizationId: true, frequencyHours: true },
    });
  }

  async function alert(orgId: string, jobName: string, title: string, detail: string) {
    await notifySlack(orgId, config.ENCRYPTION_KEY, {
      title,
      severity: "critical",
      repository: `Sauvegarde « ${jobName} »`,
      detail,
    });
  }

  app.post("/api/v1/backups/agent/run", async (req, reply) => {
    const job = await jobFromToken(req);
    if (!job) return reply.code(401).send({ error: "invalid_backup_token" });
    const body = backupRunReportSchema.parse(req.body);
    const run = await prisma.backupRun.create({
      data: { jobId: job.id, ...body, finishedAt: new Date(body.finishedAt) },
    });
    const evaluation = evaluate(
      await prisma.backupJob.findUniqueOrThrow({ where: { id: job.id }, include: latestInclude }),
    );
    await recordAudit({
      organizationId: job.organizationId,
      actorType: "system",
      action: "backup.run_reported",
      resourceType: "backup_job",
      resourceId: job.id,
      metadata: { status: body.status, encrypted: body.encrypted, score: evaluation.score },
    });
    if (body.status === "failed") {
      await alert(job.organizationId, job.name, "Échec de sauvegarde", "La dernière exécution a échoué.");
    }
    return reply.code(202).send({ runId: run.id, score: evaluation.score, status: evaluation.status });
  });

  app.post("/api/v1/backups/agent/verify", async (req, reply) => {
    const job = await jobFromToken(req);
    if (!job) return reply.code(401).send({ error: "invalid_backup_token" });
    const { sha256 } = backupVerifyReportSchema.parse(req.body);
    // The copy is genuine if it matches any backup recorded for this job.
    const match = await prisma.backupRun.findFirst({
      where: { jobId: job.id, sha256 },
      orderBy: { finishedAt: "desc" },
    });
    const target =
      match ??
      (await prisma.backupRun.findFirst({ where: { jobId: job.id }, orderBy: { finishedAt: "desc" } }));
    if (!target) return reply.code(409).send({ error: "no_backup_reported" });
    await prisma.backupRun.update({
      where: { id: target.id },
      data: { integrityCheckedAt: new Date(), integrityOk: match !== null },
    });
    await recordAudit({
      organizationId: job.organizationId,
      actorType: "system",
      action: match ? "backup.integrity_ok" : "backup.integrity_mismatch",
      resourceType: "backup_job",
      resourceId: job.id,
      metadata: { runId: target.id },
    });
    if (!match) {
      await alert(
        job.organizationId,
        job.name,
        "Sauvegarde altérée",
        "Une copie stockée ne correspond à aucune empreinte enregistrée (corruption ou modification).",
      );
    }
    return { integrityOk: match !== null, runId: target.id };
  });

  app.post("/api/v1/backups/agent/restore-test", async (req, reply) => {
    const job = await jobFromToken(req);
    if (!job) return reply.code(401).send({ error: "invalid_backup_token" });
    const body = restoreTestReportSchema.parse(req.body);
    const test = await prisma.backupRestoreTest.create({
      data: {
        jobId: job.id,
        ...body,
        startedAt: new Date(body.startedAt),
        completedAt: new Date(body.completedAt),
      },
    });
    await recordAudit({
      organizationId: job.organizationId,
      actorType: "system",
      action: `backup.restore_${body.result}`,
      resourceType: "backup_job",
      resourceId: job.id,
      metadata: {
        engine: body.engine,
        durationSeconds: body.durationSeconds,
        restoredTables: body.restoredTables,
      },
    });
    if (body.result === "failed") {
      await alert(
        job.organizationId,
        job.name,
        "Restauration impossible",
        `Le test de restauration a échoué${body.detail ? ` : ${body.detail}` : ""}.`,
      );
    }
    return reply.code(201).send({ restoreTestId: test.id });
  });
}
