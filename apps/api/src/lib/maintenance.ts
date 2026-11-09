import { prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { recordAudit } from "./audit.js";
import { notifySlack } from "./notify.js";
import { remindExpiringExceptions } from "./exceptions.js";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** An agent scheduled every 6 h that has been quiet for a day is down or removed. */
const SILENT_AGENT_HOURS = 24;

export interface MaintenanceSummary {
  purged: {
    pullRequests: number;
    auditEvents: number;
    bruteforceTests: number;
    backupRuns: number;
    throttles: number;
    deliveries: number;
  };
  alerts: { missingBackups: number; silentAgents: number; expiringExceptions: number };
}

/**
 * Daily maintenance (Vercel Cron): data retention (cahier §11.2 « rétention
 * limitée ») and proactive alerts — a backup that stopped running (extension
 * §12, detection < 24 h) or a server agent that went silent. Each alert fires
 * once and re-arms when the job / agent reports again.
 */
export async function runMaintenance(config: AppConfig, now = new Date()): Promise<MaintenanceSummary> {
  const before = (days: number) => new Date(now.getTime() - days * DAY);

  const [pullRequests, auditEvents, bruteforceTests, backupRuns, throttles, deliveries] =
    await Promise.all([
      prisma.pullRequest.deleteMany({ where: { createdAt: { lt: before(config.RETENTION_DAYS) } } }),
      prisma.auditEvent.deleteMany({ where: { createdAt: { lt: before(config.AUDIT_RETENTION_DAYS) } } }),
      prisma.bruteForceTest.deleteMany({ where: { createdAt: { lt: before(config.RETENTION_DAYS) } } }),
      prisma.backupRun.deleteMany({ where: { finishedAt: { lt: before(config.RETENTION_DAYS) } } }),
      prisma.authThrottle.deleteMany({
        where: {
          updatedAt: { lt: before(2) },
          OR: [{ lockedUntil: null }, { lockedUntil: { lt: now } }],
        },
      }),
      prisma.webhookDelivery.deleteMany({ where: { createdAt: { lt: before(7) } } }),
    ]);

  // ── Missing backups ──
  let missingBackups = 0;
  const jobs = await prisma.backupJob.findMany({
    where: { lateAlertedAt: null },
    include: { runs: { orderBy: { finishedAt: "desc" }, take: 1, select: { finishedAt: true } } },
  });
  for (const job of jobs) {
    const last = job.runs[0]?.finishedAt ?? job.createdAt;
    const lateHours = (now.getTime() - last.getTime()) / HOUR;
    if (lateHours <= job.frequencyHours * 1.5) continue;
    missingBackups++;
    await prisma.backupJob.update({ where: { id: job.id }, data: { lateAlertedAt: now } });
    await recordAudit({
      organizationId: job.organizationId,
      actorType: "system",
      action: "backup.missing",
      resourceType: "backup_job",
      resourceId: job.id,
      metadata: { lastRunAt: job.runs[0]?.finishedAt?.toISOString() ?? null, frequencyHours: job.frequencyHours },
    });
    await notifySlack(job.organizationId, config.ENCRYPTION_KEY, {
      title: "Sauvegarde manquante",
      severity: "critical",
      repository: `Sauvegarde « ${job.name} »`,
      detail: job.runs[0]
        ? `Aucune exécution depuis ${Math.round(lateHours)} h (attendue toutes les ${job.frequencyHours} h).`
        : `Aucune exécution n'a jamais été déclarée depuis la création du job.`,
    });
  }

  // ── Silent server agents ──
  let silentAgents = 0;
  const servers = await prisma.server.findMany({
    where: { silentAlertedAt: null, lastReportAt: { lt: new Date(now.getTime() - SILENT_AGENT_HOURS * HOUR) } },
    select: { id: true, name: true, organizationId: true, lastReportAt: true },
  });
  for (const server of servers) {
    silentAgents++;
    await prisma.server.update({ where: { id: server.id }, data: { silentAlertedAt: now } });
    await recordAudit({
      organizationId: server.organizationId,
      actorType: "system",
      action: "server.agent_silent",
      resourceType: "server",
      resourceId: server.id,
      metadata: { lastReportAt: server.lastReportAt!.toISOString() },
    });
    await notifySlack(server.organizationId, config.ENCRYPTION_KEY, {
      title: "Agent serveur silencieux",
      severity: "warning",
      repository: server.name,
      detail: `Aucun rapport depuis plus de ${SILENT_AGENT_HOURS} h : serveur arrêté, agent retiré ou cron supprimé.`,
    });
  }

  // Exceptions about to lapse: their owners renew them or let the alerts back.
  const expiring = await remindExpiringExceptions(config.ENCRYPTION_KEY, now);

  return {
    purged: {
      pullRequests: pullRequests.count,
      auditEvents: auditEvents.count,
      bruteforceTests: bruteforceTests.count,
      backupRuns: backupRuns.count,
      throttles: throttles.count,
      deliveries: deliveries.count,
    },
    alerts: { missingBackups, silentAgents, expiringExceptions: expiring.reminded },
  };
}
