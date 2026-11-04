import { prisma, type Prisma } from "@codegate/db";
import type { AppConfig } from "../config.js";
import { analyzeFiles } from "../analysis/analyzer.js";
import { enrichDependencies } from "../analysis/dependency-intel.js";
import { dedupeDependencies, lockedNpmVersions, resolveInstalledVersions } from "../analysis/lockfiles.js";
import { decide } from "../analysis/risk.js";
import { analyzeArchitecture, type ArchitectureReport } from "../analysis/architecture.js";
import { recordAudit } from "./audit.js";
import { notifySlack } from "./notify.js";
import { getInstallationOctokit } from "./github.js";
import { gitlabForOrg } from "./gitlab.js";
import { extractTarGz } from "./repo-archive.js";

/**
 * Analysis of a repository's existing code (default branch), on demand or
 * automatically. Same pipeline as pull requests — Rust engine, rules, prompt
 * injection, dependencies — over every file of the snapshot. The scan record
 * carries a `phase` so the dashboard can show live progress.
 */

const MAX_FINDINGS_STORED = 500;

export type ScanPhase = "download" | "extract" | "analysis" | "dependencies" | "done";

async function setPhase(id: string, phase: ScanPhase, extra: Prisma.RepositoryScanUpdateInput = {}) {
  await prisma.repositoryScan.update({ where: { id }, data: { phase, ...extra } });
}

interface Snapshot {
  archive: Buffer;
  ref: string;
  sha: string | null;
}

async function githubSnapshot(config: AppConfig, installationId: number, fullName: string, ref: string): Promise<Snapshot> {
  const [owner, repo] = fullName.split("/") as [string, string];
  const octokit = await getInstallationOctokit(config, installationId);
  const branch = await octokit.request("GET /repos/{owner}/{repo}/branches/{branch}", { owner, repo, branch: ref });
  const sha = branch.data.commit.sha;
  const res = await octokit.request("GET /repos/{owner}/{repo}/tarball/{ref}", { owner, repo, ref: sha });
  return { archive: Buffer.from(res.data as ArrayBuffer), ref, sha };
}

async function gitlabSnapshot(organizationId: string, key: string, projectId: string, ref: string): Promise<Snapshot> {
  const api = await gitlabForOrg(organizationId, key);
  if (!api) throw new Error("gitlab_api_not_configured");
  const id = encodeURIComponent(projectId);
  const commit = await api.request<{ id: string }>(`/projects/${id}/repository/commits/${encodeURIComponent(ref)}`);
  const archive = await api.raw(`/projects/${id}/repository/archive.tar.gz?sha=${commit.id}`);
  return { archive, ref, sha: commit.id };
}

/** Create a scan record (or return the one already running) for a repository. */
export async function createScan(params: {
  repositoryId: string;
  organizationId: string;
  trigger: "manual" | "auto" | "connect";
  requestedById?: string | null;
}): Promise<{ id: string; reused: boolean }> {
  const running = await prisma.repositoryScan.findFirst({
    where: {
      repositoryId: params.repositoryId,
      status: { in: ["queued", "running"] },
      createdAt: { gt: new Date(Date.now() - 10 * 60_000) },
    },
    select: { id: true },
  });
  if (running) return { id: running.id, reused: true };
  const scan = await prisma.repositoryScan.create({
    data: {
      repositoryId: params.repositoryId,
      organizationId: params.organizationId,
      trigger: params.trigger,
      requestedById: params.requestedById ?? null,
    },
    select: { id: true },
  });
  return { id: scan.id, reused: false };
}

/** Run one scan to completion; never throws (failures are recorded). */
export async function runScan(config: AppConfig, scanId: string): Promise<void> {
  const scan = await prisma.repositoryScan.findUnique({
    where: { id: scanId },
    include: { repository: true },
  });
  if (!scan || scan.status !== "queued") return;
  const repo = scan.repository;

  try {
    await setPhase(scanId, "download", { status: "running" });
    const ref = repo.defaultBranch || "main";
    let snapshot: Snapshot;
    if (repo.provider === "github") {
      if (repo.installationId == null) throw new Error("github_not_installed");
      snapshot = await githubSnapshot(config, Number(repo.installationId), repo.name, ref);
    } else {
      snapshot = await gitlabSnapshot(repo.organizationId, config.ENCRYPTION_KEY, repo.externalId, ref);
    }

    await setPhase(scanId, "extract", { ref: snapshot.ref, commitSha: snapshot.sha });
    const { files, lockfiles, skipped, truncated } = extractTarGz(snapshot.archive);

    await setPhase(scanId, "analysis", { filesScanned: files.length });
    const suppressions = await prisma.findingSuppression.findMany({
      where: { repositoryId: repo.id },
      select: { fingerprint: true },
    });
    const base = analyzeFiles(files, new Set(suppressions.map((s) => s.fingerprint)));

    await setPhase(scanId, "dependencies");
    // Evaluate what is installed (lockfile), once per package and version.
    const declared = dedupeDependencies(resolveInstalledVersions(base.dependencies, lockedNpmVersions(lockfiles)));
    const dependencies = await enrichDependencies(declared);
    const verdict = decide({ findings: base.findings, secrets: base.secrets, dependencies });

    // Architecture graph, fragility and blast radius — never blocks the scan.
    let architecture: ArchitectureReport | null = null;
    try {
      architecture = analyzeArchitecture(files, { findings: base.findings, secrets: base.secrets });
    } catch {
      architecture = null;
    }
    const bySeverity: Record<string, number> = {};
    for (const f of base.findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    const summary = {
      files: files.length,
      skippedFiles: skipped,
      truncated,
      secrets: base.secrets.length,
      findings: base.findings.filter((f) => f.severity !== "info").length,
      informational: base.findings.filter((f) => f.severity === "info").length,
      riskyDependencies: dependencies.filter((d) => d.riskLevel !== "low").length,
      bySeverity,
      engine: base.engine,
      fragility: architecture ? { score: architecture.fragility.score, grade: architecture.fragility.grade } : null,
    };
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    const findings = [...base.findings].sort((a, b) => order[a.severity] - order[b.severity]);

    await prisma.repositoryScan.update({
      where: { id: scanId },
      data: {
        status: "done",
        phase: "done",
        riskScore: verdict.riskScore,
        decision: verdict.decision,
        summary: summary as Prisma.InputJsonValue,
        result: {
          secrets: base.secrets,
          findings: findings.slice(0, MAX_FINDINGS_STORED),
          dependencies: dependencies.filter((d) => d.riskLevel !== "low"),
          suppressed: base.suppressed.length,
          architecture,
        } as unknown as Prisma.InputJsonValue,
        finishedAt: new Date(),
      },
    });
    await recordAudit({
      organizationId: repo.organizationId,
      actorType: scan.requestedById ? "user" : "system",
      actorId: scan.requestedById,
      action: "repository.scanned",
      resourceType: "repository",
      resourceId: repo.id,
      metadata: { scanId, trigger: scan.trigger, riskScore: verdict.riskScore, commitSha: snapshot.sha, ...summary },
    });
    if (base.secrets.length || verdict.decision === "block") {
      await notifySlack(repo.organizationId, config.ENCRYPTION_KEY, {
        title: base.secrets.length ? "Secret présent dans le code du dépôt" : "Risque élevé dans le code du dépôt",
        severity: "critical",
        repository: repo.name,
        detail: `Analyse de ${snapshot.ref} : risque ${verdict.riskScore}/100, ${base.secrets.length} secret(s), ${summary.findings} problème(s).`,
      });
    }
  } catch (err) {
    await prisma.repositoryScan.update({
      where: { id: scanId },
      data: {
        status: "failed",
        error: err instanceof Error ? err.message.slice(0, 300) : "scan_failed",
        finishedAt: new Date(),
      },
    });
  }
}

/**
 * Daily automatic re-scan: repositories with `autoScan` whose default branch
 * moved since their last completed scan. Capped per run (serverless budget).
 */
export async function scheduleAutoScans(config: AppConfig, max = 3): Promise<string[]> {
  const repos = await prisma.repository.findMany({
    where: { autoScan: true, OR: [{ provider: "gitlab" }, { installationId: { not: null } }] },
    select: {
      id: true,
      name: true,
      provider: true,
      organizationId: true,
      installationId: true,
      externalId: true,
      defaultBranch: true,
      scans: {
        where: { status: "done" },
        orderBy: { createdAt: "desc" },
        take: 1,
        select: { commitSha: true, createdAt: true },
      },
    },
    take: 50,
  });
  const ids: string[] = [];
  for (const repo of repos) {
    if (ids.length >= max) break;
    const last = repo.scans[0];
    if (last && Date.now() - last.createdAt.getTime() < 20 * 3_600_000) continue;
    try {
      let head: string | null = null;
      if (repo.provider === "github") {
        const [owner, name] = repo.name.split("/") as [string, string];
        const octokit = await getInstallationOctokit(config, Number(repo.installationId));
        const b = await octokit.request("GET /repos/{owner}/{repo}/branches/{branch}", {
          owner,
          repo: name,
          branch: repo.defaultBranch,
        });
        head = b.data.commit.sha;
      } else {
        const api = await gitlabForOrg(repo.organizationId, config.ENCRYPTION_KEY);
        if (!api) continue;
        const c = await api.request<{ id: string }>(
          `/projects/${encodeURIComponent(repo.externalId)}/repository/commits/${encodeURIComponent(repo.defaultBranch)}`,
        );
        head = c.id;
      }
      if (last && last.commitSha === head) continue; // nothing new on the branch
      const scan = await createScan({ repositoryId: repo.id, organizationId: repo.organizationId, trigger: "auto" });
      if (!scan.reused) ids.push(scan.id);
    } catch {
      /* repository unreachable today — retried tomorrow */
    }
  }
  return ids;
}
