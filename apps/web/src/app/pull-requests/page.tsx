"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { Bot, ExternalLink, Info } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, StatusBadge } from "@/components/ui";
import type { OpenPullRequest, PullRequestListItem, RepositoryRow } from "@/lib/types";

const ERRORS: Record<string, string> = {
  github_not_installed: "L'App GitHub n'a pas accès à ce dépôt : installez-la dessus depuis Intégrations.",
  gitlab_api_not_configured: "Ajoutez un jeton d'accès GitLab dans Intégrations pour lister ses merge requests.",
  provider_unreachable: "Impossible de joindre GitHub / GitLab pour le moment.",
  pull_request_not_open: "Cette PR n'est plus ouverte.",
  mfa_enrollment_required: "Activez d'abord la MFA (Sécurité du compte).",
};
const errorText = (err: unknown, fallback: string) =>
  err instanceof ApiError ? (ERRORS[err.code] ?? fallback) : fallback;

export default function PullRequestsPage() {
  return (
    <Shell>
      <PullRequests />
    </Shell>
  );
}

function PullRequests() {
  const router = useRouter();
  const [repos, setRepos] = useState<RepositoryRow[]>([]);
  const [repoId, setRepoId] = useState("");
  const [prs, setPrs] = useState<PullRequestListItem[]>([]);
  const [open, setOpen] = useState<OpenPullRequest[] | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    api<{ repositories: RepositoryRow[] }>("/api/v1/repositories")
      .then((r) => setRepos(r.repositories))
      .catch(() => {});
  }, []);

  const loadPrs = useCallback(() => {
    const q = repoId ? `?repositoryId=${repoId}` : "";
    api<{ pullRequests: PullRequestListItem[] }>(`/api/v1/pull-requests${q}`)
      .then((r) => setPrs(r.pullRequests))
      .catch(() => setError("Impossible de charger les pull requests."))
      .finally(() => setLoaded(true));
  }, [repoId]);

  const loadOpen = useCallback(() => {
    setOpen(null);
    setOpenError(null);
    if (!repoId) return;
    api<{ pullRequests: OpenPullRequest[] }>(`/api/v1/repositories/${repoId}/open-pull-requests`)
      .then((r) => setOpen(r.pullRequests))
      .catch((err) => setOpenError(errorText(err, "Impossible de lister les PR ouvertes.")));
  }, [repoId]);

  useEffect(() => {
    loadPrs();
    loadOpen();
  }, [loadPrs, loadOpen]);

  async function analyze(pr: OpenPullRequest) {
    setBusy(pr.number);
    setOpenError(null);
    try {
      const r = await api<{ pullRequestId: string }>(
        `/api/v1/repositories/${repoId}/pull-requests/${pr.number}/analyze`,
        { method: "POST" },
      );
      router.push(`/pull-requests/${r.pullRequestId}`);
    } catch (err) {
      setOpenError(errorText(err, "Analyse impossible."));
      setBusy(null);
    }
  }

  const repo = repos.find((r) => r.id === repoId);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Pull requests</h1>
          <p className="text-sm text-muted-foreground">Analyses de sécurité des PR, générées par IA ou non.</p>
        </div>
        <label className="block min-w-[260px]">
          <span className="mb-1 block text-xs font-medium text-muted-foreground">Projet</span>
          <select
            value={repoId}
            onChange={(e) => setRepoId(e.target.value)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          >
            <option value="">Tous les projets</option>
            {repos.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name} ({r.provider})
              </option>
            ))}
          </select>
        </label>
      </header>

      <Card className="flex gap-3 p-4 text-sm">
        <Info className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
        <div className="space-y-1 text-muted-foreground">
          <p>
            <span className="font-medium text-foreground">D&apos;où viennent les PR ?</span> Dès qu&apos;une pull
            request est ouverte ou mise à jour sur un dépôt où l&apos;App GitHub CodeGate est installée (ou une merge
            request sur un projet GitLab connecté), GitHub prévient CodeGate, qui l&apos;analyse en quelques secondes et
            publie un check et un commentaire sur la PR.
          </p>
          <p>
            Choisissez un projet ci-dessus pour voir ses PR ouvertes et en analyser une tout de suite, sans attendre
            un nouveau commit.
          </p>
        </div>
      </Card>

      {repoId ? (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">PR ouvertes sur {repo?.name}</h2>
          <Card>
            {openError ? (
              <p className="px-4 py-4 text-sm text-destructive">{openError}</p>
            ) : open === null ? (
              <p className="px-4 py-4 text-sm text-muted-foreground">Chargement…</p>
            ) : !open.length ? (
              <p className="px-4 py-4 text-sm text-muted-foreground">Aucune PR ouverte sur ce projet.</p>
            ) : (
              <ul className="divide-y divide-border">
                {open.map((p) => (
                  <li key={p.number} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm">
                    <div className="min-w-0">
                      <a
                        href={p.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 hover:underline"
                      >
                        <span className="font-mono text-xs text-muted-foreground">#{p.number}</span> {p.title}
                        <ExternalLink className="size-3 text-muted-foreground" aria-hidden />
                      </a>
                      <div className="text-xs text-muted-foreground">
                        {p.author} · mise à jour {new Date(p.updatedAt).toLocaleString("fr-FR")}
                        {p.analysis ? (
                          <>
                            {" · "}
                            <Link href={`/pull-requests/${p.analysis.id}`} className="text-primary hover:underline">
                              analysée ({p.analysis.riskScore ?? "—"}/100)
                            </Link>
                            {p.analysis.upToDate ? "" : " — nouveaux commits depuis"}
                          </>
                        ) : (
                          " · pas encore analysée"
                        )}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => analyze(p)}
                      disabled={busy !== null}
                      className="cursor-pointer rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
                    >
                      {busy === p.number ? "Analyse…" : p.analysis ? "Réanalyser" : "Analyser"}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </section>
      ) : null}

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">Analyses</h2>
        {error ? (
          <Card className="p-4 text-sm text-destructive">{error}</Card>
        ) : (
          <Card>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">PR</th>
                    <th className="px-4 py-2 font-medium">Projet</th>
                    <th className="px-4 py-2 font-medium">Auteur</th>
                    <th className="px-4 py-2 font-medium">Risque</th>
                    <th className="px-4 py-2 font-medium">Problèmes</th>
                    <th className="px-4 py-2 font-medium">Statut</th>
                  </tr>
                </thead>
                <tbody>
                  {prs.map((pr) => {
                    const problems = pr.counts.secrets + pr.counts.dependencies + pr.counts.findings;
                    return (
                      <tr key={pr.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                        <td className="px-4 py-2">
                          <Link href={`/pull-requests/${pr.id}`} className="flex items-center gap-2 text-primary hover:underline">
                            {pr.aiGenerated ? <Bot className="size-4 text-accent" aria-label="Généré par IA" /> : null}
                            <span className="font-mono text-xs">#{pr.number}</span>
                            <span className="text-foreground">{pr.title}</span>
                          </Link>
                        </td>
                        <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{pr.repository}</td>
                        <td className="px-4 py-2">{pr.author}</td>
                        <td className="px-4 py-2 font-mono">{pr.riskScore ?? "—"}</td>
                        <td className="px-4 py-2 text-xs">
                          {problems ? (
                            <span>
                              {pr.counts.secrets ? `${pr.counts.secrets} secret(s) · ` : ""}
                              {pr.counts.dependencies ? `${pr.counts.dependencies} dépendance(s) à risque · ` : ""}
                              {pr.counts.findings ? `${pr.counts.findings} problème(s) de code` : ""}
                            </span>
                          ) : (
                            <span className="text-success">aucun</span>
                          )}
                          {pr.counts.dependenciesAnalyzed ? (
                            <div className="text-muted-foreground">
                              {pr.counts.dependenciesAnalyzed} dépendance(s) analysée(s)
                            </div>
                          ) : null}
                        </td>
                        <td className="px-4 py-2">
                          <StatusBadge status={pr.status} />
                        </td>
                      </tr>
                    );
                  })}
                  {loaded && !prs.length ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                        Aucune pull request analysée{repoId ? " sur ce projet" : ""} pour le moment.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </section>
    </div>
  );
}
