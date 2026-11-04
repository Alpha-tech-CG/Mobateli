"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import { RiskBadge } from "@/components/risk-badge";
import { ScanProgress } from "@/components/scan-progress";
import type { RepositoryRow, ScanDetail, ScanRow } from "@/lib/types";

const TRIGGER_LABEL: Record<ScanRow["trigger"], string> = {
  manual: "manuelle",
  auto: "automatique",
  connect: "à la connexion",
};
const ERRORS: Record<string, string> = {
  github_not_installed: "L'App GitHub n'a pas accès à ce dépôt : installez-la dessus depuis Intégrations.",
  gitlab_api_not_configured: "Ajoutez un jeton d'accès GitLab dans Intégrations pour analyser ce dépôt.",
  mfa_enrollment_required: "Activez d'abord la MFA (Sécurité du compte).",
};

export default function ScansPage() {
  return (
    <Shell>
      <Scans />
    </Shell>
  );
}

function Scans() {
  const [repos, setRepos] = useState<RepositoryRow[]>([]);
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [repoId, setRepoId] = useState("");
  const [live, setLive] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.all([
        api<{ repositories: RepositoryRow[] }>("/api/v1/repositories"),
        api<{ scans: ScanRow[] }>("/api/v1/scans"),
      ]);
      setRepos(r.repositories);
      setScans(s.scans);
      setRepoId((cur) => cur || r.repositories.find((x) => x.scannable)?.id || "");
      // Resume following a scan already in progress.
      const running = s.scans.find((x) => x.status === "queued" || x.status === "running");
      if (running) follow(running.id);
    } catch {
      setError("Impossible de charger les dépôts.");
    } finally {
      setLoaded(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    void load();
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [load]);

  function follow(scanId: string) {
    if (timer.current) clearTimeout(timer.current);
    const tick = async () => {
      try {
        const { scan } = await api<{ scan: ScanDetail }>(`/api/v1/scans/${scanId}`);
        setLive(scan);
        if (scan.status === "queued" || scan.status === "running") {
          timer.current = setTimeout(tick, 1500);
        } else {
          const s = await api<{ scans: ScanRow[] }>("/api/v1/scans");
          setScans(s.scans);
        }
      } catch {
        timer.current = setTimeout(tick, 3000);
      }
    };
    void tick();
  }

  async function start() {
    if (!repoId) return;
    setError(null);
    try {
      const r = await api<{ scanId: string }>(`/api/v1/repositories/${repoId}/scans`, { method: "POST" });
      follow(r.scanId);
    } catch (err) {
      setError(err instanceof ApiError ? (ERRORS[err.code] ?? "Analyse impossible.") : "Analyse impossible.");
    }
  }

  async function toggleAuto(repo: RepositoryRow) {
    try {
      await api(`/api/v1/repositories/${repo.id}`, {
        method: "PATCH",
        body: JSON.stringify({ autoScan: !repo.autoScan }),
      });
      setRepos((all) => all.map((r) => (r.id === repo.id ? { ...r, autoScan: !r.autoScan } : r)));
    } catch (err) {
      setError(err instanceof ApiError ? (ERRORS[err.code] ?? "Modification impossible.") : "Modification impossible.");
    }
  }

  const selected = repos.find((r) => r.id === repoId);
  const running = live && (live.status === "queued" || live.status === "running");

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Analyser un dépôt</h1>
        <p className="text-sm text-muted-foreground">
          Analysez le code existant d&apos;un dépôt connecté (branche principale) : secrets, failles de
          code, prompt injection et dépendances. Le code est lu en mémoire puis oublié ; seuls les
          résultats sont conservés.
        </p>
      </header>

      {error ? <Card className="p-4 text-sm text-destructive">{error}</Card> : null}

      <Card className="space-y-4 p-5">
        {loaded && !repos.length ? (
          <p className="text-sm text-muted-foreground">
            Aucun dépôt connecté.{" "}
            <Link href="/integrations" className="text-primary hover:underline">
              Connecter GitHub ou GitLab
            </Link>
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-end gap-3">
              <label className="block min-w-[260px] flex-1">
                <span className="mb-1 block text-xs font-medium text-muted-foreground">Dépôt</span>
                <select
                  value={repoId}
                  onChange={(e) => setRepoId(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                >
                  {repos.map((r) => (
                    <option key={r.id} value={r.id} disabled={!r.scannable}>
                      {r.name} ({r.provider} · {r.defaultBranch}){r.scannable ? "" : " — accès App manquant"}
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                onClick={start}
                disabled={!selected?.scannable || Boolean(running)}
                className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
              >
                {running ? "Analyse en cours…" : "Lancer l'analyse"}
              </button>
            </div>
            {selected ? (
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={selected.autoScan} onChange={() => toggleAuto(selected)} />
                Réanalyser automatiquement ce dépôt chaque jour si sa branche principale a changé
              </label>
            ) : null}
          </>
        )}
      </Card>

      {live ? (
        <Card className="space-y-4 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="font-medium">
              {live.repository.name}
              <span className="ml-2 font-mono text-xs text-muted-foreground">
                {live.ref ?? ""}
                {live.commitSha ? ` @ ${live.commitSha.slice(0, 7)}` : ""}
              </span>
            </h2>
            {live.status === "done" ? <RiskBadge risk={live.riskScore ?? 0} /> : null}
          </div>
          <ScanProgress status={live.status} phase={live.phase} filesScanned={live.filesScanned} />
          {live.status === "failed" ? (
            <p className="text-sm text-destructive">
              Échec : {ERRORS[live.error ?? ""] ?? live.error ?? "erreur inconnue"}
            </p>
          ) : null}
          {live.status === "done" && live.summary ? (
            <div className="space-y-3">
              <p className="text-sm">
                Risque <strong>{live.riskScore}/100</strong> · {live.summary.secrets} secret(s) ·{" "}
                {live.summary.findings} problème(s) de code · {live.summary.riskyDependencies} dépendance(s) à risque
                {live.summary.informational ? ` · ${live.summary.informational} information(s)` : ""}
              </p>
              <Link
                href={`/scans/${live.id}`}
                className="inline-block rounded-md border border-border px-3 py-2 text-sm hover:bg-muted"
              >
                Voir le détail
              </Link>
            </div>
          ) : null}
        </Card>
      ) : null}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">Historique</h2>
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Dépôt</th>
                  <th className="px-4 py-2 font-medium">Déclenchement</th>
                  <th className="px-4 py-2 font-medium">Risque</th>
                  <th className="px-4 py-2 font-medium">Constats</th>
                  <th className="px-4 py-2 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                    <td className="px-4 py-2">
                      <Link href={`/scans/${s.id}`} className="font-medium hover:underline">
                        {s.repository.name}
                      </Link>
                      <div className="font-mono text-xs text-muted-foreground">
                        {s.ref ?? ""}
                        {s.commitSha ? ` @ ${s.commitSha.slice(0, 7)}` : ""}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{TRIGGER_LABEL[s.trigger]}</td>
                    <td className="px-4 py-2 text-xs">
                      {s.status === "done" ? (
                        <RiskBadge risk={s.riskScore ?? 0} />
                      ) : s.status === "failed" ? (
                        <span className="text-destructive">échec</span>
                      ) : (
                        <span className="text-muted-foreground">en cours</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {s.summary ? `${s.summary.secrets} secret(s) · ${s.summary.findings} problème(s)` : "—"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                      {new Date(s.createdAt).toLocaleString("fr-FR")}
                    </td>
                  </tr>
                ))}
                {loaded && !scans.length ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      Aucune analyse pour le moment.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>
      </section>
    </div>
  );
}
