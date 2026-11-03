"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, RefreshCw, ShieldCheck, TrendingDown, TrendingUp } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { ReportButton } from "@/components/report-button";
import { Card, SeverityBadge } from "@/components/ui";
import { ScoreBadge } from "@/components/score";
import { AgentInstall } from "@/components/agent-install";
import type { InfraCategory, ServerDetail, ServerFinding } from "@/lib/types";

const CATEGORY_LABEL: Record<InfraCategory, string> = {
  ports: "Ports & services",
  ssh: "SSH",
  firewall: "Firewall",
  bruteforce: "Brute force",
  docker: "Docker",
  updates: "Mises à jour",
  backups: "Sauvegardes",
  tls: "TLS",
  secrets: "Secrets",
  network: "Réseau",
  admin: "Console d'administration",
  http: "En-têtes HTTP",
  daemon: "Démon Docker",
};

export default function ServerPage() {
  return (
    <Shell>
      <ServerView />
    </Shell>
  );
}

function ServerView() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [server, setServer] = useState<ServerDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);

  function load() {
    api<{ server: ServerDetail }>(`/api/v1/servers/${id}`)
      .then((r) => setServer(r.server))
      .catch(() => setError("Serveur introuvable."));
  }
  useEffect(load, [id]);

  async function rescan() {
    await api(`/api/v1/servers/${id}/rescan`, { method: "POST" });
    load();
  }

  async function rotate() {
    if (!confirm("Révoquer le token actuel ? L'agent devra être reconfiguré.")) return;
    const r = await api<{ agentToken: string }>(`/api/v1/servers/${id}/rotate-token`, {
      method: "POST",
    });
    setToken(r.agentToken);
  }

  async function remove() {
    if (!confirm("Retirer ce serveur de CodeGate ? Son historique d'audit sera supprimé.")) return;
    await api(`/api/v1/servers/${id}`, { method: "DELETE" });
    router.push("/servers");
  }

  if (error) return <Card className="p-4 text-sm text-destructive">{error}</Card>;
  if (!server) return <p className="text-sm text-muted-foreground">Chargement…</p>;

  const open = server.findings.filter((f) => !f.acceptance);
  const accepted = server.findings.filter((f) => f.acceptance);
  const rescanPending =
    !!server.rescanRequestedAt &&
    (!server.lastReportAt || new Date(server.rescanRequestedAt) > new Date(server.lastReportAt));
  const publicPorts = (server.lastReport?.listening ?? []).filter(
    (l) => l.proto === "tcp" && !/^(127\.|::1$|localhost$)/.test(l.address),
  );

  return (
    <div className="space-y-6">
      <Link
        href="/servers"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Serveurs
      </Link>

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-3 text-xl font-semibold">
            {server.name} <ScoreBadge score={server.securityScore} />
          </h1>
          <p className="font-mono text-xs text-muted-foreground">
            {server.hostname ?? "agent non installé"}
            {server.os ? ` · ${server.os}` : ""} · {server.environment}
            {server.agentVersion ? ` · agent ${server.agentVersion}` : ""}
            {server.lastReportAt
              ? ` · audité le ${new Date(server.lastReportAt).toLocaleString("fr-FR")}`
              : ""}
          </p>
        </div>
        <div className="flex items-start gap-2">
          <div className="flex flex-col items-end">
            <button
              onClick={rescan}
              disabled={rescanPending}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-60"
            >
              <RefreshCw className={`size-4 ${rescanPending ? "animate-spin" : ""}`} aria-hidden />
              {rescanPending ? "Audit demandé" : "Relancer l'audit"}
            </button>
            {rescanPending ? (
              <span className="mt-1 text-[11px] text-muted-foreground">L&apos;agent le lance d&apos;ici 15 min</span>
            ) : null}
          </div>
          <ReportButton type="server" id={server.id} name={server.name} />
          <button
            onClick={rotate}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted"
          >
            Nouveau token
          </button>
          <button
            onClick={remove}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted"
          >
            Retirer
          </button>
        </div>
      </header>

      {token ? (
        <Card className="p-4">
          <AgentInstall token={token} />
        </Card>
      ) : null}

      {!server.lastReportAt && !token ? (
        <Card className="p-4 text-sm text-muted-foreground">
          En attente du premier rapport de l&apos;agent. Si vous avez perdu le token, générez-en
          un nouveau.
        </Card>
      ) : null}

      {server.lastReportAt ? (
        <>
          <ScoreTrend server={server} />

          {server.analysis?.chains.length ? (
            <section className="space-y-3">
              <h2 className="text-sm font-semibold">Chaînes d&apos;attaque ({server.analysis.chains.length})</h2>
              <p className="text-xs text-muted-foreground">
                Des points qui, combinés, ouvrent un chemin jusqu&apos;au serveur. Casser un maillon suffit à couper le
                chemin.
              </p>
              {server.analysis.chains.map((c) => (
                <Card key={c.id} className="border-destructive/40 p-4">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={c.severity} />
                    <span className="font-medium">{c.title}</span>
                  </div>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
                    {c.steps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                </Card>
              ))}
            </section>
          ) : null}

          <section className="space-y-3">
            <h2 className="text-sm font-semibold">Points à corriger ({open.length})</h2>
            {open.length === 0 ? (
              <Card className="p-4 text-sm text-success">
                Aucun problème ouvert sur les contrôles Infra Shield.
              </Card>
            ) : (
              open.map((f) => <FindingCard key={f.id} serverId={server.id} finding={f} onChange={load} />)
            )}
          </section>

          {accepted.length ? (
            <section className="space-y-3">
              <h2 className="text-sm font-semibold">Risques acceptés ou atténués ({accepted.length})</h2>
              <p className="text-xs text-muted-foreground">
                Exclus du score, mais toujours suivis : chaque décision est tracée dans le journal d&apos;audit et
                figure dans le rapport signé.
              </p>
              {accepted.map((f) => (
                <FindingCard key={f.id} serverId={server.id} finding={f} onChange={load} />
              ))}
            </section>
          ) : null}

          {server.analysis?.mitigations.length ? (
            <section className="space-y-3">
              <h2 className="text-sm font-semibold">Contrôles en place</h2>
              <Card className="p-4">
                <ul className="space-y-1.5 text-sm">
                  {server.analysis.mitigations.map((m) => (
                    <li key={m} className="flex gap-2">
                      <ShieldCheck className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
                      <span>{m}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            </section>
          ) : null}

          <section className="space-y-3">
            <h2 className="text-sm font-semibold">Ports joignables depuis le réseau</h2>
            <Card>
              <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-xs text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Port</th>
                    <th className="px-4 py-2 font-medium">Adresse</th>
                    <th className="px-4 py-2 font-medium">Processus</th>
                  </tr>
                </thead>
                <tbody>
                  {publicPorts.map((l) => (
                    <tr key={`${l.address}:${l.port}`} className="border-b border-border last:border-0">
                      <td className="px-4 py-2 font-mono text-xs">{l.port}/tcp</td>
                      <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{l.address}</td>
                      <td className="px-4 py-2 font-mono text-xs">{l.process ?? "—"}</td>
                    </tr>
                  ))}
                  {!publicPorts.length ? (
                    <tr>
                      <td colSpan={3} className="px-4 py-6 text-center text-muted-foreground">
                        Aucun port TCP public.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
          </div>
            </Card>
          </section>
        </>
      ) : null}
    </div>
  );
}

/** Score delta since the previous audit and the recent history (P0-5, P2-7). */
function ScoreTrend({ server }: { server: ServerDetail }) {
  const scans = server.scans ?? [];
  const last = scans[0];
  if (!last) return null;
  const delta = server.previousScore !== null && server.securityScore !== null ? server.securityScore - server.previousScore : null;
  return (
    <section className="space-y-3">
      <Card className="flex flex-wrap items-center gap-x-6 gap-y-2 p-4 text-sm">
        {delta !== null && delta !== 0 ? (
          <span className={`inline-flex items-center gap-1.5 font-medium ${delta > 0 ? "text-success" : "text-destructive"}`}>
            {delta > 0 ? <TrendingUp className="size-4" aria-hidden /> : <TrendingDown className="size-4" aria-hidden />}
            {delta > 0 ? "+" : ""}
            {delta} point(s) depuis le dernier audit
          </span>
        ) : (
          <span className="text-muted-foreground">Score stable depuis le dernier audit</span>
        )}
        {last.resolved.length ? <span className="text-success">{last.resolved.length} point(s) corrigé(s) confirmé(s)</span> : null}
        {last.introduced.length ? <span className="text-destructive">{last.introduced.length} nouveau(x) point(s)</span> : null}
        {server.analysis?.acceptedCount ? (
          <span className="text-muted-foreground">{server.analysis.acceptedCount} risque(s) accepté(s) ou atténué(s)</span>
        ) : null}
      </Card>
      {scans.length > 1 ? (
        <div className="flex items-end gap-1" aria-label="Historique du score">
          {[...scans].reverse().map((s) => (
            <div key={s.id} className="flex flex-1 flex-col items-center gap-1">
              <div
                className={`w-full max-w-8 rounded-sm ${s.score >= 80 ? "bg-success/70" : s.score >= 50 ? "bg-warning/70" : "bg-destructive/70"}`}
                style={{ height: `${Math.max(4, s.score * 0.6)}px` }}
                title={`${new Date(s.createdAt).toLocaleString("fr-FR")} : ${s.score}/100`}
              />
              <span className="font-mono text-[10px] text-muted-foreground">{s.score}</span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

/** A finding with its proof, how to check it, and the accept / mitigate workflow (P1-9, P2-2). */
function FindingCard({ serverId, finding: f, onChange }: { serverId: string; finding: ServerFinding; onChange: () => void }) {
  const [mode, setMode] = useState<"accepted" | "mitigated" | null>(null);
  const [justification, setJustification] = useState("");
  const [review, setReview] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const path = `/api/v1/servers/${serverId}/acceptances/${encodeURIComponent(f.checkId)}`;

  async function save() {
    if (!mode) return;
    setBusy(true);
    setError(null);
    try {
      await api(path, {
        method: "PUT",
        body: JSON.stringify({
          kind: mode,
          justification,
          ...(review ? { expiresAt: new Date(`${review}T00:00:00Z`).toISOString() } : {}),
        }),
      });
      setMode(null);
      onChange();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 403
          ? "Réservé aux rôles Owner, Admin et Security Manager (avec MFA)."
          : "Justification trop courte (10 caractères minimum) ou enregistrement impossible.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function reopen() {
    await api(path, { method: "DELETE" });
    onChange();
  }

  return (
    <Card className={`p-4 ${f.acceptance ? "opacity-80" : ""}`}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={f.severity} />
        <span className="text-xs uppercase tracking-wide text-muted-foreground">{CATEGORY_LABEL[f.category] ?? f.category}</span>
        {f.exposure ? (
          <span
            className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
              f.exposure === "public" ? "bg-destructive/10 text-destructive" : "bg-muted text-muted-foreground"
            }`}
          >
            {f.exposure === "public" ? "exposé à Internet" : "interne"}
          </span>
        ) : null}
      </div>
      <p className="mt-2 font-medium">{f.title}</p>
      <p className="mt-1 text-sm text-muted-foreground">{f.detail}</p>
      {f.evidence ? (
        <p className="mt-2 text-xs">
          <span className="font-medium">Preuve : </span>
          <code className="break-all rounded bg-muted px-1 py-0.5 font-mono">{f.evidence}</code>
        </p>
      ) : null}
      {f.exploitScenario ? (
        <p className="mt-2 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">Scénario d&apos;attaque : </span>
          <Recommendation text={f.exploitScenario} />
        </p>
      ) : null}
      <p className="mt-2 text-sm">
        <span className="font-medium">Correctif : </span>
        <Recommendation text={f.recommendation} />
      </p>
      {f.verifyCommand ? (
        <div className="mt-2 text-xs">
          <span className="font-medium">Vérifier sur le serveur :</span>
          <pre className="mt-1 overflow-x-auto rounded bg-muted p-2 font-mono">{f.verifyCommand}</pre>
        </div>
      ) : null}

      {f.acceptance ? (
        <div className="mt-3 rounded-md border border-border bg-muted/40 p-3 text-xs">
          <p>
            <span className="font-medium">{f.acceptance.kind === "accepted" ? "Risque accepté" : "Atténué par un contrôle"}</span>
            {" · "}
            {new Date(f.acceptance.createdAt).toLocaleDateString("fr-FR")}
            {f.acceptance.expiresAt ? ` · à revoir le ${new Date(f.acceptance.expiresAt).toLocaleDateString("fr-FR")}` : ""}
          </p>
          <p className="mt-1 text-muted-foreground">{f.acceptance.justification}</p>
          <button type="button" onClick={reopen} className="mt-2 cursor-pointer text-primary hover:underline">
            Rouvrir (le point compte de nouveau dans le score)
          </button>
        </div>
      ) : mode ? (
        <div className="mt-3 space-y-2 rounded-md border border-border p-3 text-xs">
          <p className="font-medium">
            {mode === "accepted" ? "Accepter ce risque" : "Décrire le contrôle qui l'atténue"} — sera tracé dans le journal d&apos;audit
          </p>
          <textarea
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            rows={3}
            placeholder={
              mode === "accepted"
                ? "Pourquoi ce risque est acceptable (ex. besoin d'architecture, service non exposé)…"
                : "Quel contrôle le couvre (ex. accès limité par VPN, WAF devant le service)…"
            }
            className="w-full rounded-md border border-border bg-background p-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
          <label className="flex items-center gap-2">
            À revoir le (facultatif)
            <input
              type="date"
              value={review}
              onChange={(e) => setReview(e.target.value)}
              className="rounded-md border border-border bg-background px-2 py-1"
            />
          </label>
          {error ? <p className="text-destructive">{error}</p> : null}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={save}
              disabled={busy || justification.trim().length < 10}
              className="cursor-pointer rounded-md bg-primary px-3 py-1.5 font-medium text-on-primary disabled:opacity-50"
            >
              Enregistrer
            </button>
            <button type="button" onClick={() => setMode(null)} className="cursor-pointer rounded-md border border-border px-3 py-1.5">
              Annuler
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-3 flex gap-3 text-xs">
          <button type="button" onClick={() => setMode("mitigated")} className="cursor-pointer text-muted-foreground hover:text-foreground hover:underline">
            Atténué par un contrôle
          </button>
          <button type="button" onClick={() => setMode("accepted")} className="cursor-pointer text-muted-foreground hover:text-foreground hover:underline">
            Accepter le risque
          </button>
        </div>
      )}
    </Card>
  );
}

/** Render `inline code` spans of a recommendation as monospace. */
function Recommendation({ text }: { text: string }) {
  return (
    <>
      {text.split(/(`[^`]+`)/).map((part, i) =>
        part.startsWith("`") ? (
          <code key={i} className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            {part.slice(1, -1)}
          </code>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </>
  );
}
