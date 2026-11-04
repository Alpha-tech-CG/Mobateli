"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, KpiCard } from "@/components/ui";
import { ScoreBadge } from "@/components/score";
import { AgentInstall } from "@/components/agent-install";
import type { ServerRow } from "@/lib/types";

const inputClass =
  "w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring";

export default function ServersPage() {
  return (
    <Shell>
      <Servers />
    </Shell>
  );
}

function Servers() {
  const [servers, setServers] = useState<ServerRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", environment: "production", provider: "" });
  const [busy, setBusy] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);

  const load = useCallback(() => {
    api<{ servers: ServerRow[] }>("/api/v1/servers")
      .then((r) => setServers(r.servers))
      .catch(() => setError("Impossible de charger les serveurs."))
      .finally(() => setLoaded(true));
  }, []);

  useEffect(load, [load]);

  async function connect(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ agentToken: string }>("/api/v1/servers/connect", {
        method: "POST",
        body: JSON.stringify({
          name: form.name,
          environment: form.environment,
          ...(form.provider ? { provider: form.provider } : {}),
        }),
      });
      setNewToken(res.agentToken);
      setForm({ name: "", environment: "production", provider: "" });
      load();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 403
          ? "Votre rôle ne permet pas de connecter un serveur."
          : "Connexion du serveur impossible.",
      );
    } finally {
      setBusy(false);
    }
  }

  const scored = servers.filter((s) => s.securityScore !== null);
  const average = scored.length
    ? Math.round(scored.reduce((sum, s) => sum + (s.securityScore ?? 0), 0) / scored.length)
    : null;
  const critical = servers.reduce((sum, s) => sum + s.counts.critical, 0);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Serveurs</h1>
        <p className="text-sm text-muted-foreground">
          Infra Shield : ports exposés, SSH, firewall, Docker et mises à jour de vos VPS, audités
          par un agent en lecture seule.
        </p>
      </header>

      <div className="grid gap-4 sm:grid-cols-3">
        <KpiCard label="Serveurs" value={servers.length} />
        <KpiCard label="Score moyen" value={average === null ? "—" : `${average}/100`} />
        <KpiCard label="Risques critiques" value={critical} />
      </div>

      {error ? <Card className="p-4 text-sm text-destructive">{error}</Card> : null}

      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold">Connecter un serveur</h2>
        {newToken ? (
          <div className="space-y-3">
            <AgentInstall token={newToken} />
            <button
              type="button"
              onClick={() => setNewToken(null)}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted"
            >
              J&apos;ai copié le token
            </button>
          </div>
        ) : (
          <form onSubmit={connect} className="grid gap-3 sm:grid-cols-[1fr_180px_180px_auto] sm:items-end">
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Nom</span>
              <input
                required
                maxLength={100}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="vps-prod-1"
                className={inputClass}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Environnement
              </span>
              <select
                value={form.environment}
                onChange={(e) => setForm({ ...form, environment: e.target.value })}
                className={inputClass}
              >
                <option value="production">production</option>
                <option value="staging">staging</option>
                <option value="development">development</option>
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Hébergeur (optionnel)
              </span>
              <input
                maxLength={60}
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value })}
                placeholder="OVH, Hetzner…"
                className={inputClass}
              />
            </label>
            <button
              type="submit"
              disabled={busy}
              className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
            >
              Générer le token
            </button>
          </form>
        )}
      </Card>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-4 py-2 font-medium">Serveur</th>
              <th className="px-4 py-2 font-medium">Environnement</th>
              <th className="px-4 py-2 font-medium">Score</th>
              <th className="px-4 py-2 font-medium">Points à corriger</th>
              <th className="px-4 py-2 font-medium">Dernier audit</th>
            </tr>
          </thead>
          <tbody>
            {servers.map((s) => (
              <tr key={s.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                <td className="px-4 py-2">
                  <Link href={`/servers/${s.id}`} className="font-medium hover:underline">
                    {s.name}
                  </Link>
                  <div className="font-mono text-xs text-muted-foreground">
                    {s.hostname ?? "agent non installé"}
                    {s.os ? ` · ${s.os}` : ""}
                  </div>
                </td>
                <td className="px-4 py-2 text-xs text-muted-foreground">{s.environment}</td>
                <td className="px-4 py-2">
                  <ScoreBadge score={s.securityScore} />
                </td>
                <td className="px-4 py-2 text-xs">
                  {s.counts.total ? (
                    <>
                      {s.counts.total}
                      {s.counts.critical ? (
                        <span className="text-destructive"> · {s.counts.critical} critique(s)</span>
                      ) : null}
                    </>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                  {s.lastReportAt ? new Date(s.lastReportAt).toLocaleString("fr-FR") : "—"}
                </td>
              </tr>
            ))}
            {loaded && !servers.length ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                  Aucun serveur connecté. Générez un token ci-dessus pour installer l&apos;agent.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
          </div>
      </Card>
    </div>
  );
}
