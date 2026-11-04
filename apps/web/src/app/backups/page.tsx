"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, KpiCard } from "@/components/ui";
import { ScoreBadge } from "@/components/score";
import { BackupStatusBadge } from "@/components/backup-status";
import { BackupInstall } from "@/components/backup-install";
import type { BackupRow, ServerRow } from "@/lib/types";

const inputClass =
  "w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring";

const TYPES = [
  ["postgres", "PostgreSQL"],
  ["mysql", "MySQL / MariaDB"],
  ["mongodb", "MongoDB"],
  ["files", "Fichiers / uploads"],
  ["other", "Autre"],
] as const;

export default function BackupsPage() {
  return (
    <Shell>
      <Backups />
    </Shell>
  );
}

function Backups() {
  const [backups, setBackups] = useState<BackupRow[]>([]);
  const [servers, setServers] = useState<ServerRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", type: "postgres", frequencyHours: 24, serverId: "" });
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState<string | null>(null);

  const load = useCallback(() => {
    api<{ backups: BackupRow[] }>("/api/v1/backups")
      .then((r) => setBackups(r.backups))
      .catch(() => setError("Impossible de charger les sauvegardes."))
      .finally(() => setLoaded(true));
  }, []);
  useEffect(() => {
    load();
    void api<{ servers: ServerRow[] }>("/api/v1/servers").then((r) => setServers(r.servers));
  }, [load]);

  async function create(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ reportToken: string }>("/api/v1/backups", {
        method: "POST",
        body: JSON.stringify({
          name: form.name,
          type: form.type,
          frequencyHours: form.frequencyHours,
          ...(form.serverId ? { serverId: form.serverId } : {}),
        }),
      });
      setToken(res.reportToken);
      setForm({ name: "", type: "postgres", frequencyHours: 24, serverId: "" });
      load();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 403
          ? "Votre rôle ne permet pas de déclarer une sauvegarde."
          : "Création impossible.",
      );
    } finally {
      setBusy(false);
    }
  }

  const recovery = backups.length
    ? Math.round(backups.reduce((s, b) => s + b.score, 0) / backups.length)
    : null;
  const critical = backups.filter((b) => b.status === "critical").length;
  const ransomware = backups.filter((b) => b.ransomwareReady).length;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Sauvegardes</h1>
        <p className="text-sm text-muted-foreground">
          Backup Shield : vos sauvegardes existent-elles, sont-elles chiffrées, intègres, isolées
          et réellement restaurables ? Une sauvegarde non testée n&apos;est pas une sauvegarde
          fiable.
        </p>
      </header>

      <div className="grid gap-4 sm:grid-cols-3">
        <KpiCard label="Score de récupération" value={recovery === null ? "—" : `${recovery}/100`} />
        <KpiCard label="Sauvegardes critiques" value={critical} />
        <KpiCard
          label="Prêtes face au ransomware"
          value={`${ransomware}/${backups.length}`}
          hint="Chiffrées, clé isolée, hors site, compte séparé, immuables"
        />
      </div>

      {error ? <Card className="p-4 text-sm text-destructive">{error}</Card> : null}

      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold">Déclarer une sauvegarde</h2>
        {token ? (
          <div className="space-y-3">
            <BackupInstall token={token} />
            <button
              type="button"
              onClick={() => setToken(null)}
              className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted"
            >
              J&apos;ai copié le token
            </button>
          </div>
        ) : (
          <form
            onSubmit={create}
            className="grid gap-3 sm:grid-cols-[1fr_170px_130px_170px_auto] sm:items-end"
          >
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Nom</span>
              <input
                required
                maxLength={100}
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="postgres-quotidien"
                className={inputClass}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Type</span>
              <select
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value })}
                className={inputClass}
              >
                {TYPES.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">
                Fréquence (h)
              </span>
              <input
                type="number"
                min={1}
                value={form.frequencyHours}
                onChange={(e) => setForm({ ...form, frequencyHours: Number(e.target.value) })}
                className={inputClass}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs font-medium text-muted-foreground">Serveur</span>
              <select
                value={form.serverId}
                onChange={(e) => setForm({ ...form, serverId: e.target.value })}
                className={inputClass}
              >
                <option value="">—</option>
                {servers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
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
          <table className="w-full min-w-[620px] text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">Sauvegarde</th>
                <th className="px-4 py-2 font-medium">Statut</th>
                <th className="px-4 py-2 font-medium">Score</th>
                <th className="px-4 py-2 font-medium">Dernière exécution</th>
                <th className="px-4 py-2 font-medium">Dernière restauration</th>
              </tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                  <td className="px-4 py-2">
                    <Link href={`/backups/${b.id}`} className="font-medium hover:underline">
                      {b.name}
                    </Link>
                    <div className="text-xs text-muted-foreground">
                      {TYPES.find(([v]) => v === b.type)?.[1] ?? b.type} · toutes les{" "}
                      {b.frequencyHours} h{b.server ? ` · ${b.server}` : ""}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <BackupStatusBadge status={b.status} />
                  </td>
                  <td className="px-4 py-2">
                    <ScoreBadge score={b.score} />
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                    {b.lastRunAt ? new Date(b.lastRunAt).toLocaleString("fr-FR") : "jamais"}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                    {b.lastRestoreAt ? new Date(b.lastRestoreAt).toLocaleString("fr-FR") : "jamais"}
                  </td>
                </tr>
              ))}
              {loaded && !backups.length ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                    Aucune sauvegarde déclarée.
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
