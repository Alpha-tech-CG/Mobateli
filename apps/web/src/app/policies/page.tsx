"use client";

import { useEffect, useState } from "react";
import { Plus } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, SeverityBadge } from "@/components/ui";
import type { Policy, Severity } from "@/lib/types";

const ACTIONS = ["allow", "warn", "block", "require_approval"] as const;
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export default function PoliciesPage() {
  return (
    <Shell>
      <Policies />
    </Shell>
  );
}

function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [rule, setRule] = useState("");
  const [action, setAction] = useState<(typeof ACTIONS)[number]>("block");
  const [threshold, setThreshold] = useState<Severity>("high");
  const [busy, setBusy] = useState(false);

  function load() {
    api<{ policies: Policy[] }>("/api/v1/policies")
      .then((r) => setPolicies(r.policies))
      .catch(() => setError("Impossible de charger les politiques."));
  }
  useEffect(load, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/v1/policies", {
        method: "POST",
        body: JSON.stringify({ rule, action, severityThreshold: threshold }),
      });
      setRule("");
      load();
    } catch {
      setError("Création impossible (droits insuffisants ?).");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Politiques</h1>
        <p className="text-sm text-muted-foreground">
          Définissez l&apos;action à appliquer au-delà d&apos;un seuil de sévérité.
        </p>
      </header>

      <Card className="mb-6 p-4">
        <form onSubmit={create} className="flex flex-wrap items-end gap-3">
          <label className="flex-1 min-w-48">
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Nom de la règle</span>
            <input
              required
              value={rule}
              onChange={(e) => setRule(e.target.value)}
              placeholder="Bloquer les secrets exposés"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          <label>
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Action</span>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value as (typeof ACTIONS)[number])}
              className="cursor-pointer rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              {ACTIONS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="mb-1 block text-xs font-medium text-muted-foreground">Seuil</span>
            <select
              value={threshold}
              onChange={(e) => setThreshold(e.target.value as Severity)}
              className="cursor-pointer rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            disabled={busy}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50"
          >
            <Plus className="size-4" aria-hidden />
            {busy ? "Ajout…" : "Ajouter"}
          </button>
        </form>
        {error ? <p className="mt-2 text-sm text-destructive">{error}</p> : null}
      </Card>

      <Card>
        <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-4 py-2 font-medium">Règle</th>
              <th className="px-4 py-2 font-medium">Action</th>
              <th className="px-4 py-2 font-medium">Seuil</th>
              <th className="px-4 py-2 font-medium">Portée</th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr key={p.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                <td className="px-4 py-2">{p.rule}</td>
                <td className="px-4 py-2 font-mono text-xs">{p.action}</td>
                <td className="px-4 py-2">
                  <SeverityBadge severity={p.severityThreshold} />
                </td>
                <td className="px-4 py-2 text-xs text-muted-foreground">
                  {p.repositoryId ? "dépôt" : "organisation"}
                </td>
              </tr>
            ))}
            {!policies.length ? (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                  Aucune politique. Ajoutez-en une ci-dessus.
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
