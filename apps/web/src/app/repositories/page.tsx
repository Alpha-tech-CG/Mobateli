"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type { Repository } from "@/lib/types";

export default function RepositoriesPage() {
  return (
    <Shell>
      <Repositories />
    </Shell>
  );
}

const LEVELS: { value: string; label: string; hint: string }[] = [
  { value: "observe", label: "Observer", hint: "Rapporte sans jamais bloquer (check neutre)." },
  { value: "warn", label: "Avertir", hint: "Signale les risques, ne bloque pas la fusion." },
  {
    value: "block",
    label: "Bloquer",
    hint: "Check en échec sur un risque bloquant (à exiger dans la protection de branche GitHub).",
  },
];

function Repositories() {
  const [repos, setRepos] = useState<Repository[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  function load() {
    api<{ repositories: Repository[] }>("/api/v1/repositories")
      .then((r) => setRepos(r.repositories))
      .catch(() => setError("Impossible de charger les dépôts."));
  }
  useEffect(load, []);

  async function setLevel(repo: Repository, protectionLevel: string) {
    setSaving(repo.id);
    setMsg(null);
    try {
      await api(`/api/v1/repositories/${repo.id}/settings`, {
        method: "PUT",
        body: JSON.stringify({ protectionLevel }),
      });
      setRepos((list) => list?.map((r) => (r.id === repo.id ? { ...r, protectionLevel } : r)) ?? null);
      setMsg(`${repo.name} : niveau « ${LEVELS.find((l) => l.value === protectionLevel)?.label} » enregistré.`);
    } catch {
      setMsg("Modification refusée (droits insuffisants ?).");
    } finally {
      setSaving(null);
    }
  }

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Dépôts</h1>
        <p className="text-sm text-muted-foreground">
          Choisissez pour chaque dépôt si CodeGate observe, avertit ou bloque.
        </p>
      </header>

      <Card className="mb-4 p-4 text-xs text-muted-foreground">
        <ul className="space-y-1">
          {LEVELS.map((l) => (
            <li key={l.value}>
              <span className="font-medium text-foreground">{l.label}</span> — {l.hint}
            </li>
          ))}
        </ul>
      </Card>

      {msg ? (
        <p className="mb-3 text-sm text-muted-foreground" role="status">
          {msg}
        </p>
      ) : null}
      {error ? <Card className="p-4 text-sm text-destructive">{error}</Card> : null}

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">Dépôt</th>
                <th className="px-4 py-2 font-medium">Fournisseur</th>
                <th className="px-4 py-2 font-medium">Protection</th>
              </tr>
            </thead>
            <tbody>
              {(repos ?? []).map((r) => (
                <tr key={r.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                  <td className="px-4 py-2 font-mono text-xs">{r.name}</td>
                  <td className="px-4 py-2 text-xs">{r.provider}</td>
                  <td className="px-4 py-2">
                    <select
                      aria-label={`Niveau de protection de ${r.name}`}
                      value={r.protectionLevel}
                      disabled={saving === r.id}
                      onChange={(e) => setLevel(r, e.target.value)}
                      className="cursor-pointer rounded-md border border-border bg-background px-2 py-1 text-xs outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
                    >
                      {LEVELS.map((l) => (
                        <option key={l.value} value={l.value}>
                          {l.label}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
              {repos && !repos.length ? (
                <tr>
                  <td colSpan={3} className="px-4 py-6 text-center text-muted-foreground">
                    Aucun dépôt. Connectez GitHub dans Intégrations.
                  </td>
                </tr>
              ) : null}
              {!repos && !error ? (
                <tr>
                  <td colSpan={3} className="px-4 py-6 text-center text-muted-foreground">
                    Chargement…
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
