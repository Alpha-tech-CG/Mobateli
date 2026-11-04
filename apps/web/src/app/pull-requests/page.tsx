"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Bot } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, StatusBadge } from "@/components/ui";
import type { PullRequestListItem } from "@/lib/types";

export default function PullRequestsPage() {
  return (
    <Shell>
      <PullRequests />
    </Shell>
  );
}

function PullRequests() {
  const [prs, setPrs] = useState<PullRequestListItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    api<{ pullRequests: PullRequestListItem[] }>("/api/v1/pull-requests")
      .then((r) => setPrs(r.pullRequests))
      .catch(() => setError("Impossible de charger les pull requests."))
      .finally(() => setLoaded(true));
  }, []);

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Pull requests</h1>
        <p className="text-sm text-muted-foreground">
          Analyses de sécurité des PR générées par IA.
        </p>
      </header>

      {error ? (
        <Card className="p-4 text-sm text-destructive">{error}</Card>
      ) : (
        <Card>
          <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="px-4 py-2 font-medium">PR</th>
                <th className="px-4 py-2 font-medium">Dépôt</th>
                <th className="px-4 py-2 font-medium">Auteur</th>
                <th className="px-4 py-2 font-medium">Risque</th>
                <th className="px-4 py-2 font-medium">Problèmes</th>
                <th className="px-4 py-2 font-medium">Statut</th>
              </tr>
            </thead>
            <tbody>
              {prs.map((pr) => (
                <tr
                  key={pr.id}
                  className="border-b border-border last:border-0 hover:bg-muted/50"
                >
                  <td className="px-4 py-2">
                    <Link
                      href={`/pull-requests/${pr.id}`}
                      className="flex items-center gap-2 text-primary hover:underline"
                    >
                      {pr.aiGenerated ? (
                        <Bot className="size-4 text-accent" aria-label="Généré par IA" />
                      ) : null}
                      <span className="font-mono text-xs">#{pr.number}</span>
                      <span className="text-foreground">{pr.title}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                    {pr.repository}
                  </td>
                  <td className="px-4 py-2">{pr.author}</td>
                  <td className="px-4 py-2 font-mono">{pr.riskScore ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {pr.counts.secrets}🔑 · {pr.counts.dependencies}📦 · {pr.counts.findings}🔎
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={pr.status} />
                  </td>
                </tr>
              ))}
              {loaded && !prs.length ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                    Aucune pull request analysée pour le moment.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
          </div>
        </Card>
      )}
    </div>
  );
}
