"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type { DeployCheckRow, DeployDecision } from "@/lib/types";

const DECISION_STYLE: Record<DeployDecision, string> = {
  authorized: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  blocked: "bg-destructive/15 text-destructive",
  requires_approval: "bg-accent/15 text-accent",
};

export default function DeploymentsPage() {
  return (
    <Shell>
      <Deployments />
    </Shell>
  );
}

function Deployments() {
  const [checks, setChecks] = useState<DeployCheckRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    api<{ deployChecks: DeployCheckRow[] }>("/api/v1/deploy-checks")
      .then((r) => setChecks(r.deployChecks))
      .catch(() => setError("Impossible de charger les contrôles de déploiement."))
      .finally(() => setLoaded(true));
  }, []);

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Déploiements</h1>
        <p className="text-sm text-muted-foreground">
          Contrôle de sécurité avant chaque déploiement Vercel.
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
                <th className="px-4 py-2 font-medium">Dépôt</th>
                <th className="px-4 py-2 font-medium">Cible</th>
                <th className="px-4 py-2 font-medium">Décision</th>
                <th className="px-4 py-2 font-medium">Motif</th>
                <th className="px-4 py-2 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((c) => (
                <tr key={c.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                  <td className="px-4 py-2 font-mono text-xs">{c.repository}</td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                    {c.target ?? "—"}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${DECISION_STYLE[c.decision]}`}
                    >
                      {c.decision}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{c.reason}</td>
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                    {new Date(c.createdAt).toLocaleString("fr-FR")}
                  </td>
                </tr>
              ))}
              {loaded && !checks.length ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                    Aucun contrôle de déploiement pour le moment.
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
