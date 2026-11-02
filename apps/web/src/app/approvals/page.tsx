"use client";

import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type { ApprovalRow } from "@/lib/types";

const STATUS_STYLE: Record<ApprovalRow["status"], string> = {
  pending: "bg-warning/15 text-warning",
  approved: "bg-success/15 text-success",
  denied: "bg-destructive/15 text-destructive",
  expired: "bg-muted text-muted-foreground",
};
const STATUS_LABEL: Record<ApprovalRow["status"], string> = {
  pending: "en attente",
  approved: "approuvée",
  denied: "refusée",
  expired: "expirée",
};

export default function ApprovalsPage() {
  return (
    <Shell>
      <Approvals />
    </Shell>
  );
}

function Approvals() {
  const [rows, setRows] = useState<ApprovalRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<{ approvals: ApprovalRow[] }>("/api/v1/approvals")
      .then((r) => setRows(r.approvals))
      .catch(() => setError("Impossible de charger les approbations."))
      .finally(() => setLoaded(true));
  }, []);
  useEffect(load, [load]);

  async function decide(id: string, decision: "approve" | "deny") {
    const reason =
      decision === "deny" ? (prompt("Motif du refus (journal d'audit) :") ?? undefined) : undefined;
    if (decision === "deny" && reason === undefined) return;
    setError(null);
    try {
      await api(`/api/v1/approvals/${id}/decision`, {
        method: "POST",
        body: JSON.stringify({ decision, ...(reason ? { reason } : {}) }),
      });
      load();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 403
          ? "Seuls les rôles Owner, Admin et Security Manager (avec MFA) peuvent décider."
          : "Décision impossible (déjà traitée ou expirée).",
      );
      load();
    }
  }

  const pending = rows.filter((r) => r.status === "pending");
  const history = rows.filter((r) => r.status !== "pending");

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Approbations</h1>
        <p className="text-sm text-muted-foreground">
          Actions sensibles d&apos;agents IA et déploiements en attente d&apos;une décision humaine.
          Sans réponse sous 24 h, la demande expire et l&apos;action reste bloquée.
        </p>
      </header>

      {error ? <Card className="p-4 text-sm text-destructive">{error}</Card> : null}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">En attente ({pending.length})</h2>
        {loaded && !pending.length ? (
          <Card className="p-4 text-sm text-muted-foreground">Rien à valider.</Card>
        ) : null}
        {pending.map((r) => (
          <Card key={r.id} className="p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">
                  {r.kind === "deployment" ? "Déploiement" : "Action d'agent IA"}
                </p>
                <p className="mt-1 font-medium">{r.title}</p>
                {r.detail.reason ? (
                  <p className="mt-1 text-sm text-muted-foreground">{r.detail.reason}</p>
                ) : null}
                <p className="mt-1 font-mono text-xs text-muted-foreground">
                  demandé le {new Date(r.createdAt).toLocaleString("fr-FR")} · expire le{" "}
                  {new Date(r.expiresAt).toLocaleString("fr-FR")}
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => decide(r.id, "approve")}
                  className="cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary hover:opacity-90"
                >
                  Approuver
                </button>
                <button
                  type="button"
                  onClick={() => decide(r.id, "deny")}
                  className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive hover:bg-muted"
                >
                  Refuser
                </button>
              </div>
            </div>
          </Card>
        ))}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">Historique</h2>
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Demande</th>
                  <th className="px-4 py-2 font-medium">Statut</th>
                  <th className="px-4 py-2 font-medium">Décision</th>
                </tr>
              </thead>
              <tbody>
                {history.map((r) => (
                  <tr key={r.id} className="border-b border-border last:border-0">
                    <td className="px-4 py-2">{r.title}</td>
                    <td className="px-4 py-2">
                      <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_STYLE[r.status]}`}>
                        {STATUS_LABEL[r.status]}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {r.decidedAt ? new Date(r.decidedAt).toLocaleString("fr-FR") : "—"}
                      {r.reason ? ` · ${r.reason}` : ""}
                    </td>
                  </tr>
                ))}
                {loaded && !history.length ? (
                  <tr>
                    <td colSpan={3} className="px-4 py-6 text-center text-muted-foreground">
                      Aucune décision pour le moment.
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
