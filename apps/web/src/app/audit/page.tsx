"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Download, FileSignature } from "lucide-react";
import { api, apiDownload } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type { AuditEvent } from "@/lib/types";

interface IssuedReport {
  id: string;
  createdAt: string;
}

export default function AuditPage() {
  return (
    <Shell>
      <Audit />
    </Shell>
  );
}

function Audit() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [reports, setReports] = useState<IssuedReport[]>([]);

  function loadReports() {
    api<{ reports: IssuedReport[] }>("/api/v1/reports")
      .then((r) => setReports(r.reports))
      .catch(() => {});
  }

  useEffect(() => {
    api<{ events: AuditEvent[] }>("/api/v1/audit-events")
      .then((r) => setEvents(r.events))
      .catch(() => setError("Impossible de charger le journal d'audit."));
    loadReports();
  }, []);

  async function exportAs(format: "json" | "csv" | "pdf") {
    setBusy(format);
    try {
      const stamp = new Date().toISOString().slice(0, 10);
      const name = format === "pdf" ? `codegate-rapport-audit-${stamp}.pdf` : `codegate-evidence-${stamp}.${format}`;
      await apiDownload("/api/v1/audit/export", { format }, name);
      if (format === "pdf") loadReports();
    } catch {
      setError("Export impossible.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <header className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Audit & conformité</h1>
          <p className="text-sm text-muted-foreground">
            Journal immuable des décisions. Exportez le dossier de preuves.
          </p>
        </div>
        <div className="flex gap-2">
          {(["json", "csv", "pdf"] as const).map((f) => (
            <button
              key={f}
              onClick={() => exportAs(f)}
              disabled={busy !== null}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-50"
            >
              {f === "pdf" ? <FileSignature className="size-4" aria-hidden /> : <Download className="size-4" aria-hidden />}
              {busy === f ? "…" : f === "pdf" ? "Rapport PDF signé" : f.toUpperCase()}
            </button>
          ))}
        </div>
      </header>

      {error ? <Card className="mb-4 p-4 text-sm text-destructive">{error}</Card> : null}

      {reports.length ? (
        <section className="mb-6">
          <h2 className="mb-2 text-sm font-semibold">Rapports signés émis</h2>
          <Card>
            <ul className="divide-y divide-border text-sm">
              {reports.slice(0, 10).map((r) => (
                <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2">
                  <span>
                    <span className="font-mono text-xs">N° {r.id.slice(0, 8).toUpperCase()}</span>
                    <span className="text-muted-foreground"> · {new Date(r.createdAt).toLocaleString("fr-FR")}</span>
                  </span>
                  <Link href={`/verify/${r.id}`} className="text-xs text-primary hover:underline">
                    Page de vérification
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        </section>
      ) : null}

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-muted-foreground">
              <th className="px-4 py-2 font-medium">Horodatage</th>
              <th className="px-4 py-2 font-medium">Acteur</th>
              <th className="px-4 py-2 font-medium">Action</th>
              <th className="px-4 py-2 font-medium">Ressource</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-b border-border last:border-0 hover:bg-muted/50">
                <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                  {new Date(e.createdAt).toLocaleString("fr-FR")}
                </td>
                <td className="px-4 py-2 text-xs">{e.actorType}</td>
                <td className="px-4 py-2 font-mono text-xs">{e.action}</td>
                <td className="px-4 py-2 text-xs text-muted-foreground">{e.resourceType}</td>
              </tr>
            ))}
            {!events.length ? (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                  Aucun événement d&apos;audit.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
