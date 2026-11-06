"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, SeverityBadge, StatusBadge } from "@/components/ui";
import type { Finding, PullRequestDetail } from "@/lib/types";

export default function PullRequestDetailPage() {
  return (
    <Shell>
      <Detail />
    </Shell>
  );
}

const RISK_COLORS: Record<string, string> = {
  low: "text-success",
  medium: "text-warning",
  high: "text-accent",
  critical: "text-destructive",
};

function Detail() {
  const { id } = useParams<{ id: string }>();
  const [pr, setPr] = useState<PullRequestDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rescanning, setRescanning] = useState(false);

  function load() {
    api<{ pullRequest: PullRequestDetail }>(`/api/v1/pull-requests/${id}`)
      .then((r) => setPr(r.pullRequest))
      .catch(() => setError("PR introuvable."));
  }
  useEffect(load, [id]);

  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  // Team verdict on an alert (pilot false-positive tracking). A false
  // positive stops counting in later verdicts for the same code on this repo.
  async function giveFeedback(f: Finding, verdict: "false_positive" | "confirmed" | null) {
    setFeedbackError(null);
    try {
      if (verdict) {
        await api(`/api/v1/findings/${f.id}/feedback`, { method: "PUT", body: JSON.stringify({ verdict }) });
      } else {
        await api(`/api/v1/findings/${f.id}/feedback`, { method: "DELETE", body: "{}" });
      }
      load();
    } catch (e) {
      const code = e instanceof ApiError ? e.code : "";
      setFeedbackError(
        code === "forbidden"
          ? "Seuls les rôles owner, admin et security_manager peuvent qualifier une alerte."
          : code === "rescan_required"
            ? "Alerte antérieure au suivi : relancez l'analyse de la PR puis réessayez."
            : "Impossible d'enregistrer le retour.",
      );
    }
  }

  async function rescan() {
    setRescanning(true);
    try {
      await api(`/api/v1/pull-requests/${id}/rescan`, { method: "POST" });
      setTimeout(load, 2000);
    } finally {
      setTimeout(() => setRescanning(false), 2000);
    }
  }

  if (error) return <Card className="p-4 text-sm text-destructive">{error}</Card>;
  if (!pr) return <p className="text-sm text-muted-foreground">Chargement…</p>;

  return (
    <div>
      <Link
        href="/pull-requests"
        className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-4" aria-hidden /> Pull requests
      </Link>

      <header className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">
            <span className="font-mono text-muted-foreground">#{pr.number}</span> {pr.title}
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            <span className="font-mono">{pr.repository.name}</span> · {pr.author}
            {pr.aiGenerated ? " · généré par IA" : ""} · protection{" "}
            {pr.repository.protectionLevel}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="font-mono text-2xl font-semibold">{pr.riskScore ?? "—"}</p>
            <p className="text-xs text-muted-foreground">risque / 100</p>
          </div>
          <StatusBadge status={pr.status} />
          <button
            onClick={rescan}
            disabled={rescanning}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-50"
          >
            <RefreshCw className={`size-4 ${rescanning ? "animate-spin" : ""}`} aria-hidden />
            Réanalyser
          </button>
        </div>
      </header>

      <Section title={`🔑 Secrets (${pr.secretFindings.length})`}>
        {pr.secretFindings.length ? (
          <ul className="divide-y divide-border">
            {pr.secretFindings.map((s) => (
              <li key={s.id} className="flex items-center justify-between px-4 py-3 text-sm">
                <span>
                  <span className="font-medium">{s.secretType}</span>{" "}
                  <span className="font-mono text-xs text-muted-foreground">{s.location}</span>
                </span>
                <span className="font-mono text-xs text-muted-foreground">{s.maskedPreview}</span>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>Aucun secret détecté.</Empty>
        )}
      </Section>

      <Section title={`📦 Dépendances (${pr.dependencies.length})`}>
        {pr.dependencies.length ? (
          <ul className="divide-y divide-border">
            {pr.dependencies.map((d) => (
              <li key={d.id} className="px-4 py-3 text-sm">
                <div className="flex items-center justify-between">
                  <span className="font-mono">
                    {d.name}@{d.version}
                  </span>
                  <span className={`text-xs font-medium ${RISK_COLORS[d.riskLevel] ?? ""}`}>
                    {d.riskLevel} · confiance {d.trustScore ?? "—"}/100
                  </span>
                </div>
                {d.reason ? (
                  <p className="mt-1 text-xs text-muted-foreground">{d.reason}</p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <Empty>Aucune dépendance ajoutée.</Empty>
        )}
      </Section>

      <Section title={`🔎 Problèmes de code (${pr.findings.length})`}>
        {feedbackError ? <p className="px-4 pt-3 text-sm text-destructive">{feedbackError}</p> : null}
        {pr.findings.length ? (
          <ul className="divide-y divide-border">
            {pr.findings.map((f) => (
              <li key={f.id} className={`px-4 py-3 text-sm ${f.status === "false_positive" ? "opacity-60" : ""}`}>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className={`font-medium ${f.status === "false_positive" ? "line-through" : ""}`}>{f.title}</span>
                  {f.status === "false_positive" ? (
                    <span className="rounded bg-muted px-1.5 py-0.5 text-xs">fausse alerte</span>
                  ) : f.status === "acknowledged" ? (
                    <span className="rounded bg-muted px-1.5 py-0.5 text-xs">confirmée</span>
                  ) : null}
                  {f.filePath ? (
                    <span className="font-mono text-xs text-muted-foreground">
                      {f.filePath}
                      {f.line ? `:${f.line}` : ""}
                    </span>
                  ) : null}
                </div>
                <p className="mt-1 text-muted-foreground">{f.description}</p>
                {f.remediation ? (
                  <p className="mt-1 text-xs">
                    <span className="font-medium">Correctif :</span> {f.remediation}
                  </p>
                ) : null}
                <div className="mt-2 flex gap-2 text-xs">
                  {f.status === "open" ? (
                    <>
                      <button
                        type="button"
                        onClick={() => giveFeedback(f, "false_positive")}
                        className="rounded border border-border px-2 py-0.5 hover:bg-muted"
                      >
                        Fausse alerte
                      </button>
                      <button
                        type="button"
                        onClick={() => giveFeedback(f, "confirmed")}
                        className="rounded border border-border px-2 py-0.5 hover:bg-muted"
                      >
                        Confirmée
                      </button>
                    </>
                  ) : f.status === "false_positive" || f.status === "acknowledged" ? (
                    <button
                      type="button"
                      onClick={() => giveFeedback(f, null)}
                      className="rounded border border-border px-2 py-0.5 hover:bg-muted"
                    >
                      Annuler le retour
                    </button>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <Empty>Aucun problème de code détecté.</Empty>
        )}
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-6">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h2>
      <Card>{children}</Card>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-4 py-6 text-center text-sm text-muted-foreground">{children}</p>;
}
