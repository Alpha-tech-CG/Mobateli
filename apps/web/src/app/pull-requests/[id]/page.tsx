"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, SeverityBadge, StatusBadge } from "@/components/ui";
import type { LastAnalysis, PullRequestDetail } from "@/lib/types";

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
  const [lastAnalysis, setLastAnalysis] = useState<LastAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rescanning, setRescanning] = useState(false);

  function load() {
    api<{ pullRequest: PullRequestDetail; lastAnalysis: LastAnalysis | null }>(
      `/api/v1/pull-requests/${id}`,
    )
      .then((r) => {
        setPr(r.pullRequest);
        setLastAnalysis(r.lastAnalysis);
      })
      .catch(() => setError("PR introuvable."));
  }
  useEffect(load, [id]);

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

      <AnalysisCoverage last={lastAnalysis} />

      {/* Nothing was checked: "no secret detected" etc. would read as a clean bill. */}
      {lastAnalysis && lastAnalysis.outcome !== "analyzed" ? null : (
      <>
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
        {pr.findings.length ? (
          <ul className="divide-y divide-border">
            {pr.findings.map((f) => (
              <li key={f.id} className="px-4 py-3 text-sm">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-medium">{f.title}</span>
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
              </li>
            ))}
          </ul>
        ) : (
          <Empty>Aucun problème de code détecté.</Empty>
        )}
      </Section>
      </>
      )}
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

const ENGINE_LABELS: Record<string, string> = {
  osv: "Vulnérabilités connues (OSV)",
  sca: "Dépendances complètes (Trivy/Grype)",
  semgrep: "Analyse sémantique (Semgrep)",
  rust: "Analyse de flux (moteur Rust)",
};

const ENGINE_STATUS: Record<string, { mark: string; className: string }> = {
  ok: { mark: "✓", className: "text-success" },
  skipped: { mark: "–", className: "text-muted-foreground" },
  failed: { mark: "✗", className: "text-destructive" },
};

/**
 * What the last analysis actually covered. "Nothing found" only means
 * something if the checks ran — say so when they did not.
 */
function AnalysisCoverage({ last }: { last: LastAnalysis | null }) {
  if (!last) return null;
  if (last.outcome !== "analyzed") {
    const why =
      last.reason === "no_diff_source"
        ? "le code de cette PR n'est pas accessible (fournisseur non connecté ou GitLab en bêta)"
        : "le code de cette PR n'a pas pu être récupéré";
    return (
      <Card className="mb-6 border-warning/40 p-4 text-sm">
        <p className="font-medium text-warning">Non analysée — à revoir manuellement</p>
        <p className="mt-1 text-muted-foreground">CodeGate n&apos;a rien vérifié : {why}.</p>
      </Card>
    );
  }
  const entries = Object.entries(last.engines);
  if (!entries.length) return null;
  const partial = entries.some(([, r]) => r.status === "failed");
  return (
    <Card className={`mb-6 p-4 text-sm ${partial ? "border-warning/40" : ""}`}>
      <p className={`mb-2 font-medium ${partial ? "text-warning" : ""}`}>
        {partial ? "Analyse partielle" : "Couverture de l'analyse"}
      </p>
      <ul className="grid gap-1 sm:grid-cols-2">
        {entries.map(([name, r]) => {
          const s = ENGINE_STATUS[r.status] ?? ENGINE_STATUS.skipped!;
          return (
            <li key={name} className="flex gap-2">
              <span className={`font-mono ${s.className}`} aria-hidden>
                {s.mark}
              </span>
              <span>
                {ENGINE_LABELS[name] ?? name}
                {r.detail ? <span className="text-muted-foreground"> — {r.detail}</span> : null}
              </span>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-4 py-6 text-center text-sm text-muted-foreground">{children}</p>;
}
