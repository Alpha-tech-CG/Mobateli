"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card, SeverityBadge, StatusBadge } from "@/components/ui";
import type { PullRequestDetail, RevocationGuide, SecretFinding } from "@/lib/types";

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

  async function rescan() {
    setRescanning(true);
    try {
      await api(`/api/v1/pull-requests/${id}/rescan`, { method: "POST" });
      setTimeout(load, 2000);
    } finally {
      setTimeout(() => setRescanning(false), 2000);
    }
  }

  async function triage(findingId: string, status: "open" | "false_positive") {
    const reason =
      status === "false_positive"
        ? prompt("Pourquoi est-ce un faux positif ? (conservé dans le journal d'audit)") ?? undefined
        : undefined;
    if (status === "false_positive" && reason === undefined) return;
    try {
      await api(`/api/v1/findings/${findingId}`, {
        method: "PATCH",
        body: JSON.stringify({ status, ...(reason ? { reason } : {}) }),
      });
      load();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 403
          ? "Seuls les rôles Owner, Admin et Security Manager (avec MFA) peuvent qualifier un faux positif."
          : "Mise à jour impossible.",
      );
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
              <SecretRow key={s.id} secret={s} onChange={load} />
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
              <li
                key={f.id}
                className={`px-4 py-3 text-sm ${f.status === "false_positive" ? "opacity-60" : ""}`}
              >
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
                <div className="mt-2 flex items-center gap-3 text-xs">
                  {f.status === "false_positive" ? (
                    <>
                      <span className="text-muted-foreground">Marqué faux positif — exclu du score</span>
                      <button
                        type="button"
                        onClick={() => triage(f.id, "open")}
                        className="cursor-pointer text-primary hover:underline"
                      >
                        Rouvrir
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      onClick={() => triage(f.id, "false_positive")}
                      className="cursor-pointer text-muted-foreground hover:text-foreground hover:underline"
                    >
                      Marquer comme faux positif
                    </button>
                  )}
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

/** A detected secret with its guided revocation (US03). */
function SecretRow({ secret, onChange }: { secret: SecretFinding; onChange: () => void }) {
  const [guide, setGuide] = useState<RevocationGuide | null>(null);
  const [error, setError] = useState<string | null>(null);
  const revoked = Boolean(secret.revokedAt) || secret.status === "resolved";

  async function toggleGuide() {
    if (guide) return setGuide(null);
    try {
      const r = await api<{ guide: RevocationGuide }>(`/api/v1/secrets/${secret.id}/revocation`);
      setGuide(r.guide);
    } catch {
      setError("Guide indisponible.");
    }
  }

  async function markRevoked() {
    if (!confirm("Confirmez-vous que la clé a été révoquée chez le fournisseur ?")) return;
    try {
      await api(`/api/v1/secrets/${secret.id}/revoked`, { method: "POST" });
      onChange();
    } catch {
      setError("Mise à jour impossible.");
    }
  }

  return (
    <li className="px-4 py-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span>
          <span className="font-medium">{secret.secretType}</span>{" "}
          <span className="font-mono text-xs text-muted-foreground">{secret.location}</span>
        </span>
        <span className="font-mono text-xs text-muted-foreground">{secret.maskedPreview}</span>
      </div>
      <div className="mt-2 flex items-center gap-3 text-xs">
        {revoked ? (
          <span className="text-success">Révoqué — exclu du score</span>
        ) : (
          <>
            <button type="button" onClick={toggleGuide} className="cursor-pointer text-primary hover:underline">
              {guide ? "Masquer la procédure" : "Procédure de révocation"}
            </button>
            <button
              type="button"
              onClick={markRevoked}
              className="cursor-pointer text-muted-foreground hover:text-foreground hover:underline"
            >
              Marquer comme révoqué
            </button>
          </>
        )}
      </div>
      {guide ? (
        <div className="mt-2 rounded-md border border-border bg-muted/40 p-3 text-xs">
          <p className="font-medium">
            {guide.provider}
            {guide.url ? (
              <>
                {" — "}
                <a href={guide.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                  ouvrir la console
                </a>
              </>
            ) : null}
          </p>
          <ol className="mt-2 list-decimal space-y-1 pl-4">
            {guide.steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </div>
      ) : null}
      {error ? <p className="mt-1 text-xs text-destructive">{error}</p> : null}
    </li>
  );
}
