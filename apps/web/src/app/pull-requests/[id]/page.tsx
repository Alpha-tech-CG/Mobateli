"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { api, ApiError, getSession } from "@/lib/api";
import { Shell } from "@/components/shell";
import { ReportButton } from "@/components/report-button";
import { FindingCard, type FindingVerdict } from "@/components/finding-card";
import { Card, StatusBadge } from "@/components/ui";
import type { Finding, LastAnalysis, PullRequestDetail, RevocationGuide, SecretFinding } from "@/lib/types";

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

  const [feedbackError, setFeedbackError] = useState<string | null>(null);
  const canReview = ["owner", "admin", "security_manager"].includes(getSession()?.role ?? "");

  function onError(e: unknown) {
    const code = e instanceof ApiError ? e.code : "";
    setFeedbackError(
      code === "forbidden"
        ? "Seuls les rôles owner, admin et security_manager peuvent qualifier une alerte."
        : code === "rescan_required"
          ? "Alerte antérieure au suivi : relancez l'analyse de la PR puis réessayez."
          : "Impossible d'enregistrer le retour.",
    );
  }

  // Team verdict on an alert: true positive, false positive (with a category)
  // or accepted risk (with an expiry). It carries to the same alert everywhere
  // on this repository and rescores the PR.
  async function giveVerdict(f: Finding, v: FindingVerdict) {
    setFeedbackError(null);
    try {
      await api(`/api/v1/findings/${f.id}/feedback`, { method: "PUT", body: JSON.stringify(v) });
      load();
    } catch (e) {
      onError(e);
    }
  }

  async function clearVerdict(f: Finding) {
    setFeedbackError(null);
    try {
      await api(`/api/v1/findings/${f.id}/feedback`, { method: "DELETE", body: "{}" });
      load();
    } catch (e) {
      onError(e);
    }
  }

  // Feedback on the RULE itself (too noisy, to disable, to restrict…): feeds
  // the rule's improvement and the auto-observation of noisy rules.
  async function ruleFeedback(f: Finding, kind: string) {
    if (!f.ruleId) return;
    setFeedbackError(null);
    try {
      await api(`/api/v1/rules/${encodeURIComponent(f.ruleId)}/feedback`, {
        method: "POST",
        body: JSON.stringify({ kind, findingId: f.id }),
      });
    } catch (e) {
      onError(e);
    }
  }

  // Contest a block: a reviewer then upholds or overturns it.
  async function contest() {
    const reason = prompt("Pourquoi contester ce blocage ? (au moins 10 caractères)");
    if (!reason || reason.trim().length < 10) return;
    try {
      await api(`/api/v1/pull-requests/${id}/contest`, { method: "POST", body: JSON.stringify({ reason }) });
      load();
    } catch (e) {
      const code = e instanceof ApiError ? e.code : "";
      setFeedbackError(code === "already_contested" ? "Ce blocage est déjà contesté." : "Contestation impossible.");
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
          <ReportButton type="pull-request" id={pr.id} name={`${pr.repository.name}-pr-${pr.number}`} />
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
              <SecretRow key={s.id} secret={s} onChange={load} />
            ))}
          </ul>
        ) : (
          <Empty>Aucun secret détecté.</Empty>
        )}
      </Section>

      <Section
        title={`📦 Dépendances — ${pr.dependencies.length} analysée(s), ${
          pr.dependencies.filter((d) => d.riskLevel !== "low").length
        } à risque`}
      >
        {pr.dependencies.length && !pr.dependencies.some((d) => d.riskLevel !== "low") ? (
          <p className="border-b border-border px-4 py-2 text-xs text-success">
            Toutes les dépendances ajoutées ou mises à jour sont saines (vulnérabilités connues, registre,
            typosquatting vérifiés).
          </p>
        ) : null}
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

      {pr.status === "blocked" ? (
        <div className="mb-6 flex items-center justify-between gap-3 rounded border border-destructive/40 bg-destructive/5 px-4 py-2 text-sm">
          <span>Ce blocage repose sur des alertes prouvées. Vous le jugez erroné ?</span>
          <button type="button" onClick={contest} className="rounded border border-border px-2 py-1 text-xs hover:bg-muted">
            Contester le blocage
          </button>
        </div>
      ) : null}

      <Section title={`🔎 Problèmes de code (${pr.findings.length})`}>
        {feedbackError ? <p className="px-4 pt-3 text-sm text-destructive">{feedbackError}</p> : null}
        {pr.findings.length ? (
          <ul className="divide-y divide-border">
            {pr.findings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                canReview={canReview}
                onVerdict={giveVerdict}
                onClear={clearVerdict}
                onRuleFeedback={ruleFeedback}
              />
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
  secrets: "Secrets exposés",
  dependencies: "Confiance des dépendances",
  sast: "Règles de code (SAST)",
  sensitive_files: "Fichiers sensibles",
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
