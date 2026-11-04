"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { ReportButton } from "@/components/report-button";
import { Card, SeverityBadge } from "@/components/ui";
import { RiskBadge } from "@/components/risk-badge";
import { ScanProgress } from "@/components/scan-progress";
import { ArchitecturePanel } from "@/components/architecture-panel";
import type { ScanDetail } from "@/lib/types";

export default function ScanDetailPage() {
  return (
    <Shell>
      <ScanView />
    </Shell>
  );
}

function ScanView() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"issues" | "architecture">("issues");

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const r = await api<{ scan: ScanDetail }>(`/api/v1/scans/${id}`);
        setScan(r.scan);
        if (r.scan.status === "queued" || r.scan.status === "running") timer = setTimeout(tick, 1500);
      } catch {
        setError("Analyse introuvable.");
      }
    };
    void tick();
    return () => clearTimeout(timer);
  }, [id]);

  if (error) return <Card className="p-4 text-sm text-destructive">{error}</Card>;
  if (!scan) return <p className="text-sm text-muted-foreground">Chargement…</p>;

  const result = scan.result;
  const risks = result?.findings.filter((f) => f.severity !== "info") ?? [];
  const notes = result?.findings.filter((f) => f.severity === "info") ?? [];

  return (
    <div className="space-y-6">
      <Link href="/scans" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" aria-hidden /> Analyses
      </Link>

      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">{scan.repository.name}</h1>
          <p className="font-mono text-xs text-muted-foreground">
            {scan.ref ?? ""}
            {scan.commitSha ? ` @ ${scan.commitSha.slice(0, 7)}` : ""} · {scan.filesScanned} fichiers ·{" "}
            {new Date(scan.createdAt).toLocaleString("fr-FR")}
            {scan.summary?.engine ? ` · moteur ${scan.summary.engine}` : ""}
          </p>
        </div>
        <div className="flex items-start gap-3">
          {scan.status === "done" ? <RiskBadge risk={scan.riskScore ?? 0} /> : null}
          {scan.status === "done" ? <ReportButton type="scan" id={scan.id} name={`${scan.repository.name}-audit`} /> : null}
        </div>
      </header>

      {scan.status !== "done" ? (
        <Card className="p-5">
          <ScanProgress status={scan.status} phase={scan.phase} filesScanned={scan.filesScanned} />
          {scan.error ? <p className="mt-3 text-sm text-destructive">Échec : {scan.error}</p> : null}
        </Card>
      ) : null}

      {result ? (
        <>
          <div role="tablist" aria-label="Vue de l'analyse" className="flex gap-1 border-b border-border">
            {(
              [
                ["issues", "Failles & dépendances"],
                ["architecture", "Architecture & impact"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={tab === key}
                onClick={() => setTab(key)}
                className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium ${
                  tab === key ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                {label}
                {key === "architecture" && result.architecture ? (
                  <span className="ml-2 rounded-full bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                    {result.architecture.fragility.score}/100
                  </span>
                ) : null}
              </button>
            ))}
          </div>

          {tab === "architecture" ? (
            result.architecture ? (
              <ArchitecturePanel report={result.architecture} />
            ) : (
              <Card className="p-4 text-sm text-muted-foreground">
                Cette analyse date d&apos;avant la cartographie d&apos;architecture : relancez une analyse du dépôt pour obtenir le graphe.
              </Card>
            )
          ) : (
          <>
          {scan.summary?.truncated ? (
            <Card className="p-4 text-sm text-warning">
              Dépôt volumineux : seuls les {scan.filesScanned} premiers fichiers ont été analysés.
            </Card>
          ) : null}

          <Section title={`🔑 Secrets (${result.secrets.length})`}>
            {result.secrets.length ? (
              <ul className="divide-y divide-border">
                {result.secrets.map((s, i) => (
                  <li key={i} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm">
                    <span>
                      <span className="font-medium">{s.secretType}</span>{" "}
                      <span className="font-mono text-xs text-muted-foreground">{s.location}</span>
                    </span>
                    <span className="font-mono text-xs text-muted-foreground">{s.maskedPreview}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Aucun secret dans le code.</Empty>
            )}
          </Section>

          <Section title={`📦 Dépendances à risque (${result.dependencies.length})`}>
            {result.dependencies.length ? (
              <ul className="divide-y divide-border">
                {result.dependencies.map((d, i) => (
                  <li key={i} className="px-4 py-3 text-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-mono">
                        {d.name}@{d.resolvedVersion ?? d.version}{" "}
                        <span className="text-xs text-muted-foreground">
                          ({d.ecosystem}
                          {d.resolvedVersion ? `, déclaré ${d.version}` : ""})
                        </span>
                      </span>
                      <span className="text-xs font-medium">{d.riskLevel} · confiance {d.trustScore}/100</span>
                    </div>
                    {d.reason ? <p className="mt-1 text-xs text-muted-foreground">{d.reason}</p> : null}
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Aucune dépendance à risque.</Empty>
            )}
          </Section>

          <Section title={`🔎 Problèmes de code (${risks.length})`}>
            {risks.length ? (
              <ul className="divide-y divide-border">
                {risks.map((f, i) => (
                  <li key={i} className="px-4 py-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
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
              <Empty>Aucun problème de code.</Empty>
            )}
          </Section>

          {notes.length ? (
            <details className="rounded-lg border border-border bg-card">
              <summary className="cursor-pointer px-4 py-3 text-sm font-medium">
                ℹ️ {notes.length} information(s) sans impact sur le score
              </summary>
              <ul className="divide-y divide-border border-t border-border">
                {notes.map((f, i) => (
                  <li key={i} className="px-4 py-2 text-xs text-muted-foreground">
                    {f.title}
                    {f.filePath ? ` — ${f.filePath}${f.line ? `:${f.line}` : ""}` : ""}
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
          </>
          )}
        </>
      ) : null}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="text-sm font-semibold">{title}</h2>
      <Card>{children}</Card>
    </section>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="px-4 py-6 text-center text-sm text-muted-foreground">{children}</p>;
}
