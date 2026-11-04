"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, CheckCircle2, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { Shell } from "@/components/shell";
import { ReportButton } from "@/components/report-button";
import { Card, SeverityBadge } from "@/components/ui";
import { ScoreBadge } from "@/components/score";
import { BackupStatusBadge, formatBytes } from "@/components/backup-status";
import { BackupInstall } from "@/components/backup-install";
import type { BackupDetail, BackupEvaluation } from "@/lib/types";

export default function BackupPage() {
  return (
    <Shell>
      <BackupView />
    </Shell>
  );
}

function BackupView() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [backup, setBackup] = useState<BackupDetail | null>(null);
  const [evaluation, setEvaluation] = useState<BackupEvaluation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    api<{ backup: BackupDetail; evaluation: BackupEvaluation }>(`/api/v1/backups/${id}`)
      .then((r) => {
        setBackup(r.backup);
        setEvaluation(r.evaluation);
      })
      .catch(() => setError("Sauvegarde introuvable."));
  }, [id]);

  async function rotate() {
    if (!confirm("Révoquer le token actuel ? Le script de sauvegarde devra être mis à jour.")) return;
    const r = await api<{ reportToken: string }>(`/api/v1/backups/${id}/rotate-token`, {
      method: "POST",
    });
    setToken(r.reportToken);
  }

  async function remove() {
    if (!confirm("Retirer ce suivi de sauvegarde ? (vos sauvegardes ne sont pas touchées)")) return;
    await api(`/api/v1/backups/${id}`, { method: "DELETE" });
    router.push("/backups");
  }

  if (error) return <Card className="p-4 text-sm text-destructive">{error}</Card>;
  if (!backup || !evaluation) return <p className="text-sm text-muted-foreground">Chargement…</p>;

  const failed = evaluation.checks.filter((c) => !c.ok);
  const passed = evaluation.checks.filter((c) => c.ok);

  return (
    <div className="space-y-6">
      <Link
        href="/backups"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Sauvegardes
      </Link>

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex flex-wrap items-center gap-3 text-xl font-semibold">
            {backup.name} <ScoreBadge score={evaluation.score} />
            <BackupStatusBadge status={evaluation.status} />
          </h1>
          <p className="text-xs text-muted-foreground">
            {backup.type} · attendue toutes les {backup.frequencyHours} h
            {backup.server ? ` · serveur ${backup.server.name}` : ""}
          </p>
          <p
            className={`mt-2 inline-flex items-center gap-1 text-xs ${
              evaluation.ransomwareReady ? "text-success" : "text-warning"
            }`}
          >
            {evaluation.ransomwareReady ? (
              <CheckCircle2 className="h-4 w-4" />
            ) : (
              <ShieldAlert className="h-4 w-4" />
            )}
            {evaluation.ransomwareReady
              ? "Résiste à un ransomware (chiffrée, clé isolée, hors site, immuable)"
              : "Vulnérable à un ransomware qui compromettrait le serveur"}
          </p>
        </div>
        <div className="flex items-start gap-2">
          <ReportButton type="backup" id={backup.id} name={backup.name} />
          <button
            onClick={rotate}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted"
          >
            Nouveau token
          </button>
          <button
            onClick={remove}
            className="cursor-pointer rounded-md border border-border px-3 py-2 text-sm text-destructive transition-colors duration-150 hover:bg-muted"
          >
            Retirer
          </button>
        </div>
      </header>

      {token ? (
        <Card className="p-4">
          <BackupInstall token={token} />
        </Card>
      ) : null}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">À corriger ({failed.length})</h2>
        {failed.length === 0 ? (
          <Card className="p-4 text-sm text-success">Tous les contrôles Backup Shield passent.</Card>
        ) : (
          failed.map((c) => (
            <Card key={c.id} className="p-4">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={c.severity} />
                <span className="font-medium">{c.label}</span>
              </div>
              <p className="mt-1 text-sm text-muted-foreground">{c.detail}</p>
              {c.recommendation ? (
                <p className="mt-2 text-sm">
                  <span className="font-medium">Correctif : </span>
                  <Inline text={c.recommendation} />
                </p>
              ) : null}
            </Card>
          ))
        )}
      </section>

      {passed.length ? (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold">Conformes ({passed.length})</h2>
          <Card className="divide-y divide-border">
            {passed.map((c) => (
              <div key={c.id} className="flex flex-wrap items-center gap-2 px-4 py-2 text-sm">
                <CheckCircle2 className="h-4 w-4 text-success" />
                <span className="font-medium">{c.label}</span>
                <span className="text-xs text-muted-foreground">{c.detail}</span>
              </div>
            ))}
          </Card>
        </section>
      ) : null}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">Tests de restauration</h2>
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[520px] text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Date</th>
                  <th className="px-4 py-2 font-medium">Résultat</th>
                  <th className="px-4 py-2 font-medium">Durée</th>
                  <th className="px-4 py-2 font-medium">Restauré</th>
                </tr>
              </thead>
              <tbody>
                {backup.restoreTests.map((t) => (
                  <tr key={t.id} className="border-b border-border last:border-0">
                    <td className="px-4 py-2 font-mono text-xs">
                      {new Date(t.completedAt).toLocaleString("fr-FR")}
                    </td>
                    <td className={`px-4 py-2 text-xs ${t.result === "success" ? "text-success" : "text-destructive"}`}>
                      {t.result === "success" ? "réussie" : `échec${t.detail ? ` — ${t.detail}` : ""}`}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">{t.durationSeconds} s</td>
                    <td className="px-4 py-2 text-xs">
                      {t.restoredTables ?? "—"} tables · {t.restoredRecords ?? "—"} lignes
                    </td>
                  </tr>
                ))}
                {!backup.restoreTests.length ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-muted-foreground">
                      Jamais testée.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Card>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">Dernières exécutions</h2>
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2 font-medium">Date</th>
                  <th className="px-4 py-2 font-medium">Statut</th>
                  <th className="px-4 py-2 font-medium">Taille</th>
                  <th className="px-4 py-2 font-medium">Chiffrement</th>
                  <th className="px-4 py-2 font-medium">Stockage</th>
                  <th className="px-4 py-2 font-medium">Intégrité</th>
                </tr>
              </thead>
              <tbody>
                {backup.runs.map((r) => (
                  <tr key={r.id} className="border-b border-border last:border-0">
                    <td className="px-4 py-2 font-mono text-xs">
                      {new Date(r.finishedAt).toLocaleString("fr-FR")}
                    </td>
                    <td className={`px-4 py-2 text-xs ${r.status === "success" ? "" : "text-destructive"}`}>
                      {r.status === "success" ? "succès" : "échec"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">{formatBytes(r.sizeBytes)}</td>
                    <td className={`px-4 py-2 text-xs ${r.encrypted ? "" : "text-destructive"}`}>
                      {r.encrypted ? (r.encryptionAlgorithm ?? "oui") : "en clair"}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {r.storageProvider ? `${r.storageProvider} · ` : ""}
                      {r.storageLocation}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {r.integrityOk === null ? (
                        <span className="text-muted-foreground">non revérifiée</span>
                      ) : r.integrityOk ? (
                        <span className="text-success">OK</span>
                      ) : (
                        <span className="text-destructive">altérée</span>
                      )}
                    </td>
                  </tr>
                ))}
                {!backup.runs.length ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-6 text-center text-muted-foreground">
                      Aucune exécution déclarée.
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

function Inline({ text }: { text: string }) {
  return (
    <>
      {text.split(/(`[^`]+`)/).map((part, i) =>
        part.startsWith("`") ? (
          <code key={i} className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            {part.slice(1, -1)}
          </code>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </>
  );
}
