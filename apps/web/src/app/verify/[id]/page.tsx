"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { CheckCircle2, FileUp, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { AuthShell } from "@/components/auth-shell";

const KIND_LABELS: Record<string, string> = {
  organization: "Audit de l'organisation",
  pull_request: "Analyse de pull request",
  repository_scan: "Audit de dépôt",
  server: "Audit de serveur",
  bruteforce: "Test anti brute force",
  backup: "Audit de sauvegarde",
};

interface IssuedReport {
  id: string;
  kind: string;
  subject: string | null;
  organization: string;
  issuedAt: string;
  sha256: string;
  signerFingerprint: string;
  summary: {
    verdict?: string | null;
    kpis?: { label: string; value: string | number }[];
    pullRequests?: number;
    secretsBlocked?: number;
  };
}

async function sha256Hex(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Public verification of a signed audit report: the file is hashed in the
 * browser (it never leaves the visitor's machine) and compared with the
 * fingerprint CodeGate recorded when it issued the report.
 */
export default function VerifyReportPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<IssuedReport | null>(null);
  const [missing, setMissing] = useState(false);
  const [result, setResult] = useState<{ name: string; ok: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ report: IssuedReport }>(`/api/v1/reports/${id}/verify`)
      .then((r) => setReport(r.report))
      .catch((err) => setMissing(err instanceof ApiError && err.status === 404));
  }, [id]);

  async function check(file: File | undefined) {
    if (!file || !report) return;
    setBusy(true);
    try {
      setResult({ name: file.name, ok: (await sha256Hex(file)) === report.sha256 });
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Vérifier un rapport"
      subtitle="Confirmez qu'un rapport d'audit CodeGate est authentique et n'a pas été modifié."
      footer={
        <Link href="/" className="text-white underline-offset-4 hover:underline">
          Découvrir CodeGate
        </Link>
      }
    >
      {missing ? (
        <div className="flex gap-3 rounded-[6px] border border-[#5c2a22] bg-[#2a1714] p-4 text-[14px]">
          <ShieldAlert className="mt-0.5 size-5 shrink-0 text-[#e0705c]" aria-hidden />
          <p>
            Aucun rapport n&apos;a été émis par CodeGate sous ce numéro. Ce document n&apos;est pas un rapport
            CodeGate authentique.
          </p>
        </div>
      ) : !report ? (
        <p className="text-[14px] text-[#9aa3a8]">Recherche du rapport…</p>
      ) : (
        <div className="space-y-5">
          <dl className="space-y-2 rounded-[6px] border border-[#26292b] bg-[#111111] p-4 text-[13px]">
            <Row label="Rapport">
              <span className="break-all font-mono text-[12px]">{report.id}</span>
            </Row>
            <Row label="Type">{KIND_LABELS[report.kind] ?? report.kind}</Row>
            {report.subject ? (
              <Row label="Objet">
                <span className="break-all">{report.subject}</span>
              </Row>
            ) : null}
            <Row label="Organisation">{report.organization}</Row>
            <Row label="Émis le">{new Date(report.issuedAt).toLocaleString("fr-FR")}</Row>
            {report.summary.verdict ? <Row label="Verdict">{report.summary.verdict}</Row> : null}
            <Row label="Contenu">
              {report.summary.kpis
                ? report.summary.kpis.map((k) => `${k.label} : ${k.value}`).join(" · ")
                : `${report.summary.pullRequests ?? 0} PR analysées · ${report.summary.secretsBlocked ?? 0} secret(s) intercepté(s)`}
            </Row>
          </dl>

          <label
            className={`flex cursor-pointer flex-col items-center gap-2 rounded-[6px] border border-dashed border-[#3a3e41] px-4 py-6 text-center text-[14px] transition-colors hover:border-[#bb3e2c] ${
              busy ? "opacity-60" : ""
            }`}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              void check(e.dataTransfer.files[0]);
            }}
          >
            <FileUp className="size-6 text-[#bb3e2c]" aria-hidden />
            <span>Déposez le PDF reçu, ou cliquez pour le choisir</span>
            <span className="text-[12px] text-[#7d868b]">Le fichier est vérifié dans votre navigateur et n&apos;est pas envoyé.</span>
            <input
              type="file"
              accept="application/pdf"
              className="sr-only"
              onChange={(e) => void check(e.target.files?.[0])}
            />
          </label>

          {result ? (
            result.ok ? (
              <div className="flex gap-3 rounded-[6px] border border-[#1f4d33] bg-[#13261b] p-4 text-[14px]">
                <ShieldCheck className="mt-0.5 size-5 shrink-0 text-[#4cc38a]" aria-hidden />
                <div>
                  <p className="font-medium">Rapport authentique et intact</p>
                  <p className="mt-1 text-[13px] text-[#9aa3a8]">
                    « {result.name} » est exactement le fichier émis et signé par CodeGate.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex gap-3 rounded-[6px] border border-[#5c2a22] bg-[#2a1714] p-4 text-[14px]">
                <ShieldAlert className="mt-0.5 size-5 shrink-0 text-[#e0705c]" aria-hidden />
                <div>
                  <p className="font-medium">Ce fichier ne correspond pas au rapport émis</p>
                  <p className="mt-1 text-[13px] text-[#9aa3a8]">
                    Il a été modifié après signature, ou il s&apos;agit d&apos;un autre document. Ne vous y fiez pas.
                  </p>
                </div>
              </div>
            )
          ) : null}

          <p className="flex gap-2 text-[12px] text-[#7d868b]">
            <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>
              Empreinte du certificat de signature :{" "}
              <span className="break-all font-mono">{report.signerFingerprint}</span>
            </span>
          </p>
        </div>
      )}
    </AuthShell>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <dt className="w-24 shrink-0 text-[#7d868b]">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}
