"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { FileSignature } from "lucide-react";
import { api, apiDownload } from "@/lib/api";

export type ReportType = "pull-request" | "scan" | "server" | "bruteforce" | "backup";

interface IssuedReport {
  id: string;
  createdAt: string;
}

/**
 * "Rapport PDF signé" for one subject (a PR, a scan, a server…), with the
 * reports already issued for it and their public verification page.
 */
export function ReportButton({
  type,
  id,
  name,
  compact = false,
}: {
  type: ReportType;
  id: string;
  /** Used in the downloaded file name. */
  name: string;
  compact?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedReport[]>([]);

  function load() {
    api<{ reports: IssuedReport[] }>(`/api/v1/reports?subjectId=${id}`)
      .then((r) => setIssued(r.reports))
      .catch(() => {});
  }
  useEffect(load, [id]);

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || type;
      const stamp = new Date().toISOString().slice(0, 10);
      await apiDownload(`/api/v1/reports/${type}/${id}`, {}, `codegate-rapport-${slug}-${stamp}.pdf`);
      load();
    } catch {
      setError("Rapport indisponible pour le moment.");
    } finally {
      setBusy(false);
    }
  }

  const last = issued[0];
  return (
    <div className={compact ? "inline-flex flex-col items-start" : "flex flex-col items-end"}>
      <button
        type="button"
        onClick={download}
        disabled={busy}
        className={`inline-flex cursor-pointer items-center gap-2 rounded-md border border-border transition-colors duration-150 hover:bg-muted disabled:opacity-50 ${
          compact ? "px-2.5 py-1.5 text-xs" : "px-3 py-2 text-sm"
        }`}
      >
        <FileSignature className="size-4" aria-hidden />
        {busy ? "Génération…" : "Rapport PDF signé"}
      </button>
      {last ? (
        <Link href={`/verify/${last.id}`} className="mt-1 text-[11px] text-muted-foreground hover:text-foreground hover:underline">
          {issued.length} rapport(s) émis · dernier N° {last.id.slice(0, 8).toUpperCase()}
        </Link>
      ) : null}
      {error ? <p className="mt-1 text-[11px] text-destructive">{error}</p> : null}
    </div>
  );
}
