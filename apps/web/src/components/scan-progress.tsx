import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { ScanPhase, ScanStatus } from "@/lib/types";

const STEPS: { phase: ScanPhase; label: string }[] = [
  { phase: "download", label: "Récupération du code" },
  { phase: "extract", label: "Sélection des fichiers" },
  { phase: "analysis", label: "Secrets, code et prompt injection" },
  { phase: "dependencies", label: "Dépendances (OSV, registres)" },
  { phase: "done", label: "Résultat" },
];

/** Live stepper of a repository scan. */
export function ScanProgress({
  status,
  phase,
  filesScanned,
}: {
  status: ScanStatus;
  phase: ScanPhase | null;
  filesScanned: number;
}) {
  const current = status === "queued" ? -1 : STEPS.findIndex((s) => s.phase === phase);
  return (
    <ol className="space-y-2">
      {STEPS.map((step, i) => {
        const done = status === "done" || (current > i && status !== "failed");
        const active = i === current && status === "running";
        const failed = status === "failed" && i === Math.max(current, 0);
        return (
          <li key={step.phase} className="flex items-center gap-2 text-sm">
            {failed ? (
              <XCircle className="size-4 text-destructive" aria-hidden />
            ) : done ? (
              <CheckCircle2 className="size-4 text-success" aria-hidden />
            ) : active ? (
              <Loader2 className="size-4 animate-spin text-primary" aria-hidden />
            ) : (
              <Circle className="size-4 text-muted-foreground" aria-hidden />
            )}
            <span className={done || active ? "" : "text-muted-foreground"}>
              {step.label}
              {step.phase === "analysis" && filesScanned > 0 ? ` — ${filesScanned} fichiers` : ""}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
