import type { ReactNode } from "react";
import type { PullRequestStatus, Severity } from "@/lib/types";

/** Data-dense card surface. */
export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-lg border border-border bg-card text-card-foreground shadow-sm ${className}`}
    >
      {children}
    </div>
  );
}

export function KpiCard({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <Card className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 font-mono text-2xl font-semibold">{value}</p>
      {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
    </Card>
  );
}

const STATUS_STYLES: Record<PullRequestStatus, string> = {
  pending: "bg-muted text-muted-foreground",
  analyzing: "bg-secondary/15 text-secondary",
  passed: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  blocked: "bg-destructive/15 text-destructive",
  escalated: "bg-accent/15 text-accent",
};

export function StatusBadge({ status }: { status: PullRequestStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[status]}`}
    >
      {status}
    </span>
  );
}

const SEVERITY_STYLES: Record<Severity, string> = {
  info: "bg-muted text-muted-foreground",
  low: "bg-secondary/15 text-secondary",
  medium: "bg-warning/15 text-warning",
  high: "bg-accent/15 text-accent",
  critical: "bg-destructive/15 text-destructive",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}
