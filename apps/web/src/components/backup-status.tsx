import type { BackupStatus } from "@/lib/types";

const STYLE: Record<BackupStatus, string> = {
  healthy: "bg-success/15 text-success",
  attention: "bg-warning/15 text-warning",
  critical: "bg-destructive/15 text-destructive",
};
const LABEL: Record<BackupStatus, string> = {
  healthy: "prête pour recovery",
  attention: "attention",
  critical: "critique",
};

export function BackupStatusBadge({ status }: { status: BackupStatus }) {
  return (
    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${STYLE[status]}`}>
      {LABEL[status]}
    </span>
  );
}

export function formatBytes(n: number | null): string {
  if (n === null) return "—";
  const units = ["o", "Ko", "Mo", "Go", "To"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}
