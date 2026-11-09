/** Server security score pill: green ≥ 80, amber ≥ 50, red below. */
export function ScoreBadge({ score }: { score: number | null }) {
  if (score === null) {
    return <span className="text-xs text-muted-foreground">en attente</span>;
  }
  const tone =
    score >= 80
      ? "bg-success/15 text-success"
      : score >= 50
        ? "bg-warning/15 text-warning"
        : "bg-destructive/15 text-destructive";
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 font-mono text-xs font-semibold ${tone}`}
    >
      {score}/100
    </span>
  );
}
