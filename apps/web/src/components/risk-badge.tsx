/** Risk score pill (higher = riskier): 0 green, < 40 amber, ≥ 40 red. */
export function RiskBadge({ risk }: { risk: number }) {
  const tone =
    risk === 0
      ? "bg-success/15 text-success"
      : risk < 40
        ? "bg-warning/15 text-warning"
        : "bg-destructive/15 text-destructive";
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 font-mono text-xs font-semibold ${tone}`}>
      risque {risk}/100
    </span>
  );
}
