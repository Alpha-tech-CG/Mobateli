"use client";

import { useMemo, useState } from "react";
import { ArrowRight, Boxes, Crosshair, Lightbulb, Network, ShieldAlert } from "lucide-react";
import { Card, SeverityBadge } from "@/components/ui";
import type { ArchEdge, ArchModule, ArchRole, ArchitectureReport, BlastRadius, FragilityGrade } from "@/lib/types";

/**
 * Architecture of a scanned repository: the module graph, how fragile it is,
 * what an exploited vulnerability really reaches, and a structured plan to
 * make it solid.
 */
export function ArchitecturePanel({ report }: { report: ArchitectureReport }) {
  const [selected, setSelected] = useState<string | null>(
    // Start on the most impactful vulnerability that sits in the graph.
    report.blast.find((b) => b.module)?.key ?? null,
  );
  const [focus, setFocus] = useState<string | null>(null);
  const blast = report.blast.find((b) => b.key === selected) ?? null;

  if (!report.modules.length) {
    return (
      <Card className="p-4 text-sm text-muted-foreground">
        Aucun fichier source JavaScript/TypeScript ou Python à cartographier dans ce dépôt.
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <FragilityCard report={report} />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Card className="min-w-0 p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2 px-1">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <Network className="size-4" aria-hidden /> Graphe des modules
            </h3>
            {blast ? (
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
              >
                Effacer l&apos;impact
              </button>
            ) : null}
          </div>
          <Graph report={report} blast={blast} focus={focus} onFocus={setFocus} />
          <Legend withBlast={!!blast} />
          {focus ? <ModuleDetail module={report.modules.find((m) => m.id === focus)!} edges={report.edges} /> : null}
        </Card>

        <BlastList blast={report.blast} selected={selected} onSelect={setSelected} />
      </div>

      {blast ? <BlastDetail blast={blast} /> : null}

      <Proposals report={report} />
    </div>
  );
}

// ─── Fragility ─────────────────────────────────────────────────────────────

const GRADE_STYLE: Record<FragilityGrade, { text: string; bar: string; label: string }> = {
  solide: { text: "text-success", bar: "bg-success", label: "Solide" },
  correcte: { text: "text-secondary", bar: "bg-secondary", label: "Correcte" },
  fragile: { text: "text-warning", bar: "bg-warning", label: "Fragile" },
  "très fragile": { text: "text-destructive", bar: "bg-destructive", label: "Très fragile" },
};

function gradeOf(score: number): FragilityGrade {
  return score < 20 ? "solide" : score < 40 ? "correcte" : score < 60 ? "fragile" : "très fragile";
}

function FragilityCard({ report }: { report: ArchitectureReport }) {
  const { fragility, stats } = report;
  const g = GRADE_STYLE[fragility.grade];
  const projected = GRADE_STYLE[gradeOf(fragility.projectedScore)];
  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Fragilité de l&apos;architecture</p>
          <p className="mt-1 flex flex-wrap items-baseline gap-2">
            <span className={`font-mono text-3xl font-semibold ${g.text}`}>{fragility.score}</span>
            <span className="text-sm text-muted-foreground">/100</span>
            <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${g.text} bg-muted`}>{g.label}</span>
          </p>
          <p className="mt-2 text-sm">{fragility.summary}</p>
        </div>
        {fragility.projectedScore < fragility.score ? (
          <div className="rounded-lg border border-border bg-muted/50 px-4 py-3 text-sm">
            <p className="text-xs text-muted-foreground">Après le plan proposé</p>
            <p className="mt-1 flex items-center gap-2 font-mono text-lg font-semibold">
              <span className={g.text}>{fragility.score}</span>
              <ArrowRight className="size-4 text-muted-foreground" aria-hidden />
              <span className={projected.text}>{fragility.projectedScore}</span>
              <span className={`text-xs font-sans font-medium ${projected.text}`}>{projected.label}</span>
            </p>
          </div>
        ) : null}
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <Stat label="Fichiers source" value={stats.sourceFiles} />
        <Stat label="Imports internes" value={stats.imports} />
        <Stat label="Points d'entrée" value={stats.entryPoints} />
        <Stat label="Fichiers en cycle" value={stats.filesInCycles} warn={stats.filesInCycles > 0} />
      </dl>

      <ul className="mt-4 space-y-3">
        {fragility.factors.map((f) => (
          <li key={f.id}>
            <div className="flex items-center justify-between gap-2 text-sm">
              <span className="font-medium">{f.label}</span>
              <span className="font-mono text-xs text-muted-foreground">
                {f.points}/{f.max}
              </span>
            </div>
            <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
              <div
                className={`h-full rounded-full ${f.points / f.max > 0.6 ? "bg-destructive" : f.points / f.max > 0.25 ? "bg-warning" : "bg-success"}`}
                style={{ width: `${Math.max(f.points ? 4 : 0, (f.points / f.max) * 100)}%` }}
              />
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{f.detail}</p>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function Stat({ label, value, warn }: { label: string; value: number; warn?: boolean }) {
  return (
    <div className="rounded-md bg-muted/60 px-3 py-2">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={`font-mono text-base font-semibold ${warn ? "text-warning" : ""}`}>{value}</dd>
    </div>
  );
}

// ─── Graph ─────────────────────────────────────────────────────────────────

const COLUMNS: { title: string; roles: ArchRole[] }[] = [
  { title: "Points d'entrée", roles: ["entry"] },
  { title: "Interface", roles: ["ui"] },
  { title: "Logique & services", roles: ["service"] },
  { title: "Données · Auth · Config", roles: ["data", "auth", "config"] },
];
const ROLE_LABEL: Record<ArchRole, string> = {
  entry: "point d'entrée",
  ui: "interface",
  service: "service",
  data: "données",
  auth: "authentification",
  config: "configuration",
};
const NODE_W = 172;
const NODE_H = 44;
const GAP_Y = 14;
const COL_W = 232;
const TOP = 34;

type Highlight = "origin" | "impacted" | "exposed" | "asset" | "dim" | "none";

function Graph({
  report,
  blast,
  focus,
  onFocus,
}: {
  report: ArchitectureReport;
  blast: BlastRadius | null;
  focus: string | null;
  onFocus: (id: string | null) => void;
}) {
  const layout = useMemo(() => {
    const pos = new Map<string, { x: number; y: number; col: number }>();
    let rows = 0;
    COLUMNS.forEach((col, c) => {
      const mods = report.modules
        .filter((m) => col.roles.includes(m.role))
        .sort((a, b) => col.roles.indexOf(a.role) - col.roles.indexOf(b.role) || a.id.localeCompare(b.id));
      mods.forEach((m, i) => pos.set(m.id, { x: 16 + c * COL_W, y: TOP + i * (NODE_H + GAP_Y), col: c }));
      rows = Math.max(rows, mods.length);
    });
    return { pos, height: TOP + rows * (NODE_H + GAP_Y) + 8, width: 16 + (COLUMNS.length - 1) * COL_W + NODE_W + 40 };
  }, [report.modules]);

  const highlight = (id: string): Highlight => {
    if (!blast) return "none";
    if (blast.module === id) return "origin";
    if (blast.exposedModules.includes(id)) return "exposed";
    if (blast.assetModules.includes(id)) return "asset";
    if (blast.impactedModules.includes(id)) return "impacted";
    return "dim";
  };
  const involved = (id: string) => {
    const h = highlight(id);
    return h !== "dim";
  };

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        width="100%"
        style={{ minWidth: 720 }}
        role="img"
        aria-label="Graphe des dépendances entre modules"
      >
        <defs>
          {(["muted", "warn", "bad", "hot"] as const).map((k) => (
            <marker key={k} id={`arrow-${k}`} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,0 L8,4 L0,8 z" className={MARKER_CLASS[k]} />
            </marker>
          ))}
        </defs>

        {COLUMNS.map((c, i) => (
          <text key={c.title} x={16 + i * COL_W} y={18} className="fill-muted-foreground text-[11px] font-medium uppercase tracking-wide">
            {c.title}
          </text>
        ))}

        {report.edges.map((e) => {
          const a = layout.pos.get(e.from);
          const b = layout.pos.get(e.to);
          if (!a || !b) return null;
          const active = blast ? involved(e.from) && involved(e.to) : focus ? e.from === focus || e.to === focus : true;
          const hot = !!blast && active;
          const kind = hot ? "hot" : e.violation || e.cycle ? "bad" : e.mutual ? "warn" : "muted";
          return (
            <path
              key={`${e.from}→${e.to}`}
              d={edgePath(a, b)}
              fill="none"
              className={EDGE_CLASS[kind]}
              strokeWidth={Math.min(3.5, 1 + Math.log2(e.weight))}
              strokeDasharray={e.violation ? "5 4" : undefined}
              opacity={active ? 0.9 : 0.12}
              markerEnd={`url(#arrow-${kind})`}
            >
              <title>
                {e.from} → {e.to} · {e.weight} import(s)
                {e.cycle ? " · cycle" : ""}
                {e.violation ? " · dépendance à contre-sens" : ""}
                {e.mutual && !e.cycle ? " · dépendance mutuelle" : ""}
              </title>
            </path>
          );
        })}

        {report.modules.map((m) => {
          const p = layout.pos.get(m.id);
          if (!p) return null;
          const h = highlight(m.id);
          const issues = m.issues.critical + m.issues.high + m.issues.medium + m.issues.low;
          const dim = h === "dim" || (!blast && focus !== null && focus !== m.id && !neighbours(report.edges, focus).has(m.id));
          return (
            <g
              key={m.id}
              transform={`translate(${p.x},${p.y})`}
              opacity={dim ? 0.28 : 1}
              className="cursor-pointer"
              onClick={() => onFocus(focus === m.id ? null : m.id)}
              role="button"
              tabIndex={0}
              aria-label={`${m.id}, ${ROLE_LABEL[m.role]}, ${m.files} fichiers`}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" || ev.key === " ") onFocus(focus === m.id ? null : m.id);
              }}
            >
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={8}
                className={NODE_CLASS[h]}
                strokeWidth={h === "origin" || h === "exposed" || focus === m.id ? 2.5 : 1}
                strokeDasharray={m.inCycle && h === "none" ? "4 3" : undefined}
              />
              <rect width={4} height={NODE_H} rx={2} className={ROLE_BAR[m.role]} />
              <text x={12} y={18} className="fill-foreground text-[12px] font-medium">
                {truncate(m.label, 21)}
              </text>
              <text x={12} y={34} className="fill-muted-foreground text-[10px]">
                {ROLE_LABEL[m.role]} · {m.files} fichier{m.files > 1 ? "s" : ""}
                {m.inCycle ? " · cycle" : ""}
              </text>
              {issues ? (
                <g transform={`translate(${NODE_W - 14},14)`}>
                  <circle r={9} className={m.issues.critical || m.issues.high ? "fill-destructive" : "fill-warning"} />
                  <text textAnchor="middle" y={3.5} className="fill-white text-[10px] font-semibold">
                    {issues > 99 ? "99" : issues}
                  </text>
                </g>
              ) : null}
              <title>
                {m.id} — {ROLE_LABEL[m.role]}, {m.files} fichier(s), {m.loc} lignes, importé par {m.fanIn} module(s), en importe{" "}
                {m.fanOut}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

const MARKER_CLASS = {
  muted: "fill-muted-foreground",
  warn: "fill-warning",
  bad: "fill-destructive",
  hot: "fill-destructive",
} as const;
const EDGE_CLASS = {
  muted: "stroke-muted-foreground",
  warn: "stroke-warning",
  bad: "stroke-destructive",
  hot: "stroke-destructive",
} as const;
const NODE_CLASS: Record<Highlight, string> = {
  none: "fill-card stroke-border",
  dim: "fill-card stroke-border",
  origin: "fill-destructive/25 stroke-destructive",
  exposed: "fill-destructive/10 stroke-destructive",
  impacted: "fill-warning/20 stroke-warning",
  asset: "fill-primary/15 stroke-primary",
};
const ROLE_BAR: Record<ArchRole, string> = {
  entry: "fill-primary",
  ui: "fill-secondary",
  service: "fill-muted-foreground",
  data: "fill-warning",
  auth: "fill-destructive",
  config: "fill-success",
};

function edgePath(a: { x: number; y: number; col: number }, b: { x: number; y: number; col: number }): string {
  const ay = a.y + NODE_H / 2;
  const by = b.y + NODE_H / 2;
  if (b.col > a.col) {
    const x1 = a.x + NODE_W;
    const x2 = b.x - 2;
    const mid = (x1 + x2) / 2;
    return `M${x1},${ay} C${mid},${ay} ${mid},${by} ${x2},${by}`;
  }
  if (b.col < a.col) {
    // Backwards (lower layer → higher layer): leave from the left side.
    const x1 = a.x;
    const x2 = b.x + NODE_W + 2;
    const mid = (x1 + x2) / 2;
    return `M${x1},${ay} C${mid},${ay - 30} ${mid},${by - 30} ${x2},${by}`;
  }
  // Same column: arc on the right side.
  const x = a.x + NODE_W;
  const bulge = 26 + Math.min(60, Math.abs(by - ay) / 4);
  return `M${x},${ay} C${x + bulge},${ay} ${x + bulge},${by} ${x + 2},${by}`;
}

function neighbours(edges: ArchEdge[], id: string): Set<string> {
  const s = new Set<string>();
  for (const e of edges) {
    if (e.from === id) s.add(e.to);
    if (e.to === id) s.add(e.from);
  }
  return s;
}

const truncate = (s: string, n: number) => (s.length > n ? `…${s.slice(-(n - 1))}` : s);

function Legend({ withBlast }: { withBlast: boolean }) {
  const item = (cls: string, label: string, dashed = false) => (
    <span className="inline-flex items-center gap-1.5">
      <svg width="22" height="8" aria-hidden>
        <line x1="0" y1="4" x2="22" y2="4" className={cls} strokeWidth="2" strokeDasharray={dashed ? "4 3" : undefined} />
      </svg>
      {label}
    </span>
  );
  const box = (cls: string, label: string) => (
    <span className="inline-flex items-center gap-1.5">
      <span className={`inline-block size-3 rounded-sm border ${cls}`} aria-hidden />
      {label}
    </span>
  );
  return (
    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 px-1 text-[11px] text-muted-foreground">
      {item("stroke-muted-foreground", "dépendance")}
      {item("stroke-warning", "dépendance mutuelle")}
      {item("stroke-destructive", "contre-sens", true)}
      {withBlast ? (
        <>
          {box("border-destructive bg-destructive/25", "faille")}
          {box("border-destructive bg-destructive/10", "point d'entrée exposé")}
          {box("border-warning bg-warning/20", "compromis")}
          {box("border-primary bg-primary/15", "actif sensible atteint")}
        </>
      ) : (
        <span>Cliquez un module pour isoler ses dépendances.</span>
      )}
    </div>
  );
}

function ModuleDetail({ module: m, edges }: { module: ArchModule; edges: ArchEdge[] }) {
  const uses = edges.filter((e) => e.from === m.id).map((e) => e.to);
  const usedBy = edges.filter((e) => e.to === m.id).map((e) => e.from);
  return (
    <div className="mt-3 rounded-md border border-border p-3 text-xs">
      <p className="font-mono text-sm font-medium">{m.id}</p>
      <p className="mt-1 text-muted-foreground">
        {ROLE_LABEL[m.role]} · {m.files} fichier(s) · {m.loc} lignes · instabilité {Math.round(m.instability * 100)} %
        {m.sensitive.length ? ` · touche : ${m.sensitive.map((s) => ROLE_LABEL[s]).join(", ")}` : ""}
      </p>
      <p className="mt-2">
        <span className="font-medium">Utilisé par :</span> {usedBy.length ? usedBy.join(", ") : "aucun module"}
      </p>
      <p className="mt-1">
        <span className="font-medium">Dépend de :</span> {uses.length ? uses.join(", ") : "aucun module"}
      </p>
    </div>
  );
}

// ─── Blast radius ──────────────────────────────────────────────────────────

const LEVEL_STYLE: Record<BlastRadius["level"], string> = {
  critique: "bg-destructive/15 text-destructive",
  élevé: "bg-accent/15 text-accent",
  modéré: "bg-warning/15 text-warning",
  limité: "bg-muted text-muted-foreground",
};

function BlastList({
  blast,
  selected,
  onSelect,
}: {
  blast: BlastRadius[];
  selected: string | null;
  onSelect: (key: string) => void;
}) {
  return (
    <Card className="flex max-h-[560px] min-w-0 flex-col">
      <h3 className="flex items-center gap-2 border-b border-border px-4 py-3 text-sm font-semibold">
        <Crosshair className="size-4" aria-hidden /> Impact si la faille est exploitée
      </h3>
      {blast.length ? (
        <ul className="divide-y divide-border overflow-y-auto">
          {blast.map((b) => (
            <li key={b.key}>
              <button
                type="button"
                onClick={() => onSelect(b.key)}
                aria-pressed={selected === b.key}
                className={`w-full px-4 py-2.5 text-left text-sm hover:bg-muted/60 ${selected === b.key ? "bg-muted" : ""}`}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="truncate font-medium">{b.title}</span>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${LEVEL_STYLE[b.level]}`}>
                    {b.impactScore}
                  </span>
                </span>
                <span className="mt-0.5 block truncate font-mono text-[11px] text-muted-foreground">{b.location}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="px-4 py-6 text-center text-sm text-muted-foreground">Aucune faille à propager.</p>
      )}
    </Card>
  );
}

function BlastDetail({ blast: b }: { blast: BlastRadius }) {
  const kinds = { data: "Données", auth: "Authentification", config: "Configuration" } as const;
  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <ShieldAlert className="size-4 text-destructive" aria-hidden />
        <SeverityBadge severity={b.severity} />
        <span className="font-medium">{b.title}</span>
        <span className="font-mono text-xs text-muted-foreground">{b.location}</span>
        <span className={`ml-auto rounded-full px-2 py-0.5 text-xs font-medium ${LEVEL_STYLE[b.level]}`}>
          Impact {b.level} · {b.impactScore}/100
        </span>
      </div>
      <p className="mt-3 text-sm">{b.narrative}</p>
      <div className="mt-3 grid gap-3 text-xs sm:grid-cols-3">
        <Metric label="Fichiers compromis" value={b.kind === "finding" ? `${b.dependents + 1} (${b.reachPercent} %)` : "—"} />
        <Metric label="Points d'entrée exposés" value={String(b.entryPoints.length)} />
        <Metric label="Actifs sensibles atteints" value={String(b.assets.length)} />
      </div>
      {b.entryPoints.length || b.assets.length ? (
        <div className="mt-3 grid gap-3 text-xs md:grid-cols-2">
          {b.entryPoints.length ? (
            <div>
              <p className="font-medium">Atteignable depuis</p>
              <ul className="mt-1 space-y-0.5 font-mono text-muted-foreground">
                {b.entryPoints.slice(0, 8).map((e) => (
                  <li key={e} className="truncate">{e}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {b.assets.length ? (
            <div>
              <p className="font-medium">Donne accès à</p>
              <ul className="mt-1 space-y-0.5 text-muted-foreground">
                {b.assets.slice(0, 8).map((a) => (
                  <li key={`${a.kind}${a.file}`} className="truncate">
                    <span className="font-medium text-foreground">{kinds[a.kind]}</span> · <span className="font-mono">{a.file}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-muted/60 px-3 py-2">
      <p className="text-muted-foreground">{label}</p>
      <p className="font-mono text-base font-semibold">{value}</p>
    </div>
  );
}

// ─── Proposals ─────────────────────────────────────────────────────────────

const PRIORITY_LABEL = { 1: "Priorité haute", 2: "Priorité moyenne", 3: "À planifier" } as const;
const PRIORITY_STYLE = {
  1: "bg-destructive/15 text-destructive",
  2: "bg-warning/15 text-warning",
  3: "bg-muted text-muted-foreground",
} as const;

function Proposals({ report }: { report: ArchitectureReport }) {
  if (!report.proposals.length) {
    return (
      <Card className="flex items-center gap-2 p-4 text-sm">
        <Boxes className="size-4 text-success" aria-hidden /> Rien à restructurer : l&apos;architecture est saine.
      </Card>
    );
  }
  return (
    <section className="space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <Lightbulb className="size-4" aria-hidden /> Plan pour une architecture solide
      </h3>
      <ol className="space-y-3">
        {report.proposals.map((p, i) => (
          <li key={p.id}>
            <Card className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="flex size-6 items-center justify-center rounded-full bg-muted font-mono text-xs font-semibold">{i + 1}</span>
                <span className="font-medium">{p.title}</span>
                <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${PRIORITY_STYLE[p.priority]}`}>
                  {PRIORITY_LABEL[p.priority]}
                </span>
                <span className="rounded-full bg-muted px-2 py-0.5 text-[11px] text-muted-foreground">effort {p.effort}</span>
                {p.gain ? (
                  <span className="ml-auto font-mono text-xs font-semibold text-success">−{p.gain} pts de fragilité</span>
                ) : null}
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{p.problem}</p>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
                {p.actions.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ul>
              <p className="mt-3 rounded-md bg-success/10 px-3 py-2 text-sm">
                <span className="font-medium text-success">Avantage :</span> {p.advantage}
              </p>
              {p.targets.length ? (
                <p className="mt-2 truncate font-mono text-[11px] text-muted-foreground" title={p.targets.join("\n")}>
                  {p.targets.slice(0, 4).join(" · ")}
                  {p.targets.length > 4 ? ` · +${p.targets.length - 4}` : ""}
                </p>
              ) : null}
            </Card>
          </li>
        ))}
      </ol>
    </section>
  );
}
