"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";

export default function AnalysisSettingsPage() {
  return (
    <Shell>
      <AnalysisSettings />
    </Shell>
  );
}

interface EngineInfo {
  id: string;
  label: string;
  description: string;
  phase: "core" | "intel";
}

interface Effective {
  engines: Record<string, boolean>;
  ignorePaths: string[];
  minSeverity: string;
}

const SEVERITIES = [
  { value: "info", label: "Tout signaler" },
  { value: "low", label: "Faible et plus" },
  { value: "medium", label: "Moyenne et plus" },
  { value: "high", label: "Élevée et plus" },
  { value: "critical", label: "Critique uniquement" },
];

/**
 * Organization-wide analysis parameters. The engine list and the defaults come
 * from the API (single source: @codegate/shared), so a new engine or
 * parameter shows up here without duplicating its definition.
 */
function AnalysisSettings() {
  const [engines, setEngines] = useState<EngineInfo[]>([]);
  const [enabled, setEnabled] = useState<Record<string, boolean>>({});
  const [ignore, setIgnore] = useState("");
  const [minSeverity, setMinSeverity] = useState("info");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api<{ effective: Effective; engines: EngineInfo[] }>("/api/v1/settings/analysis")
      .then((r) => {
        setEngines(r.engines);
        setEnabled(r.effective.engines);
        setIgnore(r.effective.ignorePaths.join("\n"));
        setMinSeverity(r.effective.minSeverity);
      })
      .catch(() => setMsg({ ok: false, text: "Impossible de charger les paramètres." }));
  }, []);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api("/api/v1/settings/analysis", {
        method: "PUT",
        body: JSON.stringify({
          engines: enabled,
          ignorePaths: ignore
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean),
          minSeverity,
        }),
      });
      setMsg({ ok: true, text: "Paramètres enregistrés : ils s'appliquent dès la prochaine analyse." });
    } catch (err) {
      setMsg({
        ok: false,
        text:
          err instanceof ApiError && err.code === "validation_error"
            ? "Paramètres invalides (chemins relatifs, sans « .. », 100 au plus)."
            : "Enregistrement refusé (droits insuffisants ?).",
      });
    } finally {
      setBusy(false);
    }
  }

  const group = (phase: EngineInfo["phase"]) => engines.filter((e) => e.phase === phase);

  return (
    <div>
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Paramètres d&apos;analyse</h1>
        <p className="text-sm text-muted-foreground">
          S&apos;appliquent à tous les dépôts de l&apos;organisation.
        </p>
      </header>

      <form onSubmit={save} className="max-w-2xl space-y-6">
        {(["core", "intel"] as const).map((phase) =>
          group(phase).length ? (
            <Card key={phase} className="p-5">
              <h2 className="mb-1 font-semibold">
                {phase === "core" ? "Analyses intégrées" : "Analyses avancées"}
              </h2>
              <p className="mb-4 text-xs text-muted-foreground">
                {phase === "core"
                  ? "Instantanées, exécutées sur chaque PR."
                  : "Outils externes ; si l'un ne peut pas s'exécuter, le rapport l'indique (« Analyse partielle »)."}
              </p>
              <ul className="space-y-3">
                {group(phase).map((eng) => (
                  <li key={eng.id}>
                    <label className="flex cursor-pointer items-start gap-3">
                      <input
                        type="checkbox"
                        checked={enabled[eng.id] !== false}
                        onChange={(e) => setEnabled((s) => ({ ...s, [eng.id]: e.target.checked }))}
                        className="mt-1 size-4 cursor-pointer accent-primary"
                      />
                      <span>
                        <span className="text-sm font-medium">{eng.label}</span>
                        <span className="block text-xs text-muted-foreground">{eng.description}</span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </Card>
          ) : null,
        )}

        <Card className="p-5">
          <label className="block">
            <span className="mb-1 block font-semibold">Chemins ignorés</span>
            <span className="mb-2 block text-xs text-muted-foreground">
              Un motif par ligne : <code className="font-mono">vendor/**</code>,{" "}
              <code className="font-mono">*.min.js</code>,{" "}
              <code className="font-mono">src/**/__generated__/*</code>. Ces fichiers ne sont jamais analysés.
            </span>
            <textarea
              value={ignore}
              onChange={(e) => setIgnore(e.target.value)}
              rows={4}
              placeholder={"vendor/**\n*.min.js"}
              className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
        </Card>

        <Card className="p-5">
          <label className="block">
            <span className="mb-1 block font-semibold">Sévérité minimale signalée</span>
            <span className="mb-2 block text-xs text-muted-foreground">
              Les problèmes en dessous ne sont ni affichés ni comptés dans le score.
            </span>
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value)}
              className="cursor-pointer rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            >
              {SEVERITIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
        </Card>

        {msg ? (
          <p className={`text-sm ${msg.ok ? "text-success" : "text-destructive"}`} role="status">
            {msg.text}
          </p>
        ) : null}
        <button
          type="submit"
          disabled={busy || !engines.length}
          className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-medium text-on-primary hover:opacity-90 disabled:opacity-50"
        >
          {busy ? "Enregistrement…" : "Enregistrer"}
        </button>
      </form>
    </div>
  );
}
