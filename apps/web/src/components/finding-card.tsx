"use client";

import { useState } from "react";
import { SeverityBadge } from "@/components/ui";
import type { Finding } from "@/lib/types";

/** How well an alert is proven, shown next to its severity. */
const ASSURANCE: Record<string, { label: string; className: string }> = {
  verified: { label: "Prouvée", className: "bg-destructive/10 text-destructive" },
  likely: { label: "Probable", className: "bg-warning/10 text-warning" },
  uncertain: { label: "En observation", className: "bg-muted text-muted-foreground" },
  information: { label: "Information", className: "bg-muted text-muted-foreground" },
};

const STATUS_BADGE: Record<string, string> = {
  false_positive: "fausse alerte",
  accepted_risk: "risque accepté",
  acknowledged: "confirmée",
  suppressed: "exception",
  resolved: "résolu",
};

const FP_CATEGORIES: { value: string; label: string }[] = [
  { value: "wrong_file", label: "Mauvais fichier" },
  { value: "wrong_line", label: "Mauvaise ligne" },
  { value: "wrong_framework", label: "Mauvais framework" },
  { value: "wrong_rule", label: "Mauvaise règle" },
  { value: "wrong_context", label: "Faux contexte" },
  { value: "duplicate", label: "Doublon" },
  { value: "too_vague", label: "Trop vague" },
];

const RULE_ACTIONS: { kind: string; label: string }[] = [
  { kind: "noisy", label: "Règle trop bruyante" },
  { kind: "useless", label: "Règle inutile" },
  { kind: "improve", label: "Règle à améliorer" },
  { kind: "disable", label: "Règle à désactiver" },
  { kind: "restrict", label: "Règle à restreindre" },
  { kind: "raise_severity", label: "Monter en sévérité" },
  { kind: "lower_severity", label: "Baisser en sévérité" },
];

export interface FindingVerdict {
  verdict: "false_positive" | "confirmed" | "accepted_risk";
  note?: string;
  category?: string;
  expiresAt?: string;
}

export function FindingCard({
  finding: f,
  canReview,
  onVerdict,
  onClear,
  onRuleFeedback,
}: {
  finding: Finding;
  canReview: boolean;
  onVerdict: (f: Finding, v: FindingVerdict) => void;
  onClear: (f: Finding) => void;
  onRuleFeedback: (f: Finding, kind: string) => void;
}) {
  const [form, setForm] = useState<null | "false_positive" | "accepted_risk">(null);
  const [note, setNote] = useState("");
  const [category, setCategory] = useState(FP_CATEGORIES[0]!.value);
  const [expiresAt, setExpiresAt] = useState("");
  const [showRule, setShowRule] = useState(false);
  const assurance = f.assurance ? ASSURANCE[f.assurance] : null;
  const dimmed = f.status === "false_positive" || f.status === "accepted_risk" || f.status === "suppressed";
  const details = f.details ?? null;

  function submit() {
    if (form === "false_positive") {
      if (note.trim().length < 5) return;
      onVerdict(f, { verdict: "false_positive", note, category });
    } else if (form === "accepted_risk") {
      if (note.trim().length < 5 || !expiresAt) return;
      onVerdict(f, { verdict: "accepted_risk", note, expiresAt: new Date(expiresAt).toISOString() });
    }
    setForm(null);
    setNote("");
  }

  return (
    <li className={`px-4 py-3 text-sm ${dimmed ? "opacity-60" : ""}`}>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={f.severity} />
        {assurance ? <span className={`rounded px-1.5 py-0.5 text-xs ${assurance.className}`}>{assurance.label}</span> : null}
        <span className={`font-medium ${dimmed ? "line-through" : ""}`}>{f.title}</span>
        {STATUS_BADGE[f.status] ? <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{STATUS_BADGE[f.status]}</span> : null}
        {f.filePath ? (
          <span className="font-mono text-xs text-muted-foreground">
            {f.filePath}
            {f.line ? `:${f.line}` : ""}
          </span>
        ) : null}
      </div>

      <p className="mt-1 text-muted-foreground">{f.description}</p>
      {details?.evidence ? (
        <pre className="mt-2 overflow-x-auto rounded bg-muted/60 px-2 py-1 font-mono text-xs">{details.evidence}</pre>
      ) : null}
      {details?.observationReason ? (
        <p className="mt-1 text-xs italic text-muted-foreground">{details.observationReason}</p>
      ) : null}

      {details?.scenario || f.remediation ? (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">Détails, scénario et correctif</summary>
          <div className="mt-2 space-y-2">
            {details?.scenario ? (
              <p>
                <span className="font-medium">Scénario d&apos;attaque :</span> {details.scenario}
              </p>
            ) : null}
            {details?.conditions?.length ? (
              <div>
                <span className="font-medium">Conditions d&apos;exploitation :</span>
                <ul className="ml-4 list-disc">
                  {details.conditions.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {f.remediation ? (
              <p>
                <span className="font-medium">Correctif :</span> {f.remediation}
              </p>
            ) : null}
            {details?.reproduction ? (
              <p>
                <span className="font-medium">Test de reproduction :</span> {details.reproduction}
              </p>
            ) : null}
            {details?.cwe || details?.owasp ? (
              <p className="text-muted-foreground">
                {[details.cwe, details.owasp].filter(Boolean).join(" · ")}
              </p>
            ) : null}
          </div>
        </details>
      ) : null}

      {f.status === "suppressed" ? (
        <p className="mt-2 text-xs text-muted-foreground">Couverte par une exception approuvée — sans effet sur la décision.</p>
      ) : form ? (
        <div className="mt-2 space-y-2 rounded border border-border p-2">
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Raison (conservée dans le journal d'audit, 5 caractères minimum)"
            className="w-full rounded border border-border bg-background px-2 py-1 text-xs"
            rows={2}
          />
          {form === "false_positive" ? (
            <label className="block text-xs">
              Catégorie :{" "}
              <select value={category} onChange={(e) => setCategory(e.target.value)} className="rounded border border-border bg-background px-1 py-0.5">
                {FP_CATEGORIES.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <label className="block text-xs">
              Échéance : <input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className="rounded border border-border bg-background px-1 py-0.5" />
            </label>
          )}
          <div className="flex gap-2">
            <button type="button" onClick={submit} className="rounded bg-primary px-2 py-0.5 text-xs text-primary-foreground">
              Enregistrer
            </button>
            <button type="button" onClick={() => setForm(null)} className="rounded border border-border px-2 py-0.5 text-xs">
              Annuler
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-2 flex flex-wrap gap-2 text-xs">
          {f.status === "open" ? (
            <>
              <button type="button" onClick={() => onVerdict(f, { verdict: "confirmed" })} className="rounded border border-border px-2 py-0.5 hover:bg-muted">
                Vrai positif
              </button>
              {canReview ? (
                <>
                  <button type="button" onClick={() => setForm("false_positive")} className="rounded border border-border px-2 py-0.5 hover:bg-muted">
                    Fausse alerte
                  </button>
                  <button type="button" onClick={() => setForm("accepted_risk")} className="rounded border border-border px-2 py-0.5 hover:bg-muted">
                    Risque accepté
                  </button>
                </>
              ) : null}
            </>
          ) : f.status === "false_positive" || f.status === "acknowledged" || f.status === "accepted_risk" ? (
            canReview || f.status === "acknowledged" ? (
              <button type="button" onClick={() => onClear(f)} className="rounded border border-border px-2 py-0.5 hover:bg-muted">
                Annuler le retour
              </button>
            ) : null
          ) : null}
          {f.ruleId ? (
            <button type="button" onClick={() => setShowRule((s) => !s)} className="rounded border border-border px-2 py-0.5 text-muted-foreground hover:bg-muted">
              Signaler la règle
            </button>
          ) : null}
        </div>
      )}

      {showRule && f.ruleId ? (
        <div className="mt-2 flex flex-wrap gap-1 text-xs">
          {RULE_ACTIONS.map((a) => (
            <button
              key={a.kind}
              type="button"
              onClick={() => {
                onRuleFeedback(f, a.kind);
                setShowRule(false);
              }}
              className="rounded border border-border px-2 py-0.5 hover:bg-muted"
            >
              {a.label}
            </button>
          ))}
        </div>
      ) : null}
    </li>
  );
}
