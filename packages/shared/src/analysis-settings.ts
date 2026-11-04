import { z } from "zod";
import { PROTECTION_LEVELS, SEVERITIES, type Severity } from "./enums.js";

/**
 * Analysis parameters — the single place where every tunable of the analysis
 * pipeline is declared, validated and defaulted.
 *
 * Resolution: built-in defaults ← organization settings ← repository
 * overrides (each level only stores what it changes). Stored as JSON
 * (`Organization.analysisSettings`, `Repository.analysisSettings`), so adding
 * a parameter needs no database migration:
 *
 *   1. add the field to `analysisSettingsSchema` (optional) and its default
 *      to `DEFAULT_ANALYSIS_SETTINGS`;
 *   2. read it from `ctx.settings` in the engine(s) concerned
 *      (apps/api/src/analysis/engines);
 *   3. expose it in the dashboard (Paramètres d'analyse).
 */

/** Every analysis engine, in pipeline order. See apps/api/src/analysis/engines. */
export const ENGINE_IDS = [
  "secrets",
  "dependencies",
  "sast",
  "sensitive_files",
  "osv",
  "sca",
  "semgrep",
  "rust",
] as const;
export type EngineId = (typeof ENGINE_IDS)[number];

/** Human description of each engine (dashboard, PR comment). */
export const ENGINE_CATALOG: Record<
  EngineId,
  { label: string; description: string; phase: "core" | "intel" }
> = {
  secrets: {
    label: "Secrets exposés",
    description: "Clés d'API, jetons, mots de passe et URL de base de données ajoutés dans le code.",
    phase: "core",
  },
  dependencies: {
    label: "Confiance des dépendances",
    description: "Typosquatting, sources non vérifiées et noms suspects dans les package.json.",
    phase: "core",
  },
  sast: {
    label: "Règles de code (SAST)",
    description: "Injections, eval, XSS, SSRF, crypto faible, TLS désactivé…",
    phase: "core",
  },
  sensitive_files: {
    label: "Fichiers sensibles",
    description: "Modifications de CI, Dockerfile, configuration d'authentification…",
    phase: "core",
  },
  osv: {
    label: "Vulnérabilités connues (OSV)",
    description: "CVE publiées pour les dépendances ajoutées (base OSV.dev).",
    phase: "intel",
  },
  sca: {
    label: "Dépendances complètes (Trivy/Grype)",
    description: "Analyse de tout l'arbre de dépendances et des licences (nécessite une copie du dépôt).",
    phase: "intel",
  },
  semgrep: {
    label: "Analyse sémantique (Semgrep)",
    description: "Plusieurs milliers de règles maintenues par la communauté Semgrep.",
    phase: "intel",
  },
  rust: {
    label: "Analyse de flux (moteur Rust)",
    description: "Suit une entrée utilisateur jusqu'à une fonction dangereuse (taint analysis).",
    phase: "intel",
  },
};

/** A path glob: `*`, `**`, `?`; relative to the repository root. */
const globSchema = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .refine((g) => !g.startsWith("/") && !g.includes(".."), "Chemin relatif attendu, sans « .. »");

export const analysisSettingsSchema = z
  .object({
    /** Engines switched on/off (absent = default). */
    engines: z.object(Object.fromEntries(ENGINE_IDS.map((id) => [id, z.boolean()]))).partial().strict(),
    /** Files never analyzed (generated code, vendored deps, fixtures…). */
    ignorePaths: z.array(globSchema).max(100),
    /** Findings below this severity are not reported nor scored. */
    minSeverity: z.enum(SEVERITIES),
  })
  .partial()
  .strict();

export type AnalysisSettingsInput = z.infer<typeof analysisSettingsSchema>;

/** Fully-resolved settings handed to the pipeline. */
export interface AnalysisSettings {
  engines: Record<EngineId, boolean>;
  ignorePaths: string[];
  minSeverity: Severity;
}

export const DEFAULT_ANALYSIS_SETTINGS: AnalysisSettings = {
  engines: Object.fromEntries(ENGINE_IDS.map((id) => [id, true])) as Record<EngineId, boolean>,
  ignorePaths: [],
  minSeverity: "info",
};

/**
 * Merge stored levels over the defaults. Invalid stored data (an older shape,
 * a manual edit) is ignored level by level rather than breaking analysis.
 * `ignorePaths` accumulate (an org exclusion stays excluded in every repo);
 * scalars and per-engine switches are overridden by the most specific level.
 */
export function resolveAnalysisSettings(...levels: unknown[]): AnalysisSettings {
  const out: AnalysisSettings = {
    engines: { ...DEFAULT_ANALYSIS_SETTINGS.engines },
    ignorePaths: [...DEFAULT_ANALYSIS_SETTINGS.ignorePaths],
    minSeverity: DEFAULT_ANALYSIS_SETTINGS.minSeverity,
  };
  for (const level of levels) {
    if (level == null) continue;
    const parsed = analysisSettingsSchema.safeParse(level);
    if (!parsed.success) continue;
    const s = parsed.data;
    if (s.engines) Object.assign(out.engines, s.engines);
    if (s.ignorePaths) {
      for (const g of s.ignorePaths) if (!out.ignorePaths.includes(g)) out.ignorePaths.push(g);
    }
    if (s.minSeverity) out.minSeverity = s.minSeverity;
  }
  return out;
}

/** Body of PUT /repositories/:id/settings. */
export const repositorySettingsSchema = z
  .object({
    protectionLevel: z.enum(PROTECTION_LEVELS),
    /** null clears the overrides (back to organization settings). */
    analysisSettings: analysisSettingsSchema.nullable(),
  })
  .partial()
  .strict();
export type RepositorySettingsInput = z.infer<typeof repositorySettingsSchema>;
