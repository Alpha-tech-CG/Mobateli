"use client";

import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, ApiError } from "@/lib/api";
import { Shell } from "@/components/shell";
import { Card } from "@/components/ui";
import type {
  BruteForcePolicy,
  BruteForceResult,
  BruteForceTarget,
  BruteForceTestRow,
} from "@/lib/types";

const inputClass =
  "w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring";
const primaryButton =
  "cursor-pointer rounded-md bg-primary px-3 py-2 text-sm font-medium text-on-primary transition-colors duration-150 hover:opacity-90 disabled:opacity-50";
const secondaryButton =
  "cursor-pointer rounded-md border border-border px-3 py-2 text-sm transition-colors duration-150 hover:bg-muted disabled:opacity-50";

const RESULT_STYLE: Record<BruteForceResult, string> = {
  pass: "bg-success/15 text-success",
  warn: "bg-warning/15 text-warning",
  fail: "bg-destructive/15 text-destructive",
};
const RESULT_LABEL: Record<BruteForceResult, string> = {
  pass: "conforme",
  warn: "à renforcer",
  fail: "vulnérable",
};

const ERRORS: Record<string, string> = {
  target_not_verified: "La cible n'est pas encore vérifiée.",
  production_confirmation_required: "Confirmez explicitement le test sur la production.",
  test_quota_exceeded: "Limite de 10 tests par heure atteinte.",
  verification_not_found: "Preuve introuvable : vérifiez l'enregistrement DNS ou le fichier.",
  private_address: "Cette adresse pointe vers un réseau privé : refusée.",
  unresolvable_host: "Nom de domaine introuvable.",
  https_required: "HTTPS obligatoire.",
  validation_error: "Champs invalides.",
};
const errorText = (err: unknown, fallback: string) =>
  err instanceof ApiError ? (ERRORS[err.code] ?? fallback) : fallback;

export default function BruteForcePage() {
  return (
    <Shell>
      <BruteForce />
    </Shell>
  );
}

function BruteForce() {
  const [policies, setPolicies] = useState<BruteForcePolicy[]>([]);
  const [targets, setTargets] = useState<BruteForceTarget[]>([]);
  const [tests, setTests] = useState<BruteForceTestRow[]>([]);

  const load = useCallback(() => {
    void api<{ policies: BruteForcePolicy[] }>("/api/v1/bruteforce/policies").then((r) =>
      setPolicies(r.policies),
    );
    void api<{ targets: BruteForceTarget[] }>("/api/v1/bruteforce/targets").then((r) =>
      setTargets(r.targets),
    );
    void api<{ tests: BruteForceTestRow[] }>("/api/v1/bruteforce/tests").then((r) =>
      setTests(r.tests),
    );
  }, []);
  useEffect(load, [load]);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">BruteForce Shield</h1>
        <p className="text-sm text-muted-foreground">
          Vérifiez que vos endpoints de connexion résistent aux tentatives répétées. Tests
          uniquement sur des domaines dont vous avez prouvé la propriété, avec un compte de test,
          en faible volume (20 requêtes maximum).
        </p>
      </header>

      <Card className="p-4 text-sm">
        <p className="font-medium">Votre accès à CodeGate est protégé</p>
        <p className="mt-1 text-muted-foreground">
          5 échecs en 10 min verrouillent le compte (5 min, puis délai doublé), 20 échecs bloquent
          l&apos;IP, 3 codes MFA faux bloquent le second facteur. Réponses identiques que le compte
          existe ou non.
        </p>
      </Card>

      <TestRunner targets={targets} onDone={load} />
      <Results tests={tests} />
      <Targets targets={targets} onChange={load} />
      <Policies policies={policies} onChange={load} />
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

// ── Lancer un test ──

function TestRunner({ targets, onDone }: { targets: BruteForceTarget[]; onDone: () => void }) {
  const verified = targets.filter((t) => t.verifiedAt);
  const [form, setForm] = useState({
    targetId: "",
    testType: "login_lockout",
    endpoint: "/api/auth/login",
    testAccount: "",
    emailField: "email",
    passwordField: "password",
    maxAttempts: 12,
    confirmProduction: false,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const targetId = form.targetId || verified[0]?.id || "";
  const target = verified.find((t) => t.id === targetId);

  async function run(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/api/v1/bruteforce/tests", {
        method: "POST",
        body: JSON.stringify({ ...form, targetId }),
      });
      onDone();
    } catch (err) {
      setError(errorText(err, "Le test n'a pas pu être lancé."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title="Lancer un test autorisé">
      <Card className="p-4">
        {!verified.length ? (
          <p className="text-sm text-muted-foreground">
            Ajoutez et vérifiez d&apos;abord une cible (section « Cibles » ci-dessous).
          </p>
        ) : (
          <form onSubmit={run} className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Cible vérifiée">
                <select
                  value={targetId}
                  onChange={(e) => setForm({ ...form, targetId: e.target.value })}
                  className={inputClass}
                >
                  {verified.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} — {t.origin} ({t.environment})
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Type de test">
                <select
                  value={form.testType}
                  onChange={(e) => setForm({ ...form, testType: e.target.value })}
                  className={inputClass}
                >
                  <option value="login_lockout">Verrouillage du login</option>
                  <option value="account_enumeration">Énumération de comptes</option>
                </select>
              </Field>
              <Field label="Endpoint de connexion (POST JSON)">
                <input
                  required
                  value={form.endpoint}
                  onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
                  className={`${inputClass} font-mono`}
                />
              </Field>
              <Field label="Compte de test dédié (jamais un vrai utilisateur)">
                <input
                  required
                  value={form.testAccount}
                  onChange={(e) => setForm({ ...form, testAccount: e.target.value })}
                  placeholder="qa-bruteforce@votre-domaine.com"
                  className={inputClass}
                />
              </Field>
              <Field label="Champ identifiant / champ mot de passe">
                <div className="flex gap-2">
                  <input
                    value={form.emailField}
                    onChange={(e) => setForm({ ...form, emailField: e.target.value })}
                    className={`${inputClass} font-mono`}
                  />
                  <input
                    value={form.passwordField}
                    onChange={(e) => setForm({ ...form, passwordField: e.target.value })}
                    className={`${inputClass} font-mono`}
                  />
                </div>
              </Field>
              {form.testType === "login_lockout" ? (
                <Field label="Tentatives maximum (1–20)">
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={form.maxAttempts}
                    onChange={(e) => setForm({ ...form, maxAttempts: Number(e.target.value) })}
                    className={inputClass}
                  />
                </Field>
              ) : null}
            </div>
            <p className="text-xs text-muted-foreground">
              Chaque tentative utilise un mot de passe aléatoire : le compte de test sera
              probablement verrouillé à la fin du test, c&apos;est le résultat attendu.
            </p>
            {target?.environment === "production" ? (
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.confirmProduction}
                  onChange={(e) => setForm({ ...form, confirmProduction: e.target.checked })}
                  className="mt-1"
                />
                <span>
                  Je confirme lancer ce test sur un environnement de <strong>production</strong>{" "}
                  avec un compte de test dédié.
                </span>
              </label>
            ) : null}
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
            <button type="submit" disabled={busy} className={primaryButton}>
              {busy ? "Test en cours…" : "Lancer le test"}
            </button>
          </form>
        )}
      </Card>
    </Section>
  );
}

// ── Résultats ──

function Results({ tests }: { tests: BruteForceTestRow[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Section title="Résultats">
      <Card>
        {!tests.length ? (
          <p className="px-4 py-8 text-center text-sm text-muted-foreground">
            Aucun test lancé pour le moment.
          </p>
        ) : (
          <ul className="divide-y divide-border">
            {tests.map((t) => (
              <li key={t.id} className="px-4 py-3">
                <button
                  type="button"
                  onClick={() => setOpen(open === t.id ? null : t.id)}
                  className="w-full cursor-pointer text-left"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${RESULT_STYLE[t.result]}`}
                    >
                      {RESULT_LABEL[t.result]}
                    </span>
                    <span className="text-sm font-medium">
                      {t.testType === "login_lockout" ? "Verrouillage" : "Énumération"}
                    </span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {t.target.origin}
                      {t.endpoint}
                    </span>
                    <span className="ml-auto font-mono text-xs text-muted-foreground">
                      {new Date(t.createdAt).toLocaleString("fr-FR")}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">{t.summary}</p>
                </button>
                {open === t.id ? <Evidence test={t} /> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </Section>
  );
}

function Evidence({ test }: { test: BruteForceTestRow }) {
  const rows =
    test.evidence.observations ??
    [...(test.evidence.existing ?? []), ...(test.evidence.missing ?? [])].sort(
      (a, b) => a.attempt - b.attempt,
    );
  return (
    <div className="mt-3 overflow-x-auto">
      <p className="mb-2 text-xs text-muted-foreground">
        Compte de test : {test.evidence.testAccount ?? "—"} · {test.attempts} requête(s)
        {test.scope ? ` · blocage ${test.scope === "account" ? "par compte" : "par IP"}` : ""}
      </p>
      <table className="w-full min-w-[360px] text-xs">
        <thead>
          <tr className="text-left text-muted-foreground">
            <th className="py-1 pr-4 font-medium">#</th>
            <th className="py-1 pr-4 font-medium">HTTP</th>
            <th className="py-1 pr-4 font-medium">Temps</th>
            <th className="py-1 font-medium">Bloqué</th>
          </tr>
        </thead>
        <tbody className="font-mono">
          {rows.map((o) => (
            <tr key={o.attempt}>
              <td className="py-0.5 pr-4">{o.attempt}</td>
              <td className="py-0.5 pr-4">{o.status || "erreur"}</td>
              <td className="py-0.5 pr-4">{o.ms} ms</td>
              <td className="py-0.5">{"blocked" in o && o.blocked ? "oui" : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Cibles ──

function Targets({ targets, onChange }: { targets: BruteForceTarget[]; onChange: () => void }) {
  const [form, setForm] = useState({ name: "", origin: "https://", environment: "staging" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function add(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api("/api/v1/bruteforce/targets", { method: "POST", body: JSON.stringify(form) });
      setForm({ name: "", origin: "https://", environment: "staging" });
      onChange();
    } catch (err) {
      setError(errorText(err, "Ajout impossible."));
    }
  }

  async function verify(id: string) {
    setBusy(id);
    setError(null);
    try {
      await api(`/api/v1/bruteforce/targets/${id}/verify`, { method: "POST" });
      onChange();
    } catch (err) {
      setError(errorText(err, "Vérification impossible."));
    } finally {
      setBusy(null);
    }
  }

  async function remove(id: string) {
    if (!confirm("Retirer cette cible et ses résultats ?")) return;
    await api(`/api/v1/bruteforce/targets/${id}`, { method: "DELETE" });
    onChange();
  }

  return (
    <Section title="Cibles (preuve de propriété)">
      <Card className="space-y-4 p-4">
        <form onSubmit={add} className="grid gap-3 sm:grid-cols-[1fr_1.5fr_160px_auto] sm:items-end">
          <Field label="Nom">
            <input
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="App staging"
              className={inputClass}
            />
          </Field>
          <Field label="Origine HTTPS">
            <input
              required
              value={form.origin}
              onChange={(e) => setForm({ ...form, origin: e.target.value })}
              className={`${inputClass} font-mono`}
            />
          </Field>
          <Field label="Environnement">
            <select
              value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value })}
              className={inputClass}
            >
              <option value="staging">staging</option>
              <option value="development">development</option>
              <option value="production">production</option>
            </select>
          </Field>
          <button type="submit" className={primaryButton}>
            Ajouter
          </button>
        </form>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}

        {targets.map((t) => (
          <div key={t.id} className="rounded-md border border-border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{t.name}</span>
              <span className="font-mono text-xs text-muted-foreground">{t.origin}</span>
              <span className="text-xs text-muted-foreground">· {t.environment}</span>
              <span
                className={`ml-auto inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${
                  t.verifiedAt ? "bg-success/15 text-success" : "bg-warning/15 text-warning"
                }`}
              >
                {t.verifiedAt ? "vérifiée" : "non vérifiée"}
              </span>
            </div>
            {!t.verifiedAt ? (
              <div className="mt-3 space-y-2 text-xs">
                <p className="text-muted-foreground">Prouvez la propriété avec l&apos;une des deux méthodes :</p>
                <p>
                  <span className="font-medium">DNS TXT</span> sur{" "}
                  <code className="font-mono">_codegate-verification.{new URL(t.origin).hostname}</code>
                </p>
                <pre className="overflow-x-auto rounded bg-muted p-2 font-mono">
                  codegate-verification={t.verificationToken}
                </pre>
                <p>
                  <span className="font-medium">ou fichier</span>{" "}
                  <code className="font-mono">{t.origin}/.well-known/codegate-verification.txt</code>{" "}
                  contenant :
                </p>
                <pre className="overflow-x-auto rounded bg-muted p-2 font-mono">{t.verificationToken}</pre>
              </div>
            ) : null}
            <div className="mt-3 flex gap-2">
              {!t.verifiedAt ? (
                <button
                  type="button"
                  onClick={() => verify(t.id)}
                  disabled={busy === t.id}
                  className={secondaryButton}
                >
                  {busy === t.id ? "Vérification…" : "Vérifier"}
                </button>
              ) : null}
              <button
                type="button"
                onClick={() => remove(t.id)}
                className={`${secondaryButton} text-destructive`}
              >
                Retirer
              </button>
            </div>
          </div>
        ))}
      </Card>
    </Section>
  );
}

// ── Politiques ──

function Policies({ policies, onChange }: { policies: BruteForcePolicy[]; onChange: () => void }) {
  const [form, setForm] = useState({
    endpoint: "/api/auth/login",
    maxAttempts: 5,
    windowSeconds: 600,
    lockoutSeconds: 300,
  });
  const [error, setError] = useState<string | null>(null);

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api("/api/v1/bruteforce/policies", { method: "POST", body: JSON.stringify(form) });
      onChange();
    } catch (err) {
      setError(errorText(err, "Enregistrement impossible."));
    }
  }

  async function remove(id: string) {
    await api(`/api/v1/bruteforce/policies/${id}`, { method: "DELETE" });
    onChange();
  }

  const num = (k: keyof typeof form) => (e: { target: { value: string } }) =>
    setForm({ ...form, [k]: Number(e.target.value) });

  return (
    <Section title="Politiques attendues">
      <Card className="space-y-4 p-4">
        <p className="text-xs text-muted-foreground">
          Les tests sont notés par rapport à ces seuils. Sans politique, la référence est 5 échecs
          en 10 minutes (§4.4).
        </p>
        <form onSubmit={save} className="grid gap-3 sm:grid-cols-[1.5fr_1fr_1fr_1fr_auto] sm:items-end">
          <Field label="Endpoint">
            <input
              required
              value={form.endpoint}
              onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
              className={`${inputClass} font-mono`}
            />
          </Field>
          <Field label="Tentatives">
            <input type="number" min={1} value={form.maxAttempts} onChange={num("maxAttempts")} className={inputClass} />
          </Field>
          <Field label="Fenêtre (s)">
            <input type="number" min={1} value={form.windowSeconds} onChange={num("windowSeconds")} className={inputClass} />
          </Field>
          <Field label="Blocage (s)">
            <input type="number" min={0} value={form.lockoutSeconds} onChange={num("lockoutSeconds")} className={inputClass} />
          </Field>
          <button type="submit" className={primaryButton}>
            Enregistrer
          </button>
        </form>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        {policies.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[480px] text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">Endpoint</th>
                  <th className="py-2 pr-4 font-medium">Seuil</th>
                  <th className="py-2 pr-4 font-medium">Blocage</th>
                  <th className="py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id} className="border-b border-border last:border-0">
                    <td className="py-2 pr-4 font-mono text-xs">{p.endpoint}</td>
                    <td className="py-2 pr-4 text-xs">
                      {p.maxAttempts} échecs / {Math.round(p.windowSeconds / 60)} min
                    </td>
                    <td className="py-2 pr-4 text-xs">
                      {Math.round(p.lockoutSeconds / 60)} min ({p.strategy})
                    </td>
                    <td className="py-2 text-right">
                      <button
                        type="button"
                        onClick={() => remove(p.id)}
                        className="cursor-pointer text-xs text-destructive hover:underline"
                      >
                        Supprimer
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </Section>
  );
}
