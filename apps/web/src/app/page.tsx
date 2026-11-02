import Link from "next/link";
import {
  KeyRound,
  PackageSearch,
  Bot,
  Rocket,
  GitPullRequest,
  ScrollText,
  FileClock,
  ArrowRight,
} from "lucide-react";
import { Reveal } from "@/components/reveal";

export const metadata = {
  title: "CodeGate — Sécurisez le code généré par IA",
  description:
    "CodeGate analyse chaque pull request générée par IA, bloque les déploiements dangereux et vous donne une traçabilité complète.",
};

// Force the brand's dark look on the landing, regardless of system theme.
const dark: React.CSSProperties = {
  ["--background" as string]: "#0a0c0d",
  ["--foreground" as string]: "#eef1f2",
  ["--card" as string]: "#121517",
  ["--card-foreground" as string]: "#eef1f2",
  ["--primary" as string]: "#cf4a34",
  ["--on-primary" as string]: "#ffffff",
  ["--secondary" as string]: "#8ac898",
  ["--muted" as string]: "#191d20",
  ["--muted-foreground" as string]: "#9aa3a8",
  ["--border" as string]: "#24282c",
};

const FEATURES = [
  { icon: KeyRound, title: "Secret Shield", text: "Détecte clés API, tokens et secrets avant qu'ils n'atteignent un commit ou la production." },
  { icon: PackageSearch, title: "Dependency Trust", text: "Score de confiance de chaque dépendance ajoutée : typosquatting, mainteneurs, vulnérabilités." },
  { icon: GitPullRequest, title: "Revue de PR par IA", text: "Chaque pull request est analysée : diff, routes, auth, config — avec une explication en langage clair." },
  { icon: Bot, title: "Agent Guard", text: "Contrôlez ce qu'un agent IA peut faire : shell, réseau, secrets, déploiement. Les secrets, jamais." },
  { icon: Rocket, title: "Deploy Gate", text: "Aucun déploiement dangereux ne passe : secrets, dépendances critiques, approbation humaine." },
  { icon: FileClock, title: "Preuves d'audit", text: "Journal immuable et export PDF/JSON/CSV pour vos audits SOC 2, ISO 27001 ou RGPD." },
];

const STEPS = [
  { n: "01", title: "Connectez votre dépôt", text: "GitHub ou GitLab, en quelques clics, avec des permissions minimales et révocables." },
  { n: "02", title: "L'IA ouvre une PR", text: "Cursor, Claude Code, Copilot… CodeGate l'analyse automatiquement à l'ouverture." },
  { n: "03", title: "Décision claire", text: "Autoriser, corriger, bloquer ou escalader — avec un check et un commentaire sur la PR." },
  { n: "04", title: "Traçabilité", text: "Issue de remédiation, alerte Slack, et preuve d'audit conservée pour chaque décision." },
];

const STATS = [
  { v: "< 30 s", l: "premier retour sur une PR" },
  { v: "100 %", l: "des PR tracées avant production" },
  { v: "0", l: "secret écrit par un agent IA" },
  { v: "AES-256", l: "chiffrement des secrets au repos" },
];

export default function Landing() {
  return (
    <div style={dark} className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-border/60 bg-background/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3.5">
          <div className="flex items-center gap-2.5">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.webp" alt="CodeGate" className="size-8" />
            <span className="font-mono text-lg font-semibold tracking-tight">CodeGate</span>
          </div>
          <nav className="hidden items-center gap-7 text-sm text-muted-foreground md:flex">
            <a href="#features" className="transition-colors hover:text-foreground">Fonctionnalités</a>
            <a href="#how" className="transition-colors hover:text-foreground">Comment ça marche</a>
            <a href="#audit" className="transition-colors hover:text-foreground">Conformité</a>
          </nav>
          <div className="flex items-center gap-2">
            <Link
              href="/login"
              className="rounded-full px-4 py-2 text-sm text-foreground/90 transition-colors hover:bg-muted"
            >
              Connexion
            </Link>
            <Link
              href="/login"
              className="rounded-full bg-primary px-4 py-2 text-sm font-medium text-on-primary transition-transform duration-150 hover:scale-[1.03]"
            >
              Créer un compte
            </Link>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="cg-grid absolute inset-0" aria-hidden />
        <div className="cg-glow absolute inset-x-0 top-0 h-[480px]" aria-hidden />
        <div className="relative mx-auto max-w-6xl px-4 pb-24 pt-20 sm:pt-28">
          <Reveal>
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground">
              <span className="size-1.5 rounded-full bg-secondary" /> Sécurité du code généré par IA
            </span>
          </Reveal>
          <Reveal delay={80}>
            <h1 className="mt-6 max-w-3xl text-balance text-5xl font-extrabold leading-[1.05] tracking-tight sm:text-6xl">
              Livrez le code IA avec{" "}
              <span className="text-secondary">confiance</span>.
            </h1>
          </Reveal>
          <Reveal delay={160}>
            <p className="mt-6 max-w-xl text-lg text-muted-foreground">
              CodeGate analyse chaque pull request générée par IA, bloque les déploiements
              dangereux et vous donne une traçabilité complète — avant la production.
            </p>
          </Reveal>
          <Reveal delay={240}>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link
                href="/login"
                className="inline-flex items-center gap-2 rounded-full bg-primary px-6 py-3 text-sm font-semibold text-on-primary transition-transform duration-150 hover:scale-[1.03]"
              >
                Auditer mon code <ArrowRight className="size-4" aria-hidden />
              </Link>
              <a
                href="#how"
                className="rounded-full border border-border px-6 py-3 text-sm font-medium transition-colors hover:bg-muted"
              >
                Comment ça marche
              </a>
            </div>
          </Reveal>
          <Reveal delay={320}>
            <p className="mt-10 flex flex-wrap gap-x-6 gap-y-2 text-xs text-muted-foreground">
              <span>✓ GitHub &amp; GitLab</span>
              <span>✓ Vercel Deploy Gate</span>
              <span>✓ Linear &amp; Jira</span>
              <span>✓ Hébergement UE</span>
            </p>
          </Reveal>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="border-t border-border/60 py-24">
        <div className="mx-auto max-w-6xl px-4">
          <Reveal>
            <h2 className="max-w-2xl text-3xl font-bold tracking-tight sm:text-4xl">
              Une <span className="text-secondary">couche de sécurité</span> entre l'IA et votre
              production.
            </h2>
          </Reveal>
          <Reveal delay={80}>
            <p className="mt-4 max-w-xl text-muted-foreground">
              CodeGate ne remplace pas GitHub, Vercel ou Linear — il les sécurise.
            </p>
          </Reveal>
          <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f, i) => (
              <Reveal key={f.title} delay={i * 70}>
                <div className="group h-full rounded-2xl border border-border bg-card p-6 transition-colors hover:border-primary/40">
                  <div className="mb-4 inline-flex rounded-xl border border-border bg-background p-3">
                    <f.icon className="size-5 text-primary" aria-hidden />
                  </div>
                  <h3 className="font-semibold">{f.title}</h3>
                  <p className="mt-2 text-sm text-muted-foreground">{f.text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="border-t border-border/60 py-24">
        <div className="mx-auto max-w-6xl px-4">
          <Reveal>
            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">Comment ça marche</h2>
          </Reveal>
          <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((s, i) => (
              <Reveal key={s.n} delay={i * 70}>
                <div className="h-full rounded-2xl border border-border bg-card p-6">
                  <span className="font-mono text-sm text-primary">{s.n}</span>
                  <h3 className="mt-3 font-semibold">{s.title}</h3>
                  <p className="mt-2 text-sm text-muted-foreground">{s.text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* Stats / compliance */}
      <section id="audit" className="border-t border-border/60 py-24">
        <div className="mx-auto max-w-6xl px-4">
          <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
            {STATS.map((s, i) => (
              <Reveal key={s.l} delay={i * 70}>
                <div>
                  <p className="font-mono text-3xl font-bold text-secondary">{s.v}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{s.l}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* CTA band */}
      <section className="px-4 pb-24">
        <Reveal>
          <div className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl border border-primary/30 bg-card p-10 text-center sm:p-14">
            <div className="cg-glow absolute inset-x-0 top-0 h-64" aria-hidden />
            <div className="relative">
              <ScrollText className="mx-auto size-8 text-primary" aria-hidden />
              <h2 className="mx-auto mt-4 max-w-xl text-3xl font-bold tracking-tight sm:text-4xl">
                Faites auditer votre code en quelques minutes.
              </h2>
              <p className="mx-auto mt-3 max-w-md text-muted-foreground">
                Connectez un dépôt, ouvrez une pull request, et laissez CodeGate décider :
                autoriser, corriger ou bloquer.
              </p>
              <Link
                href="/login"
                className="mt-7 inline-flex items-center gap-2 rounded-full bg-primary px-6 py-3 text-sm font-semibold text-on-primary transition-transform duration-150 hover:scale-[1.03]"
              >
                Créer un compte <ArrowRight className="size-4" aria-hidden />
              </Link>
            </div>
          </div>
        </Reveal>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/60 py-10">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-4 text-sm text-muted-foreground sm:flex-row">
          <div className="flex items-center gap-2">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.webp" alt="CodeGate" className="size-6" />
            <span className="font-mono font-semibold text-foreground">CodeGate</span>
          </div>
          <p>Sécurité du code généré par IA · Hébergement UE</p>
          <Link href="/login" className="transition-colors hover:text-foreground">
            Connexion
          </Link>
        </div>
      </footer>
    </div>
  );
}
