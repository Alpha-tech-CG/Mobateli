import Link from "next/link";
import {
  Shield,
  KeyRound,
  PackageSearch,
  Bot,
  Rocket,
  GitPullRequest,
  ScrollText,
  FileClock,
  ArrowRight,
  Menu,
} from "lucide-react";
import { Reveal } from "@/components/reveal";

export const metadata = {
  title: "CodeGate — Sécurisez le code généré par IA",
  description:
    "CodeGate analyse chaque pull request générée par IA, bloque les déploiements dangereux et vous donne une traçabilité complète.",
};

// Brand dark look on the landing, regardless of system theme.
const dark: React.CSSProperties = {
  ["--background" as string]: "#0a0c0d",
  ["--foreground" as string]: "#eef1f2",
  ["--card" as string]: "#101315",
  ["--card-foreground" as string]: "#eef1f2",
  ["--primary" as string]: "#cf4a34",
  ["--on-primary" as string]: "#ffffff",
  ["--secondary" as string]: "#8ac898",
  ["--muted" as string]: "#191d20",
  ["--muted-foreground" as string]: "#9aa3a8",
  ["--border" as string]: "#23282c",
};

const MODULES = [
  { icon: KeyRound, tag: "Détection", title: "Secret Shield", text: "Clés API, tokens et secrets repérés avant qu'ils n'atteignent un commit ou la production." },
  { icon: PackageSearch, tag: "Supply chain", title: "Dependency Trust", text: "Chaque dépendance ajoutée reçoit un score : typosquatting, mainteneurs, vulnérabilités connues." },
  { icon: GitPullRequest, tag: "Analyse", title: "Revue de PR par IA", text: "Diff, routes, authentification, configuration — analysés et expliqués en langage clair." },
  { icon: Bot, tag: "Agents", title: "Agent Guard", text: "Ce qu'un agent IA peut faire : shell, réseau, déploiement. Les secrets, jamais." },
  { icon: Rocket, tag: "Déploiement", title: "Deploy Gate", text: "Aucun déploiement dangereux ne passe : secrets, dépendances critiques, approbation humaine." },
  { icon: FileClock, tag: "Conformité", title: "Preuves d'audit", text: "Journal immuable et export PDF/JSON/CSV pour SOC 2, ISO 27001 ou RGPD." },
];

const STEPS = [
  { n: "01", title: "Connectez votre dépôt", text: "GitHub ou GitLab, en quelques clics, avec des permissions minimales et révocables." },
  { n: "02", title: "L'IA ouvre une PR", text: "Cursor, Claude Code, Copilot… CodeGate l'analyse dès l'ouverture." },
  { n: "03", title: "Décision claire", text: "Autoriser, corriger, bloquer ou escalader — check et commentaire sur la PR." },
  { n: "04", title: "Traçabilité", text: "Issue de remédiation, alerte Slack, preuve d'audit pour chaque décision." },
];

const STATS = [
  { v: "< 30 s", l: "premier retour sur une PR" },
  { v: "100 %", l: "des PR tracées avant production" },
  { v: "0", l: "secret écrit par un agent IA" },
  { v: "AES-256", l: "chiffrement des secrets au repos" },
];

function Chip({
  icon: Icon,
  className,
}: {
  icon: typeof KeyRound;
  className: string;
}) {
  return (
    <div
      className={`absolute flex size-11 items-center justify-center rounded-full border border-border bg-card/90 shadow-lg backdrop-blur ${className}`}
    >
      <Icon className="size-5 text-secondary" aria-hidden />
    </div>
  );
}

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
          <nav className="hidden items-center gap-8 text-sm text-muted-foreground md:flex">
            <a href="#modules" className="transition-colors hover:text-foreground">Modules</a>
            <a href="#how" className="transition-colors hover:text-foreground">Comment ça marche</a>
            <a href="#audit" className="transition-colors hover:text-foreground">Conformité</a>
          </nav>
          <div className="flex items-center gap-2">
            <Link href="/login" className="hidden rounded-full px-4 py-2 text-sm text-foreground/90 transition-colors hover:bg-muted sm:inline-block">
              Connexion
            </Link>
            <Link href="/login" className="rounded-full bg-primary px-4 py-2 text-sm font-medium text-on-primary transition-transform duration-150 hover:scale-[1.03]">
              Créer un compte
            </Link>
            <Menu className="size-5 text-muted-foreground md:hidden" aria-hidden />
          </div>
        </div>
      </header>

      {/* Hero — centered, with the logo as focal visual */}
      <section className="relative overflow-hidden">
        <div className="cg-grid absolute inset-0 opacity-70" aria-hidden />
        <div className="cg-glow absolute inset-x-0 top-0 h-[520px]" aria-hidden />
        <div className="relative mx-auto max-w-3xl px-4 pt-20 text-center sm:pt-28">
          <Reveal>
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground">
              <span className="size-1.5 rounded-full bg-secondary" /> Sécurité du code généré par IA
            </span>
          </Reveal>
          <Reveal delay={80}>
            <h1 className="mx-auto mt-6 max-w-3xl text-balance text-5xl font-extrabold leading-[1.05] tracking-tight sm:text-[4.25rem]">
              Sécurisez le code IA pour les{" "}
              <span className="text-secondary">équipes modernes</span>
            </h1>
          </Reveal>
          <Reveal delay={160}>
            <p className="mx-auto mt-6 max-w-xl text-lg text-muted-foreground">
              CodeGate analyse chaque pull request générée par IA, bloque les déploiements
              dangereux et réduit le risque sur toute votre chaîne de livraison.
            </p>
          </Reveal>
          <Reveal delay={240}>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <Link href="/login" className="inline-flex items-center gap-2 rounded-full bg-primary px-6 py-3 text-sm font-semibold text-on-primary transition-transform duration-150 hover:scale-[1.03]">
                Auditer mon code <ArrowRight className="size-4" aria-hidden />
              </Link>
              <a href="#modules" className="rounded-full border border-border bg-card px-6 py-3 text-sm font-medium transition-colors hover:bg-muted">
                Voir les modules
              </a>
            </div>
          </Reveal>
        </div>

        {/* Focal visual: the logo + floating chips + circuit base */}
        <Reveal delay={300}>
          <div className="relative mx-auto mt-14 mb-4 h-64 w-full max-w-2xl px-4 sm:h-80">
            <div className="cg-glow absolute inset-0" aria-hidden />
            <div className="absolute left-1/2 top-6 -translate-x-1/2">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src="/logo.webp" alt="" className="size-40 drop-shadow-2xl sm:size-52" />
            </div>
            <Chip icon={KeyRound} className="left-[12%] top-10" />
            <Chip icon={PackageSearch} className="right-[12%] top-16" />
            <Chip icon={Bot} className="left-[20%] bottom-6" />
            <Chip icon={Rocket} className="right-[20%] bottom-2" />
          </div>
        </Reveal>
        {/* circuit line */}
        <div className="mx-auto max-w-5xl border-t border-dashed border-border/70" aria-hidden />
      </section>

      {/* Modules */}
      <section id="modules" className="py-24">
        <div className="mx-auto max-w-6xl px-4">
          <Reveal>
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground">
              <Shield className="size-3.5 text-secondary" aria-hidden /> Nos modules
            </span>
          </Reveal>
          <Reveal delay={80}>
            <h2 className="mt-5 max-w-2xl text-4xl font-bold leading-tight tracking-tight sm:text-5xl">
              La sécurité, à chaque <span className="text-secondary">pull request</span>
            </h2>
          </Reveal>
          <Reveal delay={140}>
            <p className="mt-4 max-w-xl text-muted-foreground">
              CodeGate ne remplace pas GitHub, Vercel ou Linear — il les sécurise.
            </p>
          </Reveal>

          <div className="mt-12 grid gap-6 md:grid-cols-2">
            {MODULES.map((m, i) => (
              <Reveal key={m.title} delay={(i % 2) * 90}>
                <div className="group h-full rounded-2xl border border-border bg-card p-7 transition-colors hover:border-primary/40">
                  <div className="mb-6 inline-flex rounded-xl border border-border bg-background p-3">
                    <m.icon className="size-6 text-primary" aria-hidden />
                  </div>
                  <p className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
                    <span className="size-1.5 rounded-full bg-primary" /> {m.tag}
                  </p>
                  <h3 className="mt-2 text-xl font-semibold">{m.title}</h3>
                  <p className="mt-2 text-sm text-muted-foreground">{m.text}</p>
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
            <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground">
              <GitPullRequest className="size-3.5 text-secondary" aria-hidden /> Le cycle
            </span>
          </Reveal>
          <Reveal delay={80}>
            <h2 className="mt-5 text-4xl font-bold tracking-tight sm:text-5xl">Comment ça marche</h2>
          </Reveal>
          <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {STEPS.map((s, i) => (
              <Reveal key={s.n} delay={i * 80}>
                <div className="h-full rounded-2xl border border-border bg-card p-6">
                  <span className="font-mono text-2xl font-bold text-primary">{s.n}</span>
                  <h3 className="mt-4 font-semibold">{s.title}</h3>
                  <p className="mt-2 text-sm text-muted-foreground">{s.text}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* Stats */}
      <section id="audit" className="border-t border-border/60 py-24">
        <div className="mx-auto max-w-6xl px-4">
          <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
            {STATS.map((s, i) => (
              <Reveal key={s.l} delay={i * 80}>
                <div>
                  <p className="font-mono text-4xl font-bold text-secondary">{s.v}</p>
                  <p className="mt-2 text-sm text-muted-foreground">{s.l}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* CTA band */}
      <section className="px-4 pb-24">
        <Reveal>
          <div className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl border border-primary/30 bg-card p-12 text-center sm:p-16">
            <div className="cg-glow absolute inset-x-0 top-0 h-72" aria-hidden />
            <div className="relative">
              <ScrollText className="mx-auto size-8 text-primary" aria-hidden />
              <h2 className="mx-auto mt-5 max-w-2xl text-4xl font-bold tracking-tight sm:text-5xl">
                Faites auditer votre code en quelques minutes
              </h2>
              <p className="mx-auto mt-4 max-w-md text-muted-foreground">
                Connectez un dépôt, ouvrez une pull request, et laissez CodeGate décider :
                autoriser, corriger ou bloquer.
              </p>
              <Link href="/login" className="mt-8 inline-flex items-center gap-2 rounded-full bg-primary px-7 py-3.5 text-sm font-semibold text-on-primary transition-transform duration-150 hover:scale-[1.03]">
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
          <Link href="/login" className="transition-colors hover:text-foreground">Connexion</Link>
        </div>
      </footer>
    </div>
  );
}
