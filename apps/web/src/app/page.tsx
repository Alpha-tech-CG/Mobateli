import Link from "next/link";
import {
  Shield,
  ArrowRight,
  Radar,
  Hexagon,
  Triangle,
  Boxes,
  KeyRound,
  PackageSearch,
  Bot,
  Rocket,
  GitPullRequest,
  FileClock,
  Code2,
  Building2,
  Briefcase,
  Users,
} from "lucide-react";
import { Reveal } from "@/components/reveal";
import { Voices } from "@/components/landing/voices";
import {
  HeroShield,
  Circuit,
  Cube,
  IsoStack,
  LineChart,
  IsoRadar,
  IsoChart,
  IsoShield,
  PixelCorner,
  Bars,
  CtaCircuit,
  TerminalScene,
  CaseVisual,
} from "@/components/landing/art";

export const metadata = {
  title: "CodeGate — Protection IA pour le code des équipes modernes",
  description:
    "CodeGate analyse chaque pull request générée par IA, bloque les déploiements dangereux et vous donne une traçabilité complète.",
};

const DARK = "#111111";
const LIGHT = "#eceef0";
const BRICK = "#bb3e2c";

function Eyebrow({ children, dark = false, center = false }: { children: React.ReactNode; dark?: boolean; center?: boolean }) {
  return (
    <p className={`flex items-center gap-2 text-[14px] font-medium ${dark ? "text-white" : "text-[#111]"} ${center ? "justify-center" : ""}`}>
      <Shield className="size-4" strokeWidth={1.6} aria-hidden /> {children}
    </p>
  );
}

function Pill({ children, href, variant = "brick" }: { children: React.ReactNode; href: string; variant?: "brick" | "dark" | "white" }) {
  const styles = {
    brick: "bg-[#bb3e2c] text-white hover:bg-[#a63523]",
    dark: "bg-[#1b1c1d] text-white hover:bg-[#262829]",
    white: "bg-white text-[#111] hover:bg-[#e9ebed]",
  }[variant];
  return (
    <Link href={href} className={`inline-flex h-12 items-center gap-2 rounded-[40px] px-6 text-[14px] font-medium transition-colors duration-200 ${styles}`}>
      {children}
    </Link>
  );
}

const SERVICES = [
  { icon: Radar, color: "#bb3e2c", tag: "Détection", title: "Secrets exposés repérés avant le commit", text: "Clés API, tokens et mots de passe détectés et masqués dans chaque diff." },
  { icon: Hexagon, color: "#3aa6b9", tag: "Analyse", title: "Revue de pull request par IA", text: "Routes, authentification et configuration expliquées en langage clair." },
  { icon: Triangle, color: "#c4372b", tag: "Prévention", title: "Score de confiance des dépendances", text: "Typosquatting, mainteneurs et vulnérabilités évalués pour chaque paquet." },
  { icon: Boxes, color: "#9b5fd0", tag: "Contrôle", title: "Garde-fous pour les agents IA", text: "Shell, réseau et déploiement encadrés. Les secrets, jamais." },
];

const STEPS = [
  { Art: IsoRadar, title: "1 - Analyser", text: "Chaque pull request générée par IA est analysée dès son ouverture." },
  { Art: IsoChart, title: "2 - Détecter", text: "Secrets, dépendances piégées et failles sont repérés et expliqués." },
  { Art: IsoShield, title: "3 - Décider", text: "Autoriser, corriger, bloquer ou escalader, avec une trace d'audit." },
];

const CASES = [
  {
    title: "Développeur solo",
    text: "Vous codez avec Cursor ou Claude Code et déployez sur Vercel. CodeGate bloque la clé Stripe oubliée avant qu'elle n'atteigne un commit public.",
    stats: [["< 30 s", "Premier retour sur la PR"], ["0", "Secret envoyé en production"]],
    visual: { title: "Ajout du paiement Stripe", status: "bloqué", tone: BRICK },
  },
  {
    title: "Startup SaaS",
    text: "Plusieurs développeurs et agents IA ouvrent des PR chaque jour. Chaque changement est analysé, priorisé et tracé avant la fusion.",
    stats: [["100 %", "Des PR tracées avant fusion"], ["4", "Intégrations natives"]],
    visual: { title: "Refonte de l'authentification", status: "autorisé", tone: "#2a2d2f" },
  },
  {
    title: "Agence web",
    text: "Vous livrez des projets clients avec une politique de sécurité vérifiable, et exportez les preuves d'audit pour chaque livraison.",
    stats: [["PDF · CSV · JSON", "Export des preuves"], ["AES-256", "Chiffrement au repos"]],
    visual: { title: "Livraison client v2.4", status: "autorisé", tone: "#3f7a52" },
  },
];

const AUDIENCES = [
  { icon: Code2, name: "Développeurs", text: "Coder vite avec l'IA, sans fuite." },
  { icon: Rocket, name: "Startups", text: "Des PR IA tracées avant production." },
  { icon: Briefcase, name: "Agences", text: "Une sécurité vérifiable pour vos clients." },
  { icon: Building2, name: "Entreprises SaaS", text: "Des preuves pour vos audits." },
];

const RESOURCES = [
  { meta: "Guide — 6 min", title: "Sécuriser le code généré par Cursor ou Claude Code" },
  { meta: "Guide — 4 min", title: "Typosquatting : repérer une dépendance piégée" },
  { meta: "Guide — 8 min", title: "Préparer un audit SOC 2 avec les preuves CodeGate" },
];

export default function Landing() {
  return (
    <div className="overflow-x-clip font-sans text-[#111]" style={{ background: DARK }}>
      {/* ── Header ─────────────────────────────────────────── */}
      <header className="sticky top-0 z-40 bg-[#111111]/90 backdrop-blur">
        <div className="mx-auto flex h-[76px] max-w-[1280px] items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2.5">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.webp" alt="CodeGate" className="size-8" />
            <span className="font-display text-[20px] text-white">CodeGate</span>
          </Link>
          <nav className="hidden items-center gap-8 text-[14px] text-white/90 md:flex">
            <a href="#about" className="transition-colors hover:text-white">À propos</a>
            <a href="#modules" className="transition-colors hover:text-white">Modules</a>
            <a href="#process" className="transition-colors hover:text-white">Processus</a>
            <a href="#cases" className="transition-colors hover:text-white">Cas d&apos;usage</a>
            <a href="#resources" className="transition-colors hover:text-white">Ressources</a>
          </nav>
          <Pill href="/login" variant="white">Connexion</Pill>
        </div>
      </header>

      {/* ── Hero ───────────────────────────────────────────── */}
      <section className="relative overflow-hidden" style={{ background: DARK }}>
        <div
          className="absolute inset-0 opacity-60"
          style={{
            backgroundImage:
              "linear-gradient(to right,#1c1d1e 1px,transparent 1px),linear-gradient(to bottom,#1c1d1e 1px,transparent 1px)",
            backgroundSize: "120px 120px",
          }}
          aria-hidden
        />
        {[[1, 0], [5, 1], [9, 0], [0, 3], [10, 2], [2, 2]].map(([x, y]) => (
          <div key={`${x}-${y}`} className="absolute size-[120px] bg-[#191a1b]" style={{ left: x! * 120, top: y! * 120 }} aria-hidden />
        ))}

        <div className="relative mx-auto max-w-[900px] px-6 pt-24 text-center sm:pt-32">
          <Reveal>
            <h1 className="font-display text-[44px] leading-[1.1] text-white sm:text-[68px]">
              Protection IA pour le code
              <br />
              des <span className="text-[#8ac898]">équipes modernes</span>
            </h1>
          </Reveal>
          <Reveal delay={100}>
            <p className="mx-auto mt-6 max-w-[620px] text-[16px] leading-6 text-white/85">
              Sécurisez chaque pull request générée par IA : secrets, dépendances piégées et failles
              sont détectés avant que le code n&apos;atteigne la production.
            </p>
          </Reveal>
          <Reveal delay={180}>
            <div className="mt-9 flex justify-center gap-3">
              <Pill href="/signup">Commencer</Pill>
              <Pill href="#about" variant="dark">En savoir plus</Pill>
            </div>
          </Reveal>
        </div>

        <Reveal delay={240}>
          <div className="relative mx-auto mt-16 h-[380px] max-w-[1280px] sm:h-[470px]">
            <Circuit className="absolute inset-x-0 bottom-10 h-[200px] w-full" />
            <div className="cg-float absolute left-1/2 top-0 -translate-x-1/2">
              <HeroShield className="h-[300px] w-[260px] drop-shadow-[0_30px_60px_rgba(0,0,0,0.8)] sm:h-[380px] sm:w-[330px]" />
            </div>
            {[
              { Icon: KeyRound, cls: "left-[12%] top-[58%]" },
              { Icon: PackageSearch, cls: "left-[24%] top-[48%]" },
              { Icon: GitPullRequest, cls: "left-[18%] top-[80%]" },
              { Icon: Bot, cls: "right-[30%] top-[62%]" },
              { Icon: Rocket, cls: "right-[12%] top-[56%]" },
              { Icon: FileClock, cls: "right-[22%] top-[82%]" },
            ].map(({ Icon, cls }) => (
              <div key={cls} className={`absolute hidden size-12 items-center justify-center rounded-full border border-[#2c2f31] bg-[#1b1d1e] sm:flex ${cls}`}>
                <Icon className="size-5 text-white" strokeWidth={1.6} aria-hidden />
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ── About ──────────────────────────────────────────── */}
      <section id="about" style={{ background: LIGHT }}>
        <div className="mx-auto grid max-w-[1280px] border-x border-[#d6d9dc] md:grid-cols-[1.45fr_1fr]">
          <div className="px-8 py-20 md:border-r md:border-[#d6d9dc] md:px-12">
            <Reveal><Eyebrow>À propos</Eyebrow></Reveal>
            <Reveal delay={80}>
              <h2 className="font-display mt-5 text-[32px] leading-[1.2] text-[#111] sm:text-[40px]">
                Allier l&apos;intelligence de l&apos;IA et une sécurité proactive pour protéger le code moderne
              </h2>
            </Reveal>
            <Reveal delay={140}>
              <p className="mt-6 max-w-[560px] text-[15px] leading-6 text-[#555b60]">
                « La sécurité ne consiste pas seulement à réagir aux incidents — elle consiste à les empêcher.
                CodeGate vérifie chaque changement avant la production pour que vos équipes livrent vite, sans compromis. »
              </p>
            </Reveal>
            <Reveal delay={200}>
              <div className="mt-10 flex items-end gap-5">
                <div className="flex size-[104px] items-center justify-center rounded-sm bg-[#111]">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src="/logo.webp" alt="" className="size-16" />
                </div>
                <div>
                  <p className="text-[15px] font-medium text-[#111]">Zlat OBAMBI</p>
                  <p className="text-[14px] text-[#6b7378]">Fondateur de CodeGate</p>
                </div>
              </div>
            </Reveal>
          </div>
          <div className="flex flex-col items-center justify-center px-8 py-16">
            <Reveal>
              <div className="flex flex-col items-center">
                <span className="rounded-full bg-[#d6f0dc] px-4 py-1.5 text-[13px] text-[#2e7a45]">Prédire</span>
                <span className="h-8 w-px bg-[#9fb3a6]" />
                <Cube className="w-[200px]" />
              </div>
            </Reveal>
            <Reveal delay={120}>
              <p className="mt-8 max-w-[280px] text-center text-[14px] text-[#555b60]">
                Des analyses par IA qui anticipent les risques du code généré
              </p>
            </Reveal>
          </div>
        </div>
      </section>

      {/* ── Services ───────────────────────────────────────── */}
      <section id="modules" className="pb-28" style={{ background: DARK }}>
        <Bars color="#ffffff" className="mx-auto max-w-[1280px] px-6" />
        <div className="mx-auto mt-20 grid max-w-[1280px] gap-6 px-6 lg:grid-cols-3">
          <div className="lg:pr-6">
            <Reveal><Eyebrow dark>Nos modules</Eyebrow></Reveal>
            <Reveal delay={80}>
              <h2 className="font-display mt-5 text-[40px] leading-[1.15] text-white sm:text-[54px]">
                Chaque PR,
                <br />
                <span className="text-[#8ac898]">sous contrôle</span>
              </h2>
            </Reveal>
          </div>
          {SERVICES.slice(0, 2).map((s, i) => (
            <Reveal key={s.title} tilt delay={i * 120}>
              <ServiceCard s={s} />
            </Reveal>
          ))}
          {SERVICES.slice(2).map((s, i) => (
            <Reveal key={s.title} tilt delay={i * 120}>
              <ServiceCard s={s} />
            </Reveal>
          ))}
          <Reveal delay={200}>
            <div className="flex h-full flex-col justify-end gap-6 pb-2 lg:pl-6">
              <p className="text-[15px] leading-6 text-white/85">
                Protégez votre chaîne de livraison avec des modules conçus pour détecter les risques,
                réduire l&apos;exposition et renforcer la confiance dans le code généré par IA.
              </p>
              <div><Pill href="/login">Tous les modules</Pill></div>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Scene ──────────────────────────────────────────── */}
      <section className="bg-[#d5d7d5]">
        <Reveal><TerminalScene /></Reveal>
      </section>

      {/* ── Process ────────────────────────────────────────── */}
      <section id="process" className="pt-28" style={{ background: DARK }}>
        <div className="mx-auto max-w-[1280px] px-6 text-center">
          <Reveal><Eyebrow dark center>Notre processus</Eyebrow></Reveal>
          <Reveal delay={80}>
            <h2 className="font-display mx-auto mt-5 max-w-[640px] text-[40px] leading-[1.15] text-white sm:text-[54px]">
              Une décision claire pour <span className="text-[#8ac898]">chaque PR</span>
            </h2>
          </Reveal>
        </div>
        <div className="mx-auto mt-16 grid max-w-[1280px] gap-6 px-6 md:grid-cols-3">
          {STEPS.map(({ Art, title, text }, i) => (
            <Reveal key={title} delay={i * 120}>
              <div className="relative h-full overflow-hidden rounded-[6px] bg-[#191b1c] p-7">
                <PixelCorner className="absolute right-0 top-0 size-12" color="#2e3133" />
                <Art className="mx-auto h-[250px] w-full" />
                <h3 className="font-display mt-4 text-[22px] text-white">{title}</h3>
                <p className="mt-2 text-[14px] leading-6 text-[#9aa3a8]">{text}</p>
              </div>
            </Reveal>
          ))}
        </div>
        <Bars color="#ffffff" className="mx-auto mt-28 max-w-[1280px] px-6" />
      </section>

      {/* ── Use cases (sticky stack) ──────────────────────── */}
      <section id="cases" className="pb-28 pt-24" style={{ background: LIGHT }}>
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-end justify-between gap-6 px-6">
          <div>
            <Reveal><Eyebrow>Cas d&apos;usage</Eyebrow></Reveal>
            <Reveal delay={80}>
              <h2 className="font-display mt-5 text-[40px] leading-[1.15] sm:text-[54px]">
                Livrer en confiance,
                <br />à toutes les échelles
              </h2>
            </Reveal>
          </div>
          <Pill href="#modules">Voir les modules</Pill>
        </div>
        <div className="mx-auto mt-14 max-w-[1280px] space-y-10 px-6">
          {CASES.map((c, i) => (
            <div key={c.title} className="sticky" style={{ top: 100 + i * 24 }}>
              <div className="grid overflow-hidden rounded-[6px] bg-white shadow-[0_20px_60px_rgba(0,0,0,0.08)] md:grid-cols-2 md:h-[500px]">
                <div className="flex flex-col justify-between p-8 sm:p-10">
                  <div>
                    <h3 className="font-display text-[32px] text-[#111]">{c.title}</h3>
                    <p className="mt-4 max-w-[440px] text-[15px] leading-6 text-[#555b60]">{c.text}</p>
                    <Link href="/signup" className="mt-6 inline-flex items-center gap-2 text-[14px] font-medium text-[#bb3e2c]">
                      Essayer <ArrowRight className="size-4" aria-hidden />
                    </Link>
                  </div>
                  <div className="mt-10 grid grid-cols-2 divide-x divide-[#e3e5e7]">
                    {c.stats.map(([v, l]) => (
                      <div key={l} className="pr-4 [&:not(:first-child)]:pl-6">
                        <p className="font-display text-[30px] text-[#111]">{v}</p>
                        <p className="mt-1 text-[13px] text-[#6b7378]">{l}</p>
                      </div>
                    ))}
                  </div>
                </div>
                <CaseVisual {...c.visual} />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Audiences + Why ───────────────────────────────── */}
      <section className="pb-28" style={{ background: LIGHT }}>
        <div className="mx-auto max-w-[1280px] px-6">
          <Reveal>
            <p className="mb-6 text-[14px] font-medium text-[#111]">Pour qui</p>
          </Reveal>
          <div className="grid border-y border-[#d6d9dc] sm:grid-cols-2 lg:grid-cols-4">
            {AUDIENCES.map((a, i) => (
              <Reveal key={a.name} delay={i * 80}>
                <div className="h-full border-[#d6d9dc] px-6 py-8 lg:border-l lg:first:border-l-0">
                  <a.icon className="size-7 text-[#111]" strokeWidth={1.3} aria-hidden />
                  <p className="font-display mt-14 text-[20px] text-[#111]">{a.name}</p>
                  <p className="mt-1 text-[14px] text-[#6b7378]">{a.text}</p>
                </div>
              </Reveal>
            ))}
          </div>

          <div className="mt-28 text-center">
            <Reveal><Eyebrow center>Pourquoi CodeGate</Eyebrow></Reveal>
            <Reveal delay={80}>
              <h2 className="font-display mx-auto mt-5 max-w-[620px] text-[40px] leading-[1.15] sm:text-[54px]">
                Là où la sécurité rencontre l&apos;IA
              </h2>
            </Reveal>
          </div>

          <div className="mt-14 grid gap-5 lg:grid-cols-12">
            <Reveal className="lg:col-span-6">
              <div className="h-full rounded-[5px] bg-white p-6">
                <div className="flex items-center justify-between">
                  <span className="rounded-full bg-[#d6f0dc] px-3 py-1 text-[13px] text-[#2e7a45]">Risque par PR</span>
                  <span className="text-[13px] text-[#6b7378]">Illustration</span>
                </div>
                <LineChart className="mt-6 w-full" />
                <div className="mt-3 flex justify-between text-[12px] text-[#6b7378]">
                  {["Jan", "Fév", "Mar", "Avr", "Mai", "Juin", "Juil", "Août", "Sep"].map((m) => <span key={m}>{m}</span>)}
                </div>
              </div>
            </Reveal>
            <Reveal delay={80} className="lg:col-span-3">
              <div className="relative flex h-full min-h-[300px] flex-col justify-between overflow-hidden rounded-[5px] p-6 text-white" style={{ background: BRICK }}>
                <PixelCorner className="absolute right-0 top-0 size-14" />
                <Shield className="size-9" strokeWidth={1.4} aria-hidden />
                <div>
                  <p className="font-display text-[44px]">AES-256</p>
                  <p className="mt-2 text-[14px] text-white/85">Tous les secrets d&apos;intégration chiffrés au repos</p>
                </div>
              </div>
            </Reveal>
            <Reveal delay={160} className="lg:col-span-3">
              <div className="flex h-full flex-col items-center justify-between rounded-[5px] bg-white p-6">
                <span className="self-end rounded-full bg-[#d6f0dc] px-3 py-1 text-[13px] text-[#2e7a45]">Traçabilité</span>
                <IsoStack className="w-[170px]" />
                <p className="text-center text-[14px] text-[#555b60]">Un journal d&apos;audit immuable pour chaque décision</p>
              </div>
            </Reveal>
            <Reveal className="lg:col-span-3">
              <div className="flex h-full min-h-[300px] flex-col justify-between rounded-[5px] bg-white p-6">
                <span className="self-start rounded-full bg-[#d6f0dc] px-3 py-1 text-[13px] text-[#2e7a45]">Rapidité</span>
                <div>
                  <p className="font-display text-[44px] text-[#111]">&lt; 30 s</p>
                  <p className="mt-2 text-[14px] text-[#555b60]">Pour le premier retour sur une pull request</p>
                </div>
              </div>
            </Reveal>
            <Reveal delay={80} className="lg:col-span-3">
              <div className="flex h-full min-h-[300px] items-center justify-center rounded-[5px] bg-[#111]">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src="/logo.webp" alt="" className="size-40" />
              </div>
            </Reveal>
            <Reveal delay={160} className="lg:col-span-6">
              <div className="flex h-full flex-col justify-between rounded-[5px] bg-white p-6">
                <span className="self-start rounded-full bg-[#d6f0dc] px-3 py-1 text-[13px] text-[#2e7a45]">Principe</span>
                <p className="font-display mt-6 text-[22px] leading-[1.35] text-[#111] sm:text-[26px]">
                  « L&apos;IA peut accélérer le développement, mais aucune action sensible ne doit atteindre la
                  production sans contrôle, traçabilité et décision explicite. »
                </p>
                <div className="mt-6 flex items-center gap-3">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src="/logo.webp" alt="" className="size-10" />
                  <div>
                    <p className="text-[14px] font-medium text-[#111]">Principe directeur</p>
                    <p className="text-[13px] text-[#6b7378]">CodeGate</p>
                  </div>
                </div>
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      {/* ── Voices ─────────────────────────────────────────── */}
      <section className="px-6 py-28" style={{ background: DARK }}>
        <Reveal><Eyebrow dark center>Ce qu&apos;ils y gagnent</Eyebrow></Reveal>
        <Reveal delay={80}><div className="mt-8"><Voices /></div></Reveal>
      </section>

      {/* ── Resources ──────────────────────────────────────── */}
      <section id="resources" className="pb-28 pt-24" style={{ background: LIGHT }}>
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-end justify-between gap-6 px-6">
          <div>
            <Reveal><Eyebrow>Ressources</Eyebrow></Reveal>
            <Reveal delay={80}>
              <h2 className="font-display mt-5 text-[40px] leading-[1.15] sm:text-[54px]">
                Garder une longueur
                <br />
                d&apos;avance sur les risques
              </h2>
            </Reveal>
          </div>
          <Pill href="/login">Toutes les ressources</Pill>
        </div>
        <div className="mx-auto mt-12 max-w-[1280px] px-6">
          <div className="border-y border-[#d6d9dc] md:w-1/2 md:border-r">
            {RESOURCES.map((r, i) => (
              <Reveal key={r.title} delay={i * 80}>
                <div className="border-b border-[#d6d9dc] px-2 py-7 last:border-b-0">
                  <p className="text-[13px] text-[#6b7378]">{r.meta}</p>
                  <p className="font-display mt-3 text-[22px] leading-[1.3] text-[#111] sm:text-[24px]">{r.title}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ────────────────────────────────────────────── */}
      <section className="px-6 pb-0" style={{ background: LIGHT }}>
        <Reveal>
          <div className="relative mx-auto flex max-w-[1280px] flex-col items-center overflow-hidden rounded-t-[6px] px-6 py-24 text-center" style={{ background: BRICK }}>
            <div className="cg-noise absolute inset-0 opacity-[0.12] mix-blend-multiply" aria-hidden />
            <CtaCircuit side="left" className="absolute left-0 top-1/2 hidden h-[260px] w-[260px] -translate-y-1/2 md:block" />
            <CtaCircuit side="right" className="absolute right-0 top-1/2 hidden h-[260px] w-[260px] -translate-y-1/2 md:block" />
            <h2 className="font-display relative max-w-[560px] text-[36px] leading-[1.15] text-white sm:text-[48px]">
              Prêt à livrer le code IA sans risque ?
            </h2>
            <div className="relative mt-8 flex flex-wrap justify-center gap-3">
              <Pill href="/signup" variant="white">Créer un compte</Pill>
              <Pill href="/login" variant="dark">Se connecter</Pill>
            </div>
          </div>
        </Reveal>
      </section>

      {/* ── Footer ─────────────────────────────────────────── */}
      <footer className="overflow-hidden pt-10" style={{ background: DARK }}>
        <Bars color={BRICK} className="mx-auto max-w-[1280px] px-6" />
        <div className="mx-auto mt-16 grid max-w-[1280px] gap-12 px-6 md:grid-cols-2">
          <div>
            <div className="flex items-center gap-2.5">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src="/logo.webp" alt="CodeGate" className="size-8" />
              <span className="font-display text-[20px] text-white">CodeGate</span>
            </div>
            <p className="font-display mt-6 max-w-[420px] text-[24px] leading-[1.3] text-white">
              La couche de sécurité entre l&apos;IA et votre production
            </p>
            <Link href="/signup" className="mt-8 flex h-12 max-w-[420px] items-center justify-between rounded-[40px] bg-[#232527] pl-5 pr-1.5 text-[14px] text-white/60 transition-colors hover:text-white">
              Créer un compte gratuitement
              <span className="flex size-9 items-center justify-center rounded-full bg-white text-[#111]">
                <ArrowRight className="size-4" aria-hidden />
              </span>
            </Link>
          </div>
          <div className="grid grid-cols-3 gap-6 text-[14px] text-white/85">
            <div className="space-y-3">
              <a href="#about" className="block hover:text-white">À propos</a>
              <a href="#modules" className="block hover:text-white">Modules</a>
              <a href="#process" className="block hover:text-white">Processus</a>
            </div>
            <div className="space-y-3">
              <a href="#cases" className="block hover:text-white">Cas d&apos;usage</a>
              <a href="#resources" className="block hover:text-white">Ressources</a>
            </div>
            <div className="space-y-3">
              <Link href="/login" className="block hover:text-white">Connexion</Link>
              <Link href="/signup" className="block hover:text-white">Créer un compte</Link>
              <Link href="/dashboard" className="block hover:text-white">Dashboard</Link>
            </div>
          </div>
        </div>
        <div className="mx-auto mt-14 flex max-w-[1280px] items-center justify-between border-t border-[#232527] px-6 pt-6 text-[13px] text-white/60">
          <span className="flex items-center gap-2"><Users className="size-4" aria-hidden /> Hébergement UE</span>
          <span>© 2026 CodeGate</span>
        </div>
        <p className="font-display mx-auto mt-6 max-w-[1280px] select-none whitespace-nowrap px-6 text-[22vw] leading-[0.8] text-[#1d1f20] lg:text-[260px]" aria-hidden>
          CodeGate
        </p>
      </footer>
    </div>
  );
}

function ServiceCard({ s }: { s: (typeof SERVICES)[number] }) {
  return (
    <div className="cg-noise flex h-[340px] flex-col justify-between rounded-[5px] p-6">
      <s.icon className="size-12" style={{ color: s.color }} strokeWidth={1.1} aria-hidden />
      <div>
        <p className="flex items-center gap-2 text-[13px] text-[#111]">
          <span className="size-1.5 rounded-full bg-[#bb3e2c]" /> {s.tag}
        </p>
        <h3 className="font-display mt-2 text-[26px] leading-[1.2] text-[#111]">{s.title}</h3>
        <div className="my-4 h-px bg-[#d6d9dc]" />
        <p className="text-[14px] leading-5 text-[#555b60]">{s.text}</p>
      </div>
    </div>
  );
}
