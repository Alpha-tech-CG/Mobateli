import Link from "next/link";
import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Sécurité — CodeGate",
  description: "Comment CodeGate protège vos données, vos accès et votre code.",
};

/**
 * Public security page (cahier §11.3 « Politique de sécurité publique »,
 * Phase 2). Every statement here describes a control implemented in the
 * product — keep it in sync with the code.
 */
const SECTIONS: { title: string; items: ReactNode[] }[] = [
  {
    title: "Hébergement et données",
    items: [
      "API et base de données hébergées dans l'Union européenne (Francfort).",
      "Chiffrement en transit (HTTPS / TLS) et au repos ; secrets d'intégration chiffrés en AES-256-GCM.",
      "Minimisation : CodeGate analyse les diffs et des métadonnées, pas votre code complet ; les secrets détectés ne sont stockés que masqués.",
      "Rétention limitée : analyses de pull requests supprimées après 365 jours, journal d'audit après 730 jours.",
      "Export de toutes vos données et suppression de l'organisation sur demande, depuis le tableau de bord (RGPD).",
      "Vos données ne servent jamais à entraîner un modèle.",
    ],
  },
  {
    title: "Accès et authentification",
    items: [
      "Mots de passe hachés avec argon2id.",
      "Double authentification (TOTP) obligatoire pour les administrateurs ; SSO SAML et provisioning SCIM pour les entreprises.",
      "Sessions limitées à 12 heures.",
      "Verrouillage progressif après des tentatives répétées, par compte et par adresse IP ; réponses identiques que le compte existe ou non.",
      "Rôles à moindre privilège : Owner, Admin, Security Manager, Developer, Auditor, Viewer.",
      "Journal d'audit de toutes les actions sensibles, exportable en PDF, JSON ou CSV.",
    ],
  },
  {
    title: "Intégrations",
    items: [
      "Application GitHub aux permissions minimales, limitée aux dépôts que vous choisissez, révocable à tout moment.",
      "Jetons d'accès GitHub à courte durée générés à la demande, jamais stockés.",
      "Webhooks vérifiés par signature (HMAC) et idempotents.",
      "Agents serveur et outil de sauvegarde en lecture seule, authentifiés par un jeton propre à chaque serveur ou sauvegarde, stocké haché et révocable.",
    ],
  },
  {
    title: "Tests et analyses responsables",
    items: [
      "Aucun scan réseau de vos serveurs depuis l'extérieur : l'audit d'infrastructure passe par un agent que vous installez.",
      "Tests de brute force uniquement sur des domaines dont vous avez prouvé la propriété, avec un compte de test, 20 requêtes maximum.",
      "Tests de restauration de sauvegarde dans un conteneur isolé, sans réseau, supprimé après usage ; la production n'est jamais touchée.",
      "Contenus de vos dépôts traités comme des données non fiables : détection des tentatives de prompt injection.",
    ],
  },
  {
    title: "Développement",
    items: [
      "Chaque modification est vérifiée par des tests automatisés (unitaires et d'intégration) avant mise en production.",
      "Principe : l'IA écrit, CodeGate vérifie — y compris pour le code de CodeGate.",
    ],
  },
];

export default function SecurityPage() {
  const contact = process.env.NEXT_PUBLIC_SECURITY_CONTACT;
  return (
    <div className="min-h-screen bg-[#111111] text-white">
      <header className="mx-auto flex h-[76px] w-full max-w-[1100px] items-center justify-between px-6">
        <Link href="/" className="flex items-center gap-2.5">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.webp" alt="CodeGate" className="size-8" />
          <span className="font-display text-[20px]">CodeGate</span>
        </Link>
        <Link
          href="/login"
          className="rounded-full bg-white px-5 py-2 text-[14px] text-[#111] transition-opacity hover:opacity-90"
        >
          Connexion
        </Link>
      </header>

      <main className="mx-auto max-w-[1100px] px-6 pb-24 pt-12">
        <p className="text-[13px] uppercase tracking-[0.2em] text-[#BB3E2C]">Sécurité</p>
        <h1 className="font-display mt-3 max-w-[760px] text-[40px] leading-[1.1] md:text-[56px]">
          Un produit de sécurité doit être plus sûr que ce qu&apos;il protège
        </h1>
        <p className="mt-6 max-w-[680px] text-[16px] leading-relaxed text-white/70">
          Voici les mesures réellement en place dans CodeGate pour protéger vos données, vos accès
          et votre code.
        </p>

        <div className="mt-14 grid gap-6 md:grid-cols-2">
          {SECTIONS.map((s) => (
            <section key={s.title} className="rounded-[6px] border border-[#26292b] bg-[#17191a] p-7">
              <h2 className="font-display text-[22px]">{s.title}</h2>
              <ul className="mt-5 space-y-3 text-[15px] leading-relaxed text-white/75">
                {s.items.map((item, i) => (
                  <li key={i} className="flex gap-3">
                    <span className="mt-2 size-1.5 shrink-0 rounded-full bg-[#8AC898]" aria-hidden />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>

        {contact ? (
          <section className="mt-6 rounded-[6px] border border-[#26292b] bg-[#17191a] p-7">
            <h2 className="font-display text-[22px]">Signaler une vulnérabilité</h2>
            <p className="mt-3 text-[15px] text-white/75">
              Écrivez à{" "}
              <a href={`mailto:${contact}`} className="text-white underline">
                {contact}
              </a>
              . Merci de ne pas divulguer publiquement avant notre correction ; nous répondons
              sous 72 heures.
            </p>
          </section>
        ) : null}
      </main>
    </div>
  );
}
