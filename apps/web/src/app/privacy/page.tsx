import type { Metadata } from "next";
import Link from "next/link";
import { Field, LegalPage, Section, contact } from "@/components/legal-page";
import { COMPANY, SUBPROCESSORS } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Politique de confidentialité — CodeGate",
  description: "Quelles données CodeGate traite, pourquoi, combien de temps, et vos droits.",
};

/**
 * Every statement describes what the code does (retention in maintenance.ts,
 * encryption in lib/crypto.ts, export/deletion in routes/privacy.ts…).
 * Keep it in sync when the product changes.
 */
export default function PrivacyPage() {
  return (
    <LegalPage
      title="Politique de confidentialité"
      intro={
        <p>
          Responsable du traitement pour les données de compte : <Field value={COMPANY.legalName} label="raison sociale" />{" "}
          ({contact()}). Pour le contenu de vos dépôts et serveurs, nous agissons en sous-traitant de votre organisation
          (voir l&apos;<Link href="/dpa" className="underline">accord de sous-traitance</Link>).
        </p>
      }
    >
      <Section title="Données traitées">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <strong className="text-white">Compte</strong> : nom, email, rôle, organisation, mot de passe haché (argon2id),
            secret de double authentification chiffré.
          </li>
          <li>
            <strong className="text-white">Sécurité et traçabilité</strong> : journal d&apos;audit des actions sensibles,
            compteurs anti-force brute par compte et par adresse IP.
          </li>
          <li>
            <strong className="text-white">Résultats d&apos;analyse</strong> : constats (fichier, ligne, règle), secrets
            détectés <em>toujours masqués</em>, dépendances, graphe d&apos;architecture (chemins de fichiers),
            rapports signés.
          </li>
          <li>
            <strong className="text-white">Code source</strong> : lu en mémoire le temps de l&apos;analyse, jamais
            enregistré.
          </li>
          <li>
            <strong className="text-white">Intégrations</strong> : jetons d&apos;accès (Slack, Linear, Jira, GitLab…)
            chiffrés en AES-256-GCM.
          </li>
        </ul>
      </Section>
      <Section title="Finalités et bases légales">
        <ul className="list-disc space-y-1 pl-5">
          <li>Fournir le Service et ses rapports — exécution du contrat.</li>
          <li>Sécuriser les comptes, prévenir les abus, garder une trace des actions — intérêt légitime.</li>
          <li>Emails de service (vérification, réinitialisation, invitations, alertes) — exécution du contrat.</li>
          <li>Facturation et obligations comptables — obligation légale.</li>
        </ul>
        <p>Nous ne vendons pas vos données et n&apos;envoyons pas de publicité.</p>
      </Section>
      <Section title="Durées de conservation">
        <ul className="list-disc space-y-1 pl-5">
          <li>Analyses de pull requests et tests : 365 jours, puis suppression automatique.</li>
          <li>Journal d&apos;audit : 730 jours.</li>
          <li>Liens envoyés par email : 1 heure (réinitialisation) à 7 jours (invitation), à usage unique.</li>
          <li>Compte et organisation : jusqu&apos;à leur suppression, que vous pouvez faire à tout moment.</li>
        </ul>
      </Section>
      <Section title="Destinataires et sous-traitants">
        <p>Vos données ne sont accessibles qu&apos;aux membres de votre organisation et aux prestataires suivants :</p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse text-left text-[14px]">
            <thead>
              <tr className="border-b border-white/15 text-white">
                <th className="py-2 pr-4 font-medium">Prestataire</th>
                <th className="py-2 pr-4 font-medium">Usage</th>
                <th className="py-2 font-medium">Localisation</th>
              </tr>
            </thead>
            <tbody>
              {SUBPROCESSORS.map((s) => (
                <tr key={s.name} className="border-b border-white/10 align-top">
                  <td className="py-2 pr-4 text-white">{s.name}{s.required ? "" : " (si activé)"}</td>
                  <td className="py-2 pr-4">{s.purpose}</td>
                  <td className="py-2">{s.location}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          Les transferts hors de l&apos;Union européenne sont encadrés par les clauses contractuelles types de la
          Commission européenne ou un mécanisme équivalent.
        </p>
      </Section>
      <Section title="Sécurité">
        <p>
          Chiffrement en transit et au repos, double authentification obligatoire pour les administrateurs, rôles à
          moindre privilège, verrouillage progressif contre la force brute, journal d&apos;audit. Détails sur la{" "}
          <Link href="/security" className="underline">page sécurité</Link>.
        </p>
      </Section>
      <Section title="Vos droits">
        <p>
          Vous pouvez accéder à vos données, les rectifier, les effacer, en obtenir une copie (export JSON depuis
          l&apos;application), vous opposer à un traitement ou en demander la limitation. Écrivez à {contact()} ; nous
          répondons sous un mois. Vous pouvez aussi saisir l&apos;autorité de protection des données de votre pays (en
          France, la CNIL).
        </p>
      </Section>
      <Section title="Cookies">
        <p>
          L&apos;application n&apos;utilise ni cookie publicitaire ni outil de mesure d&apos;audience. Votre session est
          conservée dans le stockage local de votre navigateur et expire après 12 heures.
        </p>
      </Section>
    </LegalPage>
  );
}
