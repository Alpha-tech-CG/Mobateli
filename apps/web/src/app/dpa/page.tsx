import type { Metadata } from "next";
import Link from "next/link";
import { Field, LegalPage, Section, contact } from "@/components/legal-page";
import { COMPANY, SUBPROCESSORS } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Accord de sous-traitance (DPA) — CodeGate",
  description: "Engagements de CodeGate sur les données que ses clients lui confient (article 28 RGPD).",
};

export default function DpaPage() {
  return (
    <LegalPage
      title="Accord de sous-traitance des données (DPA)"
      intro={
        <p>
          Cet accord complète les <Link href="/terms" className="underline">conditions générales</Link>. Il s&apos;applique
          lorsque le Client (responsable du traitement) confie à <Field value={COMPANY.legalName} label="raison sociale" />{" "}
          (sous-traitant) des données à caractère personnel contenues dans ses dépôts, serveurs ou sauvegardes, au sens de
          l&apos;article 28 du RGPD et des législations équivalentes.
        </p>
      }
    >
      <Section title="1. Objet, nature et durée">
        <p>
          Analyse automatisée de sécurité du code, des dépendances, de la configuration et des serveurs du Client,
          pendant la durée du contrat. Les données concernées sont celles qui figurent dans les éléments analysés
          (par exemple noms et emails d&apos;auteurs de commits, identifiants présents dans le code) et les comptes des
          membres du Client.
        </p>
      </Section>
      <Section title="2. Instructions">
        <p>
          Le sous-traitant ne traite les données que sur instruction documentée du Client, constituée par la
          configuration du Service (dépôts connectés, paramètres d&apos;analyse, intégrations activées). Il informe le
          Client si une instruction lui paraît contraire à la réglementation.
        </p>
      </Section>
      <Section title="3. Minimisation">
        <ul className="list-disc space-y-1 pl-5">
          <li>Le code source est lu en mémoire et n&apos;est jamais stocké.</li>
          <li>Les secrets détectés ne sont conservés que masqués.</li>
          <li>Seuls les résultats d&apos;analyse sont conservés, pour les durées indiquées dans la politique de confidentialité.</li>
          <li>Aucune donnée du Client ne sert à entraîner un modèle d&apos;intelligence artificielle.</li>
        </ul>
      </Section>
      <Section title="4. Confidentialité et sécurité">
        <p>
          Les personnes autorisées sont soumises à une obligation de confidentialité. Mesures techniques : chiffrement en
          transit (TLS) et au repos, chiffrement AES-256-GCM des identifiants d&apos;intégration, mots de passe argon2id,
          double authentification obligatoire pour les administrateurs, contrôle d&apos;accès par rôles, isolation des
          données par organisation, journal d&apos;audit, tests automatisés avant chaque mise en production.
        </p>
      </Section>
      <Section title="5. Sous-traitants ultérieurs">
        <p>
          Le Client autorise le recours aux sous-traitants listés ci-dessous. Tout ajout ou remplacement est notifié au
          moins 30 jours à l&apos;avance ; le Client peut s&apos;y opposer et résilier.
        </p>
        <ul className="list-disc space-y-1 pl-5">
          {SUBPROCESSORS.map((s) => (
            <li key={s.name}>
              <strong className="text-white">{s.name}</strong> — {s.purpose} ({s.location}){s.required ? "" : ", seulement si activé"}.
            </li>
          ))}
        </ul>
      </Section>
      <Section title="6. Droits des personnes et assistance">
        <p>
          Le sous-traitant aide le Client à répondre aux demandes des personnes concernées (export et suppression
          disponibles dans l&apos;application) et, le cas échéant, à réaliser une analyse d&apos;impact.
        </p>
      </Section>
      <Section title="7. Violation de données">
        <p>
          Le sous-traitant notifie au Client toute violation de données le concernant dans les meilleurs délais et au
          plus tard 48 heures après en avoir eu connaissance, avec les informations disponibles sur sa nature, ses
          conséquences et les mesures prises.
        </p>
      </Section>
      <Section title="8. Fin du contrat">
        <p>
          À la fin du contrat ou sur demande, le Client peut exporter ses données ; elles sont ensuite supprimées sous 30
          jours, sauf obligation légale de conservation.
        </p>
      </Section>
      <Section title="9. Audit">
        <p>
          Le sous-traitant met à disposition les informations nécessaires pour démontrer le respect de cet accord
          (journal d&apos;audit exportable, rapports signés) et se prête à des audits raisonnables, sur préavis écrit
          adressé à {contact()}.
        </p>
      </Section>
    </LegalPage>
  );
}
