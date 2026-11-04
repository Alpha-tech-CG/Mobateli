import type { Metadata } from "next";
import Link from "next/link";
import { Field, LegalPage, Section, contact } from "@/components/legal-page";
import { COMPANY } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Mentions légales — CodeGate",
  description: "Éditeur, hébergeur et contact du service CodeGate.",
};

export default function LegalNoticePage() {
  return (
    <LegalPage title="Mentions légales">
      <Section title="Éditeur">
        <p>
          Le service {COMPANY.brand} est édité par <Field value={COMPANY.legalName} label="raison sociale" />,{" "}
          <Field value={COMPANY.legalForm} label="forme juridique et capital" />, dont le siège est situé{" "}
          <Field value={COMPANY.address} label="adresse du siège" />, immatriculée sous le numéro{" "}
          <Field value={COMPANY.registration} label="numéro d'immatriculation" />.
        </p>
        <p>
          Directeur de la publication : <Field value={COMPANY.publicationDirector} label="nom" />. Contact : {contact()}.
        </p>
      </Section>
      <Section title="Hébergement">
        <p>
          Application et API hébergées par Vercel Inc., 440 N Barranca Ave #4133, Covina, CA 91723, États-Unis, sur des
          serveurs situés dans l&apos;Union européenne (Francfort). Base de données hébergée par Neon Inc. dans
          l&apos;Union européenne.
        </p>
      </Section>
      <Section title="Propriété intellectuelle">
        <p>
          Le service, son code, ses textes, ses rapports types et ses marques sont protégés. Toute reproduction non
          autorisée est interdite. Le code de vos dépôts et les résultats de vos analyses restent votre propriété.
        </p>
      </Section>
      <Section title="Données personnelles">
        <p>
          Le traitement de vos données est décrit dans la <Link href="/privacy" className="underline">politique de
          confidentialité</Link>. Pour les données que vous nous confiez en tant que client, voir l&apos;
          <Link href="/dpa" className="underline">accord de sous-traitance</Link>.
        </p>
      </Section>
      <Section title="Signaler une vulnérabilité">
        <p>
          Si vous découvrez une faille dans {COMPANY.brand}, écrivez-nous à {contact()} sans l&apos;exploiter ni la
          divulguer. Nous accusons réception sous 72 heures.
        </p>
      </Section>
    </LegalPage>
  );
}
