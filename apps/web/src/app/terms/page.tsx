import type { Metadata } from "next";
import Link from "next/link";
import { Field, LegalPage, Section, contact } from "@/components/legal-page";
import { COMPANY } from "@/lib/legal";

export const metadata: Metadata = {
  title: "Conditions générales — CodeGate",
  description: "Conditions générales d'utilisation et de vente du service CodeGate.",
};

export default function TermsPage() {
  return (
    <LegalPage
      title="Conditions générales d'utilisation et de vente"
      intro={
        <p>
          Les présentes conditions régissent l&apos;accès et l&apos;utilisation du service {COMPANY.brand} (le « Service »)
          par l&apos;organisation qui crée un compte (le « Client ») et ses membres. Créer un compte vaut acceptation.
        </p>
      }
    >
      <Section title="1. Objet du Service">
        <p>
          {COMPANY.brand} analyse la sécurité du code et des infrastructures du Client : secrets exposés, failles de
          code, dépendances, configuration, injection de prompt, architecture, serveurs, sauvegardes et résistance aux
          attaques par force brute. Il produit des alertes, des décisions de contrôle et des rapports signés.
        </p>
      </Section>
      <Section title="2. Nature des résultats">
        <p>
          Le Service est une aide à la décision fondée sur des analyses automatisées. Il réduit les risques mais ne
          garantit pas l&apos;absence de vulnérabilité : une analyse peut manquer une faille ou signaler un faux
          positif. Le Client reste responsable de la sécurité de ses systèmes, de ses mises en production et des
          suites données aux résultats. Les rapports décrivent l&apos;état du code au moment de l&apos;analyse.
        </p>
      </Section>
      <Section title="3. Compte et accès">
        <ul className="list-disc space-y-1 pl-5">
          <li>Le Client fournit des informations exactes et garde confidentiels ses identifiants.</li>
          <li>La double authentification est obligatoire pour les administrateurs.</li>
          <li>
            Le Client choisit les dépôts, serveurs et domaines connectés ; il garantit disposer des droits nécessaires
            pour les faire analyser.
          </li>
        </ul>
      </Section>
      <Section title="4. Usages interdits">
        <ul className="list-disc space-y-1 pl-5">
          <li>Analyser ou tester un système, un dépôt ou un domaine sans l&apos;autorisation de son propriétaire.</li>
          <li>Utiliser le Service pour attaquer, surcharger ou contourner la sécurité d&apos;un tiers.</li>
          <li>Tenter d&apos;accéder aux données d&apos;une autre organisation ou de perturber le Service.</li>
          <li>Revendre le Service ou ses rapports sans accord écrit.</li>
        </ul>
        <p>
          Les tests de force brute ne sont possibles que sur des domaines dont le Client a prouvé la propriété ; tout
          abus entraîne la suspension immédiate du compte.
        </p>
      </Section>
      <Section title="5. Offres, prix et paiement">
        <p>
          Les offres et leurs limites (nombre de dépôts, d&apos;analyses, de membres) sont décrites sur la page des
          tarifs au moment de la souscription. Les abonnements payants sont facturés d&apos;avance, mensuellement ou
          annuellement, et renouvelés tacitement sauf résiliation avant l&apos;échéance. Les prix s&apos;entendent hors
          taxes ; les taxes applicables sont ajoutées sur la facture. Un retard de paiement peut entraîner la
          suspension du Service après relance.
        </p>
      </Section>
      <Section title="6. Données du Client">
        <p>
          Le code est lu en mémoire le temps de l&apos;analyse et n&apos;est pas conservé ; seuls les résultats le sont,
          avec les secrets toujours masqués. Le traitement des données confiées par le Client est régi par l&apos;
          <Link href="/dpa" className="underline">accord de sous-traitance</Link>, qui fait partie des présentes
          conditions. Le Client peut exporter ses données et supprimer son organisation à tout moment depuis
          l&apos;application.
        </p>
      </Section>
      <Section title="7. Disponibilité et support">
        <p>
          Nous mettons en œuvre des moyens raisonnables pour assurer la disponibilité du Service, hors maintenance et
          événements indépendants de notre volonté. Le support est joignable à {contact()}. Les engagements de niveau
          de service spécifiques, le cas échéant, figurent dans un contrat dédié.
        </p>
      </Section>
      <Section title="8. Responsabilité">
        <p>
          Dans les limites permises par la loi, notre responsabilité est limitée aux dommages directs et plafonnée au
          montant payé par le Client au titre des douze mois précédant le fait générateur. Nous ne sommes pas
          responsables des pertes indirectes (perte de données, de chiffre d&apos;affaires, atteinte à l&apos;image), ni
          des dommages résultant d&apos;une vulnérabilité non détectée.
        </p>
      </Section>
      <Section title="9. Durée, résiliation">
        <p>
          Le Client peut résilier à tout moment depuis l&apos;application ; la résiliation prend effet à la fin de la
          période payée. Nous pouvons suspendre ou résilier un compte en cas de manquement grave aux présentes
          conditions. À la fin du contrat, les données sont supprimées conformément à l&apos;accord de sous-traitance.
        </p>
      </Section>
      <Section title="10. Modifications">
        <p>
          Nous pouvons faire évoluer ces conditions ; les clients sont informés au moins 30 jours avant l&apos;entrée en
          vigueur d&apos;un changement substantiel et peuvent résilier s&apos;ils le refusent.
        </p>
      </Section>
      <Section title="11. Droit applicable">
        <p>
          Les présentes conditions sont soumises au droit <Field value={COMPANY.governingLaw} label="pays" />. À
          défaut d&apos;accord amiable, tout litige relève des tribunaux de <Field value={COMPANY.courts} label="ville" />.
        </p>
      </Section>
    </LegalPage>
  );
}
