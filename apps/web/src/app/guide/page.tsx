import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowRight, BookOpen } from "lucide-react";

export const metadata = {
  title: "Guide d'utilisation — CodeGate",
  description:
    "Mettre en place CodeGate pas à pas : connexion des dépôts, analyse des pull requests, audits de dépôt, serveurs, brute force, sauvegardes et rapport d'audit signé.",
};

const SECTIONS = [
  { id: "demarrer", title: "1. Créer votre espace" },
  { id: "depots", title: "2. Connecter vos dépôts" },
  { id: "pull-requests", title: "3. Analyse des pull requests" },
  { id: "score", title: "4. Score de risque et décisions" },
  { id: "corriger", title: "5. Corriger et qualifier" },
  { id: "audit-depot", title: "6. Auditer un dépôt existant" },
  { id: "agents", title: "7. Agent Guard et approbations" },
  { id: "deploiements", title: "8. Contrôle des déploiements" },
  { id: "serveurs", title: "9. Infra Shield : serveurs" },
  { id: "bruteforce", title: "10. BruteForce Shield" },
  { id: "sauvegardes", title: "11. Backup Shield" },
  { id: "politiques", title: "12. Politiques et équipe" },
  { id: "integrations", title: "13. Intégrations" },
  { id: "rapport", title: "14. Rapport d'audit signé" },
  { id: "faq", title: "Questions fréquentes" },
];

export default function GuidePage() {
  return (
    <div className="min-h-screen bg-[#eceef0] font-sans text-[#111]">
      <header className="sticky top-0 z-40 bg-[#111111]/95 backdrop-blur">
        <div className="mx-auto flex h-[68px] max-w-[1280px] items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2.5">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/logo.webp" alt="CodeGate" className="size-8" />
            <span className="font-display text-[20px] text-white">CodeGate</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link href="/login" className="hidden text-[14px] text-white/85 hover:text-white sm:block">
              Connexion
            </Link>
            <Link
              href="/signup"
              className="inline-flex h-10 items-center rounded-[40px] bg-[#bb3e2c] px-5 text-[14px] font-medium text-white transition-colors hover:bg-[#a63523]"
            >
              Commencer
            </Link>
          </div>
        </div>
      </header>

      <section className="bg-[#111111] px-6 pb-16 pt-14 text-white">
        <div className="mx-auto max-w-[1280px]">
          <p className="flex items-center gap-2 text-[14px] font-medium">
            <BookOpen className="size-4" strokeWidth={1.6} aria-hidden /> Guide d&apos;utilisation
          </p>
          <h1 className="font-display mt-4 max-w-[760px] text-[38px] leading-[1.15] sm:text-[52px]">
            Mettre CodeGate en place, <span className="text-[#8ac898]">module par module</span>
          </h1>
          <p className="mt-5 max-w-[680px] text-[16px] leading-7 text-white/80">
            CodeGate contrôle tout le code que vous livrez, qu&apos;il soit écrit par vos développeurs ou généré
            par une IA, ainsi que vos serveurs, vos pages de connexion et vos sauvegardes. Ce guide vous mène de la
            création du compte jusqu&apos;au rapport d&apos;audit signé.
          </p>
        </div>
      </section>

      <div className="mx-auto grid max-w-[1280px] gap-10 px-6 py-14 lg:grid-cols-[240px_1fr]">
        <nav aria-label="Sommaire" className="lg:sticky lg:top-[92px] lg:self-start">
          <p className="mb-3 text-[12px] font-semibold uppercase tracking-wide text-[#6b7378]">Sommaire</p>
          <ol className="space-y-1.5 text-[14px]">
            {SECTIONS.map((s) => (
              <li key={s.id}>
                <a href={`#${s.id}`} className="text-[#3d4347] hover:text-[#bb3e2c]">
                  {s.title}
                </a>
              </li>
            ))}
          </ol>
        </nav>

        <article className="min-w-0 space-y-6">
          <Section id="demarrer" title="1. Créer votre espace">
            <Steps
              items={[
                <>
                  Cliquez sur <B>Commencer</B>, puis renseignez votre nom, votre email, un mot de passe et le nom de
                  votre organisation. Vous devenez <B>owner</B> de l&apos;organisation.
                </>,
                <>
                  Ouvrez <Path>Sécurité du compte</Path> et activez la <B>double authentification (MFA)</B> avec une
                  application comme Google Authenticator ou 1Password. Elle est obligatoire pour les rôles owner et
                  admin avant toute action d&apos;administration.
                </>,
                <>
                  La <Path>Vue d&apos;ensemble</Path> résume ensuite l&apos;état de sécurité de l&apos;organisation :
                  pull requests bloquées, secrets interceptés, serveurs, sauvegardes.
                </>,
              ]}
            />
            <Tip>
              Votre accès est lui-même protégé : 5 échecs de connexion en 10 minutes verrouillent le compte, 20
              échecs bloquent l&apos;adresse IP, et 3 codes MFA faux bloquent le second facteur.
            </Tip>
          </Section>

          <Section id="depots" title="2. Connecter vos dépôts">
            <H3>GitHub</H3>
            <Steps
              items={[
                <>
                  Allez dans <Path>Intégrations</Path>, carte <B>GitHub</B>, et cliquez sur <B>Connecter
                  GitHub</B>.
                </>,
                <>
                  Sur GitHub, choisissez le compte ou l&apos;organisation, puis <B>tous les dépôts</B> ou une sélection.
                  Les permissions demandées sont minimales et révocables à tout moment depuis GitHub.
                </>,
                <>
                  De retour sur CodeGate, les dépôts apparaissent automatiquement. Une première analyse de leur code
                  existant est lancée.
                </>,
              ]}
            />
            <H3>GitLab</H3>
            <Steps
              items={[
                <>
                  Dans <Path>Intégrations</Path>, carte <B>GitLab</B>, cliquez sur <B>Connecter GitLab</B> : CodeGate affiche un{" "}
                  <B>Secret token</B>, à copier immédiatement (il ne sera plus affiché).
                </>,
                <>
                  Dans GitLab : <Path>Settings → Webhooks</Path>, URL <Code>/webhooks/gitlab</Code> de l&apos;API
                  CodeGate, événement <B>Merge request</B>, et collez le Secret token.
                </>,
                <>Ajoutez un jeton d&apos;accès GitLab pour lister et analyser les merge requests depuis la plateforme.</>,
              ]}
            />
          </Section>

          <Section id="pull-requests" title="3. Analyse des pull requests">
            <P>
              Dès qu&apos;une pull request (ou merge request) est ouverte ou reçoit un nouveau commit, GitHub prévient
              CodeGate, qui l&apos;analyse en quelques secondes. <B>Toutes les PR sont analysées</B>, qu&apos;elles
              viennent d&apos;un développeur ou d&apos;un agent IA ; celles générées par IA sont simplement repérées
              par une icône.
            </P>
            <P>Chaque analyse vérifie :</P>
            <List
              items={[
                <><B>Secrets</B> : clés API, tokens, mots de passe, clés privées, fichiers .env commités.</>,
                <><B>Code</B> : injections SQL et de commande, XSS, eval, authentification affaiblie, cryptographie faible.</>,
                <><B>Configuration</B> : workflows GitHub Actions dangereux, conteneurs Docker privilégiés, bases exposées, CORS ouvert.</>,
                <><B>Dépendances</B> : vulnérabilités connues (base OSV), typosquatting, paquets très récents ou peu utilisés.</>,
                <><B>Instructions cachées</B> : prompt injection et caractères invisibles destinés à tromper un agent IA.</>,
              ]}
            />
            <P>
              Le résultat est publié sur la PR : un <B>check</B> (vert, orange ou rouge) et un <B>commentaire</B> qui
              explique chaque risque en clair avec son correctif. Dans <Path>Pull requests</Path>, choisissez un
              projet pour voir ses PR ouvertes et cliquez sur <B>Analyser</B> pour en contrôler une sans attendre de
              nouveau commit.
            </P>
          </Section>

          <Section id="score" title="4. Score de risque et décisions">
            <P>
              Chaque problème ajoute des points selon sa gravité ; le score est plafonné à 100. Il en découle une
              décision :
            </P>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left text-[14px]">
                <thead>
                  <tr className="border-b border-[#d6d9dc] text-[12px] uppercase tracking-wide text-[#6b7378]">
                    <th className="py-2 pr-4 font-medium">Situation</th>
                    <th className="py-2 pr-4 font-medium">Décision</th>
                    <th className="py-2 font-medium">Sur la PR</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e3e5e7]">
                  <Row a="Secret exposé, problème critique ou score ≥ 70" b="Bloquer" c="Check rouge : la fusion doit attendre" tone="#bb3e2c" />
                  <Row a="Problème élevé ou moyen, ou score entre 1 et 69" b="Corriger" c="Check orange : à corriger avant fusion" tone="#c98a12" />
                  <Row a="Aucun problème" b="Autoriser" c="Check vert" tone="#2e7a45" />
                  <Row a="Règle de politique « escalader »" b="Escalader" c="Décision humaine demandée" tone="#3d4347" />
                </tbody>
              </table>
            </div>
            <Tip>
              Les dépendances saines sont analysées mais ne comptent pas dans le score : « 10 dépendances analysées,
              0 à risque » est un bon résultat.
            </Tip>
          </Section>

          <Section id="corriger" title="5. Corriger et qualifier">
            <List
              items={[
                <>
                  <B>Secret détecté</B> : ouvrez <B>Procédure de révocation</B> sur la fiche de la PR, révoquez la
                  clé chez le fournisseur, puis cliquez sur <B>Marquer comme révoqué</B>. Retirer la clé du code ne
                  suffit pas : elle reste dans l&apos;historique Git.
                </>,
                <>
                  <B>Problème de code</B> : appliquez le correctif proposé et poussez un commit ; la PR est réanalysée
                  automatiquement.
                </>,
                <>
                  <B>Fausse alerte</B> : <B>Marquer comme faux positif</B>, avec une justification. Seuls les rôles
                  owner, admin et security manager (avec MFA) peuvent le faire, et la décision reste dans le journal
                  d&apos;audit. Le même problème ne sera plus signalé.
                </>,
              ]}
            />
          </Section>

          <Section id="audit-depot" title="6. Auditer un dépôt existant">
            <P>
              <Path>Analyser un dépôt</Path> audite tout le code de la branche principale, pas seulement les
              changements : secrets, failles, prompt injection et dépendances. Choisissez le dépôt et lancez
              l&apos;analyse : les étapes s&apos;affichent en direct et le rapport sort en quelques secondes.
            </P>
            <P>
              Cochez <B>Réanalyser automatiquement chaque jour</B> pour que le dépôt soit revérifié dès que sa branche
              principale change. Le code est lu en mémoire puis oublié : seuls les résultats sont conservés.
            </P>
          </Section>

          <Section id="agents" title="7. Agent Guard et approbations">
            <P>
              Pour chaque dépôt, <Path>Agent Guard</Path> définit ce qu&apos;un agent IA (Cursor, Claude Code,
              Copilot…) a le droit de faire : commandes shell, accès réseau, installation de paquets, déploiement.
              Chaque permission est <B>autorisée</B>, <B>refusée</B> ou <B>soumise à approbation</B>, avec une liste
              blanche (paquets, domaines, commandes). Les secrets ne sont jamais modifiables par un agent.
            </P>
            <P>
              Les actions soumises à approbation arrivent dans <Path>Approbations</Path>. Sans réponse sous 24 h, la
              demande expire et l&apos;action reste bloquée.
            </P>
          </Section>

          <Section id="deploiements" title="8. Contrôle des déploiements">
            <P>
              Quand un projet Vercel est relié à un dépôt connecté, chaque déploiement est vérifié avant la mise en
              production : si le commit déployé porte un risque bloquant, le déploiement est arrêté. L&apos;historique
              des contrôles est visible dans <Path>Déploiements</Path>.
            </P>
          </Section>

          <Section id="serveurs" title="9. Infra Shield : serveurs">
            <Steps
              items={[
                <>
                  Dans <Path>Serveurs</Path>, cliquez sur <B>Connecter un serveur</B>, donnez-lui un nom et un
                  environnement (production, staging…). CodeGate génère un token, affiché une seule fois.
                </>,
                <>
                  Copiez les commandes d&apos;installation sur votre VPS (Linux). L&apos;agent fonctionne en{" "}
                  <B>lecture seule</B> : il ne modifie rien et envoie un rapport chaque jour.
                </>,
                <>
                  Chaque serveur reçoit un score sur 100 : ports exposés, configuration SSH, firewall, Docker, mises à
                  jour de sécurité. Chaque point à corriger est accompagné de la commande à exécuter.
                </>,
              ]}
            />
          </Section>

          <Section id="bruteforce" title="10. BruteForce Shield">
            <Steps
              items={[
                <>
                  Dans <Path>Brute force</Path>, ajoutez une <B>cible</B> (l&apos;adresse de votre application) puis
                  prouvez qu&apos;elle vous appartient : enregistrement <B>DNS TXT</B>, ou fichier{" "}
                  <Code>/.well-known/codegate-verification.txt</Code>.
                </>,
                <>
                  Créez un <B>compte de test dédié</B> sur votre application, puis cliquez sur <B>Lancer un test autorisé</B> sur votre page de
                  connexion. Il reste en faible volume (20 requêtes maximum) ; le compte de test sera probablement
                  verrouillé à la fin, c&apos;est le résultat attendu.
                </>,
                <>
                  Le résultat indique si la page bloque les tentatives répétées, comparé à votre politique (par défaut
                  5 échecs en 10 minutes).
                </>,
              ]}
            />
            <Tip>Ne testez jamais un site dont vous n&apos;avez pas prouvé la propriété : CodeGate le refuse.</Tip>
          </Section>

          <Section id="sauvegardes" title="11. Backup Shield">
            <P>
              <Path>Sauvegardes</Path> vérifie que vos sauvegardes existent, sont chiffrées, intègres, stockées
              ailleurs que sur le serveur et <B>réellement restaurables</B>. Cliquez sur <B>Déclarer une sauvegarde</B> pour chacune (base de
              données, fichiers), installez l&apos;agent de sauvegarde avec son token, puis enregistrez vos tests de
              restauration.
            </P>
            <P>
              Chaque sauvegarde reçoit un score de récupération sur 100 et la mention <B>prête rançongiciel</B> quand
              une copie isolée et une restauration récente testée existent. Une sauvegarde jamais restaurée n&apos;est
              pas une sauvegarde fiable.
            </P>
          </Section>

          <Section id="politiques" title="12. Politiques et équipe">
            <P>
              <Path>Politiques</Path> fixe l&apos;action à appliquer au-delà d&apos;un seuil de sévérité (par exemple :
              bloquer tout problème élevé), pour toute l&apos;organisation ou un seul dépôt.
            </P>
            <P>
              <Path>Membres</Path> gère l&apos;équipe avec des rôles à moindre privilège : <B>owner</B>,{" "}
              <B>admin</B>, <B>security manager</B>, <B>developer</B>, <B>auditor</B> (lecture et exports) et{" "}
              <B>viewer</B> (lecture). Un membre désactivé ne peut plus se connecter.
            </P>
          </Section>

          <Section id="integrations" title="13. Intégrations">
            <List
              items={[
                <><B>Slack</B> : une alerte dans votre canal pour chaque PR bloquée, secret détecté ou déploiement arrêté.</>,
                <><B>Jira et Linear</B> : une issue de remédiation créée automatiquement pour chaque risque bloquant ; la fermer dans Linear résout le problème dans CodeGate.</>,
                <><B>SSO (SAML) et SCIM</B> : connexion unique et provisionnement des comptes depuis Okta, Entra ID et autres fournisseurs d&apos;identité.</>,
              ]}
            />
          </Section>

          <Section id="rapport" title="14. Rapport d'audit signé">
            <Steps
              items={[
                <>
                  Ouvrez <Path>Audit</Path> et cliquez sur <B>Rapport PDF signé</B>. Le rapport réunit tous les audits
                  : décisions sur les PR, serveurs, brute force, sauvegardes, politiques et journal d&apos;audit.
                </>,
                <>
                  Le PDF porte l&apos;en-tête CodeGate sur chaque page et se termine par un bloc de{" "}
                  <B>signature électronique</B> avec un QR code. Toute modification du fichier, même d&apos;un
                  caractère, invalide la signature dans Adobe Acrobat ou Foxit.
                </>,
                <>
                  Remettez-le à votre client ou à votre auditeur. Il scanne le QR code, dépose le fichier sur la page
                  de vérification et voit immédiatement s&apos;il est <B>authentique et intact</B>. Le fichier est
                  vérifié dans son navigateur, sans être envoyé.
                </>,
              ]}
            />
            <P>
              <B>Chaque fonctionnalité a aussi son propre rapport signé</B>, avec le même en-tête, la même signature et
              le même QR code : bouton <B>Rapport PDF signé</B> sur la fiche d&apos;une pull request, d&apos;un audit de
              dépôt, d&apos;un serveur, d&apos;une cible brute force (une fois vérifiée) et d&apos;une sauvegarde. Les
              rapports déjà émis restent listés sous le bouton et dans <Path>Audit</Path>.
            </P>
            <P>
              Pour vos propres outils, le journal complet s&apos;exporte aussi en <B>CSV</B> et le dossier de preuves en{" "}
              <B>JSON</B>.
            </P>
          </Section>

          <Section id="faq" title="Questions fréquentes">
            <Faq q="CodeGate analyse-t-il seulement le code généré par IA ?">
              Non. Toutes les pull requests et tout le code des dépôts connectés sont analysés, quel que soit leur
              auteur. Le code IA est simplement signalé, car il demande souvent plus d&apos;attention.
            </Faq>
            <Faq q="Mon code est-il conservé ?">
              Non. Le code est lu en mémoire le temps de l&apos;analyse ; seuls les résultats sont conservés, et les
              secrets sont toujours masqués. Les données sont hébergées dans l&apos;Union européenne.
            </Faq>
            <Faq q="Une alerte me semble fausse, que faire ?">
              Vérifiez d&apos;abord le correctif proposé : la plupart des alertes sont réelles. Si c&apos;est bien une
              fausse alerte, marquez-la comme faux positif avec une justification ; elle sera tracée dans le journal
              d&apos;audit.
            </Faq>
            <Faq q="Pourquoi Adobe indique « identité du signataire inconnue » ?">
              Par défaut, CodeGate signe avec son propre certificat : Adobe confirme que le document n&apos;a pas été
              modifié, mais ne connaît pas ce certificat. La page de vérification CodeGate confirme l&apos;authenticité.
              Un certificat reconnu par Adobe peut être installé sur la plateforme.
            </Faq>
          </Section>

          <div className="flex flex-col items-start gap-4 rounded-[6px] bg-[#bb3e2c] p-8 text-white sm:flex-row sm:items-center sm:justify-between">
            <p className="font-display text-[26px] leading-tight">Prêt à sécuriser votre code ?</p>
            <Link
              href="/signup"
              className="inline-flex h-12 items-center gap-2 rounded-[40px] bg-white px-6 text-[14px] font-medium text-[#111] transition-colors hover:bg-[#e9ebed]"
            >
              Créer un compte <ArrowRight className="size-4" aria-hidden />
            </Link>
          </div>
        </article>
      </div>
    </div>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="scroll-mt-[92px] rounded-[6px] bg-white p-6 sm:p-8">
      <h2 className="font-display text-[26px] leading-tight text-[#111]">{title}</h2>
      <div className="mt-4 space-y-4 text-[15px] leading-7 text-[#3d4347]">{children}</div>
    </section>
  );
}

const H3 = ({ children }: { children: ReactNode }) => (
  <h3 className="pt-2 text-[16px] font-semibold text-[#111]">{children}</h3>
);
const P = ({ children }: { children: ReactNode }) => <p>{children}</p>;
const B = ({ children }: { children: ReactNode }) => <strong className="font-semibold text-[#111]">{children}</strong>;
const Code = ({ children }: { children: ReactNode }) => (
  <code className="rounded bg-[#eceef0] px-1.5 py-0.5 font-mono text-[13px] text-[#111]">{children}</code>
);
const Path = ({ children }: { children: ReactNode }) => (
  <span className="whitespace-nowrap rounded bg-[#f3e4e1] px-1.5 py-0.5 text-[14px] font-medium text-[#8f2d1f]">
    {children}
  </span>
);

function Steps({ items }: { items: ReactNode[] }) {
  return (
    <ol className="space-y-3">
      {items.map((item, i) => (
        <li key={i} className="flex gap-3">
          <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full bg-[#111] text-[12px] font-semibold text-white">
            {i + 1}
          </span>
          <span>{item}</span>
        </li>
      ))}
    </ol>
  );
}

function List({ items }: { items: ReactNode[] }) {
  return (
    <ul className="space-y-2">
      {items.map((item, i) => (
        <li key={i} className="flex gap-3">
          <span className="mt-[11px] size-1.5 shrink-0 rounded-full bg-[#bb3e2c]" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

function Tip({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-[5px] border-l-[3px] border-[#bb3e2c] bg-[#f6f4f1] px-4 py-3 text-[14px] leading-6">
      {children}
    </p>
  );
}

function Row({ a, b, c, tone }: { a: string; b: string; c: string; tone: string }) {
  return (
    <tr>
      <td className="py-2.5 pr-4">{a}</td>
      <td className="py-2.5 pr-4 font-semibold" style={{ color: tone }}>
        {b}
      </td>
      <td className="py-2.5">{c}</td>
    </tr>
  );
}

function Faq({ q, children }: { q: string; children: ReactNode }) {
  return (
    <details className="group rounded-[5px] border border-[#e3e5e7] px-4 py-3 open:bg-[#fafafa]">
      <summary className="cursor-pointer list-none font-medium text-[#111] marker:hidden">
        <span className="mr-2 inline-block text-[#bb3e2c] transition-transform group-open:rotate-90">›</span>
        {q}
      </summary>
      <p className="mt-2 text-[14px] leading-6">{children}</p>
    </details>
  );
}
