# CodeGate — Plateforme de sécurité pour le code généré par IA

**Document produit : Vision, architecture et cahier des charges technique**

Version : 1.0  
Date : 26 octobre 2026  
Auteur : Zlat OBAMBI  
Statut : Document de cadrage produit et technique

---

## 1. Résumé exécutif

**CodeGate** est une plateforme SaaS B2B qui rend l’utilisation du code généré par IA plus sûre pour les développeurs, startups et petites équipes techniques.

Le produit s’installe comme une couche de contrôle entre les outils de développement assisté par IA — Cursor, Claude Code, GitHub Copilot, Codex, Windsurf, etc. — et les plateformes de livraison logicielle : GitHub, GitLab, Vercel, Linear, Jira et les environnements de production.

CodeGate ne remplace pas GitHub, Vercel ou Linear. Il les sécurise.

Sa promesse est simple :

> **Aucun code généré par IA n’atteint la production sans analyse de sécurité, validation des dépendances, contrôle des permissions de l’agent et traçabilité complète.**

Le produit répond à trois problèmes majeurs du *vibe coding* :

1. Le code IA peut contenir des vulnérabilités : injection, mauvaise validation, secrets exposés, authentification faible ou cryptographie défaillante.
2. Les agents IA peuvent exécuter des actions dangereuses : installation de paquets inconnus, modification de secrets, accès réseau, déploiement non contrôlé.
3. Les équipes n’ont souvent aucune preuve auditable montrant qui a généré, validé, corrigé et déployé un changement.

CodeGate transforme chaque pull request générée par IA en une décision de sécurité claire : **autoriser, corriger, bloquer ou escalader vers un humain**.

---

## 2. Problème à résoudre

### 2.1 Le contexte

L’IA a considérablement accéléré la création de logiciels. Un développeur solo, un founder non technique ou une petite équipe peut aujourd’hui générer une application complète en quelques heures.

Mais cette vitesse crée un déséquilibre :

- Le code est produit plus vite qu’il ne peut être relu.
- Les utilisateurs génèrent du code sans toujours comprendre les implications de sécurité.
- Les dépendances sont installées automatiquement.
- Les clés API, tokens et variables d’environnement sont souvent exposés.
- Les agents IA peuvent recevoir des instructions malveillantes via une issue, un README, une page web ou une dépendance.
- Les déploiements peuvent partir en production sans validation humaine suffisante.

### 2.2 Les risques concrets

| Risque | Exemple | Conséquence |
|---|---|---|
| Vulnérabilité dans le code IA | Requête SQL construite par concaténation | Injection SQL, vol de données |
| Secret exposé | Clé Stripe, OpenAI ou Supabase dans un commit | Facturation frauduleuse, accès aux données |
| Dépendance malveillante | Paquet npm récent imitant un paquet populaire | Exécution de code malveillant |
| Agent IA trop permissif | Agent autorisé à exécuter des commandes shell | Suppression de fichiers, exfiltration de secrets |
| Prompt injection | Instruction cachée dans une issue GitHub ou un README | L’agent exécute une action non voulue |
| Déploiement dangereux | Variables d’environnement publiques ou configuration faible | Compromission de l’application |
| Absence de traçabilité | Personne ne sait qui a validé le changement | Impossible de répondre à un audit ou à un incident |

### 2.3 Le client cible

CodeGate cible en priorité :

- Les développeurs solo et indie hackers qui déploient des SaaS avec Cursor, Claude Code, Copilot ou Codex.
- Les startups de 2 à 25 personnes utilisant GitHub, Vercel et Linear.
- Les agences web et studios de développement livrant des projets clients.
- Les entreprises SaaS B2B qui doivent prouver un contrôle de sécurité à leurs clients.
- Les équipes préparant une certification ISO 27001, SOC 2 ou une conformité NIS2.

---

## 3. Positionnement produit

### 3.1 Phrase de positionnement

**Français :**

> CodeGate sécurise le code généré par IA avant qu’il n’atteigne votre production.

**Anglais :**

> Ship AI-generated code with confidence. CodeGate reviews every AI pull request, blocks dangerous deployments, and gives your team a complete audit trail.

### 3.2 Ce que CodeGate n’est pas

CodeGate n’est pas :

- Un remplaçant de GitHub.
- Un remplaçant de Vercel.
- Un remplaçant de Linear.
- Un simple scanner SAST.
- Un outil de pentest automatique non supervisé.
- Une promesse de “code IA 100 % sécurisé”.

### 3.3 Ce que CodeGate est

CodeGate est :

- Une **security gate** pour les pull requests.
- Un **contrôleur de permissions** pour les agents IA.
- Un **détecteur de secrets et de dépendances à risque**.
- Un **bloqueur de déploiement dangereux**.
- Un **generateur de tickets de remédiation**.
- Une **source de preuves d’audit** pour la conformité.

---

## 4. Proposition de valeur

### 4.1 Pour le développeur solo

> “Je peux utiliser l’IA pour coder vite, sans envoyer accidentellement mes clés API ou déployer une faille critique.”

### 4.2 Pour la startup

> “Toutes nos pull requests générées par IA sont analysées, priorisées et tracées avant production.”

### 4.3 Pour l’agence

> “Nous livrons des projets clients avec une politique de sécurité vérifiable, même lorsque le code est généré par IA.”

### 4.4 Pour l’entreprise

> “Nous disposons de preuves exploitables pour nos audits, nos clients et nos obligations de conformité.”

---

## 5. Fonctionnalités principales

### 5.1 AI Pull Request Security Review

À chaque pull request, CodeGate analyse :

- Le diff complet.
- Les fichiers modifiés.
- Les dépendances ajoutées ou mises à jour.
- Les variables d’environnement.
- Les configurations CI/CD.
- Les routes, API et requêtes base de données.
- Les changements d’authentification et d’autorisation.
- Les fichiers sensibles : `.env`, `docker-compose.yml`, `vercel.json`, workflows GitHub Actions.

La plateforme produit :

- Un score de risque global.
- Une explication en langage clair.
- La localisation exacte du problème.
- Une proposition de correction.
- Une recommandation : approuver, demander une modification ou bloquer.

### 5.2 Secret Shield

CodeGate détecte :

- Clés API.
- Tokens d’accès.
- Mots de passe.
- Private keys.
- Connexions base de données.
- Variables sensibles dans le code ou les commits.
- Secrets présents dans les logs, tests ou fichiers de configuration.

Actions possibles :

- Alerter avant le push.
- Bloquer la fusion.
- Empêcher le déploiement.
- Guider la révocation de la clé compromise.
- Générer un incident dans Linear.

### 5.3 Dependency Trust Score

Chaque dépendance ajoutée reçoit une évaluation :

- Ancienneté du paquet.
- Nombre de mainteneurs.
- Fréquence des mises à jour.
- Présence de vulnérabilités connues.
- Licence.
- Réputation et popularité.
- Similarité avec un paquet légitime existant.
- Risque de typosquatting.
- Comportement suspect lors de l’installation.

Exemple d’alerte :

> “Le paquet `react-router-domm` ressemble fortement à `react-router-dom`, a été publié il y a 2 jours et possède un seul mainteneur. Installation bloquée.”

### 5.4 Agent Permission Policy

CodeGate permet de définir ce qu’un agent IA peut faire.

Exemples de règles :

| Permission | Autorisé par défaut | Contrôle requis |
|---|---|---|
| Lire le code du dépôt | Oui | — |
| Modifier un fichier | Oui | Diff visible et réversible |
| Installer une dépendance | Non | Approbation ou liste blanche |
| Exécuter une commande shell | Non | Approbation humaine |
| Accéder à Internet | Non | Domaines autorisés uniquement |
| Modifier les secrets | Jamais | Interdit |
| Déployer en production | Non | Approbation explicite |
| Supprimer des fichiers | Non | Interdit ou approbation forte |

### 5.5 Deploy Gate

Avant un déploiement Vercel, CodeGate vérifie :

- Les secrets exposés.
- Les dépendances critiques.
- Les changements d’authentification.
- Les configurations de sécurité.
- Les permissions de l’agent.
- Les tests de sécurité automatisés.
- La présence d’une approbation humaine si nécessaire.

Résultat possible :

- Déploiement autorisé.
- Déploiement autorisé avec avertissement.
- Déploiement bloqué.
- Déploiement nécessitant une validation humaine.

### 5.6 Risk Explainer

CodeGate ne parle pas uniquement en langage technique.

Au lieu de :

> “CWE-79 : Improper Neutralization of Input During Web Page Generation.”

Il affiche :

> “Cette page affiche une donnée utilisateur sans échappement. Un attaquant peut injecter du JavaScript dans le navigateur d’un autre utilisateur. Utilisez un échappement automatique ou une bibliothèque de rendu sûr.”

### 5.7 Linear Remediation Workflow

Lorsqu’un risque est détecté, CodeGate crée automatiquement une issue Linear contenant :

- Titre clair.
- Niveau de sévérité.
- Fichier et ligne concernés.
- Description du risque.
- Impact métier.
- Correctif recommandé.
- Responsable suggéré.
- Statut de suivi.
- Lien vers la pull request.
- Preuve d’audit.

### 5.8 Compliance Evidence Pack

CodeGate génère un dossier de preuves exportable :

- Historique des pull requests analysées.
- Décisions de sécurité.
- Vulnérabilités détectées et corrigées.
- Secrets bloqués.
- Dépendances refusées.
- Approbations humaines.
- Politiques appliquées.
- Déploiements autorisés ou bloqués.
- Export PDF, JSON ou CSV.

---

## 6. Parcours utilisateur

### 6.1 Installation

1. L’utilisateur crée un compte CodeGate.
2. Il connecte son compte GitHub.
3. Il installe l’application GitHub sur les dépôts choisis.
4. Il connecte Vercel.
5. Il connecte Linear.
6. Il choisit un niveau de protection : observation, avertissement ou blocage.
7. Il configure les règles de l’agent IA.

### 6.2 Cycle de développement

1. Le développeur demande une fonctionnalité à Claude Code, Cursor ou Copilot.
2. L’agent génère le code et ouvre une pull request.
3. CodeGate analyse automatiquement la PR.
4. La plateforme publie un commentaire structuré sur GitHub.
5. Si un risque critique est trouvé, la fusion est bloquée.
6. Une issue Linear est créée.
7. Le développeur corrige ou demande une correction à l’IA.
8. CodeGate revérifie.
9. Lorsque le risque est résolu, la PR peut être fusionnée.
10. Avant déploiement Vercel, CodeGate effectue un contrôle final.
11. Le déploiement est autorisé, averti ou bloqué.
12. Toutes les décisions sont conservées dans le journal d’audit.

---

## 7. Architecture produit

### 7.1 Vue générale

```text
[Cursor / Claude Code / Copilot]
              |
              v
       [GitHub Pull Request]
              |
              v
       [CodeGate Security Engine]
              |
     +--------+---------+
     |        |         |
     v        v         v
[Secret    [Dependency  [Static and
 Scanner]   Trust]       AI Review]
     |        |         |
     +--------+---------+
              |
              v
      [Risk Decision Engine]
              |
      +-------+--------+
      |                |
      v                v
[Linear Issue]   [Vercel Deploy Gate]
                       |
                       v
              [Audit & Compliance Store]
```

### 7.2 Modules fonctionnels

| Module | Rôle |
|---|---|
| Identity & Access | Comptes, équipes, rôles, SSO, MFA |
| Repository Connector | Intégration GitHub / GitLab |
| PR Analyzer | Analyse des diffs et pull requests |
| Secret Scanner | Détection des secrets et credentials |
| Dependency Engine | Analyse des paquets et supply chain |
| Static Security Engine | Règles SAST, OWASP, configuration |
| AI Review Agent | Explication, priorisation et correction proposée |
| Policy Engine | Décision d’autorisation, avertissement ou blocage |
| Agent Guard | Contrôle des permissions des agents IA |
| Deployment Gate | Contrôle avant déploiement |
| Ticketing Connector | Création et suivi des issues Linear |
| Audit Store | Journal immuable des décisions et preuves |
| Billing & Plans | Abonnements, limites, facturation |
| Admin Console | Back-office client et administration interne |

---

## 8. Choix du langage : Rust, JavaScript, Python ou Java ?

### 8.1 Recommandation principale

**Le choix le plus adapté est une architecture polyglotte, avec TypeScript/Node.js comme cœur produit et Rust pour les moteurs critiques de sécurité.**

Ce n’est pas un choix “tendance”. C’est le meilleur compromis entre :

- Vitesse de développement.
- Écosystème GitHub, Vercel, Linear et IA.
- Robustesse réelle.
- Recrutement et maintenance.
- Capacité à livrer un MVP rapidement.
- Performance sur les analyses lourdes.
- Sécurité mémoire des composants sensibles.

### 8.2 Répartition recommandée

| Couche | Langage recommandé | Pourquoi |
|---|---|---|
| API, backend produit, intégrations | **TypeScript / Node.js** | Écosystème excellent pour GitHub, Vercel, Linear, Stripe, OAuth et SDK IA |
| Interface web et dashboard | **TypeScript / React ou Next.js** | Productivité, UI moderne, écosystème très mature |
| Moteur d’analyse statique et scanner | **Rust** | Performance, fiabilité mémoire, exécution rapide, faible consommation |
| Analyse IA, NLP, scoring et explications | **Python** | Meilleur écosystème IA/ML, intégration facile avec modèles et bibliothèques d’analyse |
| Moteur de règles et politiques | **Rust ou TypeScript** | Rust si performance critique ; TypeScript si simplicité prioritaire |
| Workers asynchrones | **TypeScript + BullMQ ou Rust** | Traitement des PR, scans, webhooks et notifications |
| Microservices éventuels | **Rust pour le noyau, TypeScript pour le reste** | Séparation claire entre produit et moteur sécurisé |

### 8.3 Comparaison des langages

| Critère | Rust | JavaScript / TypeScript | Python | Java |
|---|---|---|---|---|
| Vitesse de développement MVP | Moyenne | Très élevée | Très élevée | Moyenne |
| Performance | Excellente | Bonne | Moyenne | Bonne à excellente |
| Sécurité mémoire | Excellente | Moyenne | Moyenne | Bonne |
| Écosystème GitHub / Vercel / Linear | Correct | Excellent | Bon | Bon |
| Écosystème IA / ML | Limité | Bon | Excellent | Moyen |
| Facilité de recrutement | Plus difficile | Très facile | Facile | Facile |
| Maintenance long terme | Excellente si équipe compétente | Bonne avec discipline | Moyenne sur gros projets | Bonne |
| Adapté au cœur du MVP | Partiellement | Oui | Oui pour l’IA | Possible mais plus lourd |
| Adapté au moteur de scan | Excellent | Possible | Possible mais moins performant | Possible |

### 8.4 Pourquoi pas uniquement Rust ?

Rust est excellent pour la performance, la sûreté mémoire et les moteurs d’analyse. Mais construire tout le SaaS en Rust ralentirait fortement le MVP :

- Les intégrations GitHub, Vercel, Linear, Stripe et OAuth sont plus rapides à développer en TypeScript.
- Le recrutement Rust est plus difficile et plus coûteux.
- L’itération produit serait plus lente.
- Le dashboard, les webhooks et les API REST seraient plus rapides à livrer en TypeScript.

### 8.5 Pourquoi pas uniquement Python ?

Python est parfait pour l’IA, mais il est moins adapté comme unique langage pour une plateforme de sécurité critique :

- Les performances sont inférieures pour les analyses massives.
- Le typage dynamique augmente le risque d’erreurs sur un produit de sécurité.
- Le déploiement et la gestion des dépendances peuvent devenir complexes.
- Rust est plus adapté aux composants qui doivent être rapides, déterministes et robustes.

### 8.6 Pourquoi pas Java ?

Java est robuste, mature et adapté aux grandes entreprises. Mais pour ce produit :

- L’écosystème GitHub, Vercel, Linear et IA-native est moins naturel qu’en TypeScript.
- Le développement est plus verbeux.
- Le time-to-market est plus lent.
- Java devient intéressant surtout pour une version entreprise très large, pas pour un MVP startup.

### 8.7 Décision technique finale

**Architecture recommandée :**

```text
Frontend : Next.js + TypeScript
API principale : Node.js + TypeScript
Base de données : PostgreSQL
Cache et files : Redis
Workers : Node.js + BullMQ
Moteur de scan : Rust
Moteur IA : Python
Infrastructure : Docker + Kubernetes ou services managés
Hébergement initial : Europe / Union européenne
```

Cette architecture permet de livrer vite sans sacrifier la robustesse du cœur de sécurité.

---

## 9. Stack technique détaillée

### 9.1 Frontend

- **Next.js**
- **TypeScript**
- **React**
- **Tailwind CSS**
- **shadcn/ui** ou équivalent
- **React Query / TanStack Query**
- **Zod** pour la validation
- **Recharts** ou équivalent pour les tableaux de bord

### 9.2 Backend principal

- **Node.js 22 LTS**
- **TypeScript strict**
- **NestJS** ou **Fastify**
- **Prisma** ou **Drizzle ORM**
- **PostgreSQL**
- **Redis**
- **BullMQ**
- **Zod** pour la validation des entrées
- **Pino** pour les logs structurés
- **OpenTelemetry** pour l’observabilité

### 9.3 Moteur de sécurité

- **Rust**
- **Axum** ou **Actix Web** si exposition API nécessaire
- **Tree-sitter** pour l’analyse syntaxique
- **Semgrep** en moteur externe complémentaire
- **Trivy** ou **Grype** pour les vulnérabilités de dépendances et conteneurs
- **OSV** pour les bases de vulnérabilités open source
- **Rego / OPA** éventuellement pour les politiques

### 9.4 Moteur IA

- **Python 3.12+**
- **FastAPI**
- **Pydantic**
- **LangGraph** ou orchestration maison
- **Claude API** pour l’analyse et l’explication
- **Embeddings** pour la détection de similarité entre paquets et code
- **PostgreSQL + pgvector** si recherche vectorielle nécessaire

### 9.5 Intégrations

| Service | Usage |
|---|---|
| GitHub App | Pull requests, checks, commentaires, statuts |
| GitLab | Deuxième intégration SCM |
| Vercel | Deploy hooks, projets, variables, déploiements |
| Linear | Création et suivi des issues |
| Jira | Intégration entreprise |
| Slack | Alertes et notifications |
| Stripe | Facturation SaaS |
| Clerk, Auth0 ou WorkOS | Authentification, SSO et gestion des organisations |
| Sentry | Monitoring des erreurs |
| Grafana / Prometheus | Métriques |
| OpenTelemetry | Traces distribuées |

---

## 10. Sécurité de CodeGate lui-même

CodeGate est un produit de sécurité. Il doit donc être plus sûr que les applications qu’il protège.

### 10.1 Principes non négociables

- Principe du moindre privilège.
- Aucun secret stocké en clair.
- Aucun accès inutile aux dépôts.
- Journalisation de toutes les actions sensibles.
- Isolation des exécutions d’agents.
- Chiffrement des données au repos et en transit.
- Hébergement dans l’Union européenne.
- Suppression des données sur demande.
- Aucune utilisation des données client pour entraîner des modèles sans consentement explicite.

### 10.2 Authentification et accès

- MFA obligatoire pour les administrateurs.
- SSO Google Workspace et Microsoft Entra ID.
- SAML / SCIM pour l’offre entreprise.
- Rôles : Owner, Admin, Security Manager, Developer, Auditor, Viewer.
- Expiration des sessions.
- Journal des connexions et actions administratives.

### 10.3 Gestion des secrets

- Chiffrement avec AES-256-GCM.
- Clés gérées via KMS.
- Rotation régulière des clés.
- Aucun secret dans les logs.
- Aucun secret dans les traces.
- Aucun secret dans les messages d’erreur.
- Accès aux secrets strictement limité et audité.

### 10.4 Isolation des agents

Les agents IA ne doivent jamais avoir un accès large au système.

Mesures :

- Exécution dans des conteneurs éphémères.
- Réseau sortant limité.
- Pas d’accès direct aux secrets.
- Liste blanche de commandes.
- Quotas de ressources CPU, RAM et temps.
- Sandbox sans privilèges root.
- Système de fichiers en lecture seule lorsque possible.
- Journalisation complète des commandes.
- Approbation humaine pour les actions à risque.

### 10.5 Protection contre le prompt injection

- Séparer les instructions système des contenus externes.
- Traiter les issues, README, commentaires et fichiers comme des données non fiables.
- Ne jamais exécuter une instruction trouvée dans un contenu externe.
- Valider toute action sensible via une politique déterministe.
- Demander une approbation humaine pour les actions irréversibles.
- Journaliser les tentatives d’injection détectées.

---

## 11. Données et conformité

### 11.1 Données collectées

- Informations de compte.
- Nom de l’organisation.
- Membres de l’équipe.
- Dépôts autorisés.
- Métadonnées des pull requests.
- Résultats d’analyse.
- Décisions de sécurité.
- Journaux d’audit.
- Informations de facturation.

### 11.2 Données sensibles

CodeGate doit éviter de stocker inutilement :

- Le code source complet.
- Les secrets.
- Les variables d’environnement.
- Les données personnelles des utilisateurs finaux des clients.

Le produit doit privilégier l’analyse des diffs et métadonnées, avec rétention limitée.

### 11.3 Conformité

À prévoir dès la conception :

- RGPD.
- Hébergement UE.
- DPA client.
- Registre des sous-traitants.
- Politique de rétention.
- Droit à l’effacement.
- Chiffrement.
- Journalisation.
- Plan de réponse aux incidents.
- Politique de sécurité publique.
- Préparation SOC 2 Type I puis Type II.
- Alignement ISO 27001.
- Préparation NIS2 pour les clients concernés.

---

## 12. Cahier des charges fonctionnel

### 12.1 Acteurs

| Acteur | Rôle |
|---|---|
| Owner | Propriétaire de l’organisation, accès complet |
| Admin | Gestion des membres, dépôts, politiques et facturation |
| Security Manager | Gestion des règles, risques et incidents |
| Developer | Consultation, correction et fusion selon droits |
| Auditor | Lecture seule des preuves et rapports |
| AI Agent | Exécution contrôlée selon politique |
| System | Automatisations, webhooks et workers |

### 12.2 Modules prioritaires MVP

| Priorité | Module | Description |
|---|---|---|
| P0 | Authentification | Inscription, connexion, MFA, organisations |
| P0 | GitHub App | Connexion des dépôts et réception des PR |
| P0 | PR Analyzer | Analyse du diff et score de risque |
| P0 | Secret Scanner | Détection des secrets |
| P0 | Dependency Scanner | Analyse des dépendances ajoutées |
| P0 | GitHub Check | Statut de sécurité sur la PR |
| P0 | Commentaire IA | Explication claire du risque |
| P1 | Linear Connector | Création automatique d’issues |
| P1 | Vercel Connector | Contrôle avant déploiement |
| P1 | Policy Engine | Règles d’autorisation et de blocage |
| P1 | Dashboard | Risques, dépôts, PR et décisions |
| P2 | Agent Guard | Politiques de permissions pour agents IA |
| P2 | Audit Export | Export PDF, JSON et CSV |
| P2 | Slack Alerts | Notifications d’incidents |
| P3 | GitLab | Deuxième fournisseur SCM |
| P3 | Jira | Intégration entreprise |
| P3 | SAML / SCIM | SSO entreprise |

### 12.3 User stories prioritaires

#### US01 — Connexion GitHub

> En tant que développeur, je veux connecter mon dépôt GitHub afin que CodeGate puisse analyser mes pull requests.

Critères d’acceptation :

- L’utilisateur peut installer l’application GitHub.
- Il choisit les dépôts autorisés.
- Les permissions demandées sont minimales.
- Il peut révoquer l’accès à tout moment.
- Toutes les connexions sont journalisées.

#### US02 — Analyse d’une pull request

> En tant que responsable sécurité, je veux que chaque PR soit analysée automatiquement afin de détecter les risques avant fusion.

Critères d’acceptation :

- L’analyse démarre à l’ouverture ou à la mise à jour d’une PR.
- Le résultat apparaît comme un check GitHub.
- Le commentaire explique les risques en langage clair.
- Le score de risque est visible.
- Les fichiers concernés sont identifiés.
- Les faux positifs peuvent être marqués.

#### US03 — Détection de secret

> En tant que développeur, je veux être alerté si une clé API est exposée afin d’éviter une compromission.

Critères d’acceptation :

- Les secrets détectés sont masqués.
- La PR peut être bloquée selon la politique.
- Une issue Linear peut être créée.
- La plateforme propose une procédure de révocation.
- L’événement est conservé dans l’audit.

#### US04 — Analyse des dépendances

> En tant que responsable technique, je veux évaluer les dépendances ajoutées par l’IA afin d’éviter les paquets malveillants.

Critères d’acceptation :

- Les dépendances ajoutées sont listées.
- Chaque dépendance reçoit un score de confiance.
- Les paquets suspects sont signalés.
- L’installation ou la fusion peut être bloquée.
- Les vulnérabilités connues sont affichées.

#### US05 — Contrôle avant déploiement

> En tant que responsable sécurité, je veux empêcher un déploiement Vercel si un risque critique est présent.

Critères d’acceptation :

- CodeGate reçoit l’événement de déploiement.
- Les contrôles sont exécutés avant mise en production.
- Le déploiement peut être autorisé, averti ou bloqué.
- La décision est journalisée.
- Le responsable reçoit une notification.

#### US06 — Gestion des agents IA

> En tant qu’administrateur, je veux limiter ce que les agents IA peuvent faire afin de réduire les risques d’action non autorisée.

Critères d’acceptation :

- Les permissions sont configurables par projet.
- Les actions sensibles nécessitent une approbation.
- Les commandes interdites sont bloquées.
- Les tentatives sont journalisées.
- Les agents s’exécutent dans un environnement isolé.

#### US07 — Preuves d’audit

> En tant qu’auditeur, je veux exporter l’historique des décisions de sécurité afin de prouver le contrôle appliqué.

Critères d’acceptation :

- L’auditeur peut filtrer par dépôt, période et sévérité.
- Les exports sont disponibles en PDF, JSON et CSV.
- Chaque décision contient l’horodatage, l’auteur et la politique appliquée.
- Les données sensibles sont masquées.

---

## 13. Cahier des charges technique

### 13.1 Exigences non fonctionnelles

| Exigence | Objectif |
|---|---|
| Disponibilité | 99,9 % pour l’API principale |
| Latence d’analyse PR | Premier retour en moins de 30 secondes |
| Analyse complète | Moins de 3 minutes pour une PR standard |
| Scalabilité | Support de milliers de PR par jour |
| Sécurité | Chiffrement, MFA, moindre privilège, audit |
| Observabilité | Logs, métriques, traces et alertes |
| Résilience | Retry, idempotence, files d’attente |
| Confidentialité | Aucune réutilisation des données client sans accord |
| Localisation | Hébergement UE par défaut |

### 13.2 Modèle de données principal

```text
Organization
- id
- name
- plan
- region
- created_at

User
- id
- organization_id
- email
- role
- mfa_enabled
- created_at

Repository
- id
- organization_id
- provider
- external_id
- name
- default_branch
- protection_level

PullRequest
- id
- repository_id
- external_id
- title
- author
- ai_generated
- risk_score
- status
- created_at

Finding
- id
- pull_request_id
- type
- severity
- title
- description
- file_path
- line
- rule_id
- remediation
- status

Dependency
- id
- pull_request_id
- ecosystem
- name
- version
- trust_score
- risk_level
- reason

SecretFinding
- id
- pull_request_id
- secret_type
- location
- masked_preview
- status
- revoked_at

Policy
- id
- organization_id
- repository_id
- rule
- action
- severity_threshold

AuditEvent
- id
- organization_id
- actor_type
- actor_id
- action
- resource_type
- resource_id
- metadata
- created_at
```

### 13.3 API principale

| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Connexion utilisateur |
| POST | `/api/v1/auth/mfa/verify` | Vérification MFA |
| GET | `/api/v1/organizations` | Liste des organisations |
| POST | `/api/v1/repositories/connect` | Connexion d’un dépôt |
| GET | `/api/v1/repositories` | Liste des dépôts |
| GET | `/api/v1/pull-requests` | Liste des PR analysées |
| GET | `/api/v1/pull-requests/:id` | Détail d’une analyse |
| POST | `/api/v1/pull-requests/:id/rescan` | Relancer une analyse |
| GET | `/api/v1/findings` | Liste des vulnérabilités |
| PATCH | `/api/v1/findings/:id` | Mettre à jour le statut |
| POST | `/api/v1/policies` | Créer une politique |
| GET | `/api/v1/audit-events` | Consulter le journal d’audit |
| POST | `/api/v1/audit/export` | Exporter les preuves |
| POST | `/webhooks/github` | Webhook GitHub |
| POST | `/webhooks/vercel` | Webhook Vercel |
| POST | `/webhooks/linear` | Webhook Linear |

### 13.4 Règles de sécurité minimales

- Toutes les entrées API validées avec Zod ou Pydantic.
- Authentification obligatoire sur toutes les routes privées.
- Autorisation vérifiée par organisation et rôle.
- Rate limiting sur toutes les routes publiques.
- Protection CSRF pour les interfaces web.
- Headers de sécurité : CSP, HSTS, X-Frame-Options, Referrer-Policy.
- Validation stricte des webhooks par signature.
- Idempotence des webhooks.
- Aucune exécution de code client sans sandbox.
- Aucun secret dans les logs.
- Rotation des tokens d’intégration.
- Sauvegardes chiffrées et testées.

---

## 14. Plan de développement

### 14.1 Phase 0 — Cadrage : 1 semaine

- Validation du positionnement.
- Choix du nom et du domaine.
- Création de la maquette Figma.
- Définition du MVP.
- Mise en place du repository GitHub.
- Mise en place CI/CD.
- Choix de l’hébergement UE.

### 14.2 Phase 1 — MVP : 6 semaines

| Semaine | Livrable |
|---|---|
| 1 | Authentification, organisations, base de données, CI/CD |
| 2 | GitHub App, réception des PR, modèle de données |
| 3 | Analyse de diff, détection de secrets, règles de base |
| 4 | Analyse des dépendances, score de risque, commentaire GitHub |
| 5 | Linear, politiques de blocage, dashboard |
| 6 | Vercel Deploy Gate, audit, tests, sécurité, bêta privée |

### 14.3 Phase 2 — Produit commercial : 8 semaines

- Agent Guard complet.
- Détection avancée de prompt injection.
- Scoring de dépendances enrichi.
- Rapports de conformité.
- Slack.
- Facturation Stripe.
- Page de sécurité publique.
- Programme de bêta clients.
- Documentation développeur.

### 14.4 Phase 3 — Scale : 3 à 6 mois

- GitLab.
- Jira.
- SAML / SCIM.
- Hébergement dédié ou VPC.
- Moteur Rust plus avancé.
- Détection comportementale des agents.
- Intégrations IDE.
- Certification SOC 2.
- Préparation ISO 27001.

---

## 15. Stratégie de qualité avec Claude Code

Claude Code peut accélérer fortement le développement, mais il ne doit jamais être le seul garant de la qualité.

### 15.1 Règle fondamentale

> **Claude Code écrit, mais CodeGate vérifie.**

Le développement de CodeGate doit lui-même utiliser :

- Revue humaine obligatoire.
- Tests automatisés.
- Analyse statique.
- Scan des dépendances.
- Revue de sécurité sur chaque PR.
- Environnements isolés.
- Déploiement progressif.

### 15.2 Règles de prompt pour Claude Code

Chaque tâche donnée à Claude Code doit contenir :

1. Le contexte produit.
2. Le rôle attendu.
3. Les contraintes de sécurité.
4. Les technologies imposées.
5. Les fichiers à créer ou modifier.
6. Les tests à écrire.
7. Les critères d’acceptation.
8. L’interdiction de créer des secrets en dur.
9. L’obligation de gérer les erreurs.
10. L’obligation de respecter le typage strict.

### 15.3 Prompt maître de développement

```text
Tu es un ingénieur logiciel senior spécialisé en SaaS de cybersécurité, TypeScript, Node.js, Next.js, PostgreSQL et Rust.

Tu travailles sur CodeGate, une plateforme qui sécurise le code généré par IA avant déploiement.

Règles obligatoires :
- Utilise TypeScript strict.
- N’utilise jamais de secret en dur.
- Valide toutes les entrées avec Zod.
- N’expose jamais d’information sensible dans les logs ou messages d’erreur.
- Applique le principe du moindre privilège.
- Écris des tests unitaires et d’intégration pour chaque fonctionnalité.
- Gère explicitement les erreurs, timeouts et cas d’échec.
- Ne crée jamais de code qui exécute des commandes shell sans sandbox ni approbation.
- Documente les décisions de sécurité importantes.
- Ne modifie pas les dépendances sans justification.
- Ne stocke pas le code source client plus longtemps que nécessaire.
- Respecte l’architecture existante.

Pour chaque tâche :
1. Analyse le besoin.
2. Propose un plan court.
3. Identifie les risques de sécurité.
4. Implémente la solution.
5. Écris les tests.
6. Explique les limites et points à vérifier.

Objectif de la tâche :
[Tâche précise ici]

Critères d’acceptation :
[Critères précis ici]
```

### 15.4 Definition of Done

Une fonctionnalité est terminée seulement si :

- Le code est relu par un humain.
- Les tests unitaires passent.
- Les tests d’intégration passent.
- Le linter passe.
- Le type checking passe.
- Le scan de dépendances ne montre pas de vulnérabilité critique.
- Le scan de secrets est négatif.
- La PR est analysée par CodeGate.
- La documentation est mise à jour.
- Les logs ne contiennent aucune donnée sensible.
- Les erreurs sont gérées proprement.
- Le déploiement est réversible.

---

## 16. Indicateurs de succès

| Indicateur | Objectif initial |
|---|---|
| PR analysées par mois | 1 000 après bêta |
| Taux de détection des risques critiques | Supérieur à 85 % sur les cas tests |
| Taux de faux positifs | Inférieur à 15 % |
| Temps moyen d’analyse | Moins de 3 minutes |
| Déploiements bloqués avant incident | Suivi mensuel |
| Temps gagné sur le tri des alertes | Supérieur à 50 % |
| Conversion essai gratuit vers payant | Supérieur à 5 % |
| Rétention à 90 jours | Supérieur à 40 % |

---

## 17. Risques projet et parades

| Risque | Impact | Parade |
|---|---|---|
| Trop de faux positifs | Perte de confiance | Règles progressives, feedback utilisateur, mode observation |
| Complexité technique excessive | Retard | MVP réduit, architecture modulaire |
| Concurrence de Snyk, Semgrep, CodeRabbit | Difficulté commerciale | Différenciation agent guard + deploy gate + conformité |
| Manque de confiance des clients | Faible adoption | Lecture seule au départ, transparence, hébergement UE |
| Coût IA élevé | Marge faible | Analyse déterministe d’abord, IA uniquement pour explication et triage |
| Accès trop large aux dépôts | Risque de sécurité | Permissions minimales et révocables |
| Prompt injection | Action non autorisée | Sandbox, séparation instructions/contenus, approbation humaine |
| Dépendance à GitHub | Risque plateforme | Architecture multi-SCM dès la phase 2 |

---

## 18. Conclusion technique

Le projet CodeGate est viable s’il est conçu comme une **couche de sécurité spécialisée**, et non comme une tentative de remplacer GitHub, Vercel ou Linear.

La stack recommandée est :

- **TypeScript / Node.js** pour le produit, l’API et les intégrations.
- **Next.js** pour l’interface.
- **Rust** pour le moteur d’analyse et les composants critiques.
- **Python** pour les capacités IA, le scoring et l’explication.
- **PostgreSQL, Redis et Docker** pour la base technique.

Cette combinaison offre le meilleur équilibre entre rapidité de livraison, robustesse, performance, sécurité et évolutivité.

Le principe directeur du produit doit rester :

> **L’IA peut accélérer le développement, mais aucune action sensible ne doit atteindre la production sans contrôle, traçabilité et décision explicite.**
