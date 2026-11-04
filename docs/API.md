# Référence API — CodeGate

Base : `http://localhost:4000`. Toutes les routes `/api/v1/*` privées exigent un en-tête `Authorization: Bearer <JWT>` (obtenu via signup/login). Les entrées sont validées par Zod ; une erreur renvoie `400 { error: "validation_error", issues: [...] }`. Rôles : `owner`, `admin`, `security_manager`, `developer`, `auditor`, `viewer`.

## Santé

| Méthode | Route | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness (ping DB) |

## Authentification

| Méthode | Route | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/signup` | — | Crée l'organisation + l'utilisateur `owner`, renvoie un JWT |
| POST | `/api/v1/auth/login` | — | `{ email, password, totp? }` → JWT (TOTP requis si MFA activé) |
| POST | `/api/v1/auth/mfa/setup` | ✅ | Génère un secret TOTP, renvoie l'`otpauth://` |
| POST | `/api/v1/auth/mfa/verify` | ✅ | Confirme le premier code et active la MFA |
| POST | `/api/v1/auth/password` | ✅ | `{ currentPassword, newPassword }` — change son propre mot de passe (l'actuel est exigé) |

## Organisation & dépôts

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/organization` | tous | Organisation courante |
| GET | `/api/v1/organization/members` | tous | Membres |
| POST | `/api/v1/organization/members` | owner/admin | Invite un membre (mot de passe temporaire renvoyé une fois ; seul un owner peut créer un owner) |
| POST | `/api/v1/organization/members/:id/reset-password` | owner/admin | Réinitialise le mot de passe d'un membre (temporaire renvoyé une fois ; seul un owner réinitialise un owner) |
| GET | `/api/v1/repositories` | tous | Dépôts connectés |

## Paramètres d'analyse

Voir [ARCHITECTURE-ANALYSE.md](ARCHITECTURE-ANALYSE.md). Chaque réponse contient `effective` (ce que la prochaine analyse utilisera : défauts ← organisation ← dépôt).

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/settings/analysis` | tous | Paramètres de l'organisation, effectifs, défauts et catalogue des moteurs |
| PUT | `/api/v1/settings/analysis` | owner/admin/security_manager | `{ engines?: { <id>: bool }, ignorePaths?: string[], minSeverity? }` |
| GET | `/api/v1/repositories/:id/settings` | tous | Niveau de protection + surcharges du dépôt + effectif |
| PUT | `/api/v1/repositories/:id/settings` | owner/admin/security_manager | `{ protectionLevel?: observe\|warn\|block, analysisSettings?: {…} \| null }` (`null` = revenir aux réglages de l'organisation) |

## Pull requests

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/pull-requests` | tous | Liste des PR analysées (+ compteurs) |
| GET | `/api/v1/pull-requests/:id` | tous | Détail : findings, secrets, dépendances + `lastAnalysis` (moteurs exécutés / sautés / en échec, ou PR non analysable) |
| POST | `/api/v1/pull-requests/:id/rescan` | tous | Relance l'analyse (enqueue) |

## Politiques

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/policies` | tous | Politiques de l'organisation |
| POST | `/api/v1/policies` | owner/admin/security_manager | Crée une règle `{ rule, action, severityThreshold, repositoryId? }` |

## Agent Guard (§5.4)

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/repositories/:id/agent-policies` | tous | Politiques effectives (défaut + overrides) |
| PUT | `/api/v1/repositories/:id/agent-policies` | owner/admin/security_manager | Définit une règle `{ permission, decision, allowlist }` (refuse d'assouplir `modify_secrets`) |
| POST | `/api/v1/agent/guard` | tous | Enforcement : `{ repositoryId, permission, target?, agentId? }` → `{ decision, reason }` (journalisé en `ai_agent`) |

Permissions : `read_repo`, `modify_file`, `install_dependency`, `run_shell`, `network_access`, `modify_secrets`, `deploy_production`, `delete_files`. Décisions : `allow`, `deny`, `require_approval`.

## Intégrations

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET/POST/DELETE | `/api/v1/integrations/linear` | POST/DELETE : owner/admin(/security_manager) | Connexion Linear `{ apiKey, teamId }` (clé chiffrée, jamais renvoyée) |
| GET/POST/DELETE | `/api/v1/integrations/slack` | idem | Connexion Slack `{ webhookUrl }` (URL chiffrée) |
| POST | `/api/v1/integrations/slack/test` | tous | Envoie une alerte de test |
| GET/POST/DELETE | `/api/v1/integrations/gitlab` | POST/DELETE : owner/admin/security_manager | GitLab : POST (re)génère le token de webhook (renvoyé une fois) |
| GET/POST/DELETE | `/api/v1/integrations/jira` | idem | Connexion Jira `{ baseUrl, email, apiToken, projectKey }` (token chiffré) |
| GET/POST/DELETE | `/api/v1/integrations/scim` | owner/admin | SCIM : POST (re)génère le bearer token (renvoyé une fois) |
| GET/POST/DELETE | `/api/v1/integrations/saml` | owner/admin | SAML : config IdP `{ idpEntityId, idpSsoUrl, idpCert }` |

## SSO entreprise (§12.2 P3)

### SCIM 2.0 — `/scim/v2/*` (auth : bearer SCIM token)

| Méthode | Route | Description |
|---|---|---|
| POST | `/scim/v2/Users` | Provisionne un utilisateur (`userName`, `displayName`, `active`) |
| GET | `/scim/v2/Users` | Liste (filtre `userName eq "x"`) |
| GET | `/scim/v2/Users/:id` | Détail |
| PATCH | `/scim/v2/Users/:id` | Met à jour `active` (dé/réactivation) |
| DELETE | `/scim/v2/Users/:id` | Désactivation douce (204) |

Un compte désactivé ne peut plus se connecter (`login` → 403 `account_disabled`).

### SAML — `/saml/:orgId/*` (public)

| Méthode | Route | Description |
|---|---|---|
| GET | `/saml/:orgId/metadata` | Métadonnées SP (XML) à fournir à l'IdP |
| GET | `/saml/:orgId/login` | SSO SP-initié → redirection vers l'IdP |
| POST | `/saml/:orgId/acs` | Consomme l'assertion signée → provisioning JIT → JWT CodeGate |

## Audit & conformité (§5.8)

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/audit-events` | tous | Journal filtrable `{ from?, to?, action?, limit? }` |
| POST | `/api/v1/audit/export` | tous | Dossier de preuves `{ format: json\|csv\|pdf, repositoryId?, from?, to?, severityThreshold? }` (fichier téléchargeable) |

## Plateforme — App GitHub en un clic

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/platform/github-app` | tous | `{ configured, source: env\|database, slug, canConfigure }` |
| POST | `/api/v1/platform/github-app/manifest` | opérateur (owner, MFA) | `{ name, githubOrganization? }` → formulaire *App manifest* à poster vers GitHub (permissions : contents/metadata lecture, pull_requests/checks écriture ; webhook `/webhooks/github`) |
| POST | `/api/v1/platform/github-app/complete` | opérateur | `{ code, state }` (retour de GitHub) → échange le code contre les identifiants de l'App, stockés chiffrés (`platform_settings`) |

L'opérateur est l'owner de `PLATFORM_ORG_ID`, ou à défaut de la première organisation créée. Les variables `GITHUB_APP_*` restent prioritaires si elles sont définies.

## Findings & GitHub (US01, US02)

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/findings` | tous | `?repositoryId&status&severity&limit` — problèmes de code de l'organisation |
| PATCH | `/api/v1/findings/:id` | dev+ (faux positif : owner/admin/security_manager) | `{ status: open\|acknowledged\|resolved\|false_positive, reason? }` — un faux positif est mémorisé (règle + fichier) pour les analyses suivantes et sort du score ; la PR est re-notée |
| GET | `/api/v1/github/install-url` | gestion | Lien d'installation de la GitHub App avec un `state` signé (15 min) |
| POST | `/api/v1/github/link` | gestion | `{ installationId, state, code? }` (retour de GitHub) → lie l'installation à l'organisation et importe les dépôts choisis. Si l'App a ses identifiants OAuth, `code` est exigé et GitHub doit confirmer que **ce compte GitHub a accès à l'installation** (sinon 403 `installation_not_authorized`, journalisé) ; une installation déjà liée ailleurs est refusée (409). |
| GET | `/api/v1/github/installations` | tous | Installations liées et nombre de dépôts |
| DELETE | `/api/v1/github/installations/:id` | gestion | Révoque : désinstalle l'App côté GitHub et délie |

**Sessions et MFA (§10.2)** : les jetons expirent après 12 h. Les rôles owner/admin doivent avoir activé la MFA pour toute action d'administration (`403 mfa_enrollment_required` sinon) ; `POST /api/v1/auth/mfa/verify` renvoie une nouvelle session qui porte la MFA. Désactivable par `MFA_REQUIRED_FOR_ADMINS=false` (tests).

**Analyse** : secrets et règles de code exécutés par le moteur Rust (WebAssembly, arbre syntaxique pour JS/TS — voir `services/scan-engine`), repli TypeScript automatique ; `GET /health` renvoie `scanEngine`. Dépendances enrichies en ligne (OSV : vulnérabilités connues ; registre npm : paquet inexistant/halluciné, âge, mainteneurs, licence, scripts d'installation, popularité) et détection de prompt injection (détournement d'instructions, ordres adressés à un agent, faux messages système, exfiltration de secrets, caractères invisibles / Trojan Source, fichiers de consignes d'agents) — chaque détection est journalisée (`security.prompt_injection_detected`).

## Approbations, membres, secrets, GitLab

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/approvals` | tous | `?status=pending\|approved\|denied\|expired` — demandes d'approbation humaine |
| POST | `/api/v1/approvals/:id/decision` | owner/admin/security_manager | `{ decision: approve\|deny, reason? }` ; un déploiement approuvé passe `authorized`, refusé `blocked` |
| GET | `/api/v1/agent/approvals/:id` | tous | Statut d'une demande, interrogé par l'agent |
| PATCH | `/api/v1/organization/members/:id` | owner/admin | `{ role?, active? }` — jamais sans owner actif, pas sur soi-même, l'admin ne touche pas aux owners |
| GET | `/api/v1/secrets/:id/revocation` | tous | Procédure de révocation guidée par fournisseur (AWS, Stripe, OpenAI, Anthropic, GitHub, Google, Slack, clé privée, base de données) |
| POST | `/api/v1/secrets/:id/revoked` | dev+ | Preuve de remédiation : secret marqué révoqué, PR re-notée |
| PUT | `/api/v1/integrations/gitlab/api` | gestion | `{ baseUrl (https), accessToken }` — jeton vérifié puis chiffré ; les MR sont alors analysées sur leur vrai diff et reçoivent un statut « CodeGate » + une note |

`POST /api/v1/agent/guard` : quand la politique exige une approbation, la réponse contient `approvalId` ; une même action redemandée réutilise la même demande, et une approbation reste valable 24 h. Le Deploy Gate crée aussi une demande quand il renvoie `requires_approval` (notification Slack). Les dépendances sont analysées pour npm, PyPI (`requirements*.txt`, `pyproject.toml`) et Go (`go.mod`).

## Infra Shield — serveurs (extension §3)

Un agent **en lecture seule** (`/agent/codegate-agent.py`, Python 3 sans dépendance) tourne sur le serveur et envoie ses constats. CodeGate ne scanne jamais un hôte depuis l'extérieur : détenir le token d'agent sur la machine vaut preuve de propriété.

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| POST | `/api/v1/servers/connect` | owner/admin/security_manager | `{ name, environment?, provider? }` → serveur + **token d'agent affiché une seule fois** (`cg_srv_…`, stocké haché) |
| GET | `/api/v1/servers` | tous | Liste avec score et compteurs (critique / élevé / total) |
| GET | `/api/v1/servers/:id` | tous | Détail : constats triés par gravité + derniers faits remontés |
| GET | `/api/v1/servers/:id/security-score` | tous | `{ securityScore, lastReportAt }` |
| POST | `/api/v1/servers/:id/rotate-token` | owner/admin/security_manager | Révoque l'ancien token, en émet un nouveau |
| DELETE | `/api/v1/servers/:id` | owner/admin/security_manager | Retire le serveur et ses constats |
| GET | `/api/v1/reports/infrastructure` | tous | Rapport d'organisation (score moyen, constats par serveur) |
| POST | `/api/v1/agent/report` | bearer `cg_srv_…` | Ingestion du rapport d'agent → règles → constats + score 0–100 ; alerte Slack si critique |

Contrôles : ports dangereux publics (Docker API, bases, Redis, Elasticsearch, Memcached, 8080 — y compris ports publiés par Docker), SSH (root, mot de passe, MaxAuthTries), firewall (UFW / nftables / iptables), Fail2ban / CrowdSec si SSH est exposé, conteneurs (socket Docker, privileged, capacités, root, limite mémoire), mises à jour de sécurité en attente et automatiques. Une valeur non vérifiable (agent non root) est signalée comme telle, jamais considérée comme sûre.

## BruteForce Shield (extension §4)

**Protection de CodeGate lui-même** (`/api/v1/auth/*`) : compteurs en base, par compte **et** par IP.

| Point d'entrée | Seuil | Blocage |
|---|---|---|
| Login, par compte | 5 échecs / 10 min | 5 min, doublé à chaque récidive (max 1 h) |
| Login, par IP | 20 échecs / 10 min | idem |
| Code MFA (TOTP), par compte | 3 échecs / 5 min | idem |
| Inscription, par IP | 5 demandes / heure | 1 h |

Réponse en cas de blocage : `429 { error: "too_many_attempts", message, retry_after }` + en-tête `Retry-After`. Un email inconnu coûte le même temps de hachage qu'un mauvais mot de passe (pas d'énumération par le temps). Verrouillage d'un compte → audit `auth.lockout` + alerte Slack.

**Tests autorisés des applications du client** — uniquement sur une origine HTTPS vérifiée (DNS TXT `_codegate-verification.<hôte>` = `codegate-verification=<token>`, ou fichier `/.well-known/codegate-verification.txt`), adresses publiques uniquement, pas de redirection suivie, 20 requêtes max, espacées, 10 tests / heure / organisation, confirmation explicite pour la production.

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/bruteforce/policies` | tous | Politiques attendues |
| POST | `/api/v1/bruteforce/policies` | owner/admin/security_manager | Upsert par endpoint `{ endpoint, maxAttempts, windowSeconds, lockoutSeconds, strategy?, applyTo?, captchaAfter?, alertAfter? }` |
| DELETE | `/api/v1/bruteforce/policies/:id` | owner/admin/security_manager | Supprimer |
| GET / POST | `/api/v1/bruteforce/targets` | tous / gestion | Cibles `{ name, origin (https), environment }` → token de vérification |
| POST | `/api/v1/bruteforce/targets/:id/verify` | gestion | Vérifie la preuve DNS ou fichier |
| DELETE | `/api/v1/bruteforce/targets/:id` | gestion | Retirer la cible et ses résultats |
| POST | `/api/v1/bruteforce/tests` | gestion | `{ targetId, testType: login_lockout\|account_enumeration, endpoint, testAccount, emailField?, passwordField?, maxAttempts? (≤20), confirmProduction? }` → résultat `pass/warn/fail`, seuil mesuré, portée (compte / IP), preuves |
| GET | `/api/v1/bruteforce/tests[/:id]` | tous | Historique et détail |

## Backup Shield — sauvegardes (extension §5)

CodeGate ne reçoit **jamais** les données : l'outil `codegate-backup` (`/agent/codegate-backup.py`, Python 3 sans dépendance) déclare des métadonnées avec un token par job (`cg_bkp_…`, stocké haché).

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/backups` | tous | Jobs avec statut (`healthy`/`attention`/`critical`), score de récupération, prêt-ransomware |
| POST | `/api/v1/backups` | gestion | `{ name, type: postgres\|mysql\|mongodb\|files\|other, frequencyHours?, serverId? }` → token affiché une fois |
| GET | `/api/v1/backups/:id` | tous | Job, 30 dernières exécutions, 10 derniers tests de restauration, contrôles §5.4 |
| POST | `/api/v1/backups/:id/verify` | tous | Réévalue maintenant (chiffrement, intégrité, fraîcheur…) |
| POST | `/api/v1/backups/:id/restore-test` | gestion | Renvoie la commande de restauration isolée à lancer côté client (PostgreSQL) |
| POST | `/api/v1/backups/:id/rotate-token` | gestion | Nouveau token, l'ancien est révoqué |
| DELETE | `/api/v1/backups/:id` | gestion | Retire le suivi (les sauvegardes ne sont pas touchées) |
| GET | `/api/v1/reports/backup` | tous | Score de récupération, part chiffrée, part testée par restauration |
| POST | `/api/v1/backups/agent/run` | bearer `cg_bkp_` | Exécution : sha256, taille, chiffrement détecté, transit, emplacement de clé, stockage, immutabilité, rétention |
| POST | `/api/v1/backups/agent/verify` | bearer `cg_bkp_` | `{ sha256 }` d'une copie re-téléchargée → intègre ou altérée (alerte) |
| POST | `/api/v1/backups/agent/restore-test` | bearer `cg_bkp_` | Résultat d'une restauration dans un conteneur jetable `--network none` |

Contrôles : exécution reçue, fraîcheur (> 1,5 × fréquence ⇒ sauvegarde manquante, détectée à la lecture), succès, chiffrement au repos (algorithme détecté depuis l'en-tête : age, OpenPGP, openssl…), en transit, clé hors serveur, SHA-256, intégrité revérifiée, copie hors site, compte séparé, rétention ≥ 30 j, immutabilité, restauration testée < 30 j. L'agent Infra (v1.1) signale aussi une base de données sans aucun job de sauvegarde (noms d'outils uniquement, jamais les lignes de commande).

## RGPD, maintenance et Linear

| Méthode | Route | Rôle | Description |
|---|---|---|---|
| GET | `/api/v1/organization/export` | owner/admin | Export JSON complet (portabilité) — sans hachés de mot de passe, secrets MFA, jetons ni identifiants d'intégration |
| DELETE | `/api/v1/organization` | owner | `{ confirmName }` (nom exact) → effacement définitif de l'organisation et de toutes ses données (cascade) |
| DELETE | `/api/v1/account` | tous | Le membre efface son compte (refusé pour le dernier owner) |
| GET/POST | `/api/v1/cron/maintenance` | `Authorization: Bearer <CRON_SECRET>` | Quotidien (Vercel Cron) : purge de rétention (PR > `RETENTION_DAYS`, audit > `AUDIT_RETENTION_DAYS`), alerte « sauvegarde manquante » et « agent serveur silencieux » (une fois, réarmée au rapport suivant) |
| POST | `/api/v1/integrations/linear/webhook` | gestion | Génère l'URL et le secret du webhook Linear |
| POST | `/webhooks/linear/:orgId` | `linear-signature` (HMAC-SHA256) | Issue terminée/annulée → statut de remédiation synchronisé ; terminée ⇒ problèmes de la PR résolus. Anti-rejeu 5 min |

Le dossier de preuves (`/api/v1/audit/export`) inclut désormais l'infrastructure (scores et points ouverts par serveur), les politiques et tests anti brute force, et l'état des sauvegardes (score de récupération, contrôles en échec). L'agent Infra v1.2 audite aussi le TLS des écoutes locales (443/8443/9443) : protocole, TLS 1.0/1.1 acceptés, expiration et auto-signature du certificat.

## Webhooks

| Méthode | Route | Signature | Description |
|---|---|---|---|
| POST | `/webhooks/github` | `x-hub-signature-256` (HMAC-SHA256) | `pull_request` (opened/synchronize/reopened) → upsert + analyse (file Redis, ou inline si `ANALYSIS_MODE=inline`) ; `installation*` |
| POST | `/webhooks/gitlab` | `x-gitlab-token` (secret partagé, haché) | `Merge Request Hook` (open/reopen/update) → upsert + enqueue analyse |
| POST | `/webhooks/vercel` | `x-vercel-signature` (HMAC-SHA1) | `deployment.created` → Deploy Gate → décision persistée |

Les deux webhooks vérifient la signature, sont **idempotents** (le verrou de livraison est libéré en cas d'échec pour permettre les retries), et renvoient `503` si l'intégration n'est pas configurée.

## Événements d'audit (actions)

`org.created`, `auth.login`, `auth.saml_login`, `auth.mfa_enabled`, `auth.password_changed`, `member.invited`, `member.password_reset`, `policy.created`, `pr.opened`, `pr.analyzed` (métadonnées `engines`), `pr.analysis_unavailable`, `pr.analysis_failed`, `pr.feedback_posted`/`_failed`, `pr.rescan_requested`, `remediation.created`/`_failed`, `agent_policy.updated`, `agent.action_allow`/`_deny`/`_require_approval`, `deploy.authorized`/`warning`/`blocked`/`requires_approval`, `scim.user_provisioned`/`_deactivated`/`_reactivated`, `integration.{github,linear,slack,gitlab,jira,scim,saml}_connected`/`_disconnected`, `integration.github_link_refused`, `settings.analysis_updated`, `repository.settings_updated`, `audit.exported`.
