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
| GET | `/api/v1/integrations/github` | tous | `{ configured, installations[] }` |
| POST | `/api/v1/integrations/github/connect` | owner/admin | URL d'installation de la GitHub App, avec un `state` signé (15 min) |
| GET | `/api/v1/integrations/github/callback` | — (redirection GitHub) | Vérifie le `state` et, par OAuth, que le compte GitHub a accès à l'installation ; lie l'installation, importe les dépôts, redirige vers `/integrations?github=…` |
| DELETE | `/api/v1/integrations/github/:installationId` | owner/admin | Délie l'installation (les dépôts restent, sans analyse) |
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

## Webhooks

| Méthode | Route | Signature | Description |
|---|---|---|---|
| POST | `/webhooks/github` | `x-hub-signature-256` (HMAC-SHA256) | `pull_request` (opened/synchronize/reopened) → upsert + enqueue analyse ; `installation*` |
| POST | `/webhooks/gitlab` | `x-gitlab-token` (secret partagé, haché) | `Merge Request Hook` (open/reopen/update) → upsert + enqueue analyse |
| POST | `/webhooks/vercel` | `x-vercel-signature` (HMAC-SHA1) | `deployment.created` → Deploy Gate → décision persistée |

Les deux webhooks vérifient la signature, sont **idempotents** (le verrou de livraison est libéré en cas d'échec pour permettre les retries), et renvoient `503` si l'intégration n'est pas configurée.

## Événements d'audit (actions)

`org.created`, `auth.login`, `auth.saml_login`, `auth.mfa_enabled`, `auth.password_changed`, `member.invited`, `member.password_reset`, `policy.created`, `pr.opened`, `pr.analyzed` (métadonnées `engines`), `pr.analysis_unavailable`, `pr.analysis_failed`, `pr.feedback_posted`/`_failed`, `pr.rescan_requested`, `remediation.created`/`_failed`, `agent_policy.updated`, `agent.action_allow`/`_deny`/`_require_approval`, `deploy.authorized`/`warning`/`blocked`/`requires_approval`, `scim.user_provisioned`/`_deactivated`/`_reactivated`, `integration.{github,linear,slack,gitlab,jira,scim,saml}_connected`/`_disconnected`, `integration.github_link_refused`, `settings.analysis_updated`, `repository.settings_updated`, `audit.exported`.
