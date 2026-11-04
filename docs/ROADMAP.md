# Roadmap de développement — CodeGate

Avancement par rapport au plan Phase 1 du cahier des charges §14.

## Étape 0 — Fondations ✅
- [x] Structure monorepo (pnpm workspaces)
- [x] Config racine, `.gitignore`, `.gitattributes`, `.env.example`, tsconfig base
- [x] Docker Compose : Postgres + Redis
- [x] Cahier des charges + docs (`README`, `DEVELOPMENT`, `API`)

## Étape 1 — Socle données & API ✅
- [x] `packages/db` : schéma Prisma (15 tables) + client résilient (retry + keep-alive)
- [x] `packages/shared` : enums + schémas Zod
- [x] `apps/api` : Fastify, config validée, logs Pino masqués, helmet/cors/rate-limit
- [x] Authentification + organisations + MFA TOTP (argon2id, JWT, AES-256-GCM)

## Étape 2 — Intégration GitHub ✅
- [x] GitHub App : webhooks signés (HMAC-SHA256), idempotence
- [x] Événements PR → upsert repo + PR, mapping installation→organisation
- [x] File BullMQ + worker d'analyse autonome

## Étape 3 — Moteurs d'analyse ✅
- [x] Secret Scanner (patterns + entropie)
- [x] Dependency Trust Score (typosquatting + heuristiques)
- [x] PR Analyzer (parse diff + règles SAST + score)
- [x] Risk Decision Engine + Risk Explainer
- [x] `services/ai-engine` (FastAPI `/explain`) — scaffold

## Étape 4 — Décision & feedback GitHub ✅
- [x] Check Run + commentaire structuré (upsert)
- [x] Policy Engine (observe/warn/block + seuils)

## Étape 5 — Connecteurs & dashboard ✅
- [x] Linear : issues de remédiation (idempotent)
- [x] Vercel Deploy Gate (webhook signé HMAC-SHA1)
- [x] Dashboard web complet (overview, PR, détail PR, policies, agent guard, déploiements, intégrations, audit)

## Étape 6 — P2 & durcissement ✅
- [x] Agent Guard (permissions des agents IA + enforcement)
- [x] Compliance Evidence Pack (export JSON/CSV/PDF)
- [x] Slack Alerts
- [x] Journal d'audit immuable
- [x] Chiffrement des secrets (AES-256-GCM)
- [x] Tests unitaires (34) + tests d'intégration bout en bout (10)
- [x] Résilience de connexion DB

## Étape 7 — P3 entreprise ✅
- [x] GitLab (2e fournisseur SCM) — webhook Merge Request → même pipeline
- [x] Jira (issues de remédiation entreprise, REST v3 + ADF)
- [x] SCIM 2.0 (provisioning d'utilisateurs, `User.active`)
- [x] SAML SSO (SP par org : métadonnées, login, ACS)

## Fait depuis (audit de novembre 2026)
- [x] Moteur Rust (taint) et Semgrep branchés dans le pipeline, image Docker du worker qui les embarque
- [x] Architecture d'analyse extensible : moteurs enregistrés + paramètres typés par organisation et par dépôt (voir [ARCHITECTURE-ANALYSE.md](ARCHITECTURE-ANALYSE.md))
- [x] Niveau de protection par dépôt (observe / warn / block) modifiable dans le dashboard
- [x] Liaison GitHub sécurisée (state signé + vérification OAuth de l'accès à l'installation)
- [x] Couverture d'analyse visible (« Analyse partielle » si un moteur n'a pas tourné)
- [x] Mots de passe : changement, réinitialisation par un admin, outil serveur
- [x] Premier test réel de bout en bout sur GitHub (PR → analyse → check + commentaire)

## Avant les premiers utilisateurs (pilote fermé)

### Bloquant
- [ ] **Déployer cette version** : fusionner la PR, migrations en production, worker dans l'image Docker sur un hébergeur à processus long (Railway, Fly.io, Render…), Redis managé. Vercel ne peut pas héberger le worker.
- [ ] **Deux GitHub Apps** (prod / dev) avec les **permissions minimales** (Checks R/W, Pull requests R/W, Contents R, Metadata R), et rotation de la clé privée exposée pendant le test.
- [ ] **Guide d'installation client** : installer l'App, choisir les dépôts, régler le niveau de protection, et **exiger le check « CodeGate » dans la protection de branche GitHub** (sans ça, même « block » n'empêche pas la fusion).
- [ ] **Emails transactionnels** (invitation, mot de passe oublié, alertes) : aucun fournisseur d'email n'est branché aujourd'hui.
- [ ] **Juridique** : CGU, politique de confidentialité, DPA (RGPD, hébergement UE, code client traité sans être conservé).
- [ ] **Exploitation** : suivi des erreurs (Sentry ou équivalent), alerte si le worker s'arrête, sauvegardes Postgres testées.
- [ ] **CI** sur ce dépôt (typecheck, tests, build, scan Trivy) : aucun workflow GitHub Actions n'existe.

### Important (valeur produit)
- [ ] **Deploy Gate Vercel qui bloque vraiment** (API Deployment Checks de Vercel) : aujourd'hui la décision est seulement enregistrée.
- [ ] **Commentaire expliqué par l'IA** (P0 du cahier) : brancher `services/ai-engine` / Claude pour l'explication et le triage ; les explications sont aujourd'hui des modèles fixes.
- [ ] **Détection d'injection de prompt** (moteur prévu, type `prompt_injection` déjà défini).
- [ ] **GitLab** : analyse réelle (token d'API, diff, retour sur la MR) ; marqué bêta d'ici là.
- [ ] **SCA dans le worker** (clone léger du dépôt) et OSV sur les versions résolues du lockfile plutôt que sur le bas d'une plage.
- [ ] **Politiques par type de problème** (secret, dépendance, code) : aujourd'hui un seuil de sévérité global.
- [ ] Doublon `eval` entre le moteur Rust (CWE-94) et Semgrep (CWE-95).
- [ ] **Facturation** (Stripe) et quotas par plan.
- [ ] **Onboarding guidé** dans le dashboard (installation → dépôts → protection).
- [ ] **RGPD** : export et suppression du compte et des données d'une organisation.

---

**Principe directeur :** Claude Code écrit, mais CodeGate vérifie. Revue humaine, tests, scan de deps et de secrets sur chaque PR — y compris pour le dev de CodeGate lui-même.
