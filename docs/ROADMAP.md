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

## Étape 8 — Mise en ligne & extension infra 🚧
- [x] API serverless sur Vercel + Neon (migrations au build)
- [x] Analyse des PR sans Redis (`ANALYSIS_MODE=inline`, idempotence en base)
- [x] **Infra Shield** : agent VPS en lecture seule, règles ports/SSH/firewall/Docker/mises à jour, score, page Serveurs
- [x] **BruteForce Shield** : verrouillage progressif compte + IP sur l'auth CodeGate, politiques, cibles vérifiées, tests login / énumération
- [ ] BruteForce Shield (suite) : tests OTP et reset password, CAPTCHA après N échecs
- [x] **Backup Shield** : déclaration des exécutions, chiffrement / SHA-256 / rétention / immutabilité, revérification d'intégrité, restauration PostgreSQL isolée, score de récupération, découverte dans l'agent
- [ ] Backup Shield (suite) : restauration MySQL / MongoDB, alerte proactive « sauvegarde manquante » (cron), lecture directe des réglages S3 Object Lock
- [x] Écran « Connecter GitHub » (installation, choix des dépôts, révocation) — reste : créer l'App GitHub et renseigner ses clés en production
- [x] Faux positifs mémorisés (US02), vulnérabilités connues OSV + paquets inexistants (US04), prompt injection (§10.5)
- [x] Sessions de 12 h, MFA obligatoire pour owner/admin (§10.2), page Sécurité du compte

## Reste à faire (post-MVP)
- [ ] Moteur de scan Rust avancé (`services/scan-engine`)
- [ ] Observabilité (OpenTelemetry), CI/CD, déploiement UE
- [ ] Enrichissement IA (triage via Claude), détection de prompt injection
- [ ] SAML : poster dans le dépôt GitLab (statut/commentaire MR), feedback GitLab-like

---

**Principe directeur :** Claude Code écrit, mais CodeGate vérifie. Revue humaine, tests, scan de deps et de secrets sur chaque PR — y compris pour le dev de CodeGate lui-même.
