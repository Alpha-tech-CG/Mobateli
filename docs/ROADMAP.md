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

## Reste à faire (P3 / post-MVP)
- [ ] GitLab (2e fournisseur SCM)
- [ ] Jira (intégration entreprise)
- [ ] SAML / SCIM (SSO entreprise)
- [ ] Moteur de scan Rust avancé (`services/scan-engine`)
- [ ] Observabilité (OpenTelemetry), CI/CD, déploiement UE
- [ ] Enrichissement IA (triage via Claude), détection de prompt injection

---

**Principe directeur :** Claude Code écrit, mais CodeGate vérifie. Revue humaine, tests, scan de deps et de secrets sur chaque PR — y compris pour le dev de CodeGate lui-même.
