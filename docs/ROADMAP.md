# Roadmap de développement — CodeGate

Ordre de construction proposé, aligné sur le plan Phase 1 (MVP, 6 semaines) du cahier des charges §14.2.

## Étape 0 — Fondations (ce dossier) ✅
- [x] Structure monorepo (pnpm workspaces)
- [x] Config racine, `.gitignore`, `.env.example`, tsconfig base
- [x] Docker Compose : Postgres + Redis
- [x] Cahier des charges archivé dans `docs/`

## Étape 1 — Socle données & API
- [ ] `packages/db` : schéma Prisma (Organization, User, Repository, PullRequest, Finding, Dependency, SecretFinding, Policy, AuditEvent) — §13.2
- [ ] `packages/shared` : types partagés + schémas Zod
- [ ] `apps/api` : serveur Fastify, santé, config, validation Zod, logs Pino
- [ ] Authentification + organisations (MFA) — P0

## Étape 2 — Intégration GitHub
- [ ] GitHub App : installation, permissions minimales, webhooks
- [ ] Réception des événements PR (ouverture / mise à jour)
- [ ] Vérification de signature + idempotence des webhooks
- [ ] File BullMQ : enqueue d'une analyse à chaque PR

## Étape 3 — Moteurs d'analyse (P0)
- [ ] Secret Scanner (détection patterns + entropie)
- [ ] Dependency Scanner (paquets ajoutés, typosquatting, OSV)
- [ ] PR Analyzer : parse du diff, règles de base, score de risque
- [ ] `services/ai-engine` (Python/FastAPI) : explication en langage clair

## Étape 4 — Boucle de décision & feedback GitHub
- [ ] Risk Decision Engine : autoriser / avertir / bloquer / escalader
- [ ] GitHub Check + commentaire structuré sur la PR
- [ ] Policy Engine (seuils par sévérité)

## Étape 5 — Connecteurs (P1)
- [ ] Linear : création d'issue de remédiation
- [ ] Vercel Deploy Gate : contrôle avant déploiement
- [ ] Dashboard (apps/web)

## Étape 6 — Durcissement
- [ ] Audit Store immuable
- [ ] Chiffrement des secrets (AES-256-GCM via KMS)
- [ ] Tests, observabilité (OpenTelemetry), bêta privée

---

**Principe directeur :** Claude Code écrit, mais CodeGate vérifie. Revue humaine, tests, scan de deps et de secrets sur chaque PR — y compris pour le dev de CodeGate lui-même.
