# CodeGate

> **Aucun code généré par IA n'atteint la production sans analyse de sécurité, validation des dépendances, contrôle des permissions de l'agent et traçabilité complète.**

CodeGate est une plateforme SaaS B2B qui sécurise le code généré par IA (Cursor, Claude Code, Copilot, Codex…) avant qu'il n'atteigne la production. Il s'installe comme une couche de contrôle entre les outils de dev assisté par IA et les plateformes de livraison (GitHub, GitLab, Vercel, Linear).

CodeGate ne remplace pas GitHub, Vercel ou Linear — **il les sécurise.** Chaque pull request générée par IA devient une décision de sécurité claire : **autoriser, corriger, bloquer ou escalader vers un humain.**

📖 Spécification complète : [`docs/cahier-des-charges.md`](docs/cahier-des-charges.md) · Guide dev : [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) · API : [`docs/API.md`](docs/API.md)

---

## Architecture (monorepo polyglotte)

| Couche | Techno | Dossier | État |
|---|---|---|---|
| Interface web / dashboard | Next.js 15 + TypeScript + Tailwind v4 | `apps/web` | ✅ |
| API produit & intégrations | Node.js + TypeScript (Fastify 5) | `apps/api` | ✅ |
| Workers async (analyse PR, feedback) | BullMQ | `apps/api` (`src/worker.ts`) | ✅ |
| Moteurs d'analyse (secrets, deps, SAST, décision) | TypeScript déterministe | `apps/api/src/analysis` | ✅ |
| Schéma & accès données | Prisma + PostgreSQL | `packages/db` | ✅ |
| Types & schémas Zod partagés | TypeScript | `packages/shared` | ✅ |
| Moteur IA (explication, triage) | Python + FastAPI | `services/ai-engine` | 🧪 scaffold |
| Moteur de scan avancé | Rust | `services/scan-engine` | ⬜ prévu |
| Infra locale | Docker Compose (Postgres, Redis) | `infra/docker` | ✅ |

```
[Cursor / Claude Code / Copilot]
          │  ouvre une PR
          ▼
   [GitHub Pull Request] ──webhook──▶ [CodeGate API]
                                          │ enqueue (BullMQ)
                                          ▼
                                   [PR Analysis Worker]
                     ┌────────────────────┼────────────────────┐
                     ▼                     ▼                    ▼
              [Secret Shield]     [Dependency Trust]     [SAST rules]
                     └────────────────────┼────────────────────┘
                                          ▼
                              [Risk Decision Engine]
             ┌──────────────┬─────────────┼───────────────┬──────────────┐
             ▼              ▼             ▼               ▼              ▼
     [GitHub Check +   [Policy      [Linear issue]  [Slack alerte]  [Audit log]
      commentaire]      Engine]
                                          │
                        [Vercel deploy] ──webhook──▶ [Deploy Gate] ──▶ décision
```

## Fonctionnalités (cahier §12.2)

**P0** ✅ Authentification + organisations (MFA TOTP) · GitHub App + webhooks · PR Analyzer (diff → score) · Secret Scanner · Dependency Trust Score · GitHub Check + commentaire structuré

**P1** ✅ Policy Engine (observe/warn/block + seuils) · Dashboard web · Linear (issues de remédiation) · Vercel Deploy Gate

**P2** ✅ Agent Guard (permissions des agents IA) · Compliance Evidence Pack (export JSON/CSV/PDF) · Slack Alerts

**P3** ✅ GitLab (2ᵉ SCM) · Jira (remédiation entreprise) · SCIM 2.0 (provisioning) · SAML SSO

**Post-MVP** ⬜ Moteur de scan Rust · détection de prompt injection · OpenTelemetry · CI/CD + déploiement UE

## Démarrage rapide

```bash
pnpm install
docker compose -f infra/docker/docker-compose.yml up -d    # Postgres :5434, Redis :6380
cp .env.example .env                                        # puis renseigner JWT_SECRET + ENCRYPTION_KEY
pnpm --filter @codegate/db exec prisma migrate dev          # crée les tables
```

Générer les secrets locaux :

```bash
node -e "console.log('ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(48).toString('base64url'))"
```

Lancer (3 terminaux) :

```bash
pnpm --filter @codegate/api dev        # API  → http://localhost:4000
pnpm --filter @codegate/api worker     # worker d'analyse
pnpm --filter @codegate/web dev        # dashboard → http://localhost:3000
```

Détails, variables d'environnement, intégrations (GitHub App, Linear, Vercel, Slack) et dépannage : [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

## Tests

**110 tests** : 76 unitaires (moteurs, policy, agent guard, builders Linear/Jira/Slack…) + 18 d'intégration bout en bout (parcours HTTP réels via `app.inject`) + 16 pour le moteur Rust (`cargo test` dans `services/scan-engine`).

```bash
pnpm --filter @codegate/api test                 # tests unitaires
pnpm --filter @codegate/api test:db:setup        # (re)crée la base codegate_test
pnpm --filter @codegate/api test:integration     # tests d'intégration bout en bout
```

## Prérequis

- Node.js ≥ 22 · pnpm ≥ 11 · Docker · (Python ≥ 3.12 pour le moteur IA optionnel)

## Sécurité

CodeGate est un produit de sécurité : il doit être plus sûr que les applications qu'il protège. Principes appliqués — moindre privilège, **aucun secret en clair** (AES-256-GCM au repos), mots de passe **argon2id**, **MFA TOTP**, validation stricte des entrées (Zod), signatures de webhooks vérifiées, en-têtes de sécurité (helmet), rate limiting, journal d'audit immuable, et l'invariant non dérogeable « un agent IA ne modifie jamais les secrets ». Voir `docs/cahier-des-charges.md` §10.

## Licence

Propriétaire — © Zlat OBAMBI.
