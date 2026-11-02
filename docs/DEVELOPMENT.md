# Guide de développement — CodeGate

## 1. Prérequis

| Outil | Version | Rôle |
|---|---|---|
| Node.js | ≥ 22 | API, web, workers |
| pnpm | ≥ 11 | gestionnaire de paquets (monorepo) |
| Docker | récent | Postgres + Redis en local |
| Python | ≥ 3.12 | moteur IA (optionnel) |

## 2. Installation

```bash
pnpm install
```

Les scripts de build natifs sont bloqués par défaut (durcissement supply-chain). Seuls `@prisma/client`, `@prisma/engines`, `argon2`, `esbuild`, `prisma` et `sharp` sont autorisés (voir `pnpm-workspace.yaml` → `onlyBuiltDependencies`).

## 3. Infrastructure locale

```bash
docker compose -f infra/docker/docker-compose.yml up -d
```

- **Postgres** sur l'hôte `localhost:5434` (conteneur `codegate-postgres`)
- **Redis** sur l'hôte `localhost:6380` (conteneur `codegate-redis`)

Les ports sont décalés (5434/6380 au lieu de 5432/6379) pour ne pas entrer en conflit avec d'autres stacks locales.

## 4. Variables d'environnement

Copier `.env.example` → `.env` et renseigner au minimum `DATABASE_URL`, `JWT_SECRET`, `ENCRYPTION_KEY`.

| Variable | Requis | Description |
|---|---|---|
| `NODE_ENV` | — | `development` (défaut), `test`, `production` |
| `API_PORT` | — | port de l'API (défaut 4000) |
| `DATABASE_URL` | ✅ | `postgresql://codegate:codegate@127.0.0.1:5434/codegate` |
| `REDIS_URL` | — | défaut `redis://127.0.0.1:6380` |
| `JWT_SECRET` | ✅ | ≥ 32 caractères |
| `ENCRYPTION_KEY` | ✅ | 32 octets encodés en base64 (AES-256-GCM) |
| `WEB_ORIGIN` | — | origine CORS en production (défaut `http://localhost:3000`) |
| `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY` / `GITHUB_WEBHOOK_SECRET` | — | GitHub App (sinon les routes GitHub renvoient 503) |
| `VERCEL_WEBHOOK_SECRET` | — | vérification du webhook Vercel |
| `NEXT_PUBLIC_API_URL` | — | (web) URL de l'API, défaut `http://127.0.0.1:4000` |

> `127.0.0.1` est préféré à `localhost` dans `DATABASE_URL` (évite une résolution IPv6 capricieuse sous Windows).

Générer les secrets :

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))" # JWT_SECRET
```

En production, CORS est verrouillé sur `WEB_ORIGIN` ; en développement, toute origine `localhost`/`127.0.0.1` est acceptée.

## 5. Base de données

```bash
pnpm --filter @codegate/db exec prisma migrate dev     # applique les migrations
pnpm --filter @codegate/db exec prisma studio          # explorateur de données
```

Modèle de données : voir `packages/db/prisma/schema.prisma`. En-têtes des tables — `organizations`, `users`, `repositories`, `pull_requests`, `findings`, `dependencies`, `secret_findings`, `policies`, `audit_events`, `github_installations`, `linear_connections`, `slack_connections`, `remediation_issues`, `agent_policies`, `deploy_checks`.

## 6. Lancer les services

```bash
pnpm --filter @codegate/api dev        # API Fastify (watch)  → :4000
pnpm --filter @codegate/api worker     # worker BullMQ d'analyse de PR
pnpm --filter @codegate/web dev        # dashboard Next.js     → :3000
```

Le worker et l'API démarrent un **keep-alive** de la connexion Postgres (ping toutes les 30 s) ; voir la note Docker ci-dessous.

## 7. Tests

```bash
pnpm --filter @codegate/api test                 # unitaires (node:test via tsx)
pnpm --filter @codegate/api test:db:setup        # (re)crée codegate_test + migrations (psql)
pnpm --filter @codegate/api test:integration     # intégration bout en bout (app.inject)
```

- **Unitaires** (`src/**/*.test.ts`) : parseur de diff, Secret Scanner, Dependency Trust, SAST, moteur de décision, Policy Engine, Agent Guard, builders Linear/Slack/deploy-gate.
- **Intégration** (`src/**/*.itest.ts`) : montent la vraie app contre `codegate_test` et couvrent les parcours HTTP réels. Nécessitent Postgres + Redis up et `test:db:setup` lancé au moins une fois.

## 8. Moteur IA (optionnel)

```bash
cd services/ai-engine
python -m venv .venv && . .venv/Scripts/activate   # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

`POST /explain` renvoie une explication en langage clair ; sans `ANTHROPIC_API_KEY`, l'explication est déterministe (templates).

## 9. Intégrations

- **GitHub App** : renseigner `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY` / `GITHUB_WEBHOOK_SECRET`, pointer le webhook sur `POST /webhooks/github`. Permissions minimales (PR, checks, commentaires).
- **Linear** : dashboard → Intégrations → coller la clé API + Team ID. Déclenche la création d'issues de remédiation sur risque bloquant.
- **Vercel** : webhook sur `POST /webhooks/vercel` (signature HMAC-SHA1) ; le déploiement est évalué avant mise en production.
- **Slack** : dashboard → Intégrations → URL de webhook entrant ; alertes sur PR bloquée, secret, déploiement bloqué.

Les secrets d'intégration (clé Linear, URL Slack, secret TOTP) sont **chiffrés au repos** (AES-256-GCM) et ne sont jamais renvoyés par l'API.

## 10. Note Docker Desktop (Windows)

Sur Docker Desktop (Windows), une connexion Postgres **inactive** est coupée par le NAT ; Prisma peut alors servir une connexion morte et le premier appel échoue en `P1001`/`P1017`. Mitigations en place :

- **keep-alive** : `startDbKeepAlive()` (API + worker) ping `SELECT 1` toutes les 30 s ;
- **retry** : le client Prisma (`packages/db`) réessaie automatiquement les erreurs de connexion transitoires (extension + `withDbRetry()` pour les transactions).

Le **schema-engine** de Prisma (migrations) reste capricieux dans cet environnement : si `prisma migrate dev` expire, réessayer, ou appliquer le SQL via le conteneur (`scripts/setup-test-db.mjs` montre le procédé). Le runtime, lui, est fiable.

## 11. Qualité

- TypeScript strict partout (`tsconfig.base.json`, `exactOptionalPropertyTypes`).
- `pnpm -r typecheck` vérifie tous les paquets.
- Fins de ligne normalisées en LF (`.gitattributes`).
