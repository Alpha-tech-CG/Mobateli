# CodeGate

> **Aucun code généré par IA n'atteint la production sans analyse de sécurité, validation des dépendances, contrôle des permissions de l'agent et traçabilité complète.**

CodeGate est une plateforme SaaS B2B qui sécurise le code généré par IA (Cursor, Claude Code, Copilot, Codex…) avant qu'il n'atteigne la production. Il se place comme une couche de contrôle entre les outils de dev assisté par IA et les plateformes de livraison (GitHub, GitLab, Vercel, Linear).

CodeGate ne remplace pas GitHub, Vercel ou Linear — **il les sécurise.**

Chaque pull request générée par IA devient une décision de sécurité claire : **autoriser, corriger, bloquer ou escalader vers un humain.**

---

## Architecture (polyglotte)

| Couche | Techno | Dossier |
|---|---|---|
| Interface web / dashboard | Next.js + TypeScript + Tailwind | `apps/web` |
| API produit & intégrations | Node.js + TypeScript (Fastify) | `apps/api` |
| Workers async (PR, scans, webhooks) | BullMQ (Node) | `apps/api` |
| Moteur d'analyse statique & scan | Rust | `services/scan-engine` |
| Moteur IA (explication, triage, scoring) | Python + FastAPI | `services/ai-engine` |
| Schéma & accès données | Prisma + PostgreSQL | `packages/db` |
| Types & logique partagés | TypeScript | `packages/shared` |
| Infra locale | Docker Compose (Postgres, Redis) | `infra/docker` |

```
[Cursor / Claude Code / Copilot]
          │
          ▼
   [GitHub Pull Request]
          │
          ▼
   [CodeGate Security Engine]
          │
   ┌──────┼──────┐
   ▼      ▼      ▼
[Secret][Dep.  ][Static +
 Scanner][Trust ] AI Review]
   └──────┼──────┘
          ▼
  [Risk Decision Engine]
   ┌──────┴──────┐
   ▼             ▼
[Linear Issue][Vercel Deploy Gate]
                 │
                 ▼
       [Audit & Compliance Store]
```

## Modules MVP (P0 → P1)

- **P0** Authentification + organisations (MFA)
- **P0** GitHub App — connexion dépôts, réception des PR
- **P0** PR Analyzer — analyse du diff, score de risque
- **P0** Secret Scanner — détection des secrets
- **P0** Dependency Scanner — analyse des dépendances ajoutées
- **P0** GitHub Check + commentaire IA structuré
- **P1** Linear Connector, Vercel Deploy Gate, Policy Engine, Dashboard

Voir [`docs/cahier-des-charges.md`](docs/cahier-des-charges.md) pour la spécification complète.

## Prérequis

- Node.js ≥ 22 (présent : 24)
- pnpm ≥ 11
- Docker (Postgres + Redis en local)
- Python ≥ 3.12 (moteur IA)
- Rust / Cargo (moteur de scan — à installer)

## Démarrage (à venir)

```bash
pnpm install
docker compose -f infra/docker/docker-compose.yml up -d   # Postgres + Redis
pnpm --filter @codegate/db migrate
pnpm dev
```

## Sécurité

CodeGate est un produit de sécurité : il doit être plus sûr que les applications qu'il protège. Principes non négociables — moindre privilège, aucun secret en clair, chiffrement au repos et en transit, hébergement UE, isolation des agents, journalisation complète. Voir `docs/cahier-des-charges.md` §10.

## Licence

Propriétaire — © Zlat OBAMBI.
