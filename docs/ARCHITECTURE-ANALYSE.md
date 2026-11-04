# Architecture de l'analyse

Comment CodeGate analyse une PR, et comment l'étendre (nouveau moteur, nouveau paramètre) sans toucher au cœur.

## Vue d'ensemble

```
webhook PR ─▶ file BullMQ ─▶ worker
                               │ 1. récupère le diff (GitHub App)
                               │ 2. paramètres effectifs = défauts ← organisation ← dépôt
                               ▼
                    runAnalysis(diff, { settings })          apps/api/src/analysis/engines/pipeline.ts
                               │
       ┌───────────────────────┼─────────────────────────────────────────┐
       │ chemins ignorés retirés du diff (settings.ignorePaths)          │
       │                                                                 │
       │ phase « core » (séquentielle, hors ligne, déterministe)         │
       │   secrets → dependencies → sast → sensitive_files               │
       │                                                                 │
       │ phase « intel » (concurrente, réseau / sous-processus,          │
       │ échoue sans bloquer)                                            │
       │   osv · sca · rust · semgrep                                    │
       │                                                                 │
       │ seuil de sévérité (settings.minSeverity) → décision (risk.ts)   │
       └───────────────────────┼─────────────────────────────────────────┘
                               ▼
         résultat + statut de CHAQUE moteur (ok / skipped / failed + raison)
                               │
          check GitHub · commentaire · journal d'audit · dashboard
```

Principe directeur : **un rapport ne doit jamais avoir l'air complet s'il ne l'est pas.** Chaque moteur, y compris un moteur désactivé ou en panne, renvoie un statut. Le commentaire de PR affiche « Analyse partielle » et le dashboard un encadré de couverture.

## Les briques

| Fichier | Rôle |
|---|---|
| `packages/shared/src/analysis-settings.ts` | **Source unique** des paramètres : schéma zod, valeurs par défaut, résolution `défauts ← org ← dépôt`, catalogue des moteurs (`ENGINE_IDS`, `ENGINE_CATALOG`). Partagé par l'API et le dashboard. |
| `apps/api/src/analysis/engines/engine.ts` | Contrat d'un moteur : `id`, `phase`, `run(ctx, setStatus) → Contribution`. |
| `apps/api/src/analysis/engines/registry.ts` | Liste ordonnée des moteurs (`ENGINES`) et leur règle de fusion. |
| `apps/api/src/analysis/engines/pipeline.ts` | Exécution générique : filtres, phases, statuts, décision. |
| `apps/api/src/analysis/*.ts` | Les détecteurs eux-mêmes (secrets, SAST, OSV, Semgrep, moteur Rust…), indépendants du pipeline. |
| `apps/api/src/routes/settings.ts` | API des paramètres (organisation, dépôt). |

### Contribution : chaque moteur décide comment il fusionne

Un moteur ne renvoie pas une liste, mais une **fonction** `(totaux) => totaux`. C'est ce qui permet des règles de fusion différentes sans `if` dans le pipeline :

- `osv` **enrichit** les dépendances trouvées par `dependencies` (CVE connues) ;
- `sca` **fusionne** l'arbre complet sans dupliquer une CVE ;
- `rust` **remplace** un résultat regex sur la même ligne par son résultat plus précis ;
- `semgrep` **ajoute** ce qui n'a pas déjà été signalé (même fichier, ligne, règle ou CWE).

Les contributions « intel » sont appliquées dans l'ordre du registre, après exécution concurrente.

## Ajouter un paramètre

Exemple : « ignorer les fichiers de test » (`skipTestFiles: boolean`).

1. **Déclarer** dans `analysis-settings.ts` :
   - le champ dans `analysisSettingsSchema` (il reste optionnel, grâce à `.partial()`) ;
   - le champ dans l'interface `AnalysisSettings` et sa valeur par défaut dans `DEFAULT_ANALYSIS_SETTINGS` ;
   - sa règle de fusion dans `resolveAnalysisSettings` (un scalaire est remplacé par le niveau le plus spécifique, une liste s'accumule).
2. **Lire** `ctx.settings.skipTestFiles` dans le(s) moteur(s) concerné(s), ou dans `pipeline.ts` si le paramètre s'applique à tous les moteurs, comme `ignorePaths`.
3. **Exposer** le paramètre dans `apps/web/src/app/settings/page.tsx`.
4. **Tester** : un cas dans `engines/pipeline.test.ts` et un cas d'API dans `__tests__/routes.itest.ts`.

**Aucune migration n'est nécessaire** : les paramètres sont stockés en JSON (`organizations.analysisSettings`, `repositories.analysisSettings`) et validés à l'entrée. Une valeur stockée devenue invalide (ancienne forme) est ignorée à la lecture, niveau par niveau, au lieu de casser les analyses.

## Ajouter un moteur

Exemple : détection d'injection de prompt (`prompt_injection`).

1. Ajouter l'id à `ENGINE_IDS` et sa fiche (libellé, description, phase) à `ENGINE_CATALOG`, dans `analysis-settings.ts`.
2. Écrire le détecteur (ex. `analysis/prompt-injection.ts`), testable seul.
3. Créer le moteur dans `engines/registry.ts` :

   ```ts
   const promptInjection: AnalysisEngine = {
     id: "prompt_injection",
     phase: "core", // "intel" s'il appelle un service ou un binaire
     run: (ctx) => {
       const found = detectPromptInjection(ctx.parsed.addedLines);
       return (t) => ({ ...t, findings: [...t.findings, ...found] });
     },
   };
   ```

   puis l'ajouter à `ENGINES`, à la bonne place dans l'ordre.
4. C'est tout. Le moteur obtient automatiquement :
   - son interrupteur dans « Paramètres d'analyse » et les surcharges par dépôt ;
   - son statut dans le commentaire de PR et sur la page de la PR ;
   - l'isolation des pannes : une exception le marque « failed » sans faire échouer l'analyse.

Un test vérifie que le registre et `ENGINE_IDS` restent synchronisés (`engines/pipeline.test.ts`).

Règles pour un moteur « intel » :
- ne jamais lever d'exception pour une cause attendue (outil absent, délai, réseau) : appeler `setStatus("failed", raison)` et renvoyer une contribution vide ;
- respecter un délai maximum (voir les `DEFAULT_TIMEOUT_MS` existants) ;
- s'il lit des fichiers, utiliser `ctx.scratchDir` (les fichiers de la PR écrits sur disque), jamais le répertoire de travail du serveur.

## Paramètres disponibles aujourd'hui

| Paramètre | Niveau | Effet |
|---|---|---|
| `engines.<id>` | org, dépôt | Active ou désactive un moteur (un moteur désactivé apparaît « skipped »). |
| `ignorePaths` | org, dépôt (s'accumulent) | Motifs de chemins jamais analysés (`vendor/**`, `*.min.js`…). |
| `minSeverity` | org, dépôt | Sévérité en dessous de laquelle rien n'est signalé ni compté. |
| `protectionLevel` | dépôt | `observe` (jamais bloquant), `warn`, `block` (check en échec sur un risque bloquant). |
