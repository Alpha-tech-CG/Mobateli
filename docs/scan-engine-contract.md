# Contrat d'intégration : moteur de scan Rust ↔ API TypeScript

Ce document décrit le contrat entre le moteur d'analyse statique en Rust
([`services/scan-engine`](../services/scan-engine)) et l'API TypeScript qui le
consomme ([`apps/api/src/analysis/rust-engine.ts`](../apps/api/src/analysis/rust-engine.ts)).

## Modèle d'intégration

Le moteur Rust est un **sous-processus**, invoqué par l'adaptateur TS — le même
patron que `osv.ts` :

- **injectable** : l'adaptateur accepte un `runner` (et le moteur un
  `binaryPath`), ce qui rend les tests déterministes sans binaire ;
- **fail-open** : binaire absent, erreur, code de sortie non nul ou timeout ⇒
  l'adaptateur renvoie `[]`. Un moteur manquant ne bloque **jamais** une PR ;
- **hors du cœur synchrone** : il fait des I/O (processus), donc il est appelé
  depuis `analyzeDiffWithIntel`, pas depuis `analyzeDiff`.

Le binaire est **optionnel** : CI/prod le compilent (`cargo build --release`)
et exposent son chemin via `CODEGATE_SCAN_BIN` ; sans lui, le pipeline TS
fonctionne à l'identique.

```
diff unifié ──► parseUnifiedDiff ──► filesFromDiff ──► manifeste JSON (stdin)
                                                              │
                                                     codegate-scan --stdin
                                                              │
   FindingResult[] ◄── parse + validation ◄── tableau JSON (stdout)
                                                              │
                              mergeRustFindings(base, moteur)  ──► décision
```

## Entrée : manifeste (stdin)

L'adaptateur envoie sur stdin un objet JSON `files` reconstruit depuis le diff
(chaque ligne ajoutée est placée à son **vrai numéro de ligne**, les trous
comblés par des lignes vides, pour que les numéros rapportés correspondent au
fichier réel) :

```json
{
  "files": [
    { "path": "apps/api/src/db.ts", "content": "…contenu…" }
  ]
}
```

Le langage est déduit de l'extension du `path` (`.js .jsx .mjs .cjs .ts .mts
.cts .tsx .py .pyi`). Une extension inconnue est ignorée.

## Sortie : findings (stdout)

Un **tableau JSON** de findings. Les noms de champs sont en `camelCase` et les
valeurs de `type`, `severity` et `confidence` sont exactement celles utilisées
côté TS, de sorte que l'adaptateur `JSON.parse` directement en
[`FindingResult[]`](../apps/api/src/analysis/types.ts) sans remappage.

```json
[
  {
    "type": "sast",
    "severity": "high",
    "title": "Injection SQL : entrée utilisateur dans une requête",
    "description": "…",
    "filePath": "apps/api/src/db.ts",
    "line": 12,
    "ruleId": "RUST-JS-SQLI-TAINT",
    "remediation": "Utilisez des requêtes paramétrées…",
    "cwe": "CWE-89",
    "owasp": "A03:2021-Injection",
    "confidence": "high"
  }
]
```

| Champ | Type | Obligatoire | Notes |
|------|------|-------------|-------|
| `type` | `FindingType` | oui | toujours `"sast"` pour ce moteur |
| `severity` | `Severity` | oui | `info` \| `low` \| `medium` \| `high` \| `critical` |
| `title` | `string` | oui | |
| `description` | `string` | oui | |
| `filePath` | `string` | non | le `path` du manifeste |
| `line` | `number` | non | 1-indexé |
| `ruleId` | `string` | non | ex. `RUST-JS-SQLI-TAINT` |
| `remediation` | `string` | non | |
| `cwe` | `string` | non | ex. `CWE-89` |
| `owasp` | `string` | non | ex. `A03:2021-Injection` |
| `confidence` | `Confidence` | non | `high` (source en ligne) \| `medium` (via variable) \| `low` |

L'adaptateur **valide** chaque objet (titre/description/severity obligatoires et
valides) et ignore silencieusement les entrées malformées.

## Déduplication

`mergeRustFindings(base, moteur)` fusionne les findings du moteur avec ceux du
pipeline de base (regex `sast.ts` + autres). La clé est
`filePath | line | famille`, où la famille est dérivée du CWE/ruleId
(`sqli` ⇐ CWE-89, `cmdi` ⇐ CWE-78, `code` ⇐ CWE-94). En cas de collision, le
finding **du moteur l'emporte** (il porte CWE/OWASP/confidence) ; les findings
de base sans équivalent moteur sont conservés.

## Variables d'environnement

| Variable | Rôle |
|----------|------|
| `CODEGATE_SCAN_BIN` | chemin du binaire (défaut : `codegate-scan` dans le PATH) |
| `CODEGATE_SCAN_DISABLE` | si défini, l'adaptateur n'invoque jamais le moteur |

## Codes de sortie du binaire

| Code | Sens |
|------|------|
| `0` | succès (y compris avec des findings) |
| `2` | erreur fatale (manifeste invalide) — `[]` est tout de même imprimé |
