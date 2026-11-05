# scan-engine

Moteur d'analyse statique sémantique de CodeGate, écrit en **Rust**
(cahier §7, §8.2, §9.3, §14.4). C'est le cœur critique de l'analyse : il
utilise [tree-sitter](https://tree-sitter.github.io/) pour construire un AST
réel et applique une **analyse de taint** intraprocédurale — bien au-delà des
règles regex ligne-à-ligne de `apps/api/src/analysis/sast.ts`.

Il est consommé par l'API TypeScript comme un **sous-processus** via
l'adaptateur [`apps/api/src/analysis/rust-engine.ts`](../../apps/api/src/analysis/rust-engine.ts),
selon le contrat décrit dans [`docs/scan-engine-contract.md`](../../docs/scan-engine-contract.md).

## Ce qu'il détecte

Analyse sémantique par taint (source entrée utilisateur → sink dangereux),
pour **JavaScript / TypeScript** et **Python** :

| Règle | CWE | OWASP | Description |
|------|-----|-------|-------------|
| `RUST-*-SQLI-TAINT` | CWE-89 | A03:2021-Injection | Entrée utilisateur atteignant une requête SQL non paramétrée (dont `$queryRawUnsafe`) |
| `RUST-*-CMDI-*-TAINT` | CWE-78 | A03:2021-Injection | Entrée utilisateur atteignant `exec`/`os.system`/`subprocess(shell=True)` |
| `RUST-*-CODE-INJECTION-TAINT` | CWE-94 | A03:2021-Injection | Entrée utilisateur atteignant `eval`/`new Function`/`vm.run*`/`exec` |
| `RUST-*-PATH-TRAVERSAL-TAINT` | CWE-22 | A01:2021-Broken Access Control | Entrée de requête atteignant `fs.*`/`sendFile`/`open()` sans contrôle `startsWith` |
| `RUST-*-SSRF-TAINT` | CWE-918 | A10:2021-SSRF | Entrée de requête déterminant l'hôte d'un appel sortant (`fetch`, `axios`, `requests`…) |
| `RUST-JS-XSS-TAINT` | CWE-79 | A03:2021-Injection | Entrée écrite telle quelle dans `res.send/write` ou `document.write` |

Faible taux de faux positifs par construction :

- **liaison de variables** (`a = source; b = a; sink(b)` est suivi jusqu'au sink
  par point fixe), pas de simple match ligne-à-ligne ;
- seul le **premier argument positionnel** d'un sink est testé, donc une requête
  **paramétrée** (`execute(sql, params)`) n'est pas signalée ;
- prise en compte des **assainisseurs** (`parseInt`, `shlex.quote`…) qui coupent
  le taint ;
- `subprocess` n'est signalé qu'avec `shell=True` ;
- le taint est suivi **par portée de fonction** (avec capture lexicale) : une
  variable `name` contaminée dans un handler ne contamine pas un `name` d'un
  autre handler ;
- un assainisseur **imbriqué** ne neutralise que ce qu'il entoure
  (`path.join(D, path.basename(req.query.f))` est sûr, `"a" + req.query.q` non) ;
- PATH/SSRF/XSS n'utilisent que les sources **web** (pas `process.argv`,
  `sys.argv`, `input()` : un CLI qui ouvre le chemin qu'on lui donne fait son
  travail) ; SSRF ignore une URL dont le schéma et l'hôte sont fixés.

La confiance (`confidence`) est `high` quand la source atteint le sink en
ligne, `medium` quand elle y arrive via une variable.

## Build

Nécessite une toolchain Rust/Cargo (voir [rustup.rs](https://rustup.rs/)). Les
grammaires tree-sitter sont compilées depuis du C, donc un compilateur C est
requis (MSVC Build Tools, ou mingw-w64 + cible `x86_64-pc-windows-gnu` sous
Windows).

```bash
cargo build --release        # produit target/release/codegate-scan
cargo test                   # suite unitaire + intégration, sans réseau
cargo clippy --all-targets   # lint
```

## CLI

Le binaire `codegate-scan` émet un tableau JSON de findings sur stdout.

```bash
# Scanner des fichiers / dossiers sur disque :
codegate-scan path/to/file.ts src/

# Ou lire un manifeste JSON sur stdin (mode utilisé par l'adaptateur TS) :
echo '{"files":[{"path":"a.js","content":"db.query(req.query.id)"}]}' \
  | codegate-scan --stdin --pretty
```

Le processus sort avec le code 0 en cas de succès (même s'il y a des findings),
et 2 uniquement sur erreur fatale (manifeste invalide) — en imprimant `[]`.

## Service HTTP (optionnel)

Un binaire Axum est disponible derrière le feature `server`, pour une
exposition HTTP ultérieure (`POST /scan` avec le même manifeste JSON) :

```bash
cargo run --features server --bin codegate-scan-server
# SCAN_ENGINE_ADDR=127.0.0.1:7878 par défaut
```

## Architecture

```
src/
  finding.rs   # le type Finding + sérialisation JSON (compatible FindingResult TS)
  lang.rs      # détection de langage + choix de la grammaire tree-sitter
  rules.rs     # DONNÉES : sources, sinks, assainisseurs par famille de langage
  engine.rs    # moteur de taint générique (parse → point fixe → sinks)
  main.rs      # CLI codegate-scan
  bin/server.rs# service HTTP optionnel (feature "server")
tests/
  integration.rs  # TP détectés, FP non signalés, fail-open
```

Ajouter une règle = ajouter une entrée `SinkRule` dans `rules.rs` (et au besoin
une source/assainisseur). Le moteur est piloté par les données : aucune
modification de `engine.rs` n'est nécessaire.
