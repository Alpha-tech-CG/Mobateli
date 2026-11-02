# scan-engine

Moteur d'analyse de CodeGate en **Rust** (cahier §8, §9.3), compilé en **WebAssembly** et exécuté dans le processus de l'API (Vercel comme VPS), sans serveur séparé.

## Ce qu'il fait

- **Secret Shield** : motifs fournisseurs (AWS, Stripe, OpenAI, Anthropic, GitHub, Google, Slack, clés privées, URL Postgres) + affectations génériques à forte entropie — mêmes règles que le moteur TypeScript.
- **SAST sur arbre syntaxique** (parseur [oxc](https://oxc.rs)) pour JavaScript / TypeScript / JSX : `eval` / `new Function`, `exec` interpolé, `innerHTML` / `dangerouslySetInnerHTML`, SQL interpolé (les gabarits balisés `sql\`…\`` sont reconnus comme paramétrés), `createHash('md5'|'sha1')`, TLS désactivé. Le code en commentaire ou dans une chaîne ne déclenche plus de règle.
- Les identifiants de règles sont ceux du moteur TypeScript : les faux positifs déjà qualifiés restent reconnus.
- Un bloc ajouté qui ne s'analyse pas (hunk coupé au milieu d'une construction) est signalé ; l'API applique alors ses règles par ligne à ce fichier. Les autres langages restent couverts par les règles par ligne.

## Contrat

Entrée JSON `{ "lines": [{ "file", "line", "content" }] }` → sortie `{ engine, version, secrets[], findings[], astFiles[] }`. ABI WebAssembly : `cg_alloc`, `cg_scan`, `cg_free` (chargeur : `apps/api/src/analysis/engine/index.ts`). `CODEGATE_SCAN_ENGINE=off` force le moteur TypeScript.

## Construire (aucune installation de Rust sur la machine)

```bash
docker run --rm -v cg-cargo:/usr/local/cargo/registry -v "$PWD:/repo" -w /repo/services/scan-engine rust:1-slim sh build-wasm.sh
```

Le script lance `cargo test`, compile `wasm32-unknown-unknown` en release et copie `codegate_scan.wasm` dans `apps/api/src/analysis/engine/`. La CI fait de même à chaque push. `GET /health` indique le moteur actif (`scanEngine: "rust-wasm"`).
