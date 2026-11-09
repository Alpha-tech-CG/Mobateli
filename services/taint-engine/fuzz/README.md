# Fuzzing du moteur Rust

Cible libFuzzer `analyze` : des octets arbitraires analysés comme un fichier
JS, TS, TSX ou Python. Un plantage **ou une lenteur** (`-timeout`) est un échec,
car un fichier qui fait dépasser au moteur le délai de l'adaptateur TS (5 s)
fait disparaître toutes ses alertes.

Nécessite une toolchain nightly et Linux/macOS (libFuzzer) :

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run analyze -- -max_total_time=300 -timeout=2 -rss_limit_mb=2048
```

La CI le lance 2 minutes à chaque PR, en partant d'un corpus construit à
partir du jeu de cas du benchmark (`apps/api/bench/golden`).

Les tests de robustesse sans nightly sont dans `tests/robustness.rs` (proptest
+ formes adversariales connues) et tournent avec `cargo test`.
