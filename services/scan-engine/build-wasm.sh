#!/bin/sh
# Build the engine to WebAssembly and drop it where the API loads it.
# Runs inside the official Rust image (no toolchain on the host):
#   docker run --rm -v cg-cargo:/usr/local/cargo/registry \
#     -v "$PWD:/repo" -w /repo/services/scan-engine rust:1-slim sh build-wasm.sh
set -eu
rustup target add wasm32-unknown-unknown >/dev/null 2>&1
cargo test --quiet
cargo build --quiet --release --target wasm32-unknown-unknown
OUT=../../apps/api/src/analysis/engine
mkdir -p "$OUT"
cp target/wasm32-unknown-unknown/release/codegate_scan.wasm "$OUT/codegate_scan.wasm"
ls -l "$OUT/codegate_scan.wasm"
