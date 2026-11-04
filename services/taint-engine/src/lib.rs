//! CodeGate semantic scan engine.
//!
//! A tree-sitter based static analyzer with an intraprocedural taint engine.
//! It is consumed by the TypeScript API as a subprocess (see the CLI in
//! `main.rs` and the adapter `apps/api/src/analysis/rust-engine.ts`), and is
//! also usable as a library.
//!
//! See `docs/scan-engine-contract.md` for the JSON contract.

pub mod engine;
pub mod finding;
pub mod lang;
pub mod rules;

pub use engine::{analyze_inputs, analyze_source, FileInput};
pub use finding::{Confidence, Finding, Severity};
pub use lang::{Family, Language};

/// The `files` manifest read from stdin by the CLI (`--stdin`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Manifest {
    pub files: Vec<FileInput>,
}
