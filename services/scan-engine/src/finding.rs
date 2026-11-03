//! The finding type emitted by the engine.
//!
//! The JSON shape is deliberately a superset-compatible subset of the
//! TypeScript `FindingResult` interface (apps/api/src/analysis/types.ts):
//! field names are camelCase and the string values of `type`, `severity`
//! and `confidence` are exactly the ones used on the TS side, so the adapter
//! (`rust-engine.ts`) can `JSON.parse` the output straight into
//! `FindingResult[]` with no remapping.

use serde::{Deserialize, Serialize};

/// Severity scale — mirrors `Severity` in packages/shared (enums.ts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence a finding is a true positive — mirrors `Confidence` (types.ts).
/// A semantic taint match is never presented with the weight of a confirmed
/// issue blindly: `High` means the user input reaches the sink inline, `Medium`
/// means we traced it through a variable binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// One finding. Serialized to the JSON array the CLI prints on stdout.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// The `FindingType` on the TS side — always "sast" for this engine.
    #[serde(rename = "type")]
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// CWE identifier, e.g. "CWE-89".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// OWASP Top 10 category, e.g. "A03:2021-Injection".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}
