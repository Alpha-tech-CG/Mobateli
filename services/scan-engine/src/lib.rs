//! CodeGate scan engine (cahier §8, §9.3) — Rust, compiled to WebAssembly and
//! called in-process by the API.
//!
//! * Secret Shield: provider patterns + generic high-entropy assignments
//!   (same rules as the TypeScript engine, so results are interchangeable).
//! * SAST on a real syntax tree for JavaScript / TypeScript (oxc parser):
//!   code in comments or strings no longer triggers a rule, tagged `sql`
//!   templates are recognised as parameterised, etc.
//!
//! Input and output are JSON so the engine stays a pure function. Blocks that
//! do not parse (a hunk cut mid-construct) are reported back so the caller
//! falls back to its line rules for those files.

mod rules;
mod secrets;

use serde::{Deserialize, Serialize};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
pub struct AddedLine {
    pub file: String,
    pub line: u32,
    pub content: String,
}

#[derive(Deserialize)]
struct Input {
    lines: Vec<AddedLine>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    pub secret_type: String,
    pub location: String,
    pub masked_preview: String,
    pub severity: &'static str,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub severity: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub file_path: String,
    pub line: u32,
    pub rule_id: &'static str,
    pub remediation: &'static str,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub engine: &'static str,
    pub version: &'static str,
    pub secrets: Vec<Secret>,
    pub findings: Vec<Finding>,
    /// Files whose added code was fully analysed on the syntax tree.
    pub ast_files: Vec<String>,
}

pub fn scan_lines(lines: &[AddedLine]) -> Output {
    let secrets = secrets::scan(lines);
    let (findings, ast_files) = rules::scan(lines);
    Output { engine: "codegate-scan", version: VERSION, secrets, findings, ast_files }
}

/// JSON in, JSON out. Malformed input yields an `{"error": …}` object.
pub fn scan_json(input: &str) -> String {
    match serde_json::from_str::<Input>(input) {
        Ok(i) => serde_json::to_string(&scan_lines(&i.lines)).unwrap_or_else(|e| error_json(&e.to_string())),
        Err(e) => error_json(&e.to_string()),
    }
}

fn error_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

// ── WebAssembly ABI (no bindgen: a tiny hand-written JS loader calls these) ──

/// Reserve `len` bytes in the module's memory for the caller to write into.
#[unsafe(no_mangle)]
pub extern "C" fn cg_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Release a buffer previously returned by `cg_alloc` or `cg_scan`.
///
/// # Safety
/// `ptr`/`len` must come from `cg_alloc` / `cg_scan` and be freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cg_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
    }
}

/// Scan the UTF-8 JSON at `ptr[..len]`; returns `(out_ptr << 32) | out_len`.
///
/// # Safety
/// `ptr[..len]` must be a buffer obtained from `cg_alloc` and filled by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cg_scan(ptr: *const u8, len: usize) -> u64 {
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    let out = match std::str::from_utf8(input) {
        Ok(s) => scan_json(s),
        Err(_) => error_json("input is not UTF-8"),
    };
    let mut bytes = out.into_bytes().into_boxed_slice();
    let out_len = bytes.len();
    let out_ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ((out_ptr as u64) << 32) | out_len as u64
}
