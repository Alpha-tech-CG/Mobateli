//! `codegate-scan` — the CLI the TypeScript API invokes as a subprocess.
//!
//! Two input modes:
//!   * positional paths: scan each file or directory (recursively, supported
//!     extensions only);
//!   * `--stdin`: read a JSON manifest `{"files":[{"path","content"}]}` and
//!     analyze those in-memory files (what the TS adapter uses — it never has
//!     to write temp files, and virtual paths work).
//!
//! The findings are printed to stdout as a JSON array, always. The process
//! exits 0 on success, 2 only on a fatal CLI/manifest error (the TS adapter
//! fails open regardless).

use std::io::Read;
use std::process::ExitCode;

use clap::Parser as ClapParser;
use codegate_scan_engine::{analyze_inputs, FileInput, Language, Manifest};
use walkdir::WalkDir;

#[derive(ClapParser, Debug)]
#[command(
    name = "codegate-scan",
    about = "CodeGate semantic static-analysis engine (tree-sitter + taint rules)",
    version
)]
struct Cli {
    /// Files or directories to scan.
    paths: Vec<String>,

    /// Read a JSON manifest {"files":[{"path","content"}]} from stdin instead
    /// of scanning paths on disk.
    #[arg(long)]
    stdin: bool,

    /// Pretty-print the JSON output.
    #[arg(long)]
    pretty: bool,
}

fn collect_path(path: &str, inputs: &mut Vec<FileInput>) {
    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path().to_string_lossy().replace('\\', "/");
        if Language::from_path(&p).is_none() {
            continue;
        }
        match std::fs::read(entry.path()) {
            Ok(bytes) => inputs.push(FileInput {
                path: p,
                content: String::from_utf8_lossy(&bytes).into_owned(),
            }),
            Err(err) => eprintln!("codegate-scan: skipping {p}: {err}"),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut inputs: Vec<FileInput> = Vec::new();
    if cli.stdin {
        let mut buf = String::new();
        if let Err(err) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("codegate-scan: failed to read stdin: {err}");
            println!("[]");
            return ExitCode::from(2);
        }
        match serde_json::from_str::<Manifest>(&buf) {
            Ok(manifest) => inputs = manifest.files,
            Err(err) => {
                eprintln!("codegate-scan: invalid manifest: {err}");
                println!("[]");
                return ExitCode::from(2);
            }
        }
    } else {
        for path in &cli.paths {
            collect_path(path, &mut inputs);
        }
    }

    let findings = analyze_inputs(&inputs);
    let json = if cli.pretty {
        serde_json::to_string_pretty(&findings)
    } else {
        serde_json::to_string(&findings)
    };
    println!("{}", json.unwrap_or_else(|_| "[]".to_string()));
    ExitCode::SUCCESS
}
