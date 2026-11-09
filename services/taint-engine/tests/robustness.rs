//! Robustness tests: the engine is fed untrusted code from pull requests, so
//! it must never panic and must stay fast on hostile input. A slow file is a
//! bypass, not just a performance bug: the TypeScript adapter kills the engine
//! after 5 s and fails open, dropping every Rust finding for the whole PR.

use std::time::{Duration, Instant};

use codegate_scan_engine::{analyze_inputs, analyze_source, FileInput};
use proptest::prelude::*;

const EXTS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "py", "txt"];

/// Budget per adversarial input. Generous (CI machines are slow, and these
/// run unoptimized under `cargo test`), yet far below the cost of the former
/// quadratic paths, which took 3–13 s in release for the same inputs.
const BUDGET: Duration = Duration::from_secs(4);

fn assert_fast(name: &str, path: &str, src: &str) -> usize {
    let t = Instant::now();
    let n = analyze_source(path, src).len();
    let took = t.elapsed();
    assert!(took < BUDGET, "{name}: {took:?} for {} KiB", src.len() / 1024);
    n
}

// ---- Adversarial shapes (former quadratic blow-ups) -------------------------

#[test]
fn reverse_taint_chain_is_linear_and_still_detected() {
    // `v{n} = v{n-1}` written before `v0 = source`: the old fixpoint needed one
    // full pass per link.
    let n = 20_000;
    let mut src: Vec<String> = (1..=n).rev().map(|i| format!("const v{i} = v{};", i - 1)).collect();
    src.push("const v0 = req.query.x;".into());
    src.push(format!("db.query(v{n});"));
    assert_eq!(assert_fast("chain", "a.js", &src.join("\n")), 1);
}

#[test]
fn wide_expression_is_linear() {
    // A left-deep `+` chain: `Node::parent()` per identifier was O(depth).
    let n = 100_000;
    let terms: Vec<String> = (0..n).map(|i| format!("y{i}")).collect();
    let src = format!("const x = {};\nconst y5 = req.query.a;\ndb.query(x);", terms.join(" + "));
    assert_eq!(assert_fast("wide", "a.js", &src), 1);
}

#[test]
fn deeply_nested_calls_do_not_overflow_or_stall() {
    let n = 50_000;
    let src = format!("db.query({}req.query.x{});", "f(".repeat(n), ")".repeat(n));
    assert_eq!(assert_fast("nest", "a.js", &src), 1);
    let py = format!("cursor.execute({}request.args{})", "f(".repeat(n), ")".repeat(n));
    assert_eq!(assert_fast("nest-py", "a.py", &py), 1);
}

#[test]
fn deeply_nested_brackets_do_not_overflow() {
    let n = 100_000;
    assert_fast("brackets", "a.js", &"[".repeat(n));
    assert_fast("braces", "a.ts", &"{".repeat(n));
    assert_fast("parens", "a.py", &"(".repeat(n));
}

#[test]
fn huge_argument_lists_are_linear() {
    // `named_child(i)` per argument was O(i): many keyword arguments before the
    // first positional one made the call quadratic.
    let kwargs = "k=1, ".repeat(50_000);
    let py = format!("cursor.execute({kwargs}request.args)");
    assert_eq!(assert_fast("kwargs", "a.py", &py), 1);
    let args = "a, ".repeat(50_000);
    assert_fast("args", "a.js", &format!("db.query(req.query.x, {args})"));
}

#[test]
fn many_sink_calls_are_linear() {
    let src: Vec<String> = (0..80_000).map(|i| format!("db.query(a{i});")).collect();
    assert_fast("calls", "a.js", &src.join("\n"));
}

#[test]
fn degenerate_inputs_do_not_panic() {
    for ext in EXTS {
        let path = format!("x.{ext}");
        for src in [
            "",
            "\0\0\0",
            "\u{feff}db.query(req.query.x)",
            "db.query(req.query.x", // unterminated
            "é\u{1F600}𝕏 = req.query.é; db.query(é)",
            "\r\n\r\n\t",
            &"\u{FFFD}".repeat(10_000),
        ] {
            let _ = analyze_source(&path, src);
        }
    }
}

// ---- Property tests ---------------------------------------------------------

/// Code-like token soup: far more likely than random bytes to reach the
/// engine's assignment / call / sink logic.
fn token_soup() -> impl Strategy<Value = String> {
    let tok = prop::sample::select(vec![
        "db.query", "cursor.execute", "exec", "eval", "os.system", "subprocess.run", "new Function",
        "req.query.id", "request.args", "sys.argv", "parseInt", "shlex.quote", "x", "y", "obj.x",
        "=", "+", "(", ")", "[", "]", "{", "}", ",", ";", ".", "`${", "}`", "\"", "'", "\n", " ",
        "const", "let", "def", "lambda", ":", "shell=True", "=>", "#", "//", "/*", "*/", "\\",
    ]);
    prop::collection::vec(tok, 0..200).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn never_panics_on_arbitrary_text(src in any::<String>(), ext in prop::sample::select(EXTS)) {
        let _ = analyze_source(&format!("f.{ext}"), &src);
    }

    #[test]
    fn never_panics_on_code_like_input(src in token_soup(), ext in prop::sample::select(EXTS)) {
        let _ = analyze_source(&format!("f.{ext}"), &src);
    }

    #[test]
    fn findings_point_inside_the_file(src in token_soup(), ext in prop::sample::select(EXTS)) {
        let lines = src.split('\n').count();
        for f in analyze_source(&format!("f.{ext}"), &src) {
            let line = f.line.expect("every finding has a line");
            prop_assert!(line >= 1 && line <= lines, "line {line} outside 1..={lines}");
        }
    }

    #[test]
    fn batch_equals_concatenation_of_single_files(a in token_soup(), b in token_soup()) {
        let inputs = vec![
            FileInput { path: "a.js".into(), content: a.clone() },
            FileInput { path: "b.py".into(), content: b.clone() },
        ];
        let mut single = analyze_source("a.js", &a);
        single.extend(analyze_source("b.py", &b));
        let batch = analyze_inputs(&inputs);
        prop_assert_eq!(
            serde_json::to_string(&batch).unwrap(),
            serde_json::to_string(&single).unwrap()
        );
    }
}
