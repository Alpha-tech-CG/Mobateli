//! Integration tests: true-positive detection, false-positive controls, and
//! fail-open behaviour. These parse real source snippets through the full
//! engine (no network, deterministic).

use codegate_scan_engine::{analyze_source, Confidence};

fn rule_ids(path: &str, src: &str) -> Vec<String> {
    analyze_source(path, src)
        .into_iter()
        .filter_map(|f| f.rule_id)
        .collect()
}

// --------------------------------------------------------------------------
// JavaScript / TypeScript — true positives
// --------------------------------------------------------------------------

#[test]
fn js_sql_injection_via_template_is_flagged() {
    let src = r#"
        app.get('/u', (req, res) => {
          const id = req.query.id;
          db.query(`SELECT * FROM users WHERE id = ${id}`);
        });
    "#;
    assert!(rule_ids("route.js", src).contains(&"RUST-JS-SQLI-TAINT".to_string()));
}

#[test]
fn js_sql_injection_inline_source_is_high_confidence() {
    let src = r#"pool.query("SELECT * FROM t WHERE n = '" + req.body.name + "'");"#;
    let findings = analyze_source("q.js", src);
    let sqli = findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("RUST-JS-SQLI-TAINT"))
        .expect("expected SQLi finding");
    assert_eq!(sqli.confidence, Some(Confidence::High));
    assert_eq!(sqli.cwe.as_deref(), Some("CWE-89"));
    assert_eq!(sqli.owasp.as_deref(), Some("A03:2021-Injection"));
}

#[test]
fn js_command_injection_via_variable_is_medium_confidence() {
    let src = r#"
        const dir = req.params.dir;
        const cmd = "ls " + dir;
        exec(cmd);
    "#;
    let findings = analyze_source("x.js", src);
    let cmdi = findings
        .iter()
        .find(|f| f.rule_id.as_deref() == Some("RUST-JS-CMDI-TAINT"))
        .expect("expected command-injection finding");
    assert_eq!(cmdi.confidence, Some(Confidence::Medium));
    assert_eq!(cmdi.cwe.as_deref(), Some("CWE-78"));
}

#[test]
fn js_eval_of_user_input_is_flagged() {
    let src = r#"eval(req.query.payload);"#;
    assert!(rule_ids("e.js", src).contains(&"RUST-JS-CODE-INJECTION-TAINT".to_string()));
}

#[test]
fn ts_sql_injection_with_types_is_flagged() {
    // Exercises the TypeScript grammar (type annotation present).
    let src = r#"
        function find(req: Request): void {
          const name: string = req.query.name as string;
          connection.query("SELECT * FROM t WHERE name = '" + name + "'");
        }
    "#;
    assert!(rule_ids("svc.ts", src).contains(&"RUST-JS-SQLI-TAINT".to_string()));
}

// --------------------------------------------------------------------------
// JavaScript — false-positive controls
// --------------------------------------------------------------------------

#[test]
fn js_parameterized_query_is_not_flagged() {
    // The untrusted value is a bound parameter (2nd arg), not the query string.
    let src = r#"
        const id = req.query.id;
        db.query("SELECT * FROM users WHERE id = $1", [id]);
    "#;
    assert!(rule_ids("safe.js", src).is_empty());
}

#[test]
fn js_constant_query_is_not_flagged() {
    let src = r#"db.query("SELECT 1");"#;
    assert!(rule_ids("safe2.js", src).is_empty());
}

#[test]
fn js_sanitized_input_is_not_flagged() {
    let src = r#"
        const id = parseInt(req.query.id);
        db.query("SELECT * FROM t WHERE id = " + id);
    "#;
    assert!(rule_ids("safe3.js", src).is_empty());
}

#[test]
fn js_regex_exec_is_not_flagged_as_command_injection() {
    let src = r#"
        const input = req.body.text;
        const re = /foo/;
        re.exec(input);
    "#;
    assert!(!rule_ids("re.js", src).contains(&"RUST-JS-CMDI-TAINT".to_string()));
}

// --------------------------------------------------------------------------
// Python — true positives and FP controls
// --------------------------------------------------------------------------

#[test]
fn py_sql_injection_fstring_is_flagged() {
    let src = r#"
@app.route("/u")
def u():
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
"#;
    assert!(rule_ids("app.py", src).contains(&"RUST-PY-SQLI-TAINT".to_string()));
}

#[test]
fn py_command_injection_os_system_is_flagged() {
    let src = r#"
def run():
    name = request.form["name"]
    os.system("echo " + name)
"#;
    assert!(rule_ids("cmd.py", src).contains(&"RUST-PY-CMDI-OS-TAINT".to_string()));
}

#[test]
fn py_subprocess_without_shell_is_not_flagged() {
    let src = r#"
def run():
    name = request.form["name"]
    subprocess.run(["echo", name])
"#;
    assert!(rule_ids("sp.py", src).is_empty());
}

#[test]
fn py_subprocess_with_shell_true_is_flagged() {
    let src = r#"
def run():
    name = request.form["name"]
    subprocess.run("echo " + name, shell=True)
"#;
    assert!(rule_ids("sp2.py", src).contains(&"RUST-PY-CMDI-SUBPROCESS-TAINT".to_string()));
}

#[test]
fn py_parameterized_query_is_not_flagged() {
    let src = r#"
def u():
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
"#;
    assert!(rule_ids("safe.py", src).is_empty());
}

// --------------------------------------------------------------------------
// Fail-open / robustness
// --------------------------------------------------------------------------

#[test]
fn unsupported_extension_returns_empty() {
    assert!(analyze_source("main.go", "package main").is_empty());
}

#[test]
fn no_taint_returns_empty() {
    let src = r#"db.query("SELECT * FROM t WHERE id = " + 42);"#;
    assert!(analyze_source("n.js", src).is_empty());
}

// --------------------------------------------------------------------------
// Scoping, nested sanitizers, PATH / SSRF / XSS sinks
// --------------------------------------------------------------------------

#[test]
fn taint_does_not_leak_between_functions() {
    // `name` is tainted in one handler and sanitized in another.
    let src = r#"
def read_file():
    name = request.args.get("name")
    return open(name).read()

def quoted():
    name = shlex.quote(request.args.get("name"))
    subprocess.run("echo " + name, shell=True)
"#;
    let ids = rule_ids("app.py", src);
    assert!(!ids.contains(&"RUST-PY-CMDI-SUBPROCESS-TAINT".to_string()), "{ids:?}");
}

#[test]
fn module_level_taint_reaches_nested_functions() {
    let src = r#"
const id = req.query.id;
app.get("/x", () => { db.query("SELECT * FROM t WHERE id = " + id); });
"#;
    assert!(rule_ids("a.js", src).contains(&"RUST-JS-SQLI-TAINT".to_string()));
}

#[test]
fn nested_sanitizer_neutralizes_only_what_it_wraps() {
    let safe = r#"res.send(`<p>${escapeHtml(req.query.q)}</p>`);"#;
    assert!(rule_ids("a.js", safe).is_empty(), "{:?}", rule_ids("a.js", safe));
    let unsafe_ = r#"res.send(`<p>${escapeHtml(req.query.q)} ${req.query.r}</p>`);"#;
    assert!(rule_ids("a.js", unsafe_).contains(&"RUST-JS-XSS-TAINT".to_string()));
    let path = "fs.readFile(path.join(DIR, path.basename(req.query.f)), cb);";
    assert!(rule_ids("a.js", path).is_empty());
}

#[test]
fn path_traversal_through_a_variable_is_flagged_unless_guarded() {
    let vuln = r#"
app.get("/d/:n", (req, res) => {
  const target = path.join(ROOT, req.params.n);
  fs.createReadStream(target).pipe(res);
});
"#;
    assert!(rule_ids("a.js", vuln).contains(&"RUST-JS-PATH-TRAVERSAL-TAINT".to_string()));
    let guarded = r#"
app.get("/d", (req, res) => {
  const target = path.resolve(ROOT, String(req.query.n));
  if (!target.startsWith(ROOT + path.sep)) return res.sendStatus(400);
  fs.createReadStream(target).pipe(res);
});
"#;
    assert!(rule_ids("a.js", guarded).is_empty(), "{:?}", rule_ids("a.js", guarded));
}

#[test]
fn cli_arguments_are_not_a_path_or_ssrf_source() {
    // A CLI opening the path / URL it was given is its job.
    assert!(rule_ids("cli.js", "fs.readFileSync(process.argv[2]);").is_empty());
    assert!(rule_ids("cli.py", "open(sys.argv[1]).read()").is_empty());
    assert!(rule_ids("cli.py", "requests.get(sys.argv[1])").is_empty());
}

#[test]
fn ssrf_requires_a_steerable_origin() {
    assert!(rule_ids("a.js", "await fetch(req.query.url);").contains(&"RUST-JS-SSRF-TAINT".to_string()));
    assert!(rule_ids("a.js", "await fetch(`https://${req.query.host}/x`);")
        .contains(&"RUST-JS-SSRF-TAINT".to_string()));
    assert!(rule_ids("a.js", "await fetch(`https://api.example.com/v1?q=${req.query.q}`);").is_empty());
    assert!(rule_ids("a.py", "requests.get(request.args.get('url'))")
        .contains(&"RUST-PY-SSRF-TAINT".to_string()));
}

#[test]
fn xss_skips_wrapped_calls_and_json() {
    assert!(rule_ids("a.js", r#"res.send("<b>" + req.query.n + "</b>");"#)
        .contains(&"RUST-JS-XSS-TAINT".to_string()));
    assert!(rule_ids("a.js", "res.json({ n: req.query.n });").is_empty());
    assert!(rule_ids("a.js", "res.send(fs.readFileSync(req.query.f));")
        .iter()
        .all(|id| id != "RUST-JS-XSS-TAINT"));
}

#[test]
fn unsafe_orm_and_vm_sinks_are_flagged() {
    assert!(rule_ids("a.ts", "prisma.$queryRawUnsafe(`SELECT ${req.body.k}`);")
        .contains(&"RUST-JS-SQLI-TAINT".to_string()));
    assert!(rule_ids("a.js", "vm.runInNewContext(req.body.code);")
        .contains(&"RUST-JS-CODE-INJECTION-TAINT".to_string()));
}

#[test]
fn encode_uri_component_does_not_sanitize_sql_or_eval() {
    // ' ( ) are left intact: still injectable in a SQL string or eval.
    let sql = r#"db.query("SELECT * FROM t WHERE n = '" + encodeURIComponent(req.query.n) + "'");"#;
    assert!(rule_ids("a.js", sql).contains(&"RUST-JS-SQLI-TAINT".to_string()));
    // ...but it does neutralize a URL path segment.
    let url = "fetch(`https://api.example.com/u/${encodeURIComponent(req.query.u)}`);";
    assert!(rule_ids("a.js", url).is_empty());
}
