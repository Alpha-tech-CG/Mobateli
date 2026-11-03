use codegate_scan::{AddedLine, scan_json, scan_lines};

fn lines(file: &str, src: &[&str]) -> Vec<AddedLine> {
    src.iter()
        .enumerate()
        .map(|(i, c)| AddedLine { file: file.into(), line: 10 + i as u32, content: (*c).into() })
        .collect()
}

fn rule_ids(file: &str, src: &[&str]) -> Vec<(&'static str, u32)> {
    let mut v: Vec<_> = scan_lines(&lines(file, src)).findings.iter().map(|f| (f.rule_id, f.line)).collect();
    v.sort();
    v
}

#[test]
fn eval_and_function_are_flagged_with_their_line() {
    assert_eq!(rule_ids("a.ts", &["const x = 1;", "eval(userInput);"]), vec![("DANGEROUS_EVAL", 11)]);
    assert_eq!(rule_ids("a.js", &["const f = new Function('a', body);"]), vec![("DANGEROUS_EVAL", 10)]);
}

#[test]
fn comments_and_strings_do_not_trigger_rules() {
    assert_eq!(
        rule_ids(
            "a.ts",
            &[
                "// never call eval(x) here",
                "const doc = 'use innerHTML = x carefully';",
                "/* exec(`rm ${dir}`) */",
                "const q = \"SELECT * FROM users WHERE id = $1\";",
            ],
        ),
        vec![]
    );
}

#[test]
fn shell_injection_only_when_interpolated() {
    assert_eq!(
        rule_ids("a.ts", &["exec(`git clone ${url}`);", "exec('ls -la');", "execSync('rm ' + path);"]),
        vec![("CHILD_PROCESS_INJECTION", 10), ("CHILD_PROCESS_INJECTION", 12)]
    );
}

#[test]
fn sql_template_flagged_but_tagged_sql_is_safe() {
    assert_eq!(
        rule_ids(
            "db.ts",
            &[
                "const a = await db.query(`SELECT * FROM users WHERE id = ${id}`);",
                "const b = await sql`SELECT * FROM users WHERE id = ${id}`;",
                "const c = db.query(\"DELETE FROM t WHERE id = \" + id);",
            ],
        ),
        vec![("SQL_STRING_CONCAT", 10), ("SQL_STRING_CONCAT", 12)]
    );
}

#[test]
fn xss_tls_and_weak_hash() {
    assert_eq!(
        rule_ids(
            "ui.tsx",
            &[
                "el.innerHTML = comment.body;",
                "el.innerHTML = '<b>ok</b>';",
                "const v = <div dangerouslySetInnerHTML={{ __html: html }} />;",
                "const agent = new https.Agent({ rejectUnauthorized: false });",
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
                "const h = crypto.createHash('md5');",
            ],
        ),
        vec![
            ("TLS_VERIFICATION_DISABLED", 13),
            ("TLS_VERIFICATION_DISABLED", 14),
            ("WEAK_HASH", 15),
            ("XSS_INNERHTML", 10),
            ("XSS_INNERHTML", 12),
        ]
    );
}

#[test]
fn unparseable_block_is_reported_for_fallback() {
    let out = scan_lines(&lines("a.ts", &["  }", "}, [deps]);", "eval(x)"]));
    assert!(out.ast_files.is_empty(), "a hunk cut mid-construct must fall back");
    let ok = scan_lines(&lines("b.ts", &["const a = 1;"]));
    assert_eq!(ok.ast_files, vec!["b.ts".to_string()]);
}

#[test]
fn non_js_files_are_left_to_the_line_rules() {
    let out = scan_lines(&lines("app.py", &["eval(x)"]));
    assert!(out.findings.is_empty());
    assert!(out.ast_files.is_empty());
}

#[test]
fn secrets_match_the_typescript_engine() {
    let key = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    let out = scan_lines(&lines(
        "config.ts",
        &[
            &format!("const id = '{key}';"),
            "const password = 'changeme-please';",
            "const api_key = 'Zx9!qL2#vR7$mT4&pW';",
        ],
    ));
    let types: Vec<_> = out.secrets.iter().map(|s| (s.secret_type.as_str(), s.location.as_str())).collect();
    assert_eq!(types, vec![("aws_access_key_id", "config.ts:10"), ("generic_apikey", "config.ts:12")]);
    assert_eq!(out.secrets[0].masked_preview, "AKIA…MPLE (20 chars)");
}

#[test]
fn json_contract() {
    let out = scan_json(r#"{"lines":[{"file":"a.ts","line":1,"content":"eval(x)"}]}"#);
    assert!(out.contains(r#""ruleId":"DANGEROUS_EVAL""#), "{out}");
    assert!(out.contains(r#""filePath":"a.ts""#));
    assert!(out.contains(r#""astFiles":["a.ts"]"#));
    assert!(scan_json("not json").contains("\"error\""));
}

#[test]
fn local_database_urls_are_not_secrets() {
    let out = scan_lines(&lines(
        "ci.yml",
        &[
            "DATABASE_URL: postgresql://codegate:codegate@127.0.0.1:5434/codegate_test",
            "url: postgres://app:s3cr3t@db.internal.example.com:5432/prod",
            "url: postgres://app:s3cr3t@db.acme-prod.io:5432/prod",
        ],
    ));
    let locations: Vec<_> = out.secrets.iter().map(|s| s.location.as_str()).collect();
    assert_eq!(locations, vec!["ci.yml:12"]);
}
