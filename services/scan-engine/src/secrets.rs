//! Secret Shield (cahier §5.2). Mirrors apps/api/src/analysis/secret-scanner.ts.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::{AddedLine, Secret};

struct Pattern {
    kind: &'static str,
    regex: Regex,
    severity: &'static str,
}

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let p = |kind, re: &str, severity| Pattern { kind, regex: Regex::new(re).unwrap(), severity };
    vec![
        p("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b", "critical"),
        p("stripe_secret_key", r"\bsk_(live|test)_[0-9a-zA-Z]{16,}\b", "critical"),
        p("openai_api_key", r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b", "critical"),
        p("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "critical"),
        p("github_token", r"\b(ghp|gho|ghs|ghu)_[0-9A-Za-z]{36}\b", "critical"),
        p("github_pat", r"\bgithub_pat_[0-9A-Za-z_]{40,}\b", "critical"),
        p("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "high"),
        p("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "high"),
        p("private_key", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical"),
        p("postgres_url", r"\bpostgres(?:ql)?://[^\s:@]+:[^\s:@]+@[^\s/]+", "high"),
    ]
});

/// "key = 'value'" where the name hints at a secret.
static GENERIC_ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]([^'"]{8,})['"]"#,
    )
    .unwrap()
});

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in &chars {
        *freq.entry(*c).or_default() += 1;
    }
    let n = chars.len() as f64;
    freq.values().fold(0.0, |h, &count| {
        let p = count as f64 / n;
        h - p * p.log2()
    })
}

pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "****".into();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail} ({} chars)", chars.len())
}

pub fn scan(lines: &[AddedLine]) -> Vec<Secret> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for l in lines {
        let location = format!("{}:{}", l.file, l.line);
        for p in PATTERNS.iter() {
            if let Some(m) = p.regex.find(&l.content) {
                if seen.insert(format!("{}:{location}", p.kind)) {
                    out.push(Secret {
                        secret_type: p.kind.into(),
                        location: location.clone(),
                        masked_preview: mask(m.as_str()),
                        severity: p.severity,
                    });
                }
            }
        }
        if let Some(c) = GENERIC_ASSIGN.captures(&l.content) {
            let value = &c[2];
            // Only random-looking values (avoids "password = 'changeme'").
            if shannon_entropy(value) >= 3.5 && value.chars().count() >= 12 && seen.insert(format!("generic:{location}")) {
                out.push(Secret {
                    secret_type: format!("generic_{}", c[1].to_lowercase().replace(['_', '-'], "")),
                    location,
                    masked_preview: mask(value),
                    severity: "high",
                });
            }
        }
    }
    out
}
