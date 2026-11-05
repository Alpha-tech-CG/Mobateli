//! The semantic taint engine.
//!
//! For each file we:
//!   1. parse with tree-sitter into a concrete syntax tree;
//!   2. compute the set of *tainted variables* by propagating taint through
//!      assignments to a fixpoint (so `a = source; b = a; sink(b)` is caught);
//!   3. visit every call/construction and, for each sink rule, test whether its
//!      first positional argument carries taint.
//!
//! This is real dataflow over the AST — a genuine step beyond the line-by-line
//! regex rules in apps/api/src/analysis/sast.ts — kept intraprocedural and
//! deliberately conservative to hold the false-positive rate down.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use tree_sitter::{Node, Parser};

use crate::finding::{Confidence, Finding};
use crate::lang::Language;
use crate::rules::{self, LangRules, SinkRule};

/// A file to analyze: a (virtual) path used for language detection and
/// reporting, plus its full text. Matches the `{ path, content }` JSON the
/// TypeScript adapter sends on stdin.
#[derive(Debug, Clone, Deserialize)]
pub struct FileInput {
    pub path: String,
    pub content: String,
}

/// Analyze a batch of in-memory files.
pub fn analyze_inputs(inputs: &[FileInput]) -> Vec<Finding> {
    let mut out = Vec::new();
    for input in inputs {
        out.extend(analyze_source(&input.path, &input.content));
    }
    out
}

/// Analyze one source string. Returns `[]` for an unsupported extension or an
/// unparseable file — the engine never errors on input, it just finds nothing.
pub fn analyze_source(path: &str, source: &str) -> Vec<Finding> {
    let Some(language) = Language::from_path(path) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&language.ts_language()).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let rules = rules::for_family(language.family());
    run(tree.root_node(), source, path, rules)
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

/// Push `node`'s children on `stack`. Uses a cursor: `Node::child(i)` is O(i)
/// in tree-sitter, so indexing every child of a node with many children (an
/// unclosed `[[[[…` yields 50 000 siblings) was quadratic.
fn push_children<'a>(node: Node<'a>, stack: &mut Vec<Node<'a>>) {
    let mut cursor = node.walk();
    stack.extend(node.children(&mut cursor));
}

/// Flatten the tree into a list of nodes (order irrelevant to the analysis).
fn descendants<'a>(root: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        push_children(node, &mut stack);
        out.push(node);
    }
    out
}

/// True when `node` is the property side of a member/attribute access (`.foo`),
/// so we don't treat `foo` in `obj.foo` as a variable reference.
fn is_property_identifier(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if !matches!(parent.kind(), "member_expression" | "attribute") {
        return false;
    }
    for field in ["property", "attribute"] {
        if let Some(prop) = parent.child_by_field_name(field) {
            if prop.id() == node.id() {
                return true;
            }
        }
    }
    false
}

/// Identifiers referenced in a subtree, excluding `.property` positions.
///
/// Linear in the subtree size: property positions are recorded while visiting
/// their member/attribute parent (pre-order), instead of calling
/// `Node::parent()` per identifier — tree-sitter's `parent()` walks down from
/// the root, which made a deeply nested expression (`a + b + c + …`) quadratic
/// and let a ~130 KiB file push the engine past the adapter's timeout.
fn referenced_idents(node: Node, source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut property_ids: HashSet<usize> = HashSet::new();
    let root_is_property = node.kind() == "identifier" && is_property_identifier(node);
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "member_expression" | "attribute") {
            for field in ["property", "attribute"] {
                if let Some(prop) = n.child_by_field_name(field) {
                    property_ids.insert(prop.id());
                }
            }
        }
        if n.kind() == "identifier"
            && !property_ids.contains(&n.id())
            && !(n.id() == node.id() && root_is_property)
        {
            out.insert(text(n, source).to_string());
        }
        push_children(n, &mut stack);
    }
    out
}

fn contains_source(text: &str, sources: &[&str]) -> bool {
    sources.iter().any(|s| text.contains(s))
}

/// The whole expression is a sanitizer call (`parseInt(x)`, `shlex.quote(x)`…).
fn is_sanitized(text: &str, sanitizers: &[&str]) -> bool {
    let t = text.trim_start();
    sanitizers
        .iter()
        .any(|s| t.starts_with(s) && t[s.len()..].trim_start().starts_with('('))
}

/// Is this expression tainted, given the current set of tainted variables?
fn expr_tainted(node: Node, source: &str, tainted: &HashSet<String>, rules: &LangRules) -> bool {
    let txt = text(node, source);
    if is_sanitized(txt, rules.sanitizers) {
        return false;
    }
    if contains_source(txt, rules.sources) {
        return true;
    }
    referenced_idents(node, source)
        .iter()
        .any(|id| tainted.contains(id))
}

/// Left-hand side variable name of an assignment node, if it is a plain
/// identifier (destructuring and member targets are not tracked in v1).
fn assign_target<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let target = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("left"))?;
    (target.kind() == "identifier").then_some(target)
}

fn assign_rhs<'a>(node: Node<'a>) -> Option<Node<'a>> {
    node.child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))
}

/// First positional argument of a call's `arguments` node (skips keyword
/// args like `shell=True` and comments). Checking only the first argument is
/// what distinguishes an injected query string from safely-bound parameters.
fn first_positional<'a>(args: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = args.walk();
    let found = args
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "keyword_argument" | "comment"));
    found
}

fn callee_matches(callee: &str, rule: &SinkRule) -> bool {
    rule.callee_equals.contains(&callee)
        || rule.callee_ends_with.iter().any(|e| callee.ends_with(e))
}

fn run(root: Node, source: &str, path: &str, rules: &LangRules) -> Vec<Finding> {
    let nodes = descendants(root);

    // --- Pass 1: compute tainted variables to a fixpoint. ---
    //
    // Worklist propagation, linear in the number of assignments: each
    // right-hand side is examined once (sanitizer / inline source / the
    // identifiers it references), then taint flows along the "variable →
    // assignments that read it" edges. Same result as re-scanning every
    // assignment until nothing changes, without the O(n²) passes a long chain
    // written in reverse order (`b = a;` before `a = source;`) used to cost.
    struct Assign {
        target: String,
        refs: HashSet<String>,
    }
    let mut assigns: Vec<Assign> = Vec::new();
    let mut tainted: HashSet<String> = HashSet::new();
    let mut work: Vec<String> = Vec::new();
    for n in nodes.iter().filter(|n| rules.assign_kinds.contains(&n.kind())) {
        let (Some(target), Some(rhs)) = (assign_target(*n), assign_rhs(*n)) else {
            continue;
        };
        let target = text(target, source).to_string();
        let rhs_text = text(rhs, source);
        if is_sanitized(rhs_text, rules.sanitizers) {
            continue; // a sanitized value never carries taint
        }
        if contains_source(rhs_text, rules.sources) {
            if tainted.insert(target.clone()) {
                work.push(target);
            }
            continue;
        }
        assigns.push(Assign {
            target,
            refs: referenced_idents(rhs, source),
        });
    }
    let mut readers: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, a) in assigns.iter().enumerate() {
        for r in &a.refs {
            readers.entry(r.as_str()).or_default().push(i);
        }
    }
    while let Some(var) = work.pop() {
        let Some(idxs) = readers.get(var.as_str()) else {
            continue;
        };
        for &i in idxs {
            let target = &assigns[i].target;
            if tainted.insert(target.clone()) {
                work.push(target.clone());
            }
        }
    }

    // --- Pass 2: check every call's first argument against each sink. ---
    let mut findings = Vec::new();
    let mut seen: HashSet<(&'static str, usize)> = HashSet::new();

    for node in &nodes {
        if !rules.call_kinds.contains(&node.kind()) {
            continue;
        }
        let Some(callee) = node
            .child_by_field_name("function")
            .or_else(|| node.child_by_field_name("constructor"))
        else {
            continue;
        };
        let callee_text = text(callee, source).trim();
        let Some(args) = node.child_by_field_name("arguments") else {
            continue;
        };
        let Some(arg0) = first_positional(args) else {
            continue;
        };
        // Built lazily: copying every call's text up front was quadratic for
        // deeply nested calls (`f(f(f(…)))`).
        let mut call_text_nospace: Option<String> = None;

        for rule in rules.sinks {
            if !callee_matches(callee_text, rule) {
                continue;
            }
            if let Some(req) = rule.require_contains {
                let nospace = call_text_nospace.get_or_insert_with(|| {
                    text(*node, source)
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect()
                });
                if !nospace.contains(req) {
                    continue;
                }
            }
            let arg_text = text(arg0, source);
            if !expr_tainted(arg0, source, &tainted, rules) {
                continue;
            }
            let line = node.start_position().row + 1;
            if !seen.insert((rule.id, line)) {
                continue;
            }
            // Inline source → High; reached through a variable binding → Medium.
            let confidence = if contains_source(arg_text, rules.sources) {
                Confidence::High
            } else {
                Confidence::Medium
            };
            findings.push(Finding {
                kind: "sast".to_string(),
                severity: rule.severity,
                title: rule.title.to_string(),
                description: rule.description.to_string(),
                file_path: Some(path.to_string()),
                line: Some(line),
                rule_id: Some(rule.id.to_string()),
                remediation: Some(rule.remediation.to_string()),
                cwe: Some(rule.cwe.to_string()),
                owasp: Some(rule.owasp.to_string()),
                confidence: Some(confidence),
            });
        }
    }

    findings
}
