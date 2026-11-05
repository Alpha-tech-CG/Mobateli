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
use crate::rules::{self, LangRules, ProfileKind, SinkRule};

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

fn contains_source(text: &str, sources: &[&str]) -> bool {
    sources.iter().any(|s| text.contains(s))
}

/// A call to a sanitizer (`parseInt(x)`, `path.basename(x)`, `shlex.quote(x)`).
fn is_sanitizer_call(node: Node, source: &str, call_kinds: &[&str], sanitizers: &[&str]) -> bool {
    if !call_kinds.contains(&node.kind()) {
        return false;
    }
    let Some(callee) = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("constructor"))
    else {
        return false;
    };
    let callee = text(callee, source).trim();
    sanitizers.iter().any(|s| {
        callee == *s
            || callee
                .strip_suffix(s)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// `store.get(key)` / `Model.findByPk(id)` whose receiver is not a source.
fn is_lookup_call(node: Node, source: &str, call_kinds: &[&str], profile: &Profile) -> bool {
    if profile.lookups.is_empty() || !call_kinds.contains(&node.kind()) {
        return false;
    }
    let Some(callee) = node.child_by_field_name("function") else {
        return false;
    };
    let callee = text(callee, source).trim();
    let Some((receiver, method)) = callee.rsplit_once('.') else {
        return false;
    };
    profile.lookups.contains(&method) && !contains_source(receiver, &profile.sources)
}

/// What an expression carries once its sanitized sub-expressions are set
/// aside: whether an untrusted source appears in it, and which variables it
/// reads. A sanitizer anywhere inside neutralizes only what it wraps —
/// `path.join(DIR, path.basename(req.query.f))` and
/// `` `<p>${escapeHtml(req.query.q)}</p>` `` are clean, `"a" + req.query.q` is not.
struct Digest {
    has_source: bool,
    refs: HashSet<String>,
}

///
/// Linear in the subtree size: property positions are recorded while visiting
/// their member/attribute parent (pre-order), instead of calling
/// `Node::parent()` per identifier — tree-sitter's `parent()` walks down from
/// the root, which made a deeply nested expression (`a + b + c + …`) quadratic
/// and let a ~130 KiB file push the engine past the adapter's timeout.
fn digest(node: Node, source: &str, call_kinds: &[&str], profile: &Profile) -> Digest {
    let start = node.start_byte();
    let mut masked: Vec<u8> = text(node, source).as_bytes().to_vec();
    let mut refs = HashSet::new();
    let mut property_ids: HashSet<usize> = HashSet::new();
    let root_is_property = node.kind() == "identifier" && is_property_identifier(node);
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if is_sanitizer_call(n, source, call_kinds, &profile.sanitizers)
            || is_lookup_call(n, source, call_kinds, profile)
        {
            let (a, b) = (n.start_byte() - start, n.end_byte() - start);
            if b <= masked.len() {
                masked[a..b].fill(b' ');
            }
            continue; // nothing inside a sanitizer call reaches the outside
        }
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
            refs.insert(text(n, source).to_string());
        }
        push_children(n, &mut stack);
    }
    let masked = String::from_utf8_lossy(&masked);
    Digest {
        has_source: contains_source(&masked, &profile.sources),
        refs,
    }
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

/// Function scopes of a tree: the scope of every node, and each scope's
/// enclosing scope. The root (module/program) is the outermost scope.
struct Scopes {
    of_node: HashMap<usize, usize>,
    parent: HashMap<usize, usize>,
}

impl Scopes {
    fn build(root: Node, kinds: &[&str]) -> Scopes {
        let mut of_node = HashMap::new();
        let mut parent = HashMap::new();
        let mut stack = vec![(root, root.id())];
        while let Some((node, scope)) = stack.pop() {
            let own = if node.id() != root.id() && kinds.contains(&node.kind()) {
                parent.insert(node.id(), scope);
                node.id()
            } else {
                scope
            };
            of_node.insert(node.id(), own);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                stack.push((child, own));
            }
        }
        Scopes { of_node, parent }
    }

    fn of(&self, node: Node) -> usize {
        self.of_node.get(&node.id()).copied().unwrap_or(0)
    }

    /// A binding made in `def` is visible from `user` when `def` is `user` or
    /// encloses it (lexical scoping, closures included).
    fn visible(&self, def: usize, mut user: usize) -> bool {
        loop {
            if user == def {
                return true;
            }
            match self.parent.get(&user) {
                Some(&p) => user = p,
                None => return false,
            }
        }
    }
}

/// A taint profile: which strings mark untrusted input and which calls
/// neutralize it. `Injection` uses every source; `Web` only request-borne ones.
struct Profile<'r> {
    sources: Vec<&'r str>,
    sanitizers: Vec<&'r str>,
    /// Lookup methods (`.get`, `.findByPk`…): a lookup KEYED by input returns
    /// server-side data (`sessions.get(req.cookies.sid)`), not the input —
    /// unless the receiver itself is a source (`request.args.get('url')`).
    lookups: Vec<&'r str>,
}

impl<'r> Profile<'r> {
    fn injection(rules: &'r LangRules) -> Self {
        Profile {
            sources: rules.sources.to_vec(),
            sanitizers: rules.sanitizers.to_vec(),
            lookups: Vec::new(),
        }
    }

    fn nosql(rules: &'r LangRules) -> Self {
        Profile {
            sources: rules
                .sources
                .iter()
                .copied()
                .filter(|s| !rules.cli_sources.contains(s) && !rules.string_sources.contains(s))
                .collect(),
            sanitizers: rules
                .sanitizers
                .iter()
                .chain(rules.nosql_sanitizers)
                .copied()
                .collect(),
            lookups: rules.lookups.to_vec(),
        }
    }

    fn of(kind: ProfileKind, rules: &'r LangRules) -> Self {
        match kind {
            ProfileKind::Injection => Profile::injection(rules),
            ProfileKind::Web => Profile::web(rules),
            ProfileKind::NoSql => Profile::nosql(rules),
        }
    }

    fn web(rules: &'r LangRules) -> Self {
        Profile {
            sources: rules
                .sources
                .iter()
                .copied()
                .filter(|s| !rules.cli_sources.contains(s))
                .collect(),
            sanitizers: rules
                .sanitizers
                .iter()
                .chain(rules.web_sanitizers)
                .copied()
                .collect(),
            lookups: rules.lookups.to_vec(),
        }
    }
}

/// One `name = rhs` binding.
struct Assign<'t> {
    scope: usize,
    target: String,
    rhs: Node<'t>,
}

/// Tainted `(scope, variable)` bindings under `profile`.
///
/// Worklist propagation, linear in the number of assignments: each right-hand
/// side was examined once (sanitizer / inline source / identifiers it reads),
/// then taint flows along "variable → assignments that read it" edges. Same
/// result as re-scanning every assignment until nothing changes, without the
/// O(n²) passes a long chain written in reverse order used to cost.
fn propagate(
    assigns: &[Assign],
    scopes: &Scopes,
    profile: &Profile,
    source: &str,
    call_kinds: &[&str],
) -> HashSet<(usize, String)> {
    let mut tainted: HashSet<(usize, String)> = HashSet::new();
    let mut work: Vec<(usize, String)> = Vec::new();
    let mut readers: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, a) in assigns.iter().enumerate() {
        let d = digest(a.rhs, source, call_kinds, profile);
        if d.has_source {
            let key = (a.scope, a.target.clone());
            if tainted.insert(key.clone()) {
                work.push(key);
            }
            continue;
        }
        for r in d.refs {
            readers.entry(r).or_default().push(i);
        }
    }
    while let Some((def_scope, var)) = work.pop() {
        let Some(idxs) = readers.get(var.as_str()) else {
            continue;
        };
        for &i in idxs {
            let a = &assigns[i];
            if scopes.visible(def_scope, a.scope) {
                let key = (a.scope, a.target.clone());
                if tainted.insert(key.clone()) {
                    work.push(key);
                }
            }
        }
    }
    tainted
}

/// Tainted bindings indexed by variable name → defining scopes.
type Tainted = HashMap<String, Vec<usize>>;

fn index_by_name(set: HashSet<(usize, String)>) -> Tainted {
    let mut out: Tainted = HashMap::new();
    for (scope, name) in set {
        out.entry(name).or_default().push(scope);
    }
    out
}

/// Is `name`, read from `scope`, bound to a tainted value?
fn var_tainted(tainted: &Tainted, scopes: &Scopes, scope: usize, name: &str) -> bool {
    tainted
        .get(name)
        .is_some_and(|defs| defs.iter().any(|def| scopes.visible(*def, scope)))
}

/// Is this expression (read from `scope`) tainted under `profile`?
/// Returns `Some(inline)` when tainted — `inline` if a source appears in the
/// expression itself rather than through a variable.
fn expr_taint(
    d: &Digest,
    scope: usize,
    tainted: &Tainted,
    scopes: &Scopes,
) -> Option<bool> {
    if d.has_source {
        return Some(true);
    }
    d.refs
        .iter()
        .any(|id| var_tainted(tainted, scopes, scope, id))
        .then_some(false)
}

/// The argument is a string/template literal whose literal prefix fixes the
/// scheme and host: `"https://api.example.com/v1?q=" + q`, or a template
/// `https://api.example.com/${path}` (host ends before the first `${`).
fn has_fixed_origin(arg_text: &str) -> bool {
    let t = arg_text.trim_start();
    let Some(rest) = t
        .strip_prefix('`')
        .or_else(|| t.strip_prefix('"'))
        .or_else(|| t.strip_prefix('\''))
        .or_else(|| t.strip_prefix("f\""))
        .or_else(|| t.strip_prefix("f'"))
    else {
        return false;
    };
    let Some(after_scheme) = rest
        .strip_prefix("https://")
        .or_else(|| rest.strip_prefix("http://"))
    else {
        return false;
    };
    // The host must be fully literal and terminated by a path/query/fragment
    // delimiter before any interpolation or the end of the literal.
    for (i, c) in after_scheme.char_indices() {
        match c {
            '/' | '?' | '#' => return i > 0,
            '$' | '{' | '`' | '"' | '\'' | '+' | '%' => return false,
            _ => {}
        }
    }
    false
}

/// An object/dict literal used as a query filter: not one whose top-level
/// keys mark an ORM's structured options (`{ where: … }`).
fn is_filter_object(node: Node, source: &str, skip_keys: &[&str]) -> bool {
    if !matches!(node.kind(), "object" | "dictionary") {
        return false;
    }
    let mut cursor = node.walk();
    let has_skipped_key = node.named_children(&mut cursor).any(|pair| {
        pair.child_by_field_name("key").is_some_and(|k| {
            let key = text(k, source).trim_matches(|c| c == '"' || c == '\'');
            skip_keys.contains(&key)
        })
    });
    !has_skipped_key
}

fn positional_count(args: Node) -> usize {
    let mut cursor = args.walk();
    let n = args
        .named_children(&mut cursor)
        .filter(|c| !matches!(c.kind(), "keyword_argument" | "comment"))
        .count();
    n
}

/// Any argument is an ORM options object (`Model.update(values, { where })`).
fn orm_options_anywhere(args: Node, source: &str, skip_keys: &[&str]) -> bool {
    let mut cursor = args.walk();
    let found = args.named_children(&mut cursor).any(|a| {
        matches!(a.kind(), "object" | "dictionary") && !is_filter_object(a, source, skip_keys)
    });
    found
}

fn is_call_kind(kind: &str) -> bool {
    matches!(kind, "call_expression" | "call" | "new_expression")
}

/// `x.startsWith(...)` / `x.startswith(...)`: (receiver identifier, method).
fn guard_call<'s>(node: Node, source: &'s str) -> Option<(&'s str, &'s str)> {
    let callee = node.child_by_field_name("function")?;
    if !matches!(callee.kind(), "member_expression" | "attribute") {
        return None;
    }
    let object = callee.child_by_field_name("object")?;
    let method = callee
        .child_by_field_name("property")
        .or_else(|| callee.child_by_field_name("attribute"))?;
    (object.kind() == "identifier").then(|| (text(object, source), text(method, source)))
}

fn run(root: Node, source: &str, path: &str, rules: &LangRules) -> Vec<Finding> {
    let nodes = descendants(root);
    let scopes = Scopes::build(root, rules.scope_kinds);

    // --- Pass 1: bindings, then tainted variables per profile. ---
    let assigns: Vec<Assign> = nodes
        .iter()
        .filter(|n| rules.assign_kinds.contains(&n.kind()))
        .filter_map(|n| {
            let target = assign_target(*n)?;
            let rhs = assign_rhs(*n)?;
            Some(Assign {
                scope: scopes.of(*n),
                target: text(target, source).to_string(),
                rhs,
            })
        })
        .collect();

    // One propagation per profile the sinks actually use.
    let mut profiles: HashMap<ProfileKind, (Profile, Tainted)> = HashMap::new();
    for rule in rules.sinks {
        profiles.entry(rule.profile).or_insert_with(|| {
            let p = Profile::of(rule.profile, rules);
            let t = index_by_name(propagate(&assigns, &scopes, &p, source, rules.call_kinds));
            (p, t)
        });
    }

    // Validation calls (`target.startsWith(ROOT)`), by scope.
    let mut guarded: Vec<(usize, &str, &str)> = Vec::new();
    for node in nodes.iter().filter(|n| rules.call_kinds.contains(&n.kind())) {
        if let Some((var, method)) = guard_call(*node, source) {
            guarded.push((scopes.of(*node), var, method));
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
        let scope = scopes.of(*node);
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
            if rule.skip_call_arg && is_call_kind(arg0.kind()) {
                continue;
            }
            if rule.skip_call_arg
                && arg0.kind() == "await_expression"
                && arg0.named_child(0).is_some_and(|c| is_call_kind(c.kind()))
            {
                continue;
            }
            if rule.skip_fixed_origin && has_fixed_origin(arg_text) {
                continue;
            }
            if rule.min_args > 0 && positional_count(args) < rule.min_args {
                continue;
            }
            if rule.require_object_arg
                && (!is_filter_object(arg0, source, rule.skip_object_keys)
                    || orm_options_anywhere(args, source, rule.skip_object_keys))
            {
                continue;
            }
            let (profile, tainted) = &profiles[&rule.profile];
            let d = digest(arg0, source, rules.call_kinds, profile);
            let Some(inline) = expr_taint(&d, scope, tainted, &scopes) else {
                continue;
            };
            if !rule.guards.is_empty() {
                let is_guarded = guarded.iter().any(|(g_scope, var, method)| {
                    rule.guards.contains(method)
                        && d.refs.contains(*var)
                        && (scopes.visible(*g_scope, scope) || scopes.visible(scope, *g_scope))
                });
                if is_guarded {
                    continue;
                }
            }
            // The argument's line: in a call spread over several lines it is
            // where the untrusted value actually is.
            let line = arg0.start_position().row + 1;
            if !seen.insert((rule.id, line)) {
                continue;
            }
            // Inline source → High; reached through a variable binding → Medium.
            let confidence = if inline {
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
