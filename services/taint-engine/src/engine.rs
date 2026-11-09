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
/// The KEY part of a lookup, whose value does not flow into the result:
/// the arguments of `store.get(key)` / `names.slice(a, b)`, or the index of
/// `users[key]`. The receiver is kept, so the result is tainted exactly when
/// the receiver is (`p.get("x")` with `p` tainted still is;
/// `sessions.get(req.cookies.sid)` is not). Web/NoSQL profiles only.
fn lookup_key<'a>(node: Node<'a>, call_kinds: &[&str], source: &str, profile: &Profile) -> Option<Node<'a>> {
    if profile.lookups.is_empty() {
        return None;
    }
    match node.kind() {
        "subscript_expression" => return node.child_by_field_name("index"), // JS
        "subscript" => return node.child_by_field_name("subscript"),        // Python
        _ => {}
    }
    if !call_kinds.contains(&node.kind()) {
        return None;
    }
    let callee = node.child_by_field_name("function")?;
    let (_, method) = text(callee, source).trim().rsplit_once('.')?;
    if profile.lookups.contains(&method) {
        node.child_by_field_name("arguments")
    } else {
        None
    }
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
        if is_sanitizer_call(n, source, call_kinds, &profile.sanitizers) {
            let (a, b) = (n.start_byte() - start, n.end_byte() - start);
            if b <= masked.len() {
                masked[a..b].fill(b' ');
            }
            continue; // nothing inside a sanitizer call reaches the outside
        }
        if let Some(key) = lookup_key(n, call_kinds, source, profile) {
            // Mask the key; keep walking the receiver.
            let (a, b) = (key.start_byte() - start, key.end_byte() - start);
            if b <= masked.len() {
                masked[a..b].fill(b' ');
            }
            let key_id = key.id();
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                if child.id() != key_id {
                    stack.push(child);
                }
            }
            continue;
        }
        if matches!(n.kind(), "member_expression" | "attribute") {
            for field in ["property", "attribute"] {
                if let Some(prop) = n.child_by_field_name(field) {
                    property_ids.insert(prop.id());
                }
            }
        }
        // `{ email }` reads the variable `email` (shorthand property).
        if (n.kind() == "identifier" || n.kind() == "shorthand_property_identifier")
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

/// Variables bound by an assignment: a plain identifier, or every name a
/// destructuring pattern binds — `const { email, password } = req.body`,
/// `const [a, b] = x`, `{ id: userId, ...rest }`, Python `a, b = …`. Each
/// gets the right-hand side's taint (a sound over-approximation: we do not
/// track which property flows where). Member targets (`obj.x = …`) are not
/// variables and are skipped.
fn assign_targets<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let Some(target) = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("left"))
    else {
        return Vec::new();
    };
    if target.kind() == "identifier" {
        return vec![target];
    }
    if !matches!(
        target.kind(),
        "object_pattern" | "array_pattern" | "pattern_list" | "tuple_pattern" | "list_pattern"
    ) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut stack = vec![target];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => out.push(n),
            // `{ key: value }` binds `value`; the key is a property name.
            "pair_pattern" => {
                if let Some(v) = n.child_by_field_name("value") {
                    stack.push(v);
                }
            }
            // `{ a = default }` / `[a = default]` binds `a`, not the default.
            "assignment_pattern" | "object_assignment_pattern" => {
                if let Some(l) = n.child_by_field_name("left") {
                    stack.push(l);
                }
            }
            _ => push_children(n, &mut stack),
        }
    }
    out
}

fn assign_rhs<'a>(node: Node<'a>) -> Option<Node<'a>> {
    node.child_by_field_name("value")
        .or_else(|| node.child_by_field_name("right"))
}

/// First positional argument of a call's `arguments` node (skips keyword
/// args like `shell=True` and comments). Checking only the first argument is
/// what distinguishes an injected query string from safely-bound parameters.
fn first_positional<'a>(args: Node<'a>) -> Option<Node<'a>> {
    nth_positional(args, 0)
}

fn nth_positional<'a>(args: Node<'a>, n: usize) -> Option<Node<'a>> {
    let mut cursor = args.walk();
    let found = args
        .named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "keyword_argument" | "comment"))
        .nth(n);
    found
}

fn callee_matches(callee: &str, rule: &SinkRule) -> bool {
    rule.callee_equals.contains(&callee)
        || rule.callee_ends_with.iter().any(|e| callee.ends_with(e))
}

// ---------------------------------------------------------------------------
// Framework request parameters
// ---------------------------------------------------------------------------

/// HTTP verbs / routing methods a handler is registered with.
const ROUTE_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "all", "route", "api_route",
    "websocket",
];

/// Parameter names that are framework plumbing, never request input.
const PLUMBING_PARAMS: &[&str] = &[
    "self", "cls", "request", "req", "res", "response", "next", "reply", "ctx", "session",
    "db", "background_tasks", "current_user", "user",
];

/// Python annotation / default that marks a request-borne value.
fn python_param_is_input(annotation: Option<&str>, default: Option<&str>) -> bool {
    if let Some(d) = default {
        if d.contains("Depends(") || d.contains("Security(") {
            return false;
        }
        if ["Query(", "Path(", "Body(", "Form(", "Header(", "Cookie(", "File("]
            .iter()
            .any(|k| d.trim_start().starts_with(k))
        {
            return true;
        }
    }
    match annotation {
        // Flask/Django-style untyped route arguments are URL parts.
        None => true,
        Some(a) => {
            if a.contains("Depends") || a.contains("Security") {
                return false;
            }
            // `str`, `str | None`, `Optional[str]`, `list[str]`,
            // `Annotated[str, Query()]`; or a request-body model by naming
            // convention (`ItemCreate`, `UserUpdate`, `LoginPayload`…).
            let is_str = a
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|w| w == "str" || w == "Any");
            let last = a
                .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                .find(|w| !w.is_empty())
                .unwrap_or("");
            let body_model = ["Create", "Update", "In", "Body", "Payload", "Input", "Form", "Params"]
                .iter()
                .any(|s| last.len() > s.len() && last.ends_with(s));
            is_str || body_model || a.contains("Query(") || a.contains("Body(") || a.contains("Form(")
        }
    }
}

/// Request parameters of route handlers, as (function node, identifier).
///
/// * Python: parameters of functions decorated with `@app.get(...)`,
///   `@router.post(...)`, `@bp.route(...)`… (FastAPI, Flask) — typed `str`,
///   untyped (URL parts), `Query/Path/Body/Form(...)` defaults or a body model;
///   not `int`/`UUID` (validated by the framework) nor `Depends(...)`.
/// * JS/TS: a handler registered with `router.get(...)`-style calls whose
///   first parameter destructures `{ query, body, params, headers, cookies }`.
/// * NestJS: method parameters decorated `@Query`, `@Body`, `@Param`,
///   `@Headers`.
fn route_parameters<'a>(nodes: &[Node<'a>], source: &str) -> Vec<(Node<'a>, Node<'a>)> {
    let mut out = Vec::new();
    for node in nodes {
        match node.kind() {
            "decorated_definition" => {
                let mut cursor = node.walk();
                let is_route = node.children(&mut cursor).any(|d| {
                    d.kind() == "decorator" && {
                        let t = text(d, source);
                        ROUTE_METHODS.iter().any(|m| t.contains(&format!(".{m}(")))
                    }
                });
                let Some(func) = node.child_by_field_name("definition") else { continue };
                if !is_route || func.kind() != "function_definition" {
                    continue;
                }
                let Some(params) = func.child_by_field_name("parameters") else { continue };
                let mut pc = params.walk();
                for p in params.named_children(&mut pc) {
                    let (name, annotation, default) = match p.kind() {
                        "identifier" => (Some(p), None, None),
                        "typed_parameter" => (
                            p.named_child(0).filter(|c| c.kind() == "identifier"),
                            p.child_by_field_name("type"),
                            None,
                        ),
                        "default_parameter" => (p.child_by_field_name("name"), None, p.child_by_field_name("value")),
                        "typed_default_parameter" => (
                            p.child_by_field_name("name"),
                            p.child_by_field_name("type"),
                            p.child_by_field_name("value"),
                        ),
                        _ => (None, None, None),
                    };
                    let Some(name) = name.filter(|n| n.kind() == "identifier") else { continue };
                    if PLUMBING_PARAMS.contains(&text(name, source)) {
                        continue;
                    }
                    if python_param_is_input(annotation.map(|a| text(a, source)), default.map(|d| text(d, source))) {
                        out.push((func, name));
                    }
                }
            }
            // router.get("/x", ({ query, body }: Request, res) => …)
            "call_expression" => {
                let Some(callee) = node.child_by_field_name("function") else { continue };
                let callee = text(callee, source);
                let Some((_, method)) = callee.rsplit_once('.') else { continue };
                if !ROUTE_METHODS.contains(&method) && method != "use" {
                    continue;
                }
                let Some(args) = node.child_by_field_name("arguments") else { continue };
                let mut ac = args.walk();
                for handler in args.named_children(&mut ac) {
                    if !matches!(handler.kind(), "arrow_function" | "function_expression" | "function") {
                        continue;
                    }
                    let Some(params) = handler.child_by_field_name("parameters") else { continue };
                    let Some(first) = params.named_child(0) else { continue };
                    // TS wraps the pattern in required_parameter.
                    let pattern = first.child_by_field_name("pattern").unwrap_or(first);
                    if pattern.kind() != "object_pattern" {
                        continue;
                    }
                    let mut stack = vec![pattern];
                    while let Some(n) = stack.pop() {
                        match n.kind() {
                            "shorthand_property_identifier_pattern" => {
                                if ["query", "body", "params", "headers", "cookies"].contains(&text(n, source)) {
                                    out.push((handler, n));
                                }
                            }
                            "pair_pattern" => {
                                let key = n.child_by_field_name("key").map(|k| text(k, source));
                                if let (Some(k), Some(v)) = (key, n.child_by_field_name("value")) {
                                    if ["query", "body", "params", "headers", "cookies"].contains(&k) && v.kind() == "identifier" {
                                        out.push((handler, v));
                                    }
                                }
                            }
                            _ => push_children(n, &mut stack),
                        }
                    }
                }
            }
            // NestJS: @Query() q: string, @Body() dto, @Param('id') id
            "required_parameter" | "optional_parameter" => {
                let mut cursor = node.walk();
                let decorated = node.children(&mut cursor).any(|c| {
                    c.kind() == "decorator" && {
                        let t = text(c, source);
                        ["@Query", "@Body", "@Param", "@Headers"].iter().any(|d| t.starts_with(d))
                    }
                });
                if !decorated {
                    continue;
                }
                let Some(pattern) = node.child_by_field_name("pattern").filter(|p| p.kind() == "identifier") else {
                    continue;
                };
                // The enclosing method: parameters → formal_parameters → method.
                if let Some(method) = node.parent().and_then(|p| p.parent()) {
                    out.push((method, pattern));
                }
            }
            _ => {}
        }
    }
    out
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
    /// A framework-bound request parameter (route handler argument): an
    /// input by definition, whatever `rhs` says.
    forced: bool,
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
        if a.forced || d.has_source {
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
    // A same-site relative path ("/user/" + id): one leading slash followed
    // by a literal character — not "//host" (protocol-relative) nor "/\\".
    let mut chars = rest.chars();
    if chars.next() == Some('/') {
        if let Some(c) = chars.next() {
            if c != '/' && c != '\\' && c != '$' && c != '{' && c != '"' && c != '\'' && c != '`' {
                return true;
            }
        }
    }
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
        .flat_map(|n| {
            let rhs = assign_rhs(*n);
            let scope = scopes.of(*n);
            assign_targets(*n)
                .into_iter()
                .filter_map(move |t| {
                    Some(Assign {
                        scope,
                        target: text(t, source).to_string(),
                        rhs: rhs?,
                        forced: false,
                    })
                })
        })
        .chain(route_parameters(&nodes, source).into_iter().map(|(func, param)| Assign {
            scope: scopes.of(func),
            target: text(param, source).to_string(),
            rhs: param,
            forced: true,
        }))
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
        if first_positional(args).is_none() {
            continue;
        }
        let scope = scopes.of(*node);
        // Built lazily: copying every call's text up front was quadratic for
        // deeply nested calls (`f(f(f(…)))`).
        let mut call_text_nospace: Option<String> = None;

        for rule in rules.sinks {
            if !callee_matches(callee_text, rule) {
                continue;
            }
            // The argument this sink is dangerous in (usually the first).
            let Some(arg0) = nth_positional(args, rule.arg_index) else {
                continue;
            };
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
            let (profile, tainted) = &profiles[&rule.profile];
            // A wrapping call transforms the input (render, readFileSync)…
            // unless it is a lookup, whose result is its receiver's data.
            if rule.skip_call_arg
                && is_call_kind(arg0.kind())
                && lookup_key(arg0, rules.call_kinds, source, profile).is_none()
            {
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
            if !rule.skip_option_keys.is_empty()
                && orm_options_anywhere(args, source, rule.skip_option_keys)
            {
                continue; // e.g. res.sendFile(p, { root }) — confined
            }
            if rule.require_object_arg {
                // `find(filter)` where `filter = { … }` in a visible scope.
                let object = if arg0.kind() == "identifier" {
                    let name = text(arg0, source);
                    assigns
                        .iter()
                        .find(|a| {
                            a.target == name
                                && scopes.visible(a.scope, scope)
                                && matches!(a.rhs.kind(), "object" | "dictionary")
                        })
                        .map(|a| a.rhs)
                } else {
                    Some(arg0)
                };
                let Some(object) = object else {
                    continue;
                };
                if !is_filter_object(object, source, rule.skip_object_keys)
                    || orm_options_anywhere(args, source, rule.skip_object_keys)
                {
                    continue;
                }
            }
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
